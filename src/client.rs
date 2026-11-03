//! HTTP client and session handling for the Wealthfront web app.
//!
//! # Status: login CAPTURED-LIVE and reachable by bare HTTP; reads VERIFIED-LIVE
//!
//! Wealthfront publishes no public API. First-party captures on 2026-08-13 and
//! 2026-08-18/19 settled the login endpoint, the API base, and the read paths.
//! A 2026-08-31 diagnosis (see below) corrected the login *request handling*:
//! the bare-HTTP `login()` here reaches credential validation without a browser.
//!
//! The failure modes are written to be loud. The alternative — endpoints that
//! look authoritative because they are spelled confidently — is how a
//! reverse-engineered CLI silently reports success for things that never
//! happened. See `docs/api.md` for the research behind each constant and the
//! owner's first-login checklist.
//!
//! The session mechanics (park-then-resume MFA, cookie write-back, HTML-means-
//! expired) are copied from the family's verified portal CLIs.
//!
//! # 2026-08-31 diagnosis — the login `login_xsrf` handshake
//!
//! The symptom: `wfr auth login --stdin` failed *immediately* with "Wealthfront
//! session expired or invalid" — a session error on a login command, even after
//! `logout`, even with a wrong password. Traced to two bugs working together:
//!
//! 1. **Wrong request shape.** `login()` POSTed a bare `{username, password}`
//!    with no prior `GET /login`, so the jar held no `login_xsrf` cookie and the
//!    body carried no `loginXsrf`. Wealthfront bounced it *before* checking
//!    credentials with HTTP 200 `{"redirectUrl":"/login","success":false}`.
//! 2. **Misclassification.** `classify_login` read that pre-auth bounce as
//!    a "logged in" outcome (it matched no rejection/MFA branch and
//!    fell through the old `status == 200 && !html` rule). `finish()` then read
//!    `/capitan/v1/me`, which 401s with no session — surfaced as "session
//!    expired". The error fired before any 2FA step because credentials were
//!    never actually checked.
//!
//! The fix: `login()` now primes `login_xsrf` via `GET /login`, sends it
//! **URL-decoded** in `loginXsrf`, and `classify_login` treats the pre-auth
//! bounce as an error rather than a session. A wrong password now yields
//! "Invalid email address or password" (a credentials error), which is the
//! distinction that localizes the bug.
//!
//! **reCAPTCHA is no longer a hard gate.** The earlier conclusion that a
//! browser-minted reCAPTCHA Enterprise token was mandatory is **wrong as of
//! 2026-08-31**: a tokenless bare-HTTP POST reaches credential validation. The
//! `--browser` path (`commands/auth.rs`, on `pk-cli-browser`) remains as a
//! reliable fallback if the reCAPTCHA score ever hardens on the *success* path.
//! See `docs/api.md` §3.1–3.2 and §3.6.

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

use pk_cli_core::CliError;
use pk_cli_secrets::{CredentialStore, Secret};
use reqwest::blocking::Client;
use reqwest::cookie::{CookieStore, Jar};
use serde_json::Value;

use crate::keychain::{PENDING_ACCOUNT, SESSION_ACCOUNT};

/// Keep the app host in one place; `docs/api.md` records why it is this host
/// and not `app.wealthfront.com`.
pub const BASE: &str = "https://www.wealthfront.com";

/// Every path this CLI uses, isolated so a live capture can correct them in
/// one diff and `docs/api.md` can cite them by name.
///
/// Confidence is not uniform, and the doc comments say which is which:
///
/// - The **UI routes** (`/login`, `/mfa`, `/transactions`, `/documents`) are
///   VERIFIED from public sources — they are real pages on the real site.
/// - [`TRANSFERS`] is the one API endpoint *name* anyone has published
///   (KrauseFx's 2021 tax exporter tells the reader to copy the
///   `transfers-for-account` XHR out of devtools). The name is VERIFIED; the
///   host, prefix, method and query parameters are not, and the capture is
///   ~4.5 years stale.
/// - [`LOGIN`] and the API base are **CAPTURED-LIVE** (2026-08-13): login is
///   `POST /api/access/login` and authenticated reads hang off `/capitan/v1/`
///   (the `/v1/…` guess 404s). The read *resource segments* under that base are
///   still guesses — the capture was blocked by reCAPTCHA before any
///   authenticated read fired.
/// - The rest is shaped by Wealthfront's engineering blog (a Swagger-generated
///   snake_case REST API) plus the captured base above.
///
/// Treat a 404 from any read path as the expected outcome until an
/// authenticated capture says otherwise.
pub mod endpoints {
    /// VERIFIED (public page). The login route.
    pub const LOGIN_PAGE: &str = "/login";
    /// VERIFIED (public page). MFA is a *distinct* route, so login is a
    /// two-step flow rather than one POST that sometimes wants a code.
    pub const MFA_PAGE: &str = "/mfa";

    /// CAPTURED-LIVE (2026-08-13, re-confirmed 2026-08-31). Credential
    /// submission is a single POST here. Its body carries `loginXsrf`,
    /// `username`, `password`, and (optionally) `maybeRecaptchaEnterpriseToken`,
    /// `sessionType`, `grantType`, `browserInfo`.
    ///
    /// **2026-08-31 correction:** the reCAPTCHA token is **not** required to
    /// reach credential validation. A bare-HTTP POST that carries the
    /// `loginXsrf` handshake (see [`LOGIN_PAGE`]) reaches "Invalid email address
    /// or password" on a wrong password — no browser-minted token needed. The
    /// one thing that *is* required is `loginXsrf`, sent **URL-decoded** to match
    /// the `login_xsrf` cookie set on `GET /login`; without it the server
    /// bounces the request to `/login` (`{"redirectUrl":"/login","success":
    /// false}`) *before* checking credentials. See `docs/api.md` §3.1.
    pub const LOGIN: &str = "/api/access/login";
    /// CAPTURED-LIVE (2026-08-31). Second-factor verification. There is **no**
    /// separate send/verify pair — the old `/api/access/mfa/send` and
    /// `/api/access/mfa/verify` guesses both **404 live**. The one live endpoint
    /// is `POST /api/access/mfa` (a no-session POST returns HTTP 200
    /// `{"tokenExpired":true,"success":false,"errorMessage":"Authorization
    /// expired. Try logging in again."}`, i.e. it exists and shares the login
    /// family's `success`/`errorMessage` envelope). The SMS is delivered as a
    /// side effect of a successful `POST /api/access/login`, so there is nothing
    /// to "send" separately. The request **body shape** (the code field name) is
    /// still UNVERIFIED-LIVE — it needs the owner's one real login to confirm.
    /// See `docs/api.md` §3.1.
    pub const VERIFY_CODE: &str = "/api/access/mfa";
    /// CAPTURED-LIVE (2026-08-18). The cheap authenticated read used to prove a
    /// session — returns `{fullName, emailAddress, userIdExternalized, …}`.
    pub const ME: &str = "/capitan/v1/me";
    /// CAPTURED-LIVE (2026-08-18). The account inventory —
    /// `{"overviews": [{accountId, accountType, accountDisplayName,
    /// accountValueSummary, …}]}`. The `filter_customer_account_states` query
    /// params the web app sends are optional (this bare path returns all
    /// accounts). See `commands/accounts.rs`.
    pub const ACCOUNTS: &str = "/capitan/v1/accounts/overviews2";

    /// CAPTURED-LIVE (2026-08-18). The account activity feed.
    ///
    /// `{"activities": [{type, headline, body, date, id, url, …}]}` — a display
    /// feed that mixes real transactions (`type` prefixed `TXN_`) with
    /// promotional/invite rows. Amounts are not structured; they live in the
    /// `body` sentence (see `commands/transactions.rs`). The 2021 KrauseFx
    /// `transfers-for-account` shape (dividends/trades) may still apply to
    /// *investment* accounts, but this owner has only cash accounts so it was
    /// not re-captured and stays UNVERIFIED-LIVE.
    pub const ACTIVITIES: &str = "/capitan/v1/activities?account_id={account}";

    /// CAPTURED-LIVE (2026-08-19). Statements and trade confirmations —
    /// `{"statements": [{accountId (numeric), type, date, externalId}]}`. This
    /// Rails endpoint (not `/capitan/`) carries the **numeric** `accountId` the
    /// download URL needs; the `/capitan/v1/documents/account-statements`
    /// equivalent returns the `ACCA-…` id instead, which the download rejects.
    /// (`/capitan/v1/documents/user` is the separate, usually-empty tax-form
    /// index.)
    pub const DOCUMENTS: &str = "/api/documents/statements";
    /// CAPTURED-LIVE (2026-08-19). Single document bytes, gated on `%PDF`.
    /// `{account}` is the **numeric** `accountId` and `{id}` the `externalId`,
    /// both from a `DOCUMENTS` record.
    pub const DOCUMENT: &str = "/documents/{account}/document/{id}";
}

/// Where a second factor comes from.
///
/// SMS and TOTP are the two factors Wealthfront documents publicly, and 2FA
/// is **mandatory** on every account — there is no path that skips it. Email
/// is deliberately absent: it appears in Wealthfront's help centre only for
/// account *recovery*, never as a login factor, so offering it here would
/// invite the user to request something that does not exist.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum CodeChannel {
    /// A texted code. Costs a message and is rate-limited.
    Sms,
    /// An authenticator app (Google Authenticator, Duo, 1Password). No code is
    /// sent — the user reads it from the app, so it is free to retry.
    Totp,
}

impl CodeChannel {
    pub fn wire(self) -> &'static str {
        match self {
            CodeChannel::Sms => "SMS",
            CodeChannel::Totp => "TOTP",
        }
    }

    /// True when asking for this factor costs a delivered message. TOTP codes
    /// are generated locally, so they are free and unlimited; SMS and email
    /// are rate-limited and should never be spent by a test.
    pub fn costs_a_message(self) -> bool {
        !matches!(self, CodeChannel::Totp)
    }
}

/// Rewrites the stored session whenever the site rotates it, so the cached
/// copy never goes stale while the provider still considers us logged in.
struct SessionSync {
    creds: CredentialStore,
    last: RefCell<String>,
}

pub struct Wf {
    http: Client,
    jar: Arc<Jar>,
    sync: Option<SessionSync>,
    base: String,
}

/// The base URL for this process: [`BASE`], unless `WFR_BASE_URL` points at a
/// **loopback** address. The override exists solely so offline tests can stand
/// up a fake server on 127.0.0.1 and drive the real login code path; anything
/// non-loopback is refused outright, because an ambient env var that silently
/// redirects a credential-bearing login POST to another host would be an
/// exfiltration hole, not a feature.
fn resolved_base() -> Result<String, CliError> {
    base_from(std::env::var("WFR_BASE_URL").ok().as_deref())
}

/// The check behind [`resolved_base`], on the `WFR_BASE_URL` value passed in
/// rather than read, so tests run it without touching the process
/// environment. `None` or a blank value is [`BASE`].
fn base_from(env_override: Option<&str>) -> Result<String, CliError> {
    match env_override {
        Some(v) if !v.trim().is_empty() => {
            let v = v.trim().trim_end_matches('/').to_string();
            let refuse = || {
                CliError::Usage(
                    "WFR_BASE_URL must be a plain http(s) URL on a loopback address — it \
                     exists only for offline tests, never to redirect a real login"
                        .into(),
                )
            };
            // A real URL parser, not a hand-rolled authority split: the naive
            // split read `http://127.0.0.1:1@evil.example.com` as host
            // `127.0.0.1`, while the HTTP stack treats `127.0.0.1:1` as
            // userinfo and connects to `evil.example.com` (PR #10 review
            // finding). Userinfo is refused outright — no test needs it, and
            // in a URL like this it exists mainly to spoof validators.
            let parsed = url::Url::parse(&v).map_err(|_| refuse())?;
            let loopback = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
            let plain = matches!(parsed.scheme(), "http" | "https")
                && parsed.username().is_empty()
                && parsed.password().is_none();
            if loopback && plain {
                Ok(v)
            } else {
                Err(refuse())
            }
        }
        _ => Ok(BASE.to_string()),
    }
}

impl Wf {
    pub fn new() -> Result<Self, CliError> {
        Self::with_base(resolved_base()?)
    }

    /// Build a client against an explicit base URL. Production callers go
    /// through [`Wf::new`]; this seam exists for the loopback fake-server unit
    /// tests (the same pattern as sofi-cli's `with_base`).
    fn with_base(base: String) -> Result<Self, CliError> {
        let jar = Arc::new(Jar::default());
        let http = pk_cli_http::builder("wfr", env!("CARGO_PKG_VERSION"))
            .cookie_provider(jar.clone())
            .timeout(Duration::from_secs(45))
            .build()
            .map_err(|e| CliError::Upstream(format!("building HTTP client: {e}")))?;
        Ok(Wf {
            http,
            jar,
            sync: None,
            base,
        })
    }

    /// Build a client from the cached session, ready to make authenticated
    /// reads and to write back a rotated cookie.
    pub fn from_cached_session(creds: &CredentialStore) -> Result<Self, CliError> {
        let session = creds.get(SESSION_ACCOUNT)?.ok_or_else(|| {
            CliError::Auth("no Wealthfront session stored — run `wfr auth login`".into())
        })?;
        let mut wf = Wf::new()?;
        wf.seed(session.expose());
        wf.sync = Some(SessionSync {
            creds: CredentialStore::new(creds.service()),
            last: RefCell::new(session.expose().to_string()),
        });
        Ok(wf)
    }

    /// Build a client seeded with a freshly-captured cookie bundle (from the
    /// browser login), so the caller can validate it before persisting.
    pub(crate) fn from_bundle(bundle: &str) -> Result<Self, CliError> {
        Self::from_bundle_at(resolved_base()?, bundle)
    }

    /// [`Wf::from_bundle`] against an explicit base URL, so a unit test can
    /// point the browser login's confirm read at a loopback server without
    /// setting `WFR_BASE_URL`, which every test in the process shares.
    pub(crate) fn from_bundle_at(base: String, bundle: &str) -> Result<Self, CliError> {
        let wf = Wf::with_base(base)?;
        wf.seed(bundle);
        Ok(wf)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// Load a parked or cached cookie bundle (`"k=v; k=v"`) into the jar.
    fn seed(&self, bundle: &str) {
        let url = self.base.parse().expect("base is a valid URL");
        // `Secure` is right for the real https site; the loopback test base is
        // plain http, where a Secure cookie would be withheld by the jar.
        let attrs = if self.base.starts_with("https://") {
            "; Path=/; Secure"
        } else {
            "; Path=/"
        };
        for pair in bundle.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            self.jar.add_cookie_str(&format!("{pair}{attrs}"), &url);
        }
    }

    /// The current cookie header, or `None` when the jar holds nothing.
    fn bundle(&self) -> Option<Secret> {
        let url = self.base.parse().ok()?;
        let header = self.jar.cookies(&url)?;
        let raw = header.to_str().ok()?;
        (!raw.is_empty()).then(|| Secret::new(raw.to_string()))
    }

    /// The `x-csrf-token` header the authenticated API requires.
    ///
    /// CAPTURED-LIVE (2026-08-18): every authenticated `/capitan/` request the
    /// web app makes carries `x-csrf-token`, whose value is the `xsrf` cookie
    /// **URL-decoded** (the cookie is percent-encoded base64). Without it the
    /// server answers 401 even with a perfectly good session cookie — this is
    /// the single reason a cookies-only client fails. See `docs/api.md` §4.
    fn csrf_token(&self) -> Option<String> {
        let bundle = self.bundle()?;
        bundle
            .expose()
            .split(';')
            .filter_map(|p| p.trim().strip_prefix("xsrf="))
            .next()
            .map(percent_decode)
    }

    /// The `loginXsrf` body value the login POST requires.
    ///
    /// CAPTURED-LIVE (2026-08-31): `GET /login` sets a `login_xsrf` cookie
    /// (HttpOnly, percent-encoded base64). The login POST must echo it back
    /// **URL-decoded** in its `loginXsrf` field; a mismatch (or a missing value)
    /// bounces the request to `/login` before credentials are checked. This is
    /// the exact same percent-decode the authenticated `xsrf`/`x-csrf-token`
    /// pair needs (`csrf_token`), just for the login handshake.
    fn login_xsrf(&self) -> Option<String> {
        let bundle = self.bundle()?;
        bundle
            .expose()
            .split(';')
            .filter_map(|p| p.trim().strip_prefix("login_xsrf="))
            .next()
            .map(percent_decode)
    }

    /// Attach the CSRF header when the jar carries an `xsrf` cookie.
    fn with_csrf(
        &self,
        rb: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        match self.csrf_token() {
            Some(t) => rb.header("x-csrf-token", t),
            None => rb,
        }
    }

    /// The session to persist after a successful login.
    ///
    /// UNVERIFIED-LIVE: with no capture, we cannot yet name *which* cookie
    /// authenticates, so this keeps the whole jar rather than filtering to a
    /// known-good subset the way the verified family CLIs do. Narrow this once
    /// a capture identifies the session cookie — storing the full jar keeps
    /// more than it needs to.
    pub fn session_bundle(&self) -> Option<Secret> {
        self.bundle()
    }

    /// The in-flight session that owns a pending MFA code.
    pub fn pending_bundle(&self) -> Option<Secret> {
        self.bundle()
    }

    /// Resume a parked login so a code is presented to the session that asked
    /// for it.
    pub fn resume_pending(&self, bundle: &str) {
        self.seed(bundle);
    }

    /// Persist a rotated session. Best-effort: a keychain failure here must
    /// not fail the read the caller actually asked for.
    fn sync_session(&self) {
        let Some(sync) = &self.sync else { return };
        let Some(current) = self.bundle() else { return };
        let current = current.expose().to_string();
        if *sync.last.borrow() == current {
            return;
        }
        if sync
            .creds
            .set(SESSION_ACCOUNT, &Secret::new(current.clone()))
            .is_ok()
        {
            *sync.last.borrow_mut() = current;
        }
    }

    pub fn get_json(&self, path: &str) -> Result<Value, CliError> {
        self.read_json(path).map_err(CliError::from)
    }

    /// [`Wf::get_json`], saying whether an edge block answered.
    fn read_json(&self, path: &str) -> Result<Value, ReadError> {
        let req = self
            .http
            .get(self.url(path))
            .header("Accept", "application/json");
        let resp = self
            .with_csrf(req)
            .send()
            .map_err(|e| ReadError::NoAnswer(e.into()))?;
        let out = self.read_response(resp, path);
        if out.is_ok() {
            self.sync_session();
        }
        out
    }

    /// `GET /capitan/v1/me`, the session check every sign-in and
    /// `auth status --verify` makes. Only an answer showing an account counts as
    /// signed in.
    /// Any other 200 is an upstream error here (a visitor gets 401
    /// `AUTHENTICATION_REQUIRED`), since a status code alone is never success.
    pub fn me(&self) -> Result<Value, CliError> {
        self.read_me().map_err(CliError::from)
    }

    /// [`Wf::me`], typed for a sign-in's hook. A 2xx alone is not acceptance: the
    /// answer must hold an account, by value.
    pub fn read_me(&self) -> Result<Value, ReadError> {
        let me = self.read_json(endpoints::ME)?;
        if shows_an_account(&me) {
            return Ok(me);
        }
        let kind = match &me {
            Value::Object(fields) if !fields.is_empty() => "an object with no account in it",
            other => json_kind(other),
        };
        let error = CliError::Upstream(format!(
            "Wealthfront answered {} with {kind} where the account object was expected",
            endpoints::ME,
        ));
        // `parse_json` reads an empty body as null, so a literal null reads the same.
        Err(if me.is_null() {
            ReadError::Empty(error)
        } else {
            ReadError::NoAccount(error)
        })
    }

    pub fn post_json(&self, path: &str, body: &Value) -> Result<Value, CliError> {
        let req = self
            .http
            .post(self.url(path))
            .header("Accept", "application/json")
            .json(body);
        let resp = self.with_csrf(req).send()?;
        let out = self.handle(resp, path);
        if out.is_ok() {
            self.sync_session();
        }
        out
    }

    /// Raw authenticated passthrough for `wfr api <METHOD> <PATH>`.
    ///
    /// This is the command that matters most while the surface is
    /// UNVERIFIED-LIVE: it is how the owner discovers the real shapes without
    /// leaving the CLI, and every mapping in `src/commands/` is meant to be
    /// corrected from what this prints.
    pub fn api(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, CliError> {
        let mut req = self
            .http
            .request(method, self.url(path))
            .header("Accept", "application/json");
        if let Some(b) = body {
            req = req.json(&b);
        }
        let out = self.handle(self.with_csrf(req).send()?, path);
        if out.is_ok() {
            self.sync_session();
        }
        out
    }

    /// Fetch document bytes, refusing anything that isn't actually a file.
    ///
    /// The magic-number check is the positive confirmation signal: an expired
    /// session answers a download with a 200 and a login page, and a CLI that
    /// trusts the status code writes that HTML to `statement.pdf` and reports
    /// success. Verifying `%PDF` means a download either produces a real
    /// document or an error — never a lie.
    pub fn download(&self, path: &str) -> Result<Vec<u8>, CliError> {
        let req = self
            .http
            .get(self.url(path))
            .header("Accept", "application/pdf");
        let resp = self.with_csrf(req).send()?;
        let status = resp.status();
        let final_url = resp.url().to_string();
        if is_login_url(&final_url) {
            return Err(expired());
        }
        if status.as_u16() == 401 {
            return Err(expired());
        }
        if status.as_u16() == 403 {
            return Err(refused(&resp.text().unwrap_or_default(), None).into());
        }
        if status.as_u16() == 404 {
            return Err(CliError::NotFound(format!("{path} (HTTP 404)")));
        }
        let bytes = resp
            .bytes()
            .map_err(|e| CliError::Upstream(format!("reading document body: {e}")))?
            .to_vec();
        if !status.is_success() {
            return Err(CliError::Upstream(format!(
                "Wealthfront returned HTTP {} for {path}",
                status.as_u16()
            )));
        }
        confirm_document(&bytes, path)?;
        self.sync_session();
        Ok(bytes)
    }

    /// Submit credentials to [`endpoints::LOGIN`] (`/api/access/login`,
    /// CAPTURED-LIVE).
    ///
    /// The request carries the **`login_xsrf` handshake**: `GET /login` first,
    /// to seed the `login_xsrf` cookie, then a POST whose `loginXsrf` field is
    /// that cookie **URL-decoded** (see [`login_xsrf`](Self::login_xsrf)).
    /// Without it the server bounces to `/login` before checking credentials —
    /// the bug that made a wrong password look like an expired session
    /// (docs/api.md §3.1). No reCAPTCHA token is sent: as of 2026-08-31 a
    /// tokenless POST reaches credential validation.
    ///
    /// Returns `Ok(())` — "credentials accepted, second factor next" — only on a
    /// positive signal: an explicit MFA marker, or `success:true` (2FA is
    /// mandatory on every Wealthfront account, so accepted credentials always
    /// mean "code next"). Never on a bare 200: a rejected login also answers 200,
    /// and treating that as "needs a code" makes the CLI prompt for a code nobody
    /// sent.
    pub fn login(&self, username: &str, password: &Secret) -> Result<(), CliError> {
        // Prime the `login_xsrf` cookie. The login POST must echo it back or the
        // server bounces the request before it ever looks at the credentials.
        self.http
            .get(self.url(endpoints::LOGIN_PAGE))
            .header("Accept", "text/html")
            .send()
            .map_err(|e| CliError::Upstream(format!("priming the login page: {e}")))?;
        let login_xsrf = self.login_xsrf().ok_or_else(|| {
            CliError::Upstream(
                "Wealthfront set no login_xsrf cookie on GET /login — the login handshake \
                 changed; re-capture per docs/api.md §3.1"
                    .into(),
            )
        })?;
        // Fields mirror the web client. `maybeRecaptchaEnterpriseToken` is sent
        // null: proven optional for credential validation on 2026-08-31, and the
        // CLI cannot mint one anyway (that is what `--browser` is for).
        let body = serde_json::json!({
            "loginXsrf": login_xsrf,
            "username": username,
            "password": password.expose(),
            "maybeRecaptchaEnterpriseToken": Value::Null,
            "sessionType": "WEB",
            "grantType": "password",
            "browserInfo": {},
        });
        let resp = self
            .http
            .post(self.url(endpoints::LOGIN))
            .header("Accept", "application/json")
            .header("Origin", self.base.clone())
            .header("Referer", self.url(endpoints::LOGIN_PAGE))
            .json(&body)
            .send()?;
        let status = resp.status();
        let text = resp
            .text()
            .map_err(|e| CliError::Upstream(format!("reading login response: {e}")))?;
        classify_login(status.as_u16(), &text)
    }

    /// Ask for a second-factor code.
    ///
    /// A no-op for both channels. TOTP is read from the user's authenticator;
    /// the SMS is delivered as a side effect of a successful `POST
    /// /api/access/login` (CAPTURED-LIVE 2026-08-31: the old
    /// `/api/access/mfa/send` endpoint 404s — there is no separate send step).
    /// Kept so the login flow reads clearly and so a future resend has a home.
    pub fn send_code(&self, _channel: CodeChannel) -> Result<(), CliError> {
        Ok(())
    }

    /// Submit a second-factor code to [`endpoints::VERIFY_CODE`]
    /// (`/api/access/mfa`). The endpoint is CAPTURED-LIVE; the request body
    /// (the code field name) is UNVERIFIED-LIVE — the owner's one real login
    /// confirms it. A wrong shape yields "not accepted" rather than a false
    /// success, so it never lies (it does spend the code — docs/api.md §3.1).
    pub fn verify_code(&self, code: &str, channel: CodeChannel) -> Result<(), CliError> {
        let body = serde_json::json!({ "code": code, "channel": channel.wire() });
        let v = self.post_json(endpoints::VERIFY_CODE, &body)?;
        // Require an explicit positive signal from the response envelope.
        //
        // NOT `session_bundle().is_some()`: `GET /login` already seeded a
        // `t-token` cookie, so the jar is *never* empty — that fallback would
        // report success for every rejected code, then fail confusingly at the
        // `/capitan/v1/me` read in `finish`. The `/api/access/mfa` envelope
        // reports `success` (a no-session probe returns `success:false`), so a
        // real accept is `success:true`; `authenticated:true` is also honored in
        // case the field name differs.
        let ok = v.get("authenticated").and_then(Value::as_bool) == Some(true)
            || v.get("success").and_then(Value::as_bool) == Some(true);
        if !ok {
            let detail = v
                .get("errorMessage")
                .and_then(Value::as_str)
                .map(|m| format!(" ({m})"))
                .unwrap_or_default();
            return Err(CliError::Auth(format!(
                "verification code was not accepted{detail}"
            )));
        }
        Ok(())
    }

    /// Map a response onto the family exit codes.
    fn handle(&self, resp: reqwest::blocking::Response, path: &str) -> Result<Value, CliError> {
        self.read_response(resp, path).map_err(CliError::from)
    }

    /// [`Wf::handle`], typed for a sign-in's hook.
    fn read_response(
        &self,
        resp: reqwest::blocking::Response,
        path: &str,
    ) -> Result<Value, ReadError> {
        let said = pk_cli_http::inconclusive(&resp);
        let retry_after = said.as_ref().and_then(|said| said.retry_after);
        let status = resp.status().as_u16();
        let judged = self.judge_response(resp, path, retry_after);
        match judged {
            Err(ReadError::Failed(error)) if said.is_some() => Err(ReadError::Inconclusive {
                status,
                retry_after,
                error,
            }),
            judged => judged,
        }
    }

    fn judge_response(
        &self,
        resp: reqwest::blocking::Response,
        path: &str,
        retry_after: Option<Duration>,
    ) -> Result<Value, ReadError> {
        let status = resp.status();
        let final_url = resp.url().to_string();
        if is_login_url(&final_url) {
            return Err(expired().into());
        }
        if status.as_u16() == 401 {
            return Err(expired().into());
        }
        if status.as_u16() == 403 {
            return Err(refused(&resp.text().unwrap_or_default(), retry_after));
        }
        if status.as_u16() == 404 {
            return Err(CliError::NotFound(format!("{path} (HTTP 404)")).into());
        }
        if status.as_u16() == 429 {
            return Err(CliError::Upstream(format!(
                "Wealthfront rate-limited {path} (HTTP 429) — wait before retrying"
            ))
            .into());
        }
        let text = resp.text().map_err(|e| {
            ReadError::NoAnswer(CliError::Upstream(format!("reading response body: {e}")))
        })?;
        if !status.is_success() {
            return Err(CliError::Upstream(format!(
                "Wealthfront HTTP {} for {path}",
                status.as_u16()
            ))
            .into());
        }
        let html = text.trim_start().starts_with('<');
        if html && html_reads_as_edge_block(&text) {
            return Err(ReadError::EdgeBlock {
                status: status.as_u16(),
                retry_after,
            });
        }
        parse_json(&text, path).map_err(|e| {
            if html {
                ReadError::Failed(e)
            } else {
                ReadError::NotJson(e)
            }
        })
    }
}

/// Whether `GET /capitan/v1/me` shows an account, by value: a non-empty
/// `emailAddress` or `userIdExternalized`, the fields [`endpoints::ME`] records.
fn shows_an_account(me: &Value) -> bool {
    ["emailAddress", "userIdExternalized"]
        .iter()
        .any(|field| matches!(me.get(field), Some(Value::String(v)) if !v.trim().is_empty()))
}

/// Landing on a login/auth URL is the real expiry signal for a cookie-session
/// web app: it answers an XHR with a redirect to the sign-in page, not a 401.
///
/// `/mfa` counts too — a session that has gone stale enough to need a fresh
/// second factor is, from the CLI's point of view, exactly as unusable as one
/// bounced to `/login`.
fn is_login_url(url: &str) -> bool {
    [
        endpoints::LOGIN_PAGE,
        endpoints::MFA_PAGE,
        "/signin",
        "/sign_in",
    ]
    .iter()
    .any(|p| url.contains(p))
}

/// Percent-decode the `xsrf` cookie into the `x-csrf-token` header value.
///
/// The cookie is percent-encoded base64 (e.g. `%2F` `%2B` `%3D`); the header is
/// the decoded form. A full URL-decoder would be overkill and a new dependency,
/// so this handles exactly the `%XX` escapes the cookie uses.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn expired() -> CliError {
    CliError::Auth("Wealthfront session expired or invalid — run `wfr auth login`".into())
}

/// Why a read returned no data, typed where a sign-in's hook acts on the kind. Each
/// variant holds what a command reports; the hook words its reason from fixed parts.
#[derive(Debug)]
pub enum ReadError {
    /// A bot check or an edge block's HTML page (exit 3, as any refusal is).
    EdgeBlock {
        status: u16,
        retry_after: Option<Duration>,
    },
    /// Any other answer whose status says nothing about the session
    /// ([`pk_cli_http::inconclusive`]): a throttle or a server error.
    Inconclusive {
        status: u16,
        retry_after: Option<Duration>,
        error: CliError,
    },
    /// No answer: the connection failed or dropped.
    NoAnswer(CliError),
    /// A 2xx that is not JSON. Its text holds the body's first bytes.
    NotJson(CliError),
    /// A 2xx with nothing in it.
    Empty(CliError),
    /// A parseable answer with no account in it.
    NoAccount(CliError),
    Failed(CliError),
}

impl From<CliError> for ReadError {
    fn from(e: CliError) -> Self {
        ReadError::Failed(e)
    }
}

impl From<ReadError> for CliError {
    fn from(e: ReadError) -> Self {
        match e {
            ReadError::EdgeBlock { status, .. } => edge_block(status),
            ReadError::Inconclusive { error, .. }
            | ReadError::NoAnswer(error)
            | ReadError::NotJson(error)
            | ReadError::Empty(error)
            | ReadError::NoAccount(error)
            | ReadError::Failed(error) => error,
        }
    }
}

/// A 403: exit 3, as any refusal is. An HTML page is an edge's answer, so it reads
/// as a possible bot check; otherwise it could be either.
fn refused(body: &str, retry_after: Option<Duration>) -> ReadError {
    if body.trim_start().starts_with('<') {
        return ReadError::EdgeBlock {
            status: 403,
            retry_after,
        };
    }
    CliError::Auth(
        "Wealthfront refused the request (HTTP 403): the session may be invalid, or this may be \
         a bot check or edge block. If a sign-in just met this, wait before trying again, \
         since a retry now may hit the same block; otherwise run `wfr auth login \
         --browser`"
            .into(),
    )
    .into()
}

/// An HTML page from the edge where data was expected: a possible bot check, which
/// a fresh sign-in may run straight into. Exit 3, as any refusal is, but not worded
/// as an expired session. It names the status only, never the page.
fn edge_block(status: u16) -> CliError {
    CliError::Auth(format!(
        "Wealthfront answered with an HTML page (HTTP {status}): possibly a bot check or edge \
         block, not an expired session. A new sign-in may not clear it, because the block is \
         on the client rather than the session. Wait or try another network, then run `wfr auth \
         login --browser`"
    ))
}

/// Whether an HTML page reads as a bot check or an edge block rather than a login
/// page: a challenge's own wording, in the `<title>`, which must open in the first
/// 8 KiB. Only the title counts, since a login page's body or scripts may hold the
/// same words, and so may its own reCAPTCHA or Turnstile.
fn html_reads_as_edge_block(text: &str) -> bool {
    let head = String::from_utf8_lossy(&text.as_bytes()[..text.len().min(8192)]).to_lowercase();
    let Some(open) = head.find("<title") else {
        return false;
    };
    let Some(start) = head[open..].find('>') else {
        return false;
    };
    let title = head[open + start + 1..]
        .split("</title")
        .next()
        .unwrap_or_default();
    ["just a moment", "attention required", "access denied"]
        .iter()
        .any(|marker| title.contains(marker))
}

/// What a JSON value is, for an error that must name the shape it got but
/// never its content. [`parse_json`] reads an empty body as `null`.
fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "an empty body or null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(fields) if fields.is_empty() => "an empty object",
        Value::Object(_) => "an object",
    }
}

/// Parse a body as JSON, reading an HTML body as session expiry.
fn parse_json(text: &str, path: &str) -> Result<Value, CliError> {
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(text).map_err(|_| {
        if text.trim_start().starts_with('<') {
            CliError::Auth(
                "Wealthfront returned HTML where JSON was expected (session expired) — \
                 run `wfr auth login`"
                    .into(),
            )
        } else {
            CliError::Upstream(format!(
                "Wealthfront returned non-JSON for {path} (first bytes: {:?})",
                text.chars().take(60).collect::<String>()
            ))
        }
    })
}

/// Decide what a login response means without trusting the status code.
///
/// Split out as a free function so the decision table is unit-testable with no
/// network — which matters here, because `/api/access/login` answers **HTTP 200
/// for every outcome** (credential failure, bot-check failure, pre-auth bounce,
/// and success alike), so the status code carries almost no information.
///
/// The branch order is load-bearing; see the inline notes. The two branches
/// added on 2026-08-31 (credential-failure text and the pre-auth bounce) are
/// what stop a wrong password from masquerading as an expired session.
///
/// `Ok(())` means "credentials accepted, second factor required" — there is no
/// verified no-MFA success path on Wealthfront (2FA is mandatory), so the caller
/// always proceeds to the code step.
fn classify_login(status: u16, body: &str) -> Result<(), CliError> {
    if status == 429 {
        return Err(CliError::Upstream(
            "Wealthfront rate-limited the login (HTTP 429) — wait before retrying".into(),
        ));
    }
    let lower = body.to_ascii_lowercase();
    let success = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("success").and_then(Value::as_bool));

    // 1. Explicit credential rejection, checked FIRST. CAPTURED-LIVE
    //    (2026-08-31): a wrong password answers HTTP 200
    //    `{"success":false,"errorMessage":"Invalid email address or password."}`.
    //    A rejected login on a portal often *also* renders an MFA-shaped page, so
    //    testing for the code prompt before testing for failure makes the CLI ask
    //    for a code that was never sent.
    if lower.contains("invalid") && (lower.contains("password") || lower.contains("credential")) {
        return Err(CliError::Auth(
            "Wealthfront rejected the username or password".into(),
        ));
    }
    // 2. reCAPTCHA / bot-check failure — HTTP 200 with "We weren't able to
    //    verify you." As of 2026-08-31 a bare-HTTP login does *not* trip this on
    //    the failure path (a tokenless POST reaches credential validation), but
    //    the score is probabilistic and could still fire on the success path, so
    //    the branch stays. `--browser` is the fallback. See docs/api.md §3.2.
    if lower.contains("verify you")
        || lower.contains("recaptcha")
        || lower.contains("unable to verify")
    {
        return Err(CliError::Auth(
            "Wealthfront could not verify the client (reCAPTCHA Enterprise) — retry, or use \
             `wfr auth login --browser`; see docs/api.md §3.2"
                .into(),
        ));
    }
    // 3. The pre-auth bounce. CAPTURED-LIVE (2026-08-31): a POST that fails the
    //    `login_xsrf` handshake is turned away *before* credentials are checked
    //    with HTTP 200 `{"redirectUrl":"/login","success":false}`. Reading this
    //    as `Authenticated` (the old `status==200 && !html` fall-through) is the
    //    bug that made `finish` read `/capitan/v1/me`, 401, and report "session
    //    expired". `login()` now sends the handshake, so hitting this branch
    //    means the handshake itself drifted — surface it as such, never as a
    //    session. Ordered after the credential/reCAPTCHA branches so their more
    //    specific `success:false` bodies win.
    if success == Some(false) || lower.contains("\"redirecturl\":\"/login\"") {
        // Carry the server's own error text when it published one — an
        // unrecognized `success:false` body may be a NEW failure mode, and
        // discarding its message would make the drift undiagnosable.
        let server_said = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| {
                v.get("errorMessage")
                    .and_then(Value::as_str)
                    .map(|m| format!(" (server said: {m})"))
            })
            .unwrap_or_default();
        return Err(CliError::Upstream(format!(
            "Wealthfront bounced the login before checking credentials (the login_xsrf \
             handshake failed) — the request shape changed; re-capture per docs/api.md \
             §3.1{server_said}"
        )));
    }
    if status == 401 || status == 403 {
        return Err(CliError::Auth(
            "Wealthfront rejected the username or password".into(),
        ));
    }
    // 4. Explicit MFA challenge marker.
    if lower.contains("mfa") || lower.contains("two_factor") || lower.contains("twofactor") {
        return Ok(());
    }
    // 5. Credentials accepted. 2FA is mandatory on every Wealthfront account
    //    (§3), so an accepted credential POST always means "second factor next":
    //    the SMS is delivered as a side effect of this POST, and the code is then
    //    verified at `/api/access/mfa`. There is no no-MFA success path to model.
    if success == Some(true) {
        return Ok(());
    }
    // 6. No positive signal. Never guess `Authenticated` — that was the old
    //    trap. Say so and re-capture.
    Err(CliError::Upstream(format!(
        "unrecognized login response (HTTP {status}) — see docs/api.md §3.1 and re-capture \
         the real request"
    )))
}

/// Require a document to actually be a document.
fn confirm_document(bytes: &[u8], path: &str) -> Result<(), CliError> {
    if bytes.starts_with(b"%PDF") {
        return Ok(());
    }
    if bytes.starts_with(b"<") {
        return Err(CliError::Auth(format!(
            "{path} returned HTML, not a PDF (session expired) — run `wfr auth login`"
        )));
    }
    Err(CliError::Upstream(format!(
        "{path} did not return a PDF ({} bytes, magic {:?}) — refusing to write it",
        bytes.len(),
        String::from_utf8_lossy(&bytes[..bytes.len().min(8)])
    )))
}

/// Clear a parked login. Called wherever a code is spent, successfully or not.
pub fn clear_pending(creds: &CredentialStore) -> Result<(), CliError> {
    creds.delete(PENDING_ACCOUNT)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_body_reads_as_session_expiry() {
        assert!(matches!(
            parse_json("<!doctype html>", "/x").unwrap_err(),
            CliError::Auth(_)
        ));
        assert_eq!(parse_json("   ", "/x").unwrap(), Value::Null);
        assert!(matches!(
            parse_json("kaboom", "/x").unwrap_err(),
            CliError::Upstream(_)
        ));
    }

    #[test]
    fn login_urls_are_recognized() {
        assert!(is_login_url("https://www.wealthfront.com/login"));
        assert!(is_login_url(
            "https://www.wealthfront.com/auth/login?next=/dashboard"
        ));
        assert!(!is_login_url("https://www.wealthfront.com/api/accounts"));
    }

    #[test]
    fn rejected_login_is_not_mistaken_for_an_mfa_prompt() {
        // The trap: a rejection body that also mentions MFA. Rejection wins.
        let body = r#"{"error":"Invalid password","mfa":{"available":true}}"#;
        assert!(matches!(
            classify_login(200, body).unwrap_err(),
            CliError::Auth(_)
        ));
    }

    #[test]
    fn recaptcha_verification_failure_is_not_read_as_success() {
        // CAPTURED-LIVE: the bot-check rejection is an HTTP 200. It must not
        // fall through to `Authenticated`.
        let body =
            r#"{"error":"We weren't able to verify you. If you're on a VPN, please disconnect."}"#;
        assert!(matches!(
            classify_login(200, body).unwrap_err(),
            CliError::Auth(_)
        ));
    }

    #[test]
    fn wrong_password_is_a_credentials_error_not_a_session_error() {
        // CAPTURED-LIVE (2026-08-31): the exact wrong-password body. This is the
        // regression guard for the reported bug — before the fix a wrong password
        // surfaced as "session expired" (an `Auth` from `/capitan/v1/me`), never
        // as a credentials rejection from the login itself.
        let body = r#"{"success":false,"errorMessage":"Invalid email address or password."}"#;
        assert!(
            matches!(classify_login(200, body).unwrap_err(), CliError::Auth(_)),
            "a wrong password must localize as a credentials error"
        );
    }

    #[test]
    fn pre_auth_bounce_is_never_read_as_authenticated() {
        // CAPTURED-LIVE (2026-08-31): the body a login POST gets when the
        // `login_xsrf` handshake is missing/wrong. The old code fell through to
        // `Authenticated`, which is precisely what produced the "session expired"
        // symptom. It must now be a (non-Auth) error and must NOT be `Ok`.
        let body = r#"{"redirectUrl":"/login","success":false}"#;
        let err = classify_login(200, body).unwrap_err();
        assert!(
            matches!(err, CliError::Upstream(_)),
            "the pre-auth bounce is a handshake/shape failure, not a session or a login"
        );
    }

    #[test]
    fn login_classification_covers_the_known_branches() {
        // An explicit MFA marker → credentials accepted, second factor next.
        assert!(classify_login(200, r#"{"mfa_required":true}"#).is_ok());
        // Accepted credentials → second factor next (2FA is mandatory on WF).
        assert!(classify_login(200, r#"{"success":true}"#).is_ok());
        assert!(matches!(
            classify_login(401, "{}").unwrap_err(),
            CliError::Auth(_)
        ));
        assert!(matches!(
            classify_login(429, "{}").unwrap_err(),
            CliError::Upstream(_)
        ));
        // A body with no positive signal is unrecognized, never `Authenticated`.
        assert!(matches!(
            classify_login(200, r#"{"user":{"id":"x"}}"#).unwrap_err(),
            CliError::Upstream(_)
        ));
        // An HTML 200 is not a successful login.
        assert!(matches!(
            classify_login(200, "<html>...</html>").unwrap_err(),
            CliError::Upstream(_)
        ));
    }

    #[test]
    fn downloads_must_be_real_pdfs() {
        assert!(confirm_document(b"%PDF-1.7 ...", "/d").is_ok());
        assert!(matches!(
            confirm_document(b"<!doctype html>", "/d").unwrap_err(),
            CliError::Auth(_)
        ));
        assert!(matches!(
            confirm_document(b"\x00\x01junk", "/d").unwrap_err(),
            CliError::Upstream(_)
        ));
    }

    #[test]
    fn totp_costs_nothing_but_sms_does() {
        assert!(!CodeChannel::Totp.costs_a_message());
        assert!(CodeChannel::Sms.costs_a_message());
    }

    #[test]
    fn percent_decode_handles_the_xsrf_cookie_escapes() {
        // The `xsrf` cookie is percent-encoded base64; the header is decoded.
        assert_eq!(percent_decode("ab%2Bcd%2Fef%3D"), "ab+cd/ef=");
        assert_eq!(percent_decode("plain"), "plain");
        // A trailing bare `%` is passed through, not panicked on.
        assert_eq!(percent_decode("a%"), "a%");
    }

    #[test]
    fn base_override_is_loopback_only() {
        // The env override exists for fake-server tests; a non-loopback value
        // would let ambient env redirect a credential-bearing POST. Refused.
        // The value is passed to `base_from` rather than set in the process
        // environment, which every test in the process shares.
        for unset in [None, Some(""), Some("   ")] {
            assert_eq!(base_from(unset).unwrap(), BASE, "{unset:?}");
        }
        assert_eq!(
            base_from(Some(" http://127.0.0.1:8080/ ")).unwrap(),
            "http://127.0.0.1:8080",
            "trimmed, without a trailing slash"
        );
        for (val, ok) in [
            ("http://127.0.0.1:8080", true),
            ("http://localhost:19", true),
            ("http://[::1]:9999", true),
            ("https://evil.example.com", false),
            ("http://127.0.0.1.evil.example.com", false),
            // Userinfo spoofing: a naive authority split reads the host as
            // 127.0.0.1, but the HTTP stack connects to evil.example.com
            // (PR #10 review finding). Userinfo is refused even with a
            // loopback host — it has no test use.
            ("http://127.0.0.1:1@evil.example.com", false),
            ("http://user:pass@evil.example.com", false),
            ("http://user:pass@127.0.0.1:8080", false),
            // Only plain http(s) schemes reach the HTTP client.
            ("file:///etc/hosts", false),
            ("not a url", false),
        ] {
            match base_from(Some(val)) {
                Ok(base) => assert!(ok, "{val} must be refused, got {base}"),
                Err(e) => {
                    assert!(!ok, "{val} must be accepted, got {e}");
                    assert_eq!(e.exit_code(), 2, "{val}");
                }
            }
        }
    }

    /// A loopback server for driving the real `login()` path offline
    /// ([`crate::loopback`]). Serves `GET /login` (setting a percent-encoded
    /// `login_xsrf` cookie), then answers the login POST with `login_body`.
    /// [`login_post`] takes the handle and hands back the POST.
    fn fake_login_server(
        login_body: &'static str,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        crate::loopback::serve(2, move |req| {
            if req.starts_with("GET /login") {
                // Percent-encoded, as the real site sets it (§3.1).
                crate::loopback::response(
                    "200 OK",
                    &[
                        "Content-Type: text/html",
                        "Set-Cookie: login_xsrf=abc%2Bxyz%3D%3D; Path=/; HttpOnly",
                        "Set-Cookie: t-token=tt.dummy; Path=/",
                    ],
                    "<html>",
                )
            } else {
                crate::loopback::response("200 OK", &["Content-Type: application/json"], login_body)
            }
        })
    }

    /// The login POST's request text, once [`fake_login_server`] is done.
    fn login_post(server: std::thread::JoinHandle<Vec<String>>) -> String {
        server
            .join()
            .expect("server thread")
            .into_iter()
            .find(|req| req.starts_with("POST "))
            .expect("the login POST arrived")
    }

    #[test]
    fn login_sends_the_decoded_login_xsrf_handshake_offline() {
        // End-to-end through the real `login()` against a loopback server: the
        // POST must carry the `login_xsrf` cookie's value URL-DECODED in
        // `loginXsrf` (the raw form is bounced pre-credential-check live), and
        // a wrong-password body must localize as a credentials Auth error.
        let (base, handle) = fake_login_server(
            r#"{"success":false,"errorMessage":"Invalid email address or password."}"#,
        );
        let wf = Wf::with_base(base).expect("client builds");
        let err = wf
            .login("probe@example.invalid", &Secret::new("wrong-pw"))
            .unwrap_err();
        assert!(
            matches!(&err, CliError::Auth(m) if m.contains("username or password")),
            "wrong password must be a credentials error, got: {err}"
        );
        let post = login_post(handle);
        assert!(
            post.contains(r#""loginXsrf":"abc+xyz==""#),
            "the POST must echo login_xsrf URL-decoded; got body: {post}"
        );
        assert!(
            post.contains("login_xsrf=abc%2Bxyz%3D%3D"),
            "the POST must replay the login_xsrf cookie: {post}"
        );
        assert!(post.contains(r#""grantType":"password""#));
    }

    #[test]
    fn accepted_credentials_mean_second_factor_next_offline() {
        // `success:true` from the login POST → `Ok(())`, i.e. the flow proceeds
        // to the park-and---code step (2FA is mandatory; the SMS was sent as a
        // side effect of this POST). This is the control flow the headless
        // (non-TTY) login follows to its park-print-exit ending.
        let (base, handle) = fake_login_server(r#"{"success":true}"#);
        let wf = Wf::with_base(base).expect("client builds");
        wf.login("probe@example.invalid", &Secret::new("accepted-pw"))
            .expect("accepted credentials proceed to the 2FA step");
        // The in-flight session must be parkable — this is what `auth login`
        // stores under `pending-login` before printing the --code instruction.
        assert!(
            wf.pending_bundle().is_some(),
            "an accepted login must yield a parkable cookie bundle"
        );
        login_post(handle);
    }

    /// `me()` is the session check behind the password login's `finish` and `auth
    /// status --verify`: only an account's value is a session. Any other 200 is an
    /// upstream error naming the shape, never a success.
    #[test]
    fn me_counts_only_an_account_as_signed_in() {
        let me_answering = |body: &'static str| {
            let (base, server) = crate::loopback::serve(1, move |_| {
                crate::loopback::response("200 OK", &["Content-Type: application/json"], body)
            });
            let out = Wf::with_base(base).expect("client builds").me();
            let requests = server.join().expect("server thread");
            assert_eq!(requests.len(), 1, "{body:?}");
            assert!(
                requests[0].starts_with(&format!("GET {} ", endpoints::ME)),
                "{body:?}: {}",
                requests[0]
            );
            out
        };

        assert_eq!(
            me_answering(r#"{"emailAddress":"user@example.com"}"#).unwrap(),
            serde_json::json!({"emailAddress": "user@example.com"})
        );
        for (body, kind) in [
            ("", "an empty body or null"),
            ("null", "an empty body or null"),
            ("{}", "an empty object"),
            (r#"{"emailAddress":""}"#, "an object with no account in it"),
            (
                r#"{"emailAddress":null}"#,
                "an object with no account in it",
            ),
            (
                r#"{"userIdExternalized":1}"#,
                "an object with no account in it",
            ),
            (
                r#"{"redirectUrl":"/login","success":false}"#,
                "an object with no account in it",
            ),
            ("[]", "an array"),
            (r#""dummy""#, "a string"),
            ("true", "a boolean"),
            ("0", "a number"),
        ] {
            match me_answering(body) {
                Err(CliError::Upstream(m)) => assert_eq!(
                    m,
                    format!(
                        "Wealthfront answered /capitan/v1/me with {kind} \
                         where the account object was expected"
                    ),
                    "{body:?}"
                ),
                other => panic!("{body:?} must be an upstream error: {other:?}"),
            }
        }
    }

    /// Each challenge's title names itself, whatever its case.
    #[test]
    fn each_challenge_title_reads_as_an_edge_block() {
        for title in [
            "Just a moment...",
            "JUST A MOMENT",
            "Attention Required! | Cloudflare",
            "Access denied",
        ] {
            let page = format!("<!DOCTYPE html><html><head><title>{title}</title></head></html>");
            assert!(html_reads_as_edge_block(&page), "{title}");
        }
        assert!(html_reads_as_edge_block(
            "<html><title data-x=\"1\">Just a moment</title></html>"
        ));
    }

    const LOGIN_PAGE_WITH_CHALLENGE_WORDS: &str =
        include_str!("../tests/fixtures/login-page-with-challenge-words.html");

    /// A login page may hold a challenge's words, in its body, a script or a meta tag,
    /// and its own bot check. Only the title counts, so none of it reads as a block.
    #[test]
    fn a_login_page_holding_challenge_words_is_not_an_edge_block() {
        let page = LOGIN_PAGE_WITH_CHALLENGE_WORDS;
        for word in [
            "access denied",
            "cf-chl",
            "just a moment",
            "attention required",
        ] {
            assert!(
                page.to_lowercase().contains(word),
                "the fixture holds {word}"
            );
        }
        assert!(!html_reads_as_edge_block(page));
        assert!(!html_reads_as_edge_block(
            "<html>access denied, cf-chl</html>"
        ));
        assert!(!html_reads_as_edge_block("<html><title"));
    }

    /// A title that opens past the first 8 KiB is not read.
    #[test]
    fn a_challenge_title_past_the_window_is_not_read() {
        let padding = " ".repeat(8192);
        let page = format!("<html>{padding}<title>Just a moment...</title></html>");
        assert!(!html_reads_as_edge_block(&page));
        // A multi-byte character across the cut does not panic.
        let page = format!("<html>{}é<title>Just a moment</title>", "a".repeat(8185));
        assert!(!html_reads_as_edge_block(&page));
    }

    /// An HTML 403 is an edge's answer; any other 403 names both causes.
    #[test]
    fn refused_tells_an_html_body_from_a_json_one() {
        for body in ["<html></html>", "  <!DOCTYPE html>"] {
            assert!(
                matches!(
                    refused(body, None),
                    ReadError::EdgeBlock { status: 403, .. }
                ),
                "{body}"
            );
        }
        for body in [r#"{"error":"forbidden"}"#, ""] {
            let err = refused(body, None);
            assert!(matches!(err, ReadError::Failed(_)), "{body}: {err:?}");
            let err = CliError::from(err);
            assert_eq!(err.exit_code(), 3, "{body}");
            let text = err.to_string();
            assert!(
                text.contains("the session may be invalid"),
                "{body}: {text}"
            );
            assert!(
                text.contains("may be a bot check or edge block"),
                "{body}: {text}"
            );
        }
    }

    /// Both the JSON read and the document read, one answer each.
    fn both_reads(status: &'static str, body: &'static str) -> [CliError; 2] {
        let answering = || {
            let (base, server) = crate::loopback::serve(1, move |_| {
                crate::loopback::response(status, &["Content-Type: text/html"], body)
            });
            (Wf::with_base(base).expect("client builds"), server)
        };
        let (wf, server) = answering();
        let read = wf.get_json("/x").unwrap_err();
        server.join().expect("server thread");
        let (wf, server) = answering();
        let document = wf.download("/x.pdf").unwrap_err();
        server.join().expect("server thread");
        [read, document]
    }

    /// `Wf::handle` and the document read tell an HTML 403 from any other, and neither
    /// reads as a plain expiry.
    #[test]
    fn a_403_reads_as_a_block_or_as_both_causes_on_every_read() {
        for err in both_reads("403 Forbidden", "<html>dummy-body</html>") {
            assert_eq!(err.exit_code(), 3);
            let text = err.to_string();
            assert!(
                text.contains("possibly a bot check or edge block"),
                "{text}"
            );
            assert!(text.contains("not an expired session"), "{text}");
            assert!(!text.contains("dummy-body"), "{text}");
        }
        for err in both_reads("403 Forbidden", r#"{"error":"forbidden"}"#) {
            assert_eq!(err.exit_code(), 3);
            let text = err.to_string();
            assert!(text.contains("the session may be invalid"), "{text}");
            assert!(!text.contains("session expired"), "{text}");
        }
        for err in both_reads("401 Unauthorized", "") {
            assert_eq!(err.exit_code(), 3);
            assert!(err.to_string().contains("session expired"), "{err}");
        }
    }

    /// Behind a 200, `Wf::handle` calls a challenge's title a block and a login page
    /// holding the same words an expired session, typing only the first.
    #[test]
    fn a_read_types_a_challenge_behind_a_200() {
        let read = |body: &'static str| {
            let (base, server) = crate::loopback::serve(1, move |_| {
                crate::loopback::response("200 OK", &["Content-Type: text/html"], body)
            });
            let out = Wf::with_base(base).expect("client builds").read_json("/x");
            server.join().expect("server thread");
            out.unwrap_err()
        };
        let err = read("<html><title>Attention Required!</title></html>");
        assert!(
            matches!(err, ReadError::EdgeBlock { status: 200, .. }),
            "{err:?}"
        );
        let err = read(LOGIN_PAGE_WITH_CHALLENGE_WORDS);
        assert!(matches!(err, ReadError::Failed(_)), "{err:?}");
        let err = CliError::from(err);
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("session expired"), "{err}");
    }
}
