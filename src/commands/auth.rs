//! `wfr auth login|status|logout|set-credential`.
//!
//! # Two-factor authentication is mandatory
//!
//! Wealthfront requires 2FA on every account and offers no way to turn it off,
//! so there is no "just log in" path to fall back on. That shapes everything
//! here:
//!
//! - **A login that needs a code parks its session.** The code Wealthfront
//!   sends belongs to the session that requested it. A second `auth login`
//!   would start a *fresh* session, and the perfectly correct code in the
//!   user's hand would be rejected against it — a failure that looks like
//!   "Wealthfront is broken" and is impossible to diagnose from the outside.
//!   So the in-flight session is stored, and `--code` resumes exactly it.
//! - **Codes cost money and patience.** SMS is rate-limited; TOTP is free
//!   because the code is generated on the user's own device. `--channel totp`
//!   is therefore the right choice for anyone with an authenticator app, and
//!   the test suite never touches this path at all.
//! - **A parked session is spent on use**, successfully or not, so a failed
//!   code cannot be replayed against a dead session.
//!
//! # The browser sign-in
//!
//! `--browser` opens a plain Chrome window at the Wealthfront login through
//! `pk-cli-browser` (cli-common DESIGN.md §2.2). The owner signs in there,
//! password and 2FA included, and the session is read out of the window
//! ([`browser_capture`]). Wealthfront sets `_wfsid` for anonymous visitors
//! too, so no cookie proves the sign-in finished: before the tab closes,
//! [`confirm_session`] makes one `GET /capitan/v1/me` with the candidate jar.

use std::io::IsTerminal;

use pk_cli_auth::{AuthMethod, AuthStatus, LoginArgs, LogoutArgs, SetCredentialArgs};
use pk_cli_browser::{BrowserArgs, Capture, Captured, Confirm, HostRule, Launch, DEFAULT_TIMEOUT};
use pk_cli_config::ConfigStore;
use pk_cli_core::CliError;
use pk_cli_secrets::{CredentialStore, Secret};
use serde_json::Value;

use crate::client::{clear_pending, endpoints, CodeChannel, Wf, BASE};
use crate::config::Config;
use crate::keychain::{DEVICE_ACCOUNT, PASSWORD_ACCOUNT, PENDING_ACCOUNT, SESSION_ACCOUNT};

/// `--browser` captures the session, so it takes no other credential source:
/// clap refuses it beside `--stdin` or `--from-env` (exit 2) before anything
/// reads the keychain or the network (cli-common DESIGN.md §2.2).
#[derive(clap::Args, Debug)]
#[command(mut_arg("browser", |a| a.conflicts_with_all(["stdin", "from_env"])))]
pub struct PortalLoginArgs {
    #[command(flatten)]
    pub base: LoginArgs,

    /// Where the second factor comes from. `totp` reads from your
    /// authenticator app and costs nothing; `sms` sends a rate-limited text.
    #[arg(long, value_enum, default_value = "sms")]
    pub channel: CodeChannel,

    /// Verification code, to resume a login that requested one.
    #[arg(long, value_name = "CODE")]
    pub code: Option<String>,

    #[command(flatten)]
    pub browser: BrowserArgs,
}

#[derive(clap::Args, Debug)]
pub struct StatusArgs {
    /// Confirm the stored session still works with one live read.
    #[arg(long)]
    pub verify: bool,
}

#[derive(clap::Subcommand, Debug)]
pub enum AuthCmd {
    /// Log in, handling the mandatory second factor.
    Login(PortalLoginArgs),
    /// Report credential/session state (auth-status/v1).
    Status(StatusArgs),
    /// Clear the session; --forget also removes the stored password.
    Logout(LogoutArgs),
    /// Raw keychain write for rotation / headless setup.
    SetCredential(SetCredentialArgs),
}

pub fn run(
    cmd: &AuthCmd,
    creds: &CredentialStore,
    store: &ConfigStore,
    json: bool,
    quiet: bool,
    interactive: bool,
) -> Result<(), CliError> {
    let cfg: Config = store.load()?;
    match cmd {
        AuthCmd::Login(args) => login(args, creds, &cfg, quiet, interactive),
        AuthCmd::Status(args) => status(args, creds, &cfg, json, quiet),
        AuthCmd::Logout(args) => logout(args, creds, store, quiet),
        AuthCmd::SetCredential(args) => {
            if creds.get(PASSWORD_ACCOUNT)?.is_some() && !args.overwrite {
                return Err(CliError::Usage(
                    "a password is already stored; pass --overwrite to replace it".into(),
                ));
            }
            let secret = args.source.read(None)?;
            creds.set(PASSWORD_ACCOUNT, &secret)?;
            if !quiet {
                eprintln!("password stored in the OS keychain");
            }
            Ok(())
        }
    }
}

fn login(
    args: &PortalLoginArgs,
    creds: &CredentialStore,
    cfg: &Config,
    quiet: bool,
    interactive: bool,
) -> Result<(), CliError> {
    // The verified sign-in: the owner signs in on Wealthfront's own page,
    // where reCAPTCHA sees a real browser (docs/api.md §3.2, §3.6), and the
    // confirmed session is stored like any other.
    if args.browser.browser {
        let session = browser_session(quiet)?;
        creds.set(SESSION_ACCOUNT, &session)?;
        if !quiet {
            eprintln!("logged in — session captured from the browser");
        }
        return Ok(());
    }

    // A code on the command line belongs to the login that requested it, so
    // resume that parked session rather than starting a fresh one.
    if let Some(code) = &args.code {
        // Announce the keychain read before it happens: a macOS keychain
        // approval dialog blocks with no terminal output, and a headless run
        // that hangs silently is undiagnosable (the 2026-08-31 lesson).
        if !quiet {
            eprintln!(
                "resuming the parked sign-in from the keychain (approve the prompt if macOS asks)"
            );
        }
        let pending = creds.get(PENDING_ACCOUNT)?.ok_or_else(|| {
            CliError::Usage("no login is waiting for a code — run `wfr auth login` first".into())
        })?;
        let wf = Wf::new()?;
        wf.resume_pending(pending.expose());
        let result = wf.verify_code(code.trim(), args.channel);
        // The parked session is spent either way; drop it before propagating
        // so a failed code can't be replayed against a dead session.
        clear_pending(creds)?;
        result?;
        return finish(&wf, creds, quiet);
    }

    let username = cfg.username.as_deref().ok_or_else(|| {
        CliError::Usage(
            "no username configured — run `wfr config set username <you@example.com>`".into(),
        )
    })?;

    // Resolve the password BEFORE any keychain access. On a headless run the
    // keychain is not consulted at all: a keychain *read* is exactly where a
    // headless run can block forever with no output — macOS raises an approval
    // dialog (e.g. after a differently-signed reinstall) that a non-TTY shell
    // can neither see nor answer. That was the 2026-08-31 headless hang: no
    // output, no SMS, killed after 5+ minutes, all before the network was ever
    // touched.
    //
    // "Headless" is any invocation whose password does not come from the
    // keychain: an explicit source (`--stdin` / `--from-env`), `--overwrite`,
    // or a **piped (non-TTY) stdin with no flags** — the bare-pipe shape
    // `printf PW | wfr auth login` reads the pipe too (the source reader
    // TTY-detects), so it must get the same no-keychain guarantee (PR #10
    // review finding).
    let explicit_source = args.base.source.stdin || args.base.source.from_env.is_some();
    let headless = explicit_source || args.base.overwrite || !std::io::stdin().is_terminal();
    let (password, password_is_new) = if headless {
        (read_password(args)?, true)
    } else {
        match creds.get(PASSWORD_ACCOUNT)? {
            Some(p) => (p, false),
            None => (read_password(args)?, true),
        }
    };
    if password.is_empty() {
        // An empty read (EOF on a pipe, a blank prompt) must not spend a login
        // attempt — and must never be stored.
        return Err(CliError::Usage(
            "the password provided is empty — pass it via --stdin or --from-env <VAR>".into(),
        ));
    }

    // Announce before the network dance so any later stall is attributable.
    // The SMS is spent by the *login POST itself* when the credentials are
    // accepted (there is no separate send endpoint — docs/api.md §3.1), so the
    // rate-limit warning has to come before that POST, not after.
    if !quiet {
        if args.channel.costs_a_message() {
            eprintln!(
                "logging in — accepted credentials will trigger a texted code \
                 (rate-limited; --channel totp is free)"
            );
        } else {
            eprintln!("logging in");
        }
    }
    let wf = Wf::new()?;
    // Device trust is an optimization, not a requirement — and it is another
    // pre-network keychain read, i.e. another place a headless run could block
    // forever on an approval dialog (the `if let Ok` absorbs only the returned
    // error, not the block — PR #10 review finding). Headless runs skip it
    // entirely; interactive runs announce it first so a block names its
    // culprit. Nothing is lost headless: no code path writes DEVICE_ACCOUNT
    // yet, and a trusted-device login would only skip a prompt the headless
    // path never shows.
    if !headless {
        if !quiet {
            eprintln!("checking for a remembered device in the keychain");
        }
        if let Ok(Some(device)) = creds.get(DEVICE_ACCOUNT) {
            wf.resume_pending(device.expose());
        }
    }

    // Credentials accepted. 2FA is mandatory on every Wealthfront account, so
    // there is no no-MFA success path: `login` returns `Ok(())` to mean "second
    // factor next" (a wrong password is an `Err` here — a credentials error,
    // never the "session expired" it used to misreport).
    wf.login(username, &password)?;
    if !quiet {
        match args.channel {
            CodeChannel::Sms => {
                eprintln!("credentials accepted — a verification code was sent by text")
            }
            CodeChannel::Totp => eprintln!(
                "credentials accepted — read the verification code from your authenticator app"
            ),
        }
    }
    wf.send_code(args.channel)?;

    // Park FIRST — before storing the password, before any prompt — so the code
    // that was just spent always has a session to resume, even on Ctrl-C. The
    // keychain write is announced beforehand for the same reason as above: if
    // macOS raises an approval dialog, the last stderr line says exactly what
    // is waiting.
    if let Some(pending) = wf.pending_bundle() {
        if !quiet {
            eprintln!("parking the sign-in in the keychain (approve the prompt if macOS asks)");
        }
        creds.set(PENDING_ACCOUNT, &pending)?;
    }
    // Store the password only now that Wealthfront has accepted it — a rejected
    // password is never persisted. Best-effort: a keychain failure must not
    // strand the SMS that was just spent.
    if password_is_new && creds.set(PASSWORD_ACCOUNT, &password).is_err() && !quiet {
        eprintln!("note: the password could not be stored in the keychain; continuing");
    }
    if !interactive {
        return Err(CliError::Auth(format!(
            "a verification code is required ({}) — re-run with \
             `wfr auth login --code <CODE>`",
            match args.channel {
                CodeChannel::Sms => "sent by text",
                CodeChannel::Totp => "from your authenticator app",
            }
        )));
    }
    let code = prompt_line("Verification code: ")?;
    let result = wf.verify_code(code.trim(), args.channel);
    clear_pending(creds)?;
    result?;
    finish(&wf, creds, quiet)
}

/// Read the password from the explicit source, or prompt when allowed.
/// `--non-interactive` suppresses the prompt (a headless run fails cleanly
/// instead); a piped stdin never prompts regardless — the source reader
/// TTY-detects before falling back to a prompt.
fn read_password(args: &PortalLoginArgs) -> Result<pk_cli_secrets::Secret, CliError> {
    let prompt = if args.base.non_interactive {
        None
    } else {
        Some("Wealthfront password")
    };
    args.base.source.read(prompt)
}

/// Prove a freshly authenticated session works, then cache it.
///
/// The read happens *before* the write so a login that authenticated but
/// cannot fetch anything leaves no broken session behind — and so the cookie
/// stored is the one that survived that read, since the site may rotate it
/// mid-flight.
fn finish(wf: &Wf, creds: &CredentialStore, quiet: bool) -> Result<(), CliError> {
    wf.me()?;
    let session = wf.session_bundle().ok_or_else(|| {
        CliError::Upstream("login succeeded but Wealthfront issued no session cookie".into())
    })?;
    creds.set(SESSION_ACCOUNT, &session)?;
    if !quiet {
        eprintln!("logged in");
    }
    Ok(())
}

/// The only host the session is read from, and whose tabs close once it is
/// read: the web app's, the host of [`BASE`].
const WEB_HOST: &str = "www.wealthfront.com";
/// The jar the stored session is: every cookie the browser would send to this
/// domain or a host under it, matched label for label.
const JAR_DOMAIN: &str = "wealthfront.com";
/// The session cookie. It is set for an anonymous visitor too, so it only
/// says the jar is loaded; [`confirm_session`] says whether the owner is in.
const SESSION_COOKIE: &str = "_wfsid";

/// What `auth login --browser` reads: the wealthfront.com jar, once a page on
/// exactly [`WEB_HOST`] is open, [`SESSION_COOKIE`] is set and
/// [`confirm_session`] accepts it. No page is evaluated in; the cookies are
/// read at the browser level.
fn browser_capture() -> Result<Capture, CliError> {
    Ok(Capture::new("Wealthfront", HostRule::exact(WEB_HOST)?)
        .cookie(format!("https://{WEB_HOST}/"), SESSION_COOKIE)
        .cookie_jar(JAR_DOMAIN)
        .hint("password and 2FA")
        .confirm(confirm_session))
}

/// The check run on each poll before the tab closes: one `GET /capitan/v1/me`
/// with the candidate jar, through the client every read uses. The request
/// is bounded by that client's timeout.
fn confirm_session(candidate: &Captured) -> Confirm {
    confirm_session_with(candidate, Wf::from_bundle)
}

/// [`confirm_session`], with the client that makes the read built by
/// `client` from the candidate's cookie header, so a unit test can point it
/// at a loopback server ([`Wf::from_bundle_at`]). A capture with no jar ends
/// the wait before any client is built.
fn confirm_session_with(
    candidate: &Captured,
    client: impl FnOnce(&str) -> Result<Wf, CliError>,
) -> Confirm {
    let Some(bundle) = candidate.cookie_header() else {
        return Confirm::Fail(no_jar());
    };
    me_verdict(client(bundle.expose()).and_then(|wf| wf.me()))
}

/// What the `/capitan/v1/me` read says about a candidate session.
fn me_verdict(me: Result<Value, CliError>) -> Confirm {
    match me {
        // The account object, the only answer `Wf::me` lets through.
        Ok(_) => Confirm::Ready,
        // The answer a visitor gets: the owner has not finished signing in.
        Err(CliError::Auth(_)) => {
            Confirm::NotYet(format!("GET {} answered as signed out", endpoints::ME))
        }
        // A 429, a 200 that is not the account object, the network, a
        // cookie or CSRF bug: waiting will not fix it, so it ends the wait
        // instead of blaming a slow sign-in.
        Err(e) => Confirm::Fail(CliError::Upstream(format!(
            "session validation failed during the browser login: {e}"
        ))),
    }
}

/// Open Chrome at the Wealthfront login, wait while the owner signs in, and
/// hand back the confirmed jar as the `k=v; k=v` bundle the session is stored
/// as. The crate closes the tab, stops Chrome and deletes its profile.
fn browser_session(quiet: bool) -> Result<Secret, CliError> {
    let launch = Launch::new(crate::BIN)
        .url(format!("{BASE}{}", endpoints::LOGIN_PAGE))
        .quiet(quiet);
    let captured = pk_cli_browser::capture(launch, &browser_capture()?, DEFAULT_TIMEOUT)?;
    captured.cookie_header().ok_or_else(no_jar)
}

fn no_jar() -> CliError {
    CliError::Other("the browser capture read no cookie jar".into())
}

fn status(
    args: &StatusArgs,
    creds: &CredentialStore,
    cfg: &Config,
    json: bool,
    quiet: bool,
) -> Result<(), CliError> {
    let has_password = creds.get(PASSWORD_ACCOUNT)?.is_some();
    let has_session = creds.get(SESSION_ACCOUNT)?.is_some();
    let pending = creds.get(PENDING_ACCOUNT)?.is_some();

    let mut st = AuthStatus::new(true, has_session, AuthMethod::Password);
    st.username = cfg.username.clone();
    st.account = cfg.account.clone();
    st.credential_in_keychain = Some(has_password);

    let mut verified_bad = false;
    if args.verify && has_session {
        // One cheap read. `session_valid` is omitted entirely unless asked
        // for, so the DTO never implies a check that never happened.
        let ok = Wf::from_cached_session(creds)
            .and_then(|wf| wf.me())
            .is_ok();
        st.session_valid = Some(ok);
        st.authenticated = ok;
        verified_bad = !ok;
    }

    // A parked MFA login is real state the user needs to know about, but
    // `auth-status/v1` has no field for it — adding one would fork the shared
    // schema. It goes to stderr instead, where it doesn't disturb the DTO.
    if pending && !quiet {
        eprintln!("note: a login is waiting for a code — run `wfr auth login --code <CODE>`");
    }

    st.emit(json);
    if verified_bad {
        // The DTO already went to stdout. Returning an error here would print
        // a *second* JSON document, so exit directly.
        std::process::exit(CliError::Auth(String::new()).exit_code());
    }
    Ok(())
}

fn logout(
    args: &LogoutArgs,
    creds: &CredentialStore,
    store: &ConfigStore,
    quiet: bool,
) -> Result<(), CliError> {
    creds.delete(SESSION_ACCOUNT)?;
    // Drop any half-finished login too, so `logout` really does leave nothing
    // session-shaped behind.
    creds.delete(PENDING_ACCOUNT)?;
    if args.forget {
        creds.delete(PASSWORD_ACCOUNT)?;
        creds.delete(DEVICE_ACCOUNT)?;
        store.clear()?;
    }
    if !quiet {
        eprintln!("logged out");
    }
    Ok(())
}

fn prompt_line(label: &str) -> Result<String, CliError> {
    use std::io::Write;
    eprint!("{label}");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| CliError::Other(format!("reading input: {e}")))?;
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loopback;
    use pk_cli_browser::{BrowserError, JarCookie};
    use serde_json::json;

    /// The `xsrf` cookie percent-encoded, as the site sets it, and the
    /// `x-csrf-token` the read must send for it (docs/api.md §3.4).
    const DUMMY_XSRF: &str = "dummy%2Bxsrf%3D%3D";
    const DUMMY_CSRF_TOKEN: &str = "dummy+xsrf==";

    /// A capture as the crate hands it to the confirm hook once a page on
    /// the web host is open: the wealthfront.com jar, `_wfsid` and `xsrf`
    /// in it. Every value is a dummy.
    fn captured_jar() -> Captured {
        Captured::for_test("Wealthfront", WEB_HOST)
            .cookie(SESSION_COOKIE, "dummy-wfsid")
            .jar([
                JarCookie::for_test(
                    SESSION_COOKIE,
                    "dummy-wfsid",
                    ".wealthfront.com",
                    false,
                    "/",
                ),
                JarCookie::for_test("xsrf", DUMMY_XSRF, WEB_HOST, true, "/"),
            ])
            .build()
    }

    /// The confirm hook on [`captured_jar`], its read sent to a loopback
    /// server that answers each of `connections` requests with `respond`:
    /// the verdict, and the requests the server saw.
    fn confirm_against<F>(connections: usize, respond: F) -> (Confirm, Vec<String>)
    where
        F: Fn(&str) -> String + Send + 'static,
    {
        let (base, server) = loopback::serve(connections, respond);
        let verdict =
            confirm_session_with(&captured_jar(), |bundle| Wf::from_bundle_at(base, bundle));
        (verdict, server.join().expect("server thread"))
    }

    /// The read the hook makes: `GET /capitan/v1/me`, with the captured jar
    /// as its cookies and the decoded `xsrf` cookie as `x-csrf-token`.
    fn assert_me_read(request: &str, case: &str) {
        assert!(
            request.starts_with(&format!("GET {} HTTP/1.1\r\n", endpoints::ME)),
            "{case}: {request}"
        );
        let cookies = loopback::header(request, "cookie").expect("the read sends the jar");
        let mut pairs: Vec<&str> = cookies.split("; ").collect();
        pairs.sort_unstable();
        assert_eq!(
            pairs,
            ["_wfsid=dummy-wfsid", &format!("xsrf={DUMMY_XSRF}")],
            "{case}"
        );
        assert_eq!(
            loopback::header(request, "x-csrf-token"),
            Some(DUMMY_CSRF_TOKEN),
            "{case}"
        );
        assert_eq!(
            loopback::header(request, "accept"),
            Some("application/json"),
            "{case}"
        );
    }

    /// The verdict a failure waiting will not fix gets: the wait ends, and
    /// `auth login` exits 5.
    /// Returns the cause the message names after its prefix.
    fn assert_ends_the_wait(verdict: Confirm, case: &str) -> String {
        let err = match verdict {
            Confirm::Fail(err) => err,
            other => panic!("{case} must end the wait: {other:?}"),
        };
        assert_eq!(err.exit_code(), 5, "{case}");
        match err {
            CliError::Upstream(m) => m
                .strip_prefix("session validation failed during the browser login: ")
                .unwrap_or_else(|| panic!("{case}: {m}"))
                .to_string(),
            other => panic!("{case} must end the wait as upstream: {other:?}"),
        }
    }

    /// A capture that holds no jar ends the wait before a client is built,
    /// so nothing is read. A named `_wfsid` alone does not count: the jar is
    /// what the read would send.
    #[test]
    fn a_capture_without_a_jar_fails_before_any_read() {
        let bare = Captured::for_test("Wealthfront", WEB_HOST).build();
        let named_only = Captured::for_test("Wealthfront", WEB_HOST)
            .cookie(SESSION_COOKIE, "dummy-wfsid")
            .build();
        for (case, candidate) in [("a bare capture", &bare), ("a named _wfsid", &named_only)] {
            for verdict in [
                confirm_session(candidate),
                confirm_session_with(candidate, |_| panic!("{case}: no client without a jar")),
            ] {
                match verdict {
                    Confirm::Fail(err) => {
                        assert!(
                            matches!(&err, CliError::Other(m)
                                if m == "the browser capture read no cookie jar"),
                            "{case}: {err:?}"
                        );
                        assert_eq!(err.exit_code(), 1, "{case}");
                    }
                    other => panic!("{case} must end the wait: {other:?}"),
                }
            }
        }
    }

    /// A 200 with JSON from `/capitan/v1/me` is a signed-in session: the tab
    /// closes and the capture is handed over.
    #[test]
    fn a_signed_in_me_read_is_ready() {
        let (verdict, requests) = confirm_against(1, |_| {
            loopback::response(
                "200 OK",
                &["Content-Type: application/json"],
                r#"{"dummy":true}"#,
            )
        });
        assert!(matches!(verdict, Confirm::Ready), "{verdict:?}");
        assert_eq!(requests.len(), 1);
        assert_me_read(&requests[0], "200");
    }

    /// The answers a visitor gets keep the tab open for the next poll: a
    /// 401 or 403, a redirect to the login or 2FA page, or an HTML page
    /// where JSON was expected.
    #[test]
    fn a_signed_out_me_read_keeps_waiting() {
        let page = || loopback::response("200 OK", &["Content-Type: text/html"], "<html>");
        for (case, connections, me) in [
            ("401", 1, loopback::response("401 Unauthorized", &[], "")),
            ("403", 1, loopback::response("403 Forbidden", &[], "")),
            (
                "a redirect to /login",
                2,
                loopback::response("302 Found", &["Location: /login"], ""),
            ),
            (
                "a redirect to /mfa",
                2,
                loopback::response("302 Found", &["Location: /mfa"], ""),
            ),
            (
                "an HTML 200",
                1,
                loopback::response("200 OK", &["Content-Type: text/html"], "<!doctype html>"),
            ),
        ] {
            let (verdict, requests) = confirm_against(connections, move |req| {
                if req.starts_with(&format!("GET {} ", endpoints::ME)) {
                    me.clone()
                } else {
                    page()
                }
            });
            match verdict {
                Confirm::NotYet(reason) => assert_eq!(
                    reason, "GET /capitan/v1/me answered as signed out",
                    "{case}"
                ),
                other => panic!("{case} must keep waiting: {other:?}"),
            }
            assert_eq!(requests.len(), connections, "{case}");
            assert_me_read(&requests[0], case);
        }
    }

    /// What waiting will not fix ends the wait: a 404, a rate limit, a
    /// server error, or a 200 that is not the account object. A visitor's
    /// `/capitan/v1/me` is a 401, so an empty, `null` or non-object 200 is
    /// not a slow sign-in, and a status code alone is never one.
    #[test]
    fn a_me_read_waiting_cannot_fix_ends_the_wait() {
        let json = &["Content-Type: application/json"][..];
        let not_the_object = |kind: &str| {
            format!("network/upstream error: Wealthfront answered /capitan/v1/me with {kind} where the account object was expected")
        };
        for (case, answer, cause) in [
            (
                "404",
                loopback::response("404 Not Found", &[], ""),
                "not found: /capitan/v1/me (HTTP 404)".to_string(),
            ),
            (
                "429",
                loopback::response("429 Too Many Requests", &[], ""),
                "network/upstream error: Wealthfront rate-limited /capitan/v1/me (HTTP 429) — wait before retrying"
                    .to_string(),
            ),
            (
                "500",
                loopback::response("500 Internal Server Error", &[], ""),
                "network/upstream error: Wealthfront HTTP 500 for /capitan/v1/me".to_string(),
            ),
            (
                "503",
                loopback::response("503 Service Unavailable", &[], ""),
                "network/upstream error: Wealthfront HTTP 503 for /capitan/v1/me".to_string(),
            ),
            (
                "a non-JSON 200",
                loopback::response("200 OK", &["Content-Type: text/plain"], "kaboom"),
                "network/upstream error: Wealthfront returned non-JSON for /capitan/v1/me (first bytes: \"kaboom\")"
                    .to_string(),
            ),
            (
                "an empty 200",
                loopback::response("200 OK", json, ""),
                not_the_object("an empty body or null"),
            ),
            (
                "a null 200",
                loopback::response("200 OK", json, "null"),
                not_the_object("an empty body or null"),
            ),
            (
                "an array 200",
                loopback::response("200 OK", json, "[]"),
                not_the_object("an array"),
            ),
            (
                "a string 200",
                loopback::response("200 OK", json, r#""dummy""#),
                not_the_object("a string"),
            ),
        ] {
            let (verdict, requests) = confirm_against(1, move |_| answer.clone());
            assert_eq!(assert_ends_the_wait(verdict, case), cause, "{case}");
            assert_eq!(requests.len(), 1, "{case}");
            assert_me_read(&requests[0], case);
        }
    }

    /// A server that refuses the connection, and a client that cannot be
    /// built (as when `WFR_BASE_URL` is refused), end the wait too.
    #[test]
    fn an_unreachable_server_or_an_unbuilt_client_ends_the_wait() {
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            format!("http://{}", listener.local_addr().unwrap())
        };
        assert_ends_the_wait(
            confirm_session_with(&captured_jar(), |bundle| Wf::from_bundle_at(closed, bundle)),
            "a refused connection",
        );
        assert_ends_the_wait(
            confirm_session_with(&captured_jar(), |_| {
                Err(CliError::Usage(
                    "WFR_BASE_URL must be a plain http(s) URL".into(),
                ))
            }),
            "a client that cannot be built",
        );
    }

    /// The definition `pk-cli-browser` checks before Chrome starts, checked
    /// here offline: a label, a cookie URL on its host, a jar domain that
    /// host is on.
    #[test]
    fn the_browser_capture_is_well_formed() {
        let capture = browser_capture().unwrap();
        capture.validate().unwrap();
        assert_eq!(capture.label(), "Wealthfront");
    }

    /// Whether the capture's hosts take `url`. Validation refuses a cookie
    /// URL that is not an https URL on one of them, so a probe cookie asks
    /// the definition itself, not a copy of its rule.
    fn reads_from(url: &str) -> bool {
        browser_capture()
            .unwrap()
            .cookie(url, "probe")
            .validate()
            .is_ok()
    }

    /// The window opens on the host the session is read from, and that is
    /// the only host read or closed: not the apex, not another
    /// wealthfront.com host, and no look-alike.
    #[test]
    fn the_session_is_read_from_www_wealthfront_com_only() {
        assert_eq!(format!("https://{WEB_HOST}"), BASE);
        assert!(reads_from(&format!("{BASE}{}", endpoints::LOGIN_PAGE)));
        assert!(reads_from("https://WWW.Wealthfront.com/dashboard"));
        for other in [
            "https://wealthfront.com/login",
            "https://app.wealthfront.com/",
            "https://www.wealthfront.com.evil.example/login",
            "https://notwealthfront.com/",
            "https://www.notwealthfront.com/",
            "https://evil.example/?next=https://www.wealthfront.com/",
            "https://www.wealthfront.com@evil.example/",
            // Cyrillic `о`, and the punycode Chrome would report for it.
            "https://www.wealthfr\u{043e}nt.com/",
            "https://www.xn--wealthfrnt-lvi.com/",
            "http://www.wealthfront.com/login",
            "https://www.wealthfront.com:8443/login",
        ] {
            assert!(!reads_from(other), "{other} must not be read");
        }
    }

    /// The jar is matched label for label. The embedded capture this
    /// replaced kept any cookie whose domain contained "wealthfront.com",
    /// which took both confusables below.
    #[test]
    fn the_jar_takes_wealthfront_com_hosts_and_no_confusable() {
        let jar = HostRule::domain(JAR_DOMAIN).unwrap();
        for host in [
            "wealthfront.com",
            "www.wealthfront.com",
            "a.b.wealthfront.com",
        ] {
            assert!(jar.matches_host(host), "{host} is in the jar");
        }
        for host in ["notwealthfront.com", "wealthfront.com.evil.example"] {
            assert!(host.contains(JAR_DOMAIN), "the old filter took {host}");
            assert!(!jar.matches_host(host), "{host} must not be in the jar");
        }
        for host in ["wealthfront.co", "xn--wealthfrnt-lvi.com", "com"] {
            assert!(!jar.matches_host(host), "{host} must not be in the jar");
        }
    }

    /// The `/capitan/v1/me` answer, mapped one to one from the embedded
    /// capture: a session keeps the tab for the read, a signed-out answer
    /// keeps waiting, anything else ends the wait as exit 5.
    #[test]
    fn the_me_read_decides_the_capture() {
        assert!(matches!(me_verdict(Ok(json!({}))), Confirm::Ready));

        match me_verdict(Err(CliError::Auth("session expired".into()))) {
            Confirm::NotYet(reason) => {
                assert_eq!(reason, "GET /capitan/v1/me answered as signed out");
            }
            other => panic!("an auth error must keep waiting: {other:?}"),
        }

        for e in [
            CliError::Upstream("Wealthfront HTTP 503 for /capitan/v1/me".into()),
            CliError::NotFound("/capitan/v1/me (HTTP 404)".into()),
            CliError::Usage("WFR_BASE_URL must be a plain http(s) URL".into()),
            CliError::Other("connection reset".into()),
        ] {
            let cause = e.to_string();
            let Confirm::Fail(err) = me_verdict(Err(e)) else {
                panic!("{cause} must end the wait");
            };
            assert_eq!(err.exit_code(), 5, "{cause}");
            match &err {
                CliError::Upstream(message) => assert_eq!(
                    message,
                    &format!("session validation failed during the browser login: {cause}")
                ),
                other => panic!("{cause} must end the wait as upstream: {other:?}"),
            }
            // As the crate hands it back to `auth login`.
            assert_eq!(CliError::from(BrowserError::Handler(err)).exit_code(), 5);
        }
    }
}
