# Wealthfront's private API — findings, guesses, and traps

## 2026-08-31 diagnosis — the bare-HTTP login was fixable all along

The reported symptom: `wfr auth login --stdin --overwrite` failed **immediately**
with `Wealthfront session expired or invalid — run wfr auth login`, even right
after `logout`, even with `-v`, and even with a *wrong* password. A session error
on a login command was the tell. Root cause, traced live (evidence below):

1. **The request was missing the `login_xsrf` handshake.** `client.rs::login`
   POSTed a bare `{username, password}` to `/api/access/login` with no prior
   `GET /login`, so the cookie jar held no `login_xsrf` and the body carried no
   `loginXsrf`. Wealthfront turned the request away **before checking
   credentials** with `HTTP 200 {"redirectUrl":"/login","success":false}`.
2. **`classify_login` misread that pre-auth bounce as `Authenticated`** (it
   matched no rejection/MFA branch and fell through the old `status==200 && !html`
   rule). `finish()` then read `/capitan/v1/me`, got **HTTP 401
   `{"errorType":"AUTHENTICATION_REQUIRED"}`**, and mapped it to "session
   expired". Credentials were never actually checked, which is why it fired
   before any 2FA step and `-v` showed nothing.

The endpoint is **not** dead (contrast sofi-cli, whose `/login-service/v1/login`
404s). `/api/access/login` is live and HTTP-reachable. The fix: `login()` now
primes `login_xsrf` via `GET /login`, sends it **URL-decoded** in `loginXsrf`,
and `classify_login` treats the bounce as an error, not a session.

**reCAPTCHA is no longer a hard gate (correction to §3.2).** A tokenless
bare-HTTP POST — no browser, no `maybeRecaptchaEnterpriseToken` — reaches
credential validation. Evidence, all `POST /api/access/login`, HTTP 200, with a
throwaway wrong password (`probe@example.invalid` / `wrong-password-probe`):

| Request | Response body |
|---|---|
| bare `{username, password}` (old CLI) | `{"redirectUrl":"/login","success":false}` |
| + `loginXsrf` sent **raw/percent-encoded** | `{"redirectUrl":"/login","success":false}` |
| + `loginXsrf` sent **URL-decoded** | `{"success":false,"errorMessage":"Invalid email address or password."}` |
| decoded `loginXsrf` + username + password only (no recaptcha/sessionType/browserInfo) | `{"success":false,"errorMessage":"Invalid email address or password."}` |

So the *only* thing separating "bounced" from "credentials checked" is sending
`loginXsrf` URL-decoded to match the `login_xsrf` cookie — the same percent-decode
the authenticated `xsrf`/`x-csrf-token` pair already needs (§3.4). A wrong
password now localizes as a credentials error (exit 3, "rejected the username or
password") — verified through the installed binary. `--browser` remains a
fallback if the reCAPTCHA score ever hardens on the *success* path.

**MFA endpoints (correction to §2).** `POST /api/access/mfa/send` and `POST
/api/access/mfa/verify` — the CLI's guesses — both **404 live**. The one live
endpoint is **`POST /api/access/mfa`** (a no-session probe returns HTTP 200
`{"tokenExpired":true,"success":false,"errorMessage":"Authorization expired. Try
logging in again."}`, sharing the login family's `success`/`errorMessage`
envelope). There is no separate "send" step — the SMS is delivered as a side
effect of a successful `POST /api/access/login`, so `send_code` is now a no-op and
`verify_code` posts the code to `/api/access/mfa`. The MFA **request body** (the
code field name) is still UNVERIFIED-LIVE — it needs the owner's one real login.

## 2026-09-01 follow-up — the headless real-password login hung silently

After the fix above merged, a **real**-password headless run (`printf PW | wfr
auth login --stdin --overwrite` from a non-TTY shell) hung 5+ minutes with no
output and **no SMS**, and had to be killed. Control-flow analysis of the login
path found exactly one *unbounded* blocker — every HTTP call carries a 45s
client timeout, the `--stdin` read gets EOF from a closed pipe, and the code
prompt is gated on stdin being a TTY (`CommonArgs::interactive`), so none of
those can hang. What *can* block forever is the **OS keychain**: `login()`
performed a keychain **read** of the stored password before anything else —
even with `--stdin --overwrite`, whose whole point is to not want the stored
value — and a macOS keychain approval dialog (raised, e.g., when a
**differently-signed reinstall** loses the "Always Allow" grant; a
`self-update`-installed release binary is **not** dev-signed) blocks
indefinitely, invisible to a non-TTY shell. No output and no SMS both fit: the
hang precedes the network.

Hardening (all offline-tested against a loopback fake server; `WFR_BASE_URL` is
the loopback-**only** test seam — validated with a real URL parser, and userinfo
is refused outright, so ambient env can never redirect a credential-bearing POST
by spoofing the authority, e.g. `http://127.0.0.1:1@evil.example.com`):

- **A headless run performs no pre-network keychain read at all.** "Headless"
  is `--stdin`, `--from-env`, `--overwrite`, **or a piped (non-TTY) stdin with
  no flags** — the bare-pipe shape reads the pipe anyway, so it gets the same
  guarantee. Both the stored-password read **and the device-trust read** are
  skipped (the device read is an optimization; nothing writes `device` yet).
  The headless path reads the pipe, then goes straight to the network.
- **The password is stored only after Wealthfront accepts it** (a rejected
  password is never persisted), and the store is best-effort — a keychain
  failure cannot strand a spent SMS.
- **Every potentially-blocking phase announces itself on stderr first**
  ("logging in…", "credentials accepted…", "checking for a remembered device in
  the keychain" on interactive runs, "parking the sign-in in the keychain
  (approve the prompt if macOS asks)") — a future block names its culprit
  instead of hanging silently. The SMS rate-limit warning moved **before** the
  login POST, because that POST is what spends the SMS.
- The non-TTY ending is unchanged and now regression-tested end to end through
  the real binary, in both the flagged and bare-pipe shapes: park the in-flight
  session, print the ``re-run with `wfr auth login --code <CODE>` ``
  instruction, exit 3 — never prompt (`tests/cli_surface.rs::
  headless_login_with_piped_stdin_never_prompts_or_hangs`,
  `::bare_piped_stdin_without_flags_is_headless_too`).

If a headless run ever stalls again, the last stderr line now names the phase;
a stall on a keychain line is the macOS approval dialog — run once from a real
terminal session and click Always Allow, or re-sign via `make install` (the
stable `pk-cli-codesign` identity keeps the grant).

---

**Status: first-party live captures on 2026-08-13, 2026-08-18, and 2026-08-31.**
The 2026-08-18 capture **completed an authenticated login** (de-automated browser
+ real password + one SMS code) and the CLI reads the real API end to end; the
2026-08-31 diagnosis (above) revived the **bare-HTTP** login. Key findings:

- The web login runs **reCAPTCHA Enterprise**, an *automation-fingerprint* gate,
  **not an absolute wall**: a default Playwright browser is rejected, while one
  with the automation flags removed passes it and reaches credential validation
  (§3.2). The **app-specific password is rejected** by the web login (§3.3) — a
  real login needs the real password + 2FA.
- With a session in hand, authenticated `/capitan/` reads require the session
  cookies **plus an `x-csrf-token` header** derived from the `xsrf` cookie (§3.4)
  — the piece a cookies-only client misses.
- **`wfr accounts list` / `transactions list` / `api` are VERIFIED-LIVE** against
  `/capitan/v1/accounts/overviews2` and `/capitan/v1/activities`. The CLI
  obtains the session itself with `wfr auth login --browser` (§3.6). The
  bare-HTTP `wfr auth login` reaches 2FA too, but its code step is
  UNVERIFIED-LIVE (the 2026-08-31 diagnosis above).

Everything below is labelled with what is actually known.

| Label | Meaning |
|---|---|
| **VERIFIED** | Stated outright in a public source, cited inline. |
| **CAPTURED-LIVE** | Observed directly in the 2026-08-13 capture against the real site. Real, not a guess. |
| **ATTESTED** | Read off open-source code that was written against a real capture, so the shape is real but possibly stale. |
| **UNVERIFIED-LIVE** | A hypothesis. Nobody has confirmed it, including us. Expect it to be wrong. |

`wfr import csv` touches no network and is **verified end to end offline** by
the test suite. It — and a future `import qfx` — are still the *simplest* way to
get Wealthfront tax data into this CLI. The live-API path works too (`wfr auth login --browser` for the
session, §3.6), just heavier; see §10 for the CSV-vs-QFX-vs-API recommendation.

---

## 1. There is no public API — VERIFIED

Wealthfront publishes no developer API, no OAuth, no sandbox, no SDK, and no
webhooks. Its REST API is internal to its own apps.

> "At Wealthfront, we have an API server which exposes a REST API that's
> consumed by our iOS and Android apps."
> — [Wealthfront Engineering](https://eng.wealthfront.com/2016/08/31/enforce-rest-api-standard-with-swagger/)

Third-party read access is sanctioned only through aggregators (Plaid, MX,
Yodlee), which authenticate with the user's own credentials.
See [Supergood's API report card](https://supergood.ai/api-report-card/wealthfront)
and [API Tracker](https://apitracker.io/a/wealthfront).

**Consequence:** any CLI for Wealthfront is unsanctioned automation of a
private surface. It can break without notice, and it may violate the terms of
service — that is the owner's call to make knowingly, not a detail to discover
later.

## 2. What the internal API looks like

| Fact | Confidence | Source |
|---|---|---|
| REST, not GraphQL | VERIFIED | [eng blog](https://eng.wealthfront.com/2016/08/31/enforce-rest-api-standard-with-swagger/) |
| Defined in Swagger/OpenAPI; clients generated with Swagger Codegen; JAX-RS (Java) server stubs | VERIFIED | same |
| JSON, `snake_case` | VERIFIED | same, plus the attested payload below |
| Version-prefixed paths — the blog's worked example is `/v1/account?account_id=…&account_type=…` | VERIFIED (as a 2016 example) | same |
| Web and mobile share **one** API server — the web frontend was deliberately migrated onto it | VERIFIED | same |
| Web wraps it in an in-house SDK, and since 2024 a React Query `useApiQuery` hook | VERIFIED | [eng blog 2024](https://eng.wealthfront.com/2024/08/01/revamping-data-fetching-patterns-on-the-web-platform/) |
| Host is `www.wealthfront.com` | **CAPTURED-LIVE** | every request in the 2026-08-13 capture, login and API alike, was to `https://www.wealthfront.com/...` |
| The authenticated API base is **`/capitan/v1/`** — *not* `/v1/` | **CAPTURED-LIVE** | observed XHRs `GET /capitan/v1/loan/interest-range`, `GET /capitan/v1/mortgages/marketing-quote`, `POST /capitan/v1/webauthn/start-assertion`. The old `/v1/` guess never existed (see below). |
| Login/session lives under **`/api/access/`** | **CAPTURED-LIVE** | the login `POST` is `/api/access/login` (§3.1) |
| A separate `app.` / `api.` host or a web BFF | **not observed** | no request left `www.wealthfront.com`; the shared-API claim holds |
| Stack is Rails behind Fastly/Varnish, React/Vite SPA front end | **CAPTURED-LIVE** | `x-runtime`, `x-request-id`, `via: varnish`, `x-served-by: cache-*`; `cdn.wealthfront.com/vite/…` bundles. Confirms "expiry is a redirect, not a 401". |

### UI routes — VERIFIED

`/login`, `/mfa`, `/transactions`, `/documents` are all real pages.
That `/mfa` is a **distinct route** is the useful part: login is a two-step
flow, not one POST that sometimes returns a code challenge.

### The one endpoint anyone has published — ATTESTED

[KrauseFx/wealthfront-tax-info-exporter](https://github.com/KrauseFx/wealthfront-tax-info-exporter)
instructs the reader to open `/transactions`, filter devtools to XHR, and copy
the response of the **`transfers-for-account`** request.

Its [parser](https://raw.githubusercontent.com/KrauseFx/wealthfront-tax-info-exporter/master/generate_tax_documents.rb)
was written against a real capture, so the response shape is attested:

```jsonc
{ "transfers": { "completed_transfers": [
  { "created_at": "...", "class_type": "dividend", "amount": "$18.44",
    "type": "...", "transaction_type": "...",
    "dividends": [ { "symbol": "...", "ex_date": "...",
                     "amount_per_share": "...", "amount": "$..." } ],
    "trades":    [ { "symbol": "...", "type": "...", "shares": "...",
                     "share_price": "$...", "date": "...", "value": "$..." } ],
    "your_fee": "$...", "period": "..." }   // fee records only
] } }
```

`class_type` values seen in that source: `dividend`, `dividend-investment`,
`other-investment`, `index-optimization`, `harvest`, `withdrawal`,
`liquidation`, and `fee`.

**Trap:** `amount` is a **string with a `$` prefix**, not a number. A mapper
that assumes a float drops every row. `tests/fixtures/transfers-for-account.json`
pins this and `tests/fixture_shapes.rs` asserts it.

**Caveats:** only the request *name* is public — the host, path prefix, method
and query parameters are all **UNVERIFIED-LIVE**. The repo's last commit was
in **2021**, so this is a roughly four-and-a-half-year-old observation.

### The read endpoints in `src/client.rs` — now captured

The 2026-08-13 capture settled the *base*; the 2026-08-18/19 authenticated
captures settled the read *resource paths*:

- The old `/v1/…` prefix is **confirmed wrong**. Unauthenticated `GET`s to
  `/v1/user`, `/v1/accounts`, `/v1/me`, `/api/v1/user`, `/api/user` all returned
  **HTTP 404 `{}`** (even with HTTP Basic Auth using the app-specific password —
  Basic Auth is not the mechanism). The real base is **`/capitan/v1/`**.
- The reads are **CAPTURED-LIVE** and their exact segments observed:
  `/capitan/v1/me`, `/capitan/v1/accounts/overviews2`,
  `/capitan/v1/activities?account_id=…` (§3.4). Documents are the exception to
  the `/capitan/` rule — they live on the Rails `/api/` host:
  `/api/documents/statements` for the list and
  `/documents/{accountId}/document/{externalId}` for the PDF (§3.4, §4). So the
  earlier guess that `/v1/documents` would re-prefix to `/capitan/v1/documents`
  was **wrong**; the working paths are the captured ones above. The one read
  still uncaptured is `transfers-for-account` (investment activity) — its 2021
  path now **404s**, and this owner has only cash accounts, so it is not wired.
- The MFA sub-endpoints `/api/access/mfa/send` and `/api/access/mfa/verify`
  **404 live (2026-08-31)** — they do not exist. The real second-factor endpoint
  is a *single* **`POST /api/access/mfa`** (CAPTURED-LIVE: a no-session probe
  returns HTTP 200 `{"tokenExpired":true,"success":false,"errorMessage":
  "Authorization expired. Try logging in again."}`). There is no separate "send"
  call: the SMS is delivered as a side effect of a successful `POST
  /api/access/login`. So the flow is two POSTs — `login` then `mfa` — not three.
  See the 2026-08-31 diagnosis at the top of this file and §3.1.

## 3. Authentication

| Fact | Confidence | Source |
|---|---|---|
| Email address + password | VERIFIED | [2FA help](https://support.wealthfront.com/hc/en-us/articles/211004563-Two-Factor-Authentication) |
| **2FA is mandatory and cannot be disabled** | VERIFIED | same |
| Second factor is **SMS** or **TOTP** (Google Authenticator, Duo, 1Password) | VERIFIED | same; [blog](https://www.wealthfront.com/blog/secure-wealthfront-accounts-two-step-authentication/) |
| Email as a login factor | **no public source** — appears only for account recovery. Not offered by this CLI. |
| "Remember this device" exists; trusted devices skip the prompt; re-verification roughly every six months | VERIFIED | [2FA help](https://support.wealthfront.com/hc/en-us/articles/211004563-Two-Factor-Authentication) |
| Login endpoint and POST field names | **CAPTURED-LIVE** — `POST /api/access/login`, body fields `loginXsrf, username, password, maybeRecaptchaEnterpriseToken, sessionType, grantType, browserInfo` (§3.1). **Only `loginXsrf` (URL-decoded) + `username` + `password` are required** to reach credential validation (2026-08-31); the reCAPTCHA token is **not** required. `client.rs::login` now sends the handshake correctly. |
| Session is a cookie, not a bearer token | **CAPTURED-LIVE** — the flow is cookie-based. The login page sets `login_xsrf` (HttpOnly) and `t-token`; the login attempt added `_wfsid`, `_wfvid`, `_wfmvid`. *Which* cookie authenticates could not be confirmed (login never succeeded), so `session_bundle()` must still keep the whole jar. |
| Device-trust token name/format | **UNVERIFIED-LIVE** — not observed |

### 3.1 The real login flow — CAPTURED-LIVE

Driving `www.wealthfront.com/login` in a real browser and intercepting the
network showed the login is a single XHR, not the guessed `/v1/login`:

```
POST https://www.wealthfront.com/api/access/login
body (JSON) fields:
  loginXsrf                       # echoes the login_xsrf cookie set on GET /login
  username                        # the login email
  password                        # the password (regular password — NOT the app-specific one)
  maybeRecaptchaEnterpriseToken   # a reCAPTCHA Enterprise token minted by the page's JS
  sessionType                     # "WEB" for the web form (see §3.3 — not an app-password switch)
  grantType                       # "password" (OAuth2 resource-owner password grant)
  browserInfo                     # device/browser fingerprint object
```

This is an **OAuth2-style token endpoint** (`grant_type=password`), and it is one
of a `/api/access/*` family mapped from the login JS (CAPTURED-LIVE):
`login`, `mfa`, `oauth_login`, `finish_webauthn_assertion_and_login`,
`backup_code`, `forgot_password`, `choose_password`, `reset_mfa_to_sms`,
`add_sms_mfa_device_for_required_mfa_session`,
`confirm_sms_mfa_device_for_required_mfa_session`, plus `/oauth/url/new` and
`/oauth/url/existing`. The `oauth_login` + `/oauth/url/*` endpoints show
Wealthfront is (or is becoming) an OAuth data provider — the sanctioned
third-party path, but a partner-registration flow, not one a CLI can self-serve.

The page first `GET`s `/login`, which sets `login_xsrf` (HttpOnly, Secure) and
`t-token`. The login `POST` returns **HTTP 200** regardless of outcome — a
reCAPTCHA failure ("We weren't able to verify you"), a credential failure
("Invalid email address or password"), or success are all 200s with different
bodies — and the response added `_wfsid`, `_wfvid`, `_wfmvid` cookies. A passkey
path also exists (`POST /capitan/v1/webauthn/start-assertion`, "Continue with
passkey").

**Trap for `client.rs` — FIXED 2026-08-31.** The original `login()` posted a bare
`{username, password}` with no `login_xsrf` handshake, and `classify_login` fell
through to `Authenticated` on the resulting pre-auth bounce (neither "invalid
password" nor "mfa" appears in `{"redirectUrl":"/login","success":false}`). That
is the bug behind the "session expired" symptom (see the 2026-08-31 diagnosis at
the top of this file). The current `login()`:

- **Primes `login_xsrf`** with `GET /login`, then sends it **URL-decoded** in the
  `loginXsrf` body field (a raw/percent-encoded value is bounced — table above).
- Sends the web client's other fields (`sessionType:"WEB"`, `grantType:
  "password"`, `browserInfo:{}`) and `maybeRecaptchaEnterpriseToken:null` — the
  reCAPTCHA token is **not required** to reach credential validation (§3.2
  correction).
- `classify_login` now treats the `{"redirectUrl":"/login","success":false}`
  bounce and the `{"errorMessage":"Invalid email address or password."}`
  rejection as hard failures, and only proceeds on a positive `success:true` /
  MFA marker — never on a bare 200. A wrong password localizes as a credentials
  error, which is the distinction that found this bug.

### 3.2 reCAPTCHA Enterprise — not even required on the JSON login endpoint (2026-08-31)

> **Correction (2026-08-31):** the conclusion below — that a browser was needed
> to mint a reCAPTCHA token — is **overturned for the JSON login endpoint**. A
> tokenless bare-HTTP `POST /api/access/login` with the `login_xsrf` handshake
> reaches credential validation (a wrong password returns "Invalid email address
> or password"). No `maybeRecaptchaEnterpriseToken` is needed there. The reCAPTCHA
> badge still loads on the *page*, but this endpoint does not enforce it on the
> failure path. Two honesty caveats stand: the score is probabilistic, and the
> *success* path (correct password) was not re-tested tokenless — if it ever
> hardens, `wfr auth login --browser` is the fallback. The rest of this section
> is the 2026-08-13 browser-based finding, kept for history.

The login page loads Google **reCAPTCHA Enterprise** (`recaptchaEnterpriseSiteKey`,
`https://www.google.com/recaptcha/api.js`) as an **invisible** badge (no
checkbox). Its risk score keys on **automation fingerprinting**, and testing on
2026-08-13 showed it is bypassable from a real browser context:

- **Default Playwright browser (automation signals present)** → the login `POST`
  was rejected *before* credential validation with:
  > **"We weren't able to verify you. If you're on a VPN, please disconnect and
  > try again."**
- **Playwright with the automation flags removed** (`--enable-automation`
  dropped via `ignoreDefaultArgs`, `--disable-blink-features=AutomationControlled`,
  and `navigator.webdriver` masked) → the *same* `POST` **passed reCAPTCHA and
  reached credential validation**, returning **"Invalid email address or
  password"** (§3.3).

So reCAPTCHA here is **not** an absolute wall — a browser that doesn't advertise
itself as automated gets through. Two honesty caveats: (1) reCAPTCHA Enterprise
scoring is **probabilistic**; one clean pass is not proof of reliability, and a
low score can still challenge or block. (2) Passing it still requires a real
**browser** to mint the token — a bare `curl`/`reqwest` cannot — so a CLI that
wants to log in must **embed a headless browser** (e.g. Playwright) with these
mitigations, then carry the real password + 2FA (§3.3). That is a heavier
architecture than the offline `import csv` / `import qfx` path (§10), but it is
**feasible**, which the earlier "infeasible" conclusion in this doc got wrong.

### App-specific passwords — VERIFIED, and probably the right answer

Wealthfront issues **read-only app-specific passwords** for third-party
linking, precisely because 2FA blocks the normal password:

> "If you use two-factor verification with Wealthfront, you won't be able to
> use your Wealthfront password to link to Wealthfront from another app or
> website."
> — [app-specific passwords](https://support.wealthfront.com/hc/en-us/articles/360045750632-Link-to-Wealthfront-with-app-specific-passwords)

Generate one at: log in → your name (top right) → **Settings → Security → "Link
Wealthfront to other apps" → "Generate an app specific password"**
([steps confirmed by Empower's docs](https://support-personalwealth.empower.com/hc/en-us/articles/360051450594-Linking-Wealthfront-with-Two-Factor-Authentication-2FA)).

This is what Plaid, TurboTax, and Empower use. It is read-only, which matches
this CLI's read-only scope, and it sidesteps the second factor entirely.

### 3.3 App-specific password verdict — ANSWERED: the web login rejects it

We staged a read-only app-specific password and tried it two ways:

1. **HTTP Basic Auth** against `/v1/user`, `/v1/accounts`, `/v1/me`,
   `/api/v1/user`, `/api/user`, and the `/transactions` / `/documents` pages —
   all 404 or 302-to-login. Basic Auth is **not** the mechanism.
2. **The real web login** (`POST /api/access/login`), driven through the
   lower-fingerprint browser that passed reCAPTCHA (§3.2). The form returned
   **"Invalid email address or password."** The email is correct, so the
   **app-specific password is not a valid credential for the interactive web
   login.** (Earlier this doc said "still unknown" because the default browser
   was reCAPTCHA-blocked before the password was checked; once we passed
   reCAPTCHA, the answer was unambiguous.)

This matches Wealthfront's own design: the app-specific password is consumed by
**aggregators' back ends** (Plaid, Quicken Connect, Empower/Yodlee) through their
negotiated linking, **not** the interactive web login — and there is **no OFX
Direct Connect** server (only Web Connect / manual `.qfx`). So a web login for
this CLI needs the **real password + 2FA**; the app-specific password does not
substitute for it here. Keep it in the keychain only for aggregator linking, or
delete it — it does nothing for `wfr`'s own login.

**We probed `session_type` — it is not a hidden switch.** The login body carries
`grant_type` + `session_type` (the web form sends `grant_type=password`,
`session_type=WEB`). A plausible theory was that an aggregator `session_type`
validates against the app-password store and skips 2FA/reCAPTCHA. Tested via the
de-automated browser (which reaches real credential validation), the app
password was rejected **identically** under `WEB`, `AGGREGATION`, and
`THIRD_PARTY` — same "Invalid email address or password" every time (no lockout).
So `/api/access/login` checks the regular-password store regardless of
`session_type`; the app password is simply not consumed by this endpoint. Note:
a bare `curl` can't probe this — tokenless requests are bounced pre-auth with a
generic `{"redirectUrl":"/login","success":false}`, so a browser-minted
reCAPTCHA token is required just to reach credential validation.

**How aggregators actually use it (generic mechanism, for the record).** There
is no special "app-password protocol" and nothing Wealthfront-specific to find.
Aggregators like Yodlee document **credential-based account aggregation**
(FastLink): the user hands the aggregator their site credentials — and an
app-specific password is just a **revocable password substitute** in that
password field — which the aggregator encrypts, stores, and **replays from its
own allowlisted backend via a proprietary per-institution "site connector."**
That connector is the aggregator's, not a public Wealthfront endpoint, which is
why our probing found no reachable surface. The industry is also moving to
token-based data sharing (US Open Banking / FDX), consistent with the
`/api/access/oauth_login` and `/oauth/url/{new,existing}` endpoints seen here —
but that is a registered-data-recipient (partner) flow, not something a personal
CLI can initiate. **Conclusion: do not re-chase an app-password login path for
`wfr`; there is no accessible one.** See the newly-mapped `/api/access/*` surface
in §3.1.

### 3.4 Making authenticated reads work — CAPTURED-LIVE (2026-08-18)

Once a browser login completes, the reads are reachable from the CLI. Two
things are required on every authenticated `/capitan/` request, and the second
is the one a cookies-only client misses:

1. **The session cookies.** A completed login sets `_wfsid` (plus `token`,
   `device_secret`, `xsrf`, `login_xsrf`, `t-token`, …). The whole jar is stored
   under keychain `piekstra.wfr/session`.
2. **The `x-csrf-token` header.** Its value is the **`xsrf` cookie, URL-decoded**
   (the cookie is percent-encoded base64: 86 chars → 82). Without it every
   authenticated `/capitan/` GET is **401**, even with a perfect session cookie.
   `client.rs::csrf_token` extracts and decodes it; `with_csrf` attaches it.

With both, `wfr accounts list` / `transactions list` / `api GET /capitan/v1/me`
return real data — **verified end to end on 2026-08-18**. That session was
first persisted from a de-automated browser login (real password + one SMS
code); `wfr auth login --browser` now does that step (§3.6).

**Verified read endpoints:** `GET /capitan/v1/me` (session check), `GET
/capitan/v1/accounts/overviews2` (accounts → `overviews[]`), `GET
/capitan/v1/activities?account_id=…` (activity feed; real transactions are
`TXN_*`, amount is in the `body` sentence), and `GET /api/documents/statements`
(statements + trade confirmations → `statements[{accountId(numeric), type, date
(YYYYMMDD), externalId}]`) with the PDF at `GET /documents/{accountId}/document/
{externalId}` (2026-08-19). Notes: `/capitan/v1/documents/user` is the tax-form
list (empty when no forms issued, not wired); the 2021 `transfers-for-account`
endpoint now **404s** (investment-account activity has no captured shape).

### 3.5 Net worth — a client-side rollup of `accounts/overviews2`

`wfr net-worth` emits the family `net-worth/v1` DTO (the same shape `m1f
net-worth` and `rhd net-worth` emit). Its read is the **CAPTURED-LIVE**
accounts endpoint (§3.4) — the command is **VERIFIED-LIVE (2026-08-24)**: the
owner's smoke against a live session returned three real accounts
(PERSONAL_CASH / JOINT_CASH / JOINT) with the household total equal to their
sum. It introduces no new endpoint:

- **Endpoint:** `GET /capitan/v1/accounts/overviews2` — exactly what
  `accounts list` reads. Both commands go through the shared
  `src/commands/overviews.rs` module (one envelope unwrap, one set of field
  readers), so they can never disagree about which accounts exist or how a
  balance is read.
- **Field mapping:** per `overviews[]` row, `account_number` ← `accountId`,
  `type` ← `accountType` (verbatim — `PERSONAL_CASH`, `JOINT_CASH`,
  `TAXABLE_INVESTMENT`, …), `total` ←
  `accountValueSummary.formattedTotalValue`/`.totalValue` (top-level money
  fields as fallback). `assets`/`liabilities`/`total` are then summed from the
  rows.
- **Why the rollup is client-side:** no captured `/capitan/v1` endpoint
  serves a household total — the 2026-08-13/18/19 captures saw per-account
  values only. The sum is integer cents (every amount passes through
  `Money::parse_usd`, which normalizes to two fraction digits, so cents
  summation is lossless with respect to what the CLI reports — Robinhood's
  sub-cent-equity lesson does not apply here). If a live capture ever finds a
  provider-served household total, prefer it and record it in this section.
- **Liabilities:** `overviews2` carries no captured margin/borrow shape (this
  owner has no Portfolio Line of Credit, so none was observable). A row whose
  own `totalValue` is negative lands in `liabilities`; otherwise the field is
  omitted per the profile. If a borrow account is ever captured, its shape
  belongs here.
- **Traps.** (1) The bare `overviews2` path returns **all** accounts (the web
  app's `filter_customer_account_states` params are optional) — completeness
  relies on that; never add the filter params to this read. (2) Neither the
  config file's persisted `account` default **nor the `WFR_ACCOUNT` env var**
  scopes this command — only a `-a` typed on the command line narrows it (the
  dispatcher checks clap's `ValueSource`), and even that announces itself on
  stderr. Both are ambient state that outlives an invocation, and a household
  figure silently narrowed by ambient state — indistinguishable in the DTO
  from a genuine single-account household — is the exact misreport the
  honesty rules exist to prevent. (3) A record that fails to map is a **hard
  error** here, not a counted skip as in `accounts list`: a household figure
  quietly missing an account must not be a stderr footnote.

### 3.6 Browser sign-in — `wfr auth login --browser`

**Status.** The flow was VERIFIED-LIVE on 2026-08-18 with a Chrome capture
embedded in this repo. It now runs on cli-common's shared `pk-cli-browser`
crate
([cli-common DESIGN.md §2.2](https://github.com/piekstra/cli-common/blob/v0.14.0/DESIGN.md)),
which makes the same reads and stores the same session. That build is
UNVERIFIED-LIVE until the owner's next sign-in through it.

The owner signs in on Wealthfront's own page in a plain Chrome window. The
window has a debug port and a scratch profile, and none of the automation
flags reCAPTCHA scores (§3.2). The CLI reads the session out of the window
over the Chrome DevTools Protocol. It never evaluates anything in a page:
the page list and the cookies are browser-level reads.

| Step | What `browser_capture` (`src/commands/auth.rs`) does |
|---|---|
| Start page | `https://www.wealthfront.com/login` |
| Host | pages on exactly `www.wealthfront.com` (`https`, default port), parsed and compared label for label. The apex, other wealthfront.com hosts and look-alikes are never read or closed. |
| Gate | the `_wfsid` cookie, as the browser would send it to `https://www.wealthfront.com/` |
| The session | every cookie the browser would send to `wealthfront.com` or a host under it, `HttpOnly` included, as one `k=v; k=v` header: the jar §3.4 needs |
| Confirm | on each 3-second poll, once the gate passes and before the tab closes, one `GET /capitan/v1/me` with that jar. A JSON object closes the tab and hands the jar over. A signed-out answer (401, 403, a redirect to the sign-in or 2FA page, or HTML where JSON was expected) keeps waiting. Anything else ends the login as exit 5: 404, 429, 5xx, a 200 that is empty, `null`, not JSON or JSON other than an object (no signed-out answer has that shape; a visitor gets 401), the network, a cookie or CSRF bug, `session validation failed during the browser login: …`. |
| Stored | the confirmed jar, unchanged, under keychain `piekstra.wfr/session`: the bundle the password login stores and every read seeds from |

Each Confirm outcome is tested offline. The unit tests in
`src/commands/auth.rs` build the capture with `pk-cli-browser`'s `test-util`
constructors and answer the `/capitan/v1/me` read from a loopback server
(`src/loopback.rs`). They also check that the read sends the jar and the
decoded `x-csrf-token`.

The crate stops Chrome and deletes the profile on every exit. The profile is
`0700`, created exclusively under an unpredictable name in the temp dir.
`WFR_CHROME` points at a Chrome binary. Without it, the crate looks in the
standard macOS paths (Chrome, Chromium, Edge, also under `~/Applications`),
then the Linux ones.

On stderr, unless `-q`:

```
A Chrome window opened at the Wealthfront sign-in. Sign in there (password and 2FA); this waits for the session and captures it (up to 10 minutes; Ctrl-C cancels).
Wealthfront: session captured, tab closed.
logged in — session captured from the browser
```

| Outcome | Exit |
|---|---|
| Signed in and confirmed | 0 |
| 10 minutes pass, or the window is closed first. The message names what was seen (no `www.wealthfront.com` page open, `_wfsid` not set, or `GET /capitan/v1/me answered as signed out`, with the jar's cookie names, never values) and ends ``Re-run `wfr auth login --browser` and finish signing in.`` | 3 |
| The confirm read failed for a reason other than sign-in | 5 |
| Ctrl-C (`browser login canceled`), no Chrome found, or Chrome failed to start | 1 |
| A second Ctrl-C, when the first did not end the wait: Chrome is killed and the profile deleted | 130 |

**The surface around it.** `--browser` takes no other credential source: with
`--stdin` or `--from-env` it is exit 2 from clap, before anything reads the
keychain or the network. `wfr info` gives `wfr auth login --browser` as its
`login_hint`. `auth status` reports `method: "password"` whichever login stored
the session, although cli-common DESIGN.md §2.2 asks for `browser-session`
after a browser sign-in. Both logins store the same `k=v; k=v` cookie string
under `session`, so nothing stored says which one ran, and recording it would
mean new state beside the session.

**Traps.**

1. `_wfsid` is set for an anonymous visitor on the login page, so its
   presence proves nothing. The tab closes the moment the session is read,
   so a premature read cannot be retried. The `/capitan/v1/me` confirm is
   what proves the sign-in.
2. Match cookie domains label for label, never by substring. The embedded
   capture kept every cookie whose domain *contained* `wealthfront.com`, which
   takes `notwealthfront.com` and `wealthfront.com.evil.example`. The shared
   jar does not.
3. Keep the launch plain. The embedded capture also passed
   `--no-service-autorun --disable-background-networking`. The crate leaves
   service-disabling flags out because bot checks read them as automation.

### How this CLI handles MFA (the parking pattern)

The code Wealthfront sends belongs to **the session that requested it**. Two
separate `auth login` invocations create two sessions, and a code from the
first will be rejected by the second — a failure that looks like "Wealthfront
is broken" and cannot be diagnosed from the outside.

So `wfr auth login`:

1. submits credentials;
2. on a second-factor challenge, requests a code and **parks the in-flight
   session** in the keychain under `pending-login`;
3. exits 3 with `re-run with 'wfr auth login --code <CODE>'`;
4. `wfr auth login --code 123456` **resumes that exact session**, verifies, and
   deletes the parked entry — spent whether it succeeded or failed, so a dead
   session is never replayed.

`--channel totp` costs nothing (the code is generated on your device).
`--channel sms` spends a rate-limited message; the CLI says so before sending.

## 4. Statements and tax documents

| Fact | Confidence |
|---|---|
| Documents live at `/documents`, segmented by account then document type | VERIFIED — [KrauseFx](https://github.com/KrauseFx/wealthfront-tax-info-exporter), [help](https://support.wealthfront.com/hc/en-us/articles/209357766-Where-can-I-get-my-tax-documents) |
| Statements are **per-month PDFs, one at a time — no bulk download** | VERIFIED — same, and [alecbw](https://gist.github.com/alecbw/a14fab00e58be94c7540905fcb4283df) |
| Forms issued: consolidated 1099 (DIV + B), 1099-INT for Cash Accounts, 1099-R, 5498, 1099-Q | VERIFIED — [which documents](https://support.wealthfront.com/hc/en-us/articles/211006003-Which-tax-documents-will-I-receive-for-my-account) |
| Timing: Cash Account 1099 by **Jan 31**; consolidated 1099 around **Feb 15** | VERIFIED — [when delivered](https://support.wealthfront.com/hc/en-us/articles/211006023-When-will-my-tax-documents-be-delivered) |
| An Excel transactions / realized gain-loss sheet is posted next to the 1099 | VERIFIED — [help](https://support.wealthfront.com/hc/en-us/articles/115000268423-How-should-I-use-Wealthfront-s-tax-documents-if-I-don-t-use-TurboTax) |
| **Export to Quicken (QFX)**: Documents → "Get Started" under Export to Quicken → pick account + date range → `.qfx`. Not available for 529s. | VERIFIED — [help](https://support.wealthfront.com/hc/en-us/articles/209353346-Can-I-export-my-Wealthfront-account-data-to-another-personal-finance-tool-like-Quicken) |
| The documents-list JSON endpoint | **CAPTURED-LIVE (2026-08-19)** — `GET /api/documents/statements` → `statements[{accountId(numeric), type, date(YYYYMMDD), externalId}]` (§3.4) |
| The per-document download URL | **CAPTURED-LIVE (2026-08-19)** — `GET /documents/{accountId}/document/{externalId}` returns the PDF (not pre-signed/S3; a plain authenticated Rails route, gated on `%PDF`). §3.4 |

**The QFX export is the most under-appreciated finding here**: it is a native,
structured, account-scoped, date-ranged export covering investment accounts.
No one has published its endpoint, but it is the highest-value thing to capture
first (see follow-ups).

## 5. The CSV export

Wealthfront shipped a native Cash Account CSV export in H2 2025 —
*"The ability to export your Cash Account transactions to CSV"*
([What We Shipped H2 2025](https://www.wealthfront.com/blog/what-we-shipped-h2-2025/)).
Before that there was no CSV at all; people scraped the DOM
([mikebian.co](https://mikebian.co/download-a-csv-of-wealthfront-financial-activity/)).

**The column headers are not published anywhere.** The help centre has not
caught up with the feature.

The header sets this CLI accepts therefore come from a **working Wealthfront
CSV parser written for a previous project against real exports** — format
knowledge only; no data was copied and no export file was opened while building
this. Accepted spellings:

- date: `Date`, `Transaction date` / `Transaction Date`, `Trade Date`,
  `Post Date`, `Settlement Date`
- description: `Description`, `Transaction`, `Details`, `Memo`
- amount: `Amount`
- type: `Type`, `Transaction Type`, `Category`
- `Balance` is recognized and deliberately **not** emitted (see §6)

Matching is case- and whitespace-insensitive, because the exports disagree with
each other about capitalization.

> **Actively rejected as a source:** pocketportfolio.app publishes
> `Date,Symbol,Type,Quantity,Price,Amount` under the title "Wealthfront CSV
> Export". That is that tool's own generic import schema — the same page
> advertises "auto-detection for 20+ brokers" and never shows a real
> Wealthfront file. Adopting it would hard-code a format Wealthfront does not
> emit.

### Related formats, for reference

The [QFX→CSV converter](https://gist.github.com/dblume/946f6d88701371eec07d9e8c0d8432f6)
reveals what Wealthfront puts in its **QFX**, which is genuinely informative:

- bank/cash: `date, payee, memo, debit, credit, balance`
- investment: `type, tradeDate, settleDate, memo, income_type, units,
  unit_price, comission, fees, total, tferaction, securityid, securityname,
  securityticker, securitymemo`

Note the investment QFX carries **units, unit price, and security identity** —
everything the family `Transaction` DTO cannot represent. If per-lot detail is
ever needed, QFX is the source, not CSV.

## 6. Conventions this CLI chose, and why

**Amount sign is account-perspective, passed through unchanged.** Money in
(deposits, dividends, interest) is positive; money out (withdrawals, fees) is
negative — as the export writes it. This is the *opposite* of the `utility/v1`
reading of `Transaction`, where a charge you owe is positive. Inverting it
would be right for a power bill and nonsense for a brokerage account, so the
export's convention wins and is documented rather than silently "corrected".

**`Balance` is dropped.** The running balance is a property of the statement's
ordering, not of the transaction. Once a caller filters or sorts, a retained
balance column is actively wrong.

**Unknown `kind` values pass through verbatim.** `harvest`,
`index-optimization` and `other-investment` have no family equivalent, and
`harvest` in particular is exactly the row a tax workflow is hunting for.
Flattening it to `sell` would hide it. Known words (`dividend`, `interest`,
`fee`, `deposit`, `withdrawal`, `transfer`, `buy`, `sell`) canonicalize; the
rest keep Wealthfront's own wording.

**Records that fail to map are counted and reported on stderr**, never
silently dropped. While the shapes are unverified this is the CLI's smoke
alarm: "47 records, 3 mapped" is the signal that a field was renamed.

**An unrecognized response envelope is an error, not an empty list.** An empty
table is indistinguishable from "you have no accounts", which is the single
most dangerous silent failure available here.

## 7. Traps — the ones that cost other people hours

1. **A 200 is not success.** Portals re-render the same page with 200 on
   rejection. `classify_login` checks for explicit *rejection first*, because
   a rejected login often renders an MFA-shaped page — test for the code
   prompt first and the CLI asks for a code nobody sent.
2. **Expiry is rarely a 401.** A cookie-session web app answers an expired XHR
   with a redirect to `/login`. "Landed on a login URL" and "HTML where JSON
   was expected" are both treated as auth failures (exit 3).
3. **Downloads must be confirmed by content, not status.** An expired session
   returns 200 and a login page. `client::download` requires the `%PDF` magic
   number and refuses anything else, so a download either yields a real
   document or an error — never an HTML page saved as `1099.pdf`.
4. **A BOM will eat your header.** The export ships a UTF-8 BOM often enough
   that not stripping it renames `Date` to `\u{feff}Date` and makes every row
   report "missing date" — which reads like a corrupt file.
5. **Header casing differs between exports.** `Transaction date` and
   `Transaction Date` have both shipped. Exact-match on one and the other
   parses its header fine and then fails every row.
6. **Trailing-minus amounts.** `2.08-` from spreadsheet round-trips imports as
   **positive** unless handled — a sign error that survives into a tax total.
7. **Don't re-fetch to "confirm" a write.** Success banners are painted
   client-side; a fresh GET always shows the pre-action state.

## 8. Owner's first-login checklist

**Update (2026-08-13):** steps 1–3 below have been run. Step 1 (app-specific
password) is **answered**: it's rejected by the web login (§3.3). Steps 2–3 (the
real login) were captured — reCAPTCHA is passable from a de-automated browser
(§3.2), but the login was not *completed* (we did not submit the real password +
2FA). What remains — steps 4–6, the *authenticated* read/document/QFX shapes —
needs a completed login: either drive a de-automated Playwright browser with the
real password and supply a 2FA code, or log in normally in your own Chrome and
hand a copy of the `_wfsid` session to a devtools capture. This is the order that
spends the fewest codes and learns the most.

1. **Try an app-specific password first** (§3). Generate one, then:
   `wfr config set username <you@example.com>` and
   `wfr auth login --stdin <<< '<app-specific-password>'`.
   If this works, MFA never enters the picture. This is the single highest-
   value experiment.
2. **Capture the real login.** Open `www.wealthfront.com/login` with devtools →
   Network → preserve log. Log in normally. Record: the POST URL, the request
   body field names, the response shape, any CSRF or custom headers, and
   whether the session is a cookie (which one?) or a token.
3. **Capture the MFA step.** Note whether `/mfa` posts to a different endpoint,
   what the code field is called, and whether "remember this device" sets a
   cookie or returns a token. Record which cookie actually authenticates.
4. **Capture `transfers-for-account`.** Go to `/transactions`, filter XHR, find
   it, and record the full URL including query parameters. Confirm whether the
   account is a path segment or `?account_id=`. Diff the response against
   `tests/fixtures/transfers-for-account.json` — that fixture is a 2021 shape.
5. **Capture the documents list and one download.** Note whether the download
   URL is pre-signed (an `X-Amz-Signature` query parameter is the tell). If it
   is, it is a live credential — **never** commit it to a fixture.
6. **Capture the QFX export** (Documents → Export to Quicken). This may be the
   best structured source available.
7. **Correct `src/client.rs::endpoints` and the key lists in
   `src/commands/*.rs`** from what you captured, scrub captures into synthetic
   fixtures, and delete the UNVERIFIED-LIVE markers you have earned the right
   to delete.
8. **Check for bot defenses** while you are there: whether login is behind
   Cloudflare/Akamai/PerimeterX, whether there is a CAPTCHA, and whether the
   app fingerprints the device. None of this is publicly documented, and any
   of it could make a CLI login infeasible regardless of correct endpoints.
   **Answered 2026-08-13:** no Cloudflare/Akamai/PerimeterX/DataDome — just
   Fastly/Varnish caching. The login runs **reCAPTCHA Enterprise** (invisible)
   and sends a `browserInfo` fingerprint. It initially *looked* like a hard
   blocker (a default Playwright browser is rejected), but it turned out to be an
   automation-fingerprint gate that a de-automated browser passes (§3.2) — so it
   raises the cost of a CLI login (you must embed a browser) rather than making
   it impossible.

Budget one SMS code for step 2–3 combined. If the account uses TOTP, this is
free — prefer it.

## 9. Follow-ups

- **QFX support.** A native, structured, date-ranged export covering investment
  accounts, with per-lot units and security identity that CSV lacks. Probably
  the highest-value addition once its endpoint is known.
- **Per-lot / security-level DTOs.** The family `Transaction` has no `symbol`,
  `quantity`, or `unit_price`. Cost basis and realized gains need a richer
  shape — that is a profile conversation, not a provider hack.
- **Narrow the stored session.** `session_bundle()` currently keeps the whole
  cookie jar because no capture identifies which cookie authenticates. Once one
  does, store only that cookie plus what it needs.
- **`accounts` domain profile?** Only if a second CLI needs the same shape.
  Today it fails the PROFILES.md bar on every count.

## 10. Recommendation: the live path works end to end

The captures answer the "which source?" question that motivated this CLI. As of
2026-08-18 both halves of the live path exist: a browser login and the reads.

- **Live API — VERIFIED end to end (2026-08-18).** `wfr auth login --browser`
  opens a real Chrome window (launched *without* automation flags, so reCAPTCHA
  sees a normal browser — §3.6); you sign in (password + 2FA), and the CLI
  reads the session over CDP, confirms it against `/capitan/v1/me`, and stores
  it. A real run through the installed binary (with the embedded capture
  `pk-cli-browser` has since replaced) logged in and then
  `wfr accounts list` / `transactions list` / `api` read the live `/capitan/v1/`
  API off that session (§3.4). Caveats: it needs a local Chrome, and the session
  expires (re-run to refresh), so for a read-only tax tool the offline exports
  below are still the lowest-friction path.
- **CSV — works today.** `wfr import csv` is verified offline and is the
  reliable path. Its limit is scope: it is the Cash Account activity export, so
  no per-lot units or cost basis, and amounts follow the account-perspective
  sign convention (§6).
- **QFX — the best *structured* source, worth adding next.** Wealthfront's
  Documents → Export to Quicken produces a `.qfx` (Web Connect, a manual
  download — **not** a live endpoint) that carries `units`, `unit_price`, and
  security identity (§5) that CSV cannot represent. A `wfr import qfx` command,
  mirroring the offline `import csv` design, is the highest-value next step and
  needs no login. It was **not** built here because it should be written against
  a real `.qfx` export, and none was available in this session — do it when the
  owner can supply one (scrub to a synthetic fixture first).

**Bottom line:** the live reads (`accounts`, `transactions`, `api`) work given
a session, and `wfr auth login --browser` gets the CLI that session. For
zero-friction, no-login tax data, `import csv` today and `import qfx` next are
still the simplest path.
