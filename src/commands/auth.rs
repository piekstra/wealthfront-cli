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
//!
//! The window runs in a Chrome profile `wfr` keeps between sign-ins, so a later
//! `--browser` often needs no input; `--fresh-profile` opts out for one run,
//! and `auth logout` removes it ([`logout_browser`]). It is a full Chrome
//! profile: cookies, and browsing history with full URLs including query
//! strings, the HTTP cache and site storage, which Chrome's cookie encryption
//! does not cover and only the directory's `0700` mode protects. On Linux with no
//! desktop keyring, Chrome encrypts cookies with a fixed, publicly known key, so
//! there the session cookie has only `0700` protecting it too. A session cookie
//! left in it is never trusted alone: only [`confirm_session`]'s read accepts a
//! session.

use std::io::IsTerminal;

use pk_cli_auth::{AuthLogin, AuthMethod, AuthStatus, LoginArgs, LogoutArgs, SetCredentialArgs};
use pk_cli_browser::{
    BrowserArgs, BrowserError, Capture, Captured, Confirm, HostRule, Launch, DEFAULT_TIMEOUT,
};
use pk_cli_config::ConfigStore;
use pk_cli_core::CliError;
use pk_cli_secrets::{CredentialStore, Secret};
use serde_json::Value;

use crate::client::{clear_pending, endpoints, CodeChannel, ReadError, Wf, BASE};
use crate::config::Config;
use crate::keychain::{
    self, DEVICE_ACCOUNT, PASSWORD_ACCOUNT, PENDING_ACCOUNT, SERVICE_ENV, SESSION_ACCOUNT,
};

/// `--browser` captures the session and reads only `--fresh-profile`, so clap
/// refuses it beside every other login flag (exit 2) rather than ignore the flag,
/// before anything reads the keychain or the network or opens Chrome
/// (cli-common DESIGN.md §2.2).
#[derive(clap::Args, Debug)]
///
/// The shared `LoginArgs` brings `--no-verify`, which no login path here reads, so
/// `--help` does not offer it. It still parses, so a script that passes it does not
/// break.
#[command(
    mut_arg("browser", |a| {
        a.conflicts_with_all([
            "stdin",
            "from_env",
            "code",
            "no_verify",
            "overwrite",
            "non_interactive",
            "channel",
        ])
    }),
    mut_arg("no_verify", |a| a.hide(true))
)]
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
    /// Clear the session and remove the kept browser profile; --forget also
    /// removes the stored password.
    ///
    /// Every step is attempted. If one fails, or the profile is in use or needs
    /// repair, the rest is still cleared, and this exits nonzero saying what was
    /// cleared and what remains: fix that and run it again.
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
    keep_config: bool,
) -> Result<(), CliError> {
    // Loaded only in the arms that use it, so a logout runs every step even when
    // the file can't be parsed.
    match cmd {
        AuthCmd::Login(args) => login(args, creds, &store.load()?, json, quiet, interactive),
        AuthCmd::Status(args) => status(args, creds, &store.load()?, json, quiet),
        AuthCmd::Logout(args) => logout(args, creds, store, keep_config, quiet),
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
    json: bool,
    quiet: bool,
    interactive: bool,
) -> Result<(), CliError> {
    // The verified sign-in: the owner signs in on Wealthfront's own page,
    // where reCAPTCHA sees a real browser (docs/api.md §3.2, §3.6), and the
    // confirmed session is stored like any other.
    if args.browser.browser {
        let (fresh_profile, line) =
            scratch_profile_choice(args.browser.fresh_profile, keychain::service_overridden());
        if let (Some(line), false) = (line, quiet) {
            eprintln!("{line}");
        }
        let note = kept_profile_note(fresh_profile);
        return noting_kept_profile(note, || {
            let session = browser_session(fresh_profile, quiet)?;
            creds
                .set(SESSION_ACCOUNT, &session)
                .map_err(BrowserError::Handler)?;
            if !quiet {
                eprintln!("logged in — session captured from the browser");
            }
            if json {
                // Only `Confirm::Ready`, a read that worked, hands a session over.
                pk_cli_core::output::json(&AuthLogin::stored(true).to_json());
            }
            Ok(())
        });
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
        return finish(&wf, creds, json, quiet);
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
    finish(&wf, creds, json, quiet)
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
fn finish(wf: &Wf, creds: &CredentialStore, json: bool, quiet: bool) -> Result<(), CliError> {
    wf.me()?;
    let session = wf.session_bundle().ok_or_else(|| {
        CliError::Upstream("login succeeded but Wealthfront issued no session cookie".into())
    })?;
    creds.set(SESSION_ACCOUNT, &session)?;
    if !quiet {
        eprintln!("logged in");
    }
    if json {
        // `wf.me()` above accepted this session before it was stored.
        pk_cli_core::output::json(&AuthLogin::stored(true).to_json());
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
    me_verdict(
        client(bundle.expose())
            .map_err(ReadError::from)
            .and_then(|wf| wf.read_me()),
    )
}

/// What the `/capitan/v1/me` read says about a candidate session (cli-common
/// DESIGN.md §2.2). `_wfsid` is set for a visitor too and may be kept in the profile,
/// so no answer short of the account object stores anything. A reason holds fixed
/// parts and a status, never the answer's body or a cookie value.
fn me_verdict(me: Result<Value, ReadError>) -> Confirm {
    let read = format!("GET {}", endpoints::ME);
    match me {
        // The account object, the only answer `Wf::read_me` lets through.
        Ok(_) => Confirm::Ready,
        // The owner may not have finished signing in. A timeout gives what the read
        // was told: the client's own fixed wording.
        Err(ReadError::Failed(CliError::Auth(why))) => {
            Confirm::NotYet(format!("{read} was refused: {why}"))
        }
        Err(ReadError::NotSignedIn(_)) => {
            Confirm::NotYet(format!("{read} answered with no account in it"))
        }
        // The read could not decide. The crate keeps the tab and the jar, since the
        // cookies do not outlive the stop, and asks again after its backoff.
        Err(ReadError::EdgeBlock {
            status,
            retry_after,
        }) => Confirm::Undecided {
            reason: format!(
                "{read} answered HTTP {status} with a page that is possibly a bot check or edge \
                 block"
            ),
            retry_after,
        },
        Err(ReadError::Inconclusive {
            status,
            retry_after,
            ..
        }) => Confirm::Undecided {
            reason: format!("{read} answered HTTP {status}"),
            retry_after,
        },
        Err(ReadError::NoAnswer(_)) => Confirm::undecided(format!("{read} got no answer")),
        Err(ReadError::NotJson(_)) => {
            Confirm::undecided(format!("{read} answered with no JSON in it"))
        }
        Err(ReadError::Empty(_)) => {
            Confirm::undecided(format!("{read} answered with nothing in it"))
        }
        // A 404, or a client that can't be built: no later poll changes these.
        Err(ReadError::Failed(e)) => Confirm::Fail(CliError::Upstream(format!(
            "session validation failed during the browser login: {e}"
        ))),
    }
}

/// Open Chrome at the Wealthfront login, wait while the owner signs in, and
/// hand back the confirmed jar as the `k=v; k=v` bundle the session is stored
/// as. The crate closes the tab and stops Chrome. The profile is kept for the
/// next sign-in, unless `fresh_profile` runs this one in a scratch profile.
fn browser_session(fresh_profile: bool, quiet: bool) -> Result<Secret, BrowserError> {
    let launch = Launch::new(crate::BIN)
        .url(format!("{BASE}{}", endpoints::LOGIN_PAGE))
        .fresh_profile(fresh_profile)
        .quiet(quiet);
    let capture = browser_capture().map_err(BrowserError::Handler)?;
    let captured = pk_cli_browser::capture(launch, &capture, DEFAULT_TIMEOUT)?;
    captured
        .cookie_header()
        .ok_or_else(|| BrowserError::Handler(no_jar()))
}

/// Whether a sign-in runs in the kept profile. The crate keeps one on unix only;
/// elsewhere every sign-in is scratch.
fn runs_in_kept_profile(fresh_profile: bool) -> bool {
    !fresh_profile && cfg!(unix)
}

/// Which profile a sign-in runs in: whether it is a scratch one, and the line to
/// print when the override, not the owner's flag, made it so. A service named by
/// [`SERVICE_ENV`] is a test namespace, so a sign-in under it must not read or
/// change the real kept profile, as `auth logout` must not remove it.
fn scratch_profile_choice(
    fresh_profile_flag: bool,
    service_overridden: bool,
) -> (bool, Option<String>) {
    let line = (service_overridden && !fresh_profile_flag).then(|| {
        format!(
            "{SERVICE_ENV} is set, so this sign-in uses a scratch browser profile, as with \
             --fresh-profile"
        )
    });
    (fresh_profile_flag || service_overridden, line)
}

/// The note a sign-in's failure carries: unless it ran in a scratch profile, the
/// kept profile stays on disk, possibly signed in, so the owner is told and told
/// how to remove it. `None` for a scratch profile, and where the crate keeps no
/// profile.
fn kept_profile_note(fresh_profile: bool) -> Option<String> {
    runs_in_kept_profile(fresh_profile).then(|| {
        format!(
            "The kept browser profile stays on disk; `{} auth logout` removes it, and clears the \
             stored session too.",
            crate::BIN
        )
    })
}

/// Runs a browser sign-in, from opening the window through storing the session,
/// and adds `note` to whatever fails once Chrome may have used the profile,
/// keeping the exit code. A failure from outside the crate, such as a keychain
/// write after the capture, comes in as [`BrowserError::Handler`]. Everything but
/// the listed refusals gets the note, so a new failure path can't miss it.
///
/// The refusals come before Chrome uses the profile. They leave nothing new, and
/// the note would be false (no Chrome, so no profile) or would point at `auth
/// logout`, which refuses the same profile after clearing the stored session.
fn noting_kept_profile<T>(
    note: Option<String>,
    sign_in: impl FnOnce() -> Result<T, BrowserError>,
) -> Result<T, CliError> {
    sign_in().map_err(|err| {
        let before_the_profile_is_used = matches!(
            err,
            BrowserError::Invalid(_)
                | BrowserError::ChromeNotFound(_)
                | BrowserError::Profile(_)
                | BrowserError::ProfileInUse(_)
        );
        let err = CliError::from(err);
        match note {
            Some(note) if !before_the_profile_is_used => with_note(err, &note),
            _ => err,
        }
    })
}

fn with_note(err: CliError, note: &str) -> CliError {
    rewording(err, |message| {
        format!("{}. {note}", message.trim_end_matches('.'))
    })
}

/// The same kind of error, so the same exit code, with its message rewritten.
fn rewording(err: CliError, reword: impl FnOnce(String) -> String) -> CliError {
    match err {
        CliError::Usage(m) => CliError::Usage(reword(m)),
        CliError::Auth(m) => CliError::Auth(reword(m)),
        CliError::NotFound(m) => CliError::NotFound(reword(m)),
        CliError::Upstream(m) => CliError::Upstream(reword(m)),
        CliError::ConfirmationRequired(m) => CliError::ConfirmationRequired(reword(m)),
        CliError::Keychain(m) => CliError::Keychain(reword(m)),
        CliError::Other(m) => CliError::Other(reword(m)),
    }
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

    let (browser_profile, line) = browser_profile_status(keychain::service_overridden(), || {
        pk_cli_browser::profile_exists(crate::BIN)
    });
    st.browser_profile = browser_profile;
    if let (Some(line), false) = (line, quiet) {
        eprintln!("{line}");
    }

    st.emit(json);
    if verified_bad {
        // The DTO already went to stdout. Returning an error here would print
        // a *second* JSON document, so exit directly.
        std::process::exit(CliError::Auth(String::new()).exit_code());
    }
    Ok(())
}

/// `auth status`'s browser field: whether a `--browser` sign-in keeps a profile
/// here, not whether it is signed in. Returns the field and any line for stderr.
/// `auth status` works whatever state the CLI is in, so a profile that needs
/// repair is a warning and leaves the field out. A service `WFR_KEYCHAIN_SERVICE`
/// names is a test namespace, so while it is set nothing is read about the real
/// profile and the field is left out too.
///
/// The check is passed in: the binary binds it to `profile_exists(BIN)`, the
/// tests to `profile_exists_in` under a temp dir, so a test never reads the
/// owner's real data dir.
fn browser_profile_status(
    service_overridden: bool,
    exists: impl FnOnce() -> Result<bool, BrowserError>,
) -> (Option<bool>, Option<String>) {
    if service_overridden {
        return (
            None,
            Some(format!(
                "{} is set, so the real browser profile is not reported",
                SERVICE_ENV
            )),
        );
    }
    match exists() {
        Ok(kept) => (Some(kept), None),
        Err(e) => (None, Some(format!("warning: {e}"))),
    }
}

fn logout(
    args: &LogoutArgs,
    creds: &CredentialStore,
    store: &ConfigStore,
    keep_config: bool,
    quiet: bool,
) -> Result<(), CliError> {
    let steps = logout_steps(creds, store, args.forget, keep_config);
    let line = run_logout(
        args.forget,
        keychain::service_overridden(),
        args.forget && keep_config,
        steps,
        || pk_cli_browser::forget_profile(crate::BIN),
    )?;
    if !quiet {
        eprintln!("{line}");
    }
    Ok(())
}

/// What a logout clears before the browser profile. A half-finished login goes
/// too, so `logout` really does leave nothing session-shaped behind. Nothing here
/// parses the config, so a file that can't be parsed stops nothing, and `--forget`
/// removes it.
fn logout_steps<'a>(
    creds: &'a CredentialStore,
    store: &'a ConfigStore,
    forget: bool,
    keep_config: bool,
) -> Vec<LogoutStep<'a>> {
    let delete = |account: &'static str| -> Box<dyn FnOnce() -> Result<(), CliError> + 'a> {
        Box::new(move || creds.delete(account).map(drop))
    };
    let mut steps: Vec<LogoutStep<'a>> = vec![
        ("the session", delete(SESSION_ACCOUNT)),
        ("the parked login", delete(PENDING_ACCOUNT)),
    ];
    if forget {
        steps.push(("the stored password", delete(PASSWORD_ACCOUNT)));
        steps.push(("the device token", delete(DEVICE_ACCOUNT)));
        if !keep_config {
            steps.push(("the saved settings", Box::new(|| store.clear().map(drop))));
        }
    }
    steps
}

/// One step of `auth logout` before the browser profile: what it clears, and the
/// call that clears it.
type LogoutStep<'a> = (&'static str, Box<dyn FnOnce() -> Result<(), CliError> + 'a>);

/// Runs `auth logout`. Every step is attempted, the browser profile last, even
/// when an earlier one fails: a logout that stops early leaves things behind for
/// no reason. Returns the status line, or an error saying what was cleared and
/// what remains, with the first failure's exit code.
///
/// The profile a `--browser` sign-in keeps is a full Chrome profile: Wealthfront's own
/// cookies (its remembered device and session), and browsing history with full
/// URLs, the HTTP cache and site storage, which Chrome's cookie encryption does
/// not cover. So a logout removes it too, and the next sign-in starts signed out.
/// The removal is passed in: the binary binds it to `forget_profile(BIN)`, the
/// tests to `forget_profile_in` under a temp dir, so a test never removes the
/// owner's real profile.
///
/// [`SERVICE_ENV`] moves the keychain but not the profile or the config, so while
/// it is set (`service_overridden`) the keychain cleared here is not the real one.
/// The real profile is left alone, and so is the real config when a `--forget`
/// would have cleared it (`config_left`), and the line says so.
fn run_logout(
    forgot_credentials: bool,
    service_overridden: bool,
    config_left: bool,
    steps: Vec<LogoutStep<'_>>,
    forget_profile: impl FnOnce() -> Result<bool, BrowserError>,
) -> Result<String, CliError> {
    let mut cleared = Vec::new();
    let mut remains: Vec<(&str, CliError)> = Vec::new();
    for (what, step) in steps {
        match step() {
            Ok(()) => cleared.push(what),
            Err(e) => remains.push((what, e)),
        }
    }
    const PROFILE: &str = "the browser profile";
    let mut removed = false;
    if !service_overridden {
        match forget_profile() {
            Ok(there_was_one) => {
                removed = there_was_one;
                if removed {
                    cleared.push(PROFILE);
                }
            }
            Err(e) => remains.push((PROFILE, e.into())),
        }
    }
    let left_alone = if service_overridden {
        let what = if config_left {
            "browser profile and config were"
        } else {
            "browser profile was"
        };
        format!("{SERVICE_ENV} is set, so the real {what} left in place")
    } else {
        String::new()
    };
    let forgot = if forgot_credentials {
        " and forgot the stored credentials"
    } else {
        ""
    };
    if remains.is_empty() {
        return Ok(if service_overridden {
            format!("logged out{forgot}; {left_alone}")
        } else if removed {
            format!("logged out{forgot}; browser profile removed")
        } else {
            format!("logged out{forgot}")
        });
    }
    let what_remains = remains
        .iter()
        .map(|(what, e)| format!("{what}: {}", inner_message(e)))
        .collect::<Vec<_>>()
        .join("; ");
    // Only the profile left needs no `--forget`: the credentials are gone by then.
    let again = if forgot_credentials && remains.iter().any(|(what, _)| *what != PROFILE) {
        " --forget"
    } else {
        ""
    };
    let message = format!(
        "logout is incomplete. Cleared: {}. Still there: {what_remains}. {}Once that is fixed, \
         run `{} auth logout{again}` again to finish.",
        if cleared.is_empty() {
            "nothing".to_string()
        } else {
            cleared.join(", ")
        },
        if service_overridden {
            format!("{left_alone}. ")
        } else {
            String::new()
        },
        crate::BIN,
    );
    let (_, first) = remains.remove(0);
    // The message covers every failure, so it must not open with the kind of the
    // first. `Keychain` and `Other`, all a real logout produces, both exit 1, so
    // the plain one keeps the code; the others with a code of their own keep it,
    // and their kind.
    Err(match first {
        CliError::Keychain(_) | CliError::Other(_) => CliError::Other(message),
        other => rewording(other, |_| message),
    })
}

/// An error's own message, without the kind its `Display` puts in front.
fn inner_message(err: &CliError) -> &str {
    match err {
        CliError::Usage(m)
        | CliError::Auth(m)
        | CliError::NotFound(m)
        | CliError::Upstream(m)
        | CliError::ConfirmationRequired(m)
        | CliError::Keychain(m)
        | CliError::Other(m) => m,
    }
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
    use pk_cli_browser::JarCookie;
    use serde_json::json;
    use std::time::Duration;

    /// A temp dir standing in for the per-user data dir, and the profile
    /// `forget_profile_in` looks for under it.
    fn profile_under_temp(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("wfr-logout-{tag}-{}", std::process::id()));
        // A leftover from an aborted run must not decide the test.
        let _ = std::fs::remove_dir_all(&root);
        let profile = root
            .join(format!("piekstra.{}", crate::BIN))
            .join("browser-profile");
        (root, profile)
    }

    /// The status's browser field on a temp dir through `test-util`'s
    /// `profile_exists_in`, so it never reads the owner's real data dir.
    #[test]
    fn auth_status_reports_the_kept_browser_profile() {
        let (root, profile) = profile_under_temp("status");
        let exists = || pk_cli_browser::profile_exists_in(&root, crate::BIN);
        assert_eq!(browser_profile_status(false, exists), (Some(false), None));
        assert!(!root.exists(), "asking creates nothing");

        std::fs::create_dir_all(&profile).unwrap();
        let (field, line) = browser_profile_status(false, exists);
        assert_eq!((field, line), (Some(true), None));
        let mut status = AuthStatus::new(true, false, AuthMethod::Password);
        status.browser_profile = field;
        assert_eq!(status.to_json()["browser_profile"], true);

        // A profile that needs repair does not fail the status: the field is
        // left out, and the rest of the status still reports.
        std::fs::remove_dir(&profile).unwrap();
        std::fs::write(&profile, "x").unwrap();
        let (field, line) = browser_profile_status(false, exists);
        assert_eq!(field, None);
        assert!(line.unwrap().starts_with("warning: "));
        status.browser_profile = field;
        assert!(status.to_json().get("browser_profile").is_none());
        assert_eq!(status.to_json()["schema"], "auth-status/v1");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// While the keychain service is overridden, the status reads nothing about
    /// the real profile, and the line says so.
    #[test]
    fn auth_status_reports_nothing_about_the_real_profile_under_a_service_override() {
        let (field, line) = browser_profile_status(true, || -> Result<bool, BrowserError> {
            panic!("the real profile must not be read under a service override")
        });
        assert_eq!(field, None);
        assert_eq!(
            line.as_deref(),
            Some("WFR_KEYCHAIN_SERVICE is set, so the real browser profile is not reported")
        );
    }

    /// The logout's browser step on a temp dir through `test-util`'s
    /// `forget_profile_in`, so it never removes the owner's real profile.
    #[test]
    fn logout_removes_the_kept_browser_profile() {
        let (root, profile) = profile_under_temp("removes");
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        let forget = || pk_cli_browser::forget_profile_in(&root, crate::BIN);
        assert_eq!(
            run_logout(false, false, false, Vec::new(), forget).unwrap(),
            "logged out; browser profile removed"
        );
        assert!(!profile.exists());
        // Only the profile goes, not the directory it sits in.
        assert!(profile.parent().unwrap().exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn logout_with_no_kept_profile_still_logs_out() {
        let (root, _) = profile_under_temp("none");
        let forget = || pk_cli_browser::forget_profile_in(&root, crate::BIN);
        assert_eq!(
            run_logout(false, false, false, Vec::new(), forget).unwrap(),
            "logged out"
        );
    }

    /// A profile in use refuses the logout's last step, exit 1. The keychain
    /// steps ran first, so the error says what they cleared, then what is left,
    /// the crate's reason and how to finish. `--forget` is not needed again.
    #[test]
    fn logout_reports_a_profile_in_use() {
        let in_use = || {
            Err(BrowserError::ProfileInUse(
                "a Chrome (pid 7) is still running in dummy-profile".into(),
            ))
        };
        let session: Vec<LogoutStep<'_>> = vec![("the session", Box::new(|| Ok(())))];
        let err = run_logout(false, false, false, session, in_use).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert_eq!(
            err.to_string(),
            "logout is incomplete. Cleared: the session. Still there: the browser profile: a \
             Chrome (pid 7) is still running in dummy-profile. Once that is fixed, run `wfr \
             auth logout` again to finish."
        );
        let err = run_logout(true, false, false, Vec::new(), in_use).unwrap_err();
        assert!(err
            .to_string()
            .ends_with("run `wfr auth logout` again to finish."));
    }

    /// A failed keychain or config step does not stop the logout. Every later
    /// step runs, the profile included. The error reads as one message, each
    /// cause once with no kind prefix, and keeps the first failure's exit code.
    #[test]
    fn logout_attempts_every_step_when_one_fails() {
        let (root, profile) = profile_under_temp("every-step");
        std::fs::create_dir_all(&profile).unwrap();
        let later_step_ran = std::cell::Cell::new(false);
        let steps: Vec<LogoutStep<'_>> = vec![
            ("the session", Box::new(|| Ok(()))),
            (
                "the parked login",
                Box::new(|| Err(CliError::Auth("dummy first".into()))),
            ),
            (
                "the stored password",
                Box::new(|| Err(CliError::Keychain("dummy second".into()))),
            ),
            (
                "the saved settings",
                Box::new(|| {
                    later_step_ran.set(true);
                    Ok(())
                }),
            ),
        ];
        let err = run_logout(true, false, false, steps, || {
            pk_cli_browser::forget_profile_in(&root, crate::BIN)
        })
        .unwrap_err();
        assert!(later_step_ran.get());
        assert!(!profile.exists(), "the profile step still ran");
        assert_eq!(err.exit_code(), 3, "the first failure's exit code");
        assert_eq!(
            err.to_string(),
            "logout is incomplete. Cleared: the session, the saved settings, the browser \
             profile. Still there: the parked login: dummy first; the stored password: dummy \
             second. Once that is fixed, run `wfr auth logout --forget` again to finish."
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A keychain failure first, as a real logout has it: exit 1, and the error
    /// does not open with a kind that names only that failure. The same under a
    /// service override: the profile is never touched, and the error says so.
    #[test]
    fn a_failed_step_under_a_service_override_still_leaves_the_profile() {
        let steps: Vec<LogoutStep<'_>> = vec![(
            "the session",
            Box::new(|| Err(CliError::Keychain("dummy".into()))),
        )];
        let err = run_logout(
            false,
            true,
            false,
            steps,
            || -> Result<bool, BrowserError> {
                panic!("the real profile must not be removed under a service override")
            },
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert_eq!(
            err.to_string(),
            "logout is incomplete. Cleared: nothing. Still there: the session: dummy. WFR_KEYCHAIN_SERVICE \
             is set, so the real browser profile was left in place. Once that is fixed, run \
             `wfr auth logout` again to finish."
        );
    }

    /// A store for the config at `path`, and a credential store that the tests
    /// here only build: its steps are never run, so no keychain is reached.
    fn logout_stores(path: &std::path::Path) -> (CredentialStore, ConfigStore) {
        (
            CredentialStore::new("piekstra.wfr-unused-in-tests"),
            ConfigStore::new(crate::BIN).with_override(Some(path.to_path_buf())),
        )
    }

    fn step_names(steps: &[LogoutStep<'_>]) -> Vec<&'static str> {
        steps.iter().map(|(what, _)| *what).collect()
    }

    /// Logout never parses the config, so a file that can't be parsed stops
    /// nothing, and `--forget` clears it. The keychain steps are left out here,
    /// and the profile step runs on a temp dir.
    #[test]
    fn logout_forget_clears_a_config_that_cannot_be_parsed() {
        let (root, _) = profile_under_temp("corrupt-config");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.json");
        std::fs::write(&path, "{ not json").unwrap();
        let (creds, store) = logout_stores(&path);
        assert!(store.load::<Config>().is_err(), "the file really is broken");

        let plain = logout_steps(&creds, &store, false, false);
        assert_eq!(step_names(&plain), ["the session", "the parked login"]);

        let mut steps = logout_steps(&creds, &store, true, false);
        assert_eq!(
            step_names(&steps).last(),
            Some(&"the saved settings"),
            "the config step is the one to run"
        );
        let config_step = steps.pop().unwrap();
        let line = run_logout(true, false, false, vec![config_step], || {
            pk_cli_browser::forget_profile_in(&root, crate::BIN)
        })
        .unwrap();
        assert_eq!(line, "logged out and forgot the stored credentials");
        store.load::<Config>().expect("the broken file is cleared");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// While the keychain service is overridden and no `--config` was named, the
    /// real config is out of reach: `--forget` has no config step, and the line
    /// says what was left.
    #[test]
    fn logout_forget_leaves_the_real_config_under_a_service_override() {
        let (root, _) = profile_under_temp("override-config");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.json");
        std::fs::write(&path, "{ not json").unwrap();
        let (creds, store) = logout_stores(&path);
        let steps = logout_steps(&creds, &store, true, true);
        assert!(
            !step_names(&steps).contains(&"the saved settings"),
            "{:?}",
            step_names(&steps)
        );
        let never = || -> Result<bool, BrowserError> {
            panic!("the real profile must not be removed under a service override")
        };
        assert_eq!(
            run_logout(true, true, true, Vec::new(), never).unwrap(),
            "logged out and forgot the stored credentials; WFR_KEYCHAIN_SERVICE is set, so the real browser \
             profile and config were left in place"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ not json");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// While the keychain service is overridden, the real profile is out of
    /// reach: the removal is never called, and the line says it was left.
    #[test]
    fn logout_leaves_the_real_profile_under_a_service_override() {
        let never = || -> Result<bool, BrowserError> {
            panic!("the real profile must not be removed under a service override")
        };
        assert_eq!(
            run_logout(false, true, false, Vec::new(), never).unwrap(),
            "logged out; WFR_KEYCHAIN_SERVICE is set, so the real browser profile was left in place"
        );
        assert_eq!(
            run_logout(true, true, false, Vec::new(), never).unwrap(),
            "logged out and forgot the stored credentials; WFR_KEYCHAIN_SERVICE is set, so the real browser \
             profile was left in place"
        );
    }

    /// Every failure once Chrome may have used a kept profile carries the note
    /// and keeps its exit code, the ones most likely to leave a live session
    /// included.
    #[test]
    fn every_failed_sign_in_says_the_kept_profile_stays() {
        let note = kept_profile_note(false);
        let cases: Vec<(BrowserError, i32, &str)> = vec![
            (BrowserError::TimedOut("timed out.".into()), 3, "timed out"),
            (
                BrowserError::WindowClosed("window closed.".into()),
                3,
                "window closed",
            ),
            (BrowserError::Canceled, 1, "browser login canceled"),
            (
                BrowserError::Launch("dummy launch".into()),
                1,
                "dummy launch",
            ),
            (
                BrowserError::Handler(CliError::Upstream("HTTP 429".into())),
                5,
                "HTTP 429",
            ),
            (
                BrowserError::Handler(CliError::Keychain("dummy write".into())),
                1,
                "dummy write",
            ),
        ];
        for (err, code, message) in cases {
            let noted = noting_kept_profile::<()>(note.clone(), || Err(err)).unwrap_err();
            assert_eq!(noted.exit_code(), code, "{message}");
            let text = noted.to_string();
            assert!(text.contains(message), "{text}");
            assert!(
                text.contains(
                    "The kept browser profile stays on disk; `wfr auth logout` removes it, \
                     and clears the stored session too."
                ),
                "{text}"
            );
        }
        assert_eq!(noting_kept_profile(note, || Ok(7)).unwrap(), 7);
    }

    /// A refusal before Chrome uses the profile leaves nothing new, so it says
    /// nothing about the profile: the note would be false or point at a logout
    /// that refuses too.
    #[test]
    fn a_refusal_before_chrome_uses_the_profile_carries_no_note() {
        let refusals = [
            BrowserError::Invalid("dummy invalid".into()),
            BrowserError::ChromeNotFound("dummy no chrome".into()),
            BrowserError::Profile("dummy repair".into()),
            BrowserError::ProfileInUse("dummy in use".into()),
        ];
        for err in refusals {
            let plain = err.to_string();
            let refused =
                noting_kept_profile::<()>(kept_profile_note(false), || Err(err)).unwrap_err();
            assert_eq!(refused.exit_code(), 1, "{plain}");
            assert_eq!(refused.to_string(), plain);
        }
    }

    /// A scratch profile is gone by then, so `--fresh-profile` adds nothing.
    #[test]
    fn a_fresh_profile_sign_in_carries_no_note() {
        assert_eq!(kept_profile_note(true), None);
        let err = noting_kept_profile::<()>(kept_profile_note(true), || {
            Err(BrowserError::TimedOut("timed out.".into()))
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "timed out.");
    }

    /// A service override is a test namespace: the sign-in takes a scratch
    /// profile, as `--fresh-profile` does, and says so once. No browser runs here.
    #[test]
    fn a_service_override_makes_the_sign_in_use_a_scratch_profile() {
        let line =
            "WFR_KEYCHAIN_SERVICE is set, so this sign-in uses a scratch browser profile, as with \
                    --fresh-profile";
        assert_eq!(scratch_profile_choice(false, false), (false, None));
        assert_eq!(scratch_profile_choice(true, false), (true, None));
        assert_eq!(
            scratch_profile_choice(false, true),
            (true, Some(line.to_string()))
        );
        // The owner asked for it already, so there is nothing to explain.
        assert_eq!(scratch_profile_choice(true, true), (true, None));
        // The note follows the choice, so a failure under an override has none.
        let (fresh_profile, _) = scratch_profile_choice(false, true);
        assert_eq!(kept_profile_note(fresh_profile), None);
    }

    /// A kept profile that is a symlink needs repair: the crate refuses it,
    /// the logout says so, and neither the link nor its target goes.
    #[cfg(unix)]
    #[test]
    fn logout_refuses_a_profile_that_needs_repair() {
        let (root, profile) = profile_under_temp("repair");
        let target = root.join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(profile.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &profile).unwrap();
        let err = run_logout(false, false, false, Vec::new(), || {
            pk_cli_browser::forget_profile_in(&root, crate::BIN)
        })
        .unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("refusing to remove it"), "{err}");
        assert!(err
            .to_string()
            .contains("Still there: the browser profile: "));
        assert!(target.exists() && profile.symlink_metadata().is_ok());
        std::fs::remove_dir_all(&root).unwrap();
    }

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
                r#"{"emailAddress":"user@example.com"}"#,
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
                Confirm::NotYet(reason) => {
                    assert!(
                        reason.starts_with("GET /capitan/v1/me was refused: "),
                        "{case}: {reason}"
                    )
                }
                other => panic!("{case} must keep waiting: {other:?}"),
            }
            assert_eq!(requests.len(), connections, "{case}");
            assert_me_read(&requests[0], case);
        }
    }

    /// An edge block's page can't decide: the crate keeps the tab and the jar. The
    /// reason names it, and holds neither the answer's body nor a cookie value.
    #[test]
    fn an_edge_block_is_undecided() {
        const PAGE: &str = "<!DOCTYPE html><html><title>Just a moment...</title>dummy-body</html>";
        for (case, status, page) in [
            ("a 403 challenge", "403 Forbidden", PAGE),
            (
                "a bare 403 page",
                "403 Forbidden",
                "<html>dummy-body</html>",
            ),
            ("a 200 challenge", "200 OK", PAGE),
        ] {
            let verdict = answer_to(status, "text/html", page);
            let Confirm::Undecided { reason, .. } = verdict else {
                panic!("{case} must be undecided: {verdict:?}");
            };
            assert!(reason.contains("possibly a bot check"), "{case}: {reason}");
            assert!(!reason.contains("session expired"), "{case}: {reason}");
            // The page's marker and every cookie value in `captured_jar` are dummies.
            assert!(!reason.contains("dummy"), "{case}: {reason}");
        }
    }

    /// The hook's answer to one read of `status` and `page`.
    fn answer_to(status: &'static str, content_type: &'static str, page: &'static str) -> Confirm {
        confirm_against(1, move |_| {
            loopback::response(status, &[&format!("Content-Type: {content_type}")], page)
        })
        .0
    }

    /// A login page is a refusal, even one holding a challenge's words outside its
    /// title, and so is a parseable answer with no account: the owner may not have
    /// finished signing in. The field's value counts, not its presence.
    #[test]
    fn a_login_page_or_an_answer_with_no_account_keeps_waiting() {
        let login_page = include_str!("../../tests/fixtures/login-page-with-challenge-words.html");
        for page in ["<!doctype html>", login_page] {
            let verdict = answer_to("200 OK", "text/html", page);
            assert!(
                matches!(&verdict, Confirm::NotYet(reason) if reason.contains("was refused")),
                "{verdict:?}"
            );
        }
        for body in [
            "{}",
            "[]",
            "true",
            "0",
            r#""dummy""#,
            r#"{"dummy":true}"#,
            r#"{"emailAddress":""}"#,
            r#"{"emailAddress":"  "}"#,
            r#"{"emailAddress":null}"#,
            r#"{"userIdExternalized":1}"#,
            r#"{"redirectUrl":"/login","success":false}"#,
        ] {
            let verdict = answer_to("200 OK", "application/json", body);
            match verdict {
                Confirm::NotYet(reason) => assert_eq!(
                    reason, "GET /capitan/v1/me answered with no account in it",
                    "{body}"
                ),
                other => panic!("{body} must keep waiting: {other:?}"),
            }
        }
    }

    /// Either field, with something in it, shows an account.
    #[test]
    fn either_account_field_with_a_value_is_ready() {
        for body in [
            r#"{"emailAddress":"user@example.com"}"#,
            r#"{"userIdExternalized":"dummy-id"}"#,
            r#"{"emailAddress":"","userIdExternalized":"dummy-id"}"#,
        ] {
            let verdict = answer_to("200 OK", "application/json", body);
            assert!(matches!(verdict, Confirm::Ready), "{body}: {verdict:?}");
        }
    }

    /// What can't decide keeps the tab and the jar: a throttle, a server error, or a
    /// 2xx that is empty or not JSON. The reason holds fixed parts, not the body.
    #[test]
    fn a_read_that_cannot_decide_is_undecided() {
        let json = "application/json";
        for (case, status, content_type, body, reason) in [
            (
                "429",
                "429 Too Many Requests",
                json,
                "",
                "answered HTTP 429",
            ),
            (
                "500",
                "500 Internal Server Error",
                json,
                "",
                "answered HTTP 500",
            ),
            (
                "503",
                "503 Service Unavailable",
                json,
                "",
                "answered HTTP 503",
            ),
            (
                "HTML 502",
                "502 Bad Gateway",
                "text/html",
                "<html></html>",
                "answered HTTP 502",
            ),
            (
                "an empty 200",
                "200 OK",
                json,
                "",
                "answered with nothing in it",
            ),
            (
                "a null 200",
                "200 OK",
                json,
                "null",
                "answered with nothing in it",
            ),
            (
                "a non-JSON 200",
                "200 OK",
                "text/plain",
                "dummy-not-json",
                "answered with no JSON in it",
            ),
        ] {
            let (verdict, requests) = confirm_against(1, move |_| {
                loopback::response(status, &[&format!("Content-Type: {content_type}")], body)
            });
            match verdict {
                Confirm::Undecided {
                    reason: said,
                    retry_after,
                    ..
                } => {
                    assert_eq!(said, format!("GET /capitan/v1/me {reason}"), "{case}");
                    assert_eq!(retry_after, None, "{case}");
                }
                other => panic!("{case} must be undecided: {other:?}"),
            }
            assert_eq!(requests.len(), 1, "{case}");
            assert_me_read(&requests[0], case);
        }
    }

    /// The provider's `Retry-After` reaches the crate, from a throttle, a server error
    /// and an edge block's page.
    #[test]
    fn undecided_passes_the_providers_retry_after() {
        for (status, content_type) in [
            ("429 Too Many Requests", "application/json"),
            ("503 Service Unavailable", "application/json"),
            ("403 Forbidden", "text/html"),
        ] {
            let (verdict, _) = confirm_against(1, move |_| {
                loopback::response(
                    status,
                    &[&format!("Content-Type: {content_type}"), "Retry-After: 120"],
                    "<html></html>",
                )
            });
            match verdict {
                Confirm::Undecided { retry_after, .. } => {
                    assert_eq!(retry_after, Some(Duration::from_secs(120)), "{status}");
                }
                other => panic!("{status} must be undecided: {other:?}"),
            }
        }
    }

    /// A server that refuses the connection is undecided, with a fixed reason.
    #[test]
    fn an_unreachable_server_is_undecided() {
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            format!("http://{}", listener.local_addr().unwrap())
        };
        match confirm_session_with(&captured_jar(), |bundle| Wf::from_bundle_at(closed, bundle)) {
            Confirm::Undecided { reason, .. } => {
                assert_eq!(reason, "GET /capitan/v1/me got no answer");
            }
            other => panic!("a refused connection must be undecided: {other:?}"),
        }
    }

    /// No later poll changes a 404 or a client that can't be built, so they end the wait.
    #[test]
    fn a_missing_read_or_an_unbuilt_client_ends_the_wait() {
        let (verdict, requests) =
            confirm_against(1, |_| loopback::response("404 Not Found", &[], ""));
        assert_eq!(
            assert_ends_the_wait(verdict, "404"),
            "not found: /capitan/v1/me (HTTP 404)"
        );
        assert_me_read(&requests[0], "404");
        assert_ends_the_wait(
            confirm_session_with(&captured_jar(), |_| {
                Err(CliError::Usage(
                    "WFR_BASE_URL must be a plain http(s) URL".into(),
                ))
            }),
            "a client that cannot be built",
        );
    }

    /// A wait that runs out undecided is exit 5, and keeps the kept profile's note.
    #[test]
    fn a_wait_that_runs_out_undecided_is_exit_5() {
        let err = noting_kept_profile::<()>(Some("dummy note".into()), || {
            Err(BrowserError::Undecided("dummy reason".into()))
        })
        .unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("dummy note"), "{err}");
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

        match me_verdict(Err(CliError::Auth("session expired".into()).into())) {
            Confirm::NotYet(reason) => {
                assert_eq!(reason, "GET /capitan/v1/me was refused: session expired");
            }
            other => panic!("an auth error must keep waiting: {other:?}"),
        }

        match me_verdict(Err(ReadError::EdgeBlock {
            status: 403,
            retry_after: None,
        })) {
            Confirm::Undecided { reason, .. } => {
                assert!(reason.contains("HTTP 403"), "{reason}");
                assert!(reason.contains("possibly a bot check"), "{reason}");
            }
            other => panic!("an edge block must be undecided: {other:?}"),
        }

        for e in [
            CliError::NotFound("/capitan/v1/me (HTTP 404)".into()),
            CliError::Usage("WFR_BASE_URL must be a plain http(s) URL".into()),
            CliError::Other("connection reset".into()),
        ] {
            let cause = e.to_string();
            let Confirm::Fail(err) = me_verdict(Err(e.into())) else {
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
