//! Offline surface tests: flags, exit codes, and the JSON output contract.
//!
//! Nothing here touches the network, the keychain, or a Wealthfront
//! credential. That is not incidental — logging in to Wealthfront requires a
//! second factor, and an SMS code is both rate-limited and impossible to
//! obtain unattended, so a test suite that needed one would be a suite nobody
//! could run. The few assertions that *would* read the keychain are behind
//! `WFR_TEST_KEYCHAIN=1`.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn wfr() -> Command {
    Command::cargo_bin("wfr").unwrap()
}

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Every top-level command; the help tests iterate this so a renamed or
/// dropped command trips a test.
const COMMANDS: &[&str] = &[
    "auth",
    "config",
    "accounts",
    "net-worth",
    "transactions",
    "documents",
    "import",
    "api",
    "mcp",
    "self-update",
    "completions",
    "info",
];

#[test]
fn top_level_help_lists_every_command() {
    let out = wfr().arg("--help").assert().success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for cmd in COMMANDS {
        assert!(text.contains(cmd), "--help is missing `{cmd}`");
    }
}

#[test]
fn every_command_help_renders() {
    // Rendering each subcommand's help forces clap's debug assertions over
    // that subtree, catching a flag that collides with a global like `-q`/`-v`
    // or `-a`.
    for cmd in COMMANDS {
        wfr().args([cmd, "--help"]).assert().success();
    }
}

#[test]
fn nested_subcommand_help_renders() {
    for (group, sub) in [
        ("auth", "login"),
        ("auth", "status"),
        ("auth", "logout"),
        ("auth", "set-credential"),
        ("config", "set"),
        ("accounts", "list"),
        ("accounts", "get"),
        ("transactions", "list"),
        ("documents", "list"),
        ("documents", "download"),
        ("import", "csv"),
    ] {
        wfr().args([group, sub, "--help"]).assert().success();
    }
}

#[test]
fn auth_login_documents_the_mfa_resume_flag() {
    // The parked-session flow is unusable if `--code` isn't discoverable.
    wfr()
        .args(["auth", "login", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--code"))
        .stdout(predicate::str::contains("--channel"));
}

#[test]
fn browser_login_refuses_another_credential_source_before_anything_runs() {
    // Exit 2 from clap, before any keychain or network read. WFR_CHROME
    // points at nothing, so even a regression that let the flags through
    // would fail on the missing binary rather than open a window.
    let dir = std::env::temp_dir().join(format!("wfr-browser-conflict-{}", std::process::id()));
    let cfg = dir.join("config.toml");
    for (other, flag) in [
        (&["--stdin"][..], "'--stdin'"),
        (&["--from-env", "WFR_PASSWORD"][..], "'--from-env <VAR>'"),
    ] {
        let mut args = vec![
            "--json",
            "--config",
            cfg.to_str().unwrap(),
            "auth",
            "login",
            "--browser",
        ];
        args.extend_from_slice(other);
        wfr()
            .env("WFR_CHROME", dir.join("no-chrome"))
            .args(&args)
            .write_stdin("")
            .assert()
            .code(2)
            .stderr(predicate::str::contains(format!(
                "the argument '--browser' cannot be used with {flag}"
            )));
    }
}

#[test]
fn auth_login_documents_the_browser_flag() {
    // The family's `--browser` (pk_cli_browser::BrowserArgs), with its
    // shared help text, beside the password login's flags.
    wfr()
        .args(["auth", "login", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--browser"))
        .stdout(predicate::str::contains(
            "Sign in through a Chrome window and capture the session from it",
        ));
}

/// A loopback stand-in for www.wealthfront.com serving the two login-flow
/// requests: `GET /login` (sets the `login_xsrf` cookie) and the login POST
/// (answered with `body`). Std only — no mock library (AGENTS.md).
fn fake_wealthfront(body: &'static str) -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            // Read until the headers and any declared body have arrived.
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let text = String::from_utf8_lossy(&raw);
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let want: usize = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if raw.len() >= head_end + 4 + want {
                        break;
                    }
                }
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => raw.extend_from_slice(&chunk[..n]),
                }
            }
            let req = String::from_utf8_lossy(&raw);
            let resp = if req.starts_with("GET /login") {
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                 Set-Cookie: login_xsrf=abc%2Bxyz%3D%3D; Path=/; HttpOnly\r\n\
                 Content-Length: 6\r\nConnection: close\r\n\r\n<html>"
                    .to_string()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            };
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    format!("http://127.0.0.1:{port}")
}

#[test]
fn headless_login_with_piped_stdin_never_prompts_or_hangs() {
    // Regression for the 2026-08-31 headless hang: `printf PW | wfr auth login
    // --stdin --overwrite` from a non-TTY shell must run the whole exchange and
    // exit — never prompt for a password or a code, never read the keychain for
    // the password (--stdin supplies it), never block. Driven end to end
    // through the real binary against a loopback fake server; the credential
    // rejection path exercises every pre-park step of the headless flow.
    let base = fake_wealthfront(
        r#"{"success":false,"errorMessage":"Invalid email address or password."}"#,
    );
    let cfg = std::env::temp_dir().join(format!("wfr-headless-test-{}.json", std::process::id()));
    std::fs::write(&cfg, r#"{"username": "probe@example.invalid"}"#).expect("write config");

    let assert = wfr()
        .env("WFR_BASE_URL", &base)
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "auth",
            "login",
            "--stdin",
            "--overwrite",
        ])
        .write_stdin("wrong-password-probe")
        .timeout(std::time::Duration::from_secs(30)) // a hang fails loudly, not forever
        .assert()
        .code(3);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let _ = std::fs::remove_file(&cfg);

    assert!(
        stderr.contains("rejected the username or password"),
        "a wrong password must localize as a credentials error, got: {stderr}"
    );
    // The non-TTY contract: no interactive prompt of any kind.
    assert!(
        !stderr.contains("Wealthfront password:"),
        "must not prompt for a password on a piped stdin: {stderr}"
    );
    assert!(
        !stderr.contains("Verification code:"),
        "must not prompt for a code on a piped stdin: {stderr}"
    );
    // The phase announcements exist so a future block is attributable.
    assert!(
        stderr.contains("logging in"),
        "the pre-network announcement must precede the exchange: {stderr}"
    );
}

#[test]
fn bare_piped_stdin_without_flags_is_headless_too() {
    // The bare-pipe shape — `printf PW | wfr auth login` with NO --stdin and NO
    // --overwrite — reads the password from the pipe via the source reader's
    // non-TTY fallback, so it must get the same no-keychain, no-prompt
    // guarantee as the flagged shape (PR #10 review finding: the password-read
    // guard was flag-gated, leaving this shape exposed to the blocking keychain
    // dialog). On CI, where there is no keychain at all, this test fails
    // outright if the guard regresses to a keychain read.
    let base = fake_wealthfront(
        r#"{"success":false,"errorMessage":"Invalid email address or password."}"#,
    );
    let cfg = std::env::temp_dir().join(format!("wfr-barepipe-test-{}.json", std::process::id()));
    std::fs::write(&cfg, r#"{"username": "probe@example.invalid"}"#).expect("write config");

    let assert = wfr()
        .env("WFR_BASE_URL", &base)
        .args(["--config", cfg.to_str().unwrap(), "auth", "login"])
        .write_stdin("wrong-password-probe")
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .code(3);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let _ = std::fs::remove_file(&cfg);

    assert!(
        stderr.contains("rejected the username or password"),
        "the bare-pipe shape must reach credential validation, got: {stderr}"
    );
    assert!(
        !stderr.contains("Wealthfront password:") && !stderr.contains("Verification code:"),
        "must not prompt on a piped stdin: {stderr}"
    );
    assert!(
        !stderr.contains("remembered device"),
        "a headless run must skip the device-trust keychain read: {stderr}"
    );
}

#[test]
fn base_url_override_refuses_non_loopback() {
    // The env override exists for the fake-server tests above; pointing it at a
    // real host would redirect a credential-bearing POST. Refused before any
    // network access, regardless of stdin.
    let cfg = std::env::temp_dir().join(format!("wfr-baseurl-test-{}.json", std::process::id()));
    std::fs::write(&cfg, r#"{"username": "probe@example.invalid"}"#).expect("write config");
    let assert = wfr()
        .env("WFR_BASE_URL", "https://evil.example.com")
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "auth",
            "login",
            "--stdin",
            "--overwrite",
        ])
        .write_stdin("wrong-password-probe")
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .code(2);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let _ = std::fs::remove_file(&cfg);
    assert!(
        stderr.contains("loopback"),
        "a non-loopback WFR_BASE_URL must be refused: {stderr}"
    );
}

#[test]
fn usage_error_exits_2_with_json_error_dto() {
    let out = wfr()
        .args(["--json", "config", "set", "bogus_key", "x"])
        .assert()
        .code(2);
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(&stdout).expect("stdout is a JSON error DTO");
    assert_eq!(v["error"]["code"], "usage");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unknown config key"));
}

#[test]
fn info_emits_cli_info_v1() {
    let out = wfr().arg("info").assert().success();
    let v: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(v["schema"], "cli-info/v1");
    assert_eq!(v["name"], "wfr");
    assert_eq!(v["spec"], "piekstra-cli/1");
    assert_eq!(v["auth"]["login_hint"], "wfr auth login --browser");
    let caps: Vec<&str> = v["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    for cap in [
        "accounts",
        "net-worth",
        "transactions",
        "documents",
        "import",
        "api",
        "mcp",
    ] {
        assert!(caps.contains(&cap), "missing capability {cap}");
    }
    let profiles: Vec<&str> = v["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert!(profiles.contains(&"documents/v1"));
}

#[test]
fn completions_render_for_every_shell() {
    for shell in ["bash", "zsh", "fish"] {
        wfr().args(["completions", shell]).assert().success();
    }
}

/// no-color.org: any non-empty `NO_COLOR` turns color off. cli-common before
/// v0.15.1 parsed it as a clap bool, so `NO_COLOR=1` failed every command with
/// a usage error.
#[test]
fn no_color_in_the_environment_never_fails_a_command() {
    for v in ["1", "true", "0", ""] {
        wfr()
            .env("NO_COLOR", v)
            .args(["completions", "bash"])
            .assert()
            .success();
    }
}

// ---------------------------------------------------------------------------
// `import csv` — the one command verifiable end to end offline.
// ---------------------------------------------------------------------------

fn import(args: &[&str]) -> Value {
    let out = wfr().args(args).assert().success();
    serde_json::from_slice(&out.get_output().stdout).expect("stdout is one JSON document")
}

#[test]
fn import_csv_parses_the_cash_export() {
    let v = import(&["--json", "import", "csv", &fixture("activity-cash.csv")]);
    assert_eq!(v["schema"], "transaction-list/v1");
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["date"], "2026-01-31");
    assert_eq!(items[0]["amount"]["amount"], "4.11");
    assert_eq!(items[0]["amount"]["currency"], "USD");
    assert_eq!(
        items[0]["kind"], "interest",
        "inferred from the description"
    );
    // Money out keeps its negative sign.
    assert_eq!(items[2]["amount"]["amount"], "-42.75");
}

#[test]
fn import_csv_parses_the_investment_export() {
    let v = import(&[
        "--json",
        "import",
        "csv",
        &fixture("activity-investment.csv"),
    ]);
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 4);
    // `Transaction Date` (capital D) must resolve — the casing trap.
    assert_eq!(items[0]["date"], "2026-01-31");
    assert_eq!(items[0]["kind"], "fee");
    assert_eq!(
        items[1]["kind"], "dividend",
        "reinvested dividends are dividends"
    );
    assert_eq!(items[3]["kind"], "sell");
}

#[test]
fn import_csv_survives_every_known_export_quirk() {
    // BOM, preamble, mixed date and amount spellings, quoted commas, a blank
    // row, an impossible date, and two footer rows — all in one file.
    let v = import(&["--json", "import", "csv", &fixture("activity-messy.csv")]);
    let items = v["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        4,
        "4 real rows, 3 non-transaction rows skipped"
    );
    assert_eq!(v["total"], 4);

    // "January 31, 2026" + trailing-minus amount.
    assert_eq!(items[0]["date"], "2026-01-31");
    assert_eq!(items[0]["amount"]["amount"], "-2.08");
    assert_eq!(items[0]["description"], "Advisory fee, monthly");
    // 1/22/26 + "$18.44"
    assert_eq!(items[1]["date"], "2026-01-22");
    assert_eq!(items[1]["amount"]["amount"], "18.44");
    // 01-15-2026 + "$1,000.00"
    assert_eq!(items[2]["date"], "2026-01-15");
    assert_eq!(items[2]["amount"]["amount"], "1000.00");
    // 2026-01-09 + (250.00) accounting negative
    assert_eq!(items[3]["date"], "2026-01-09");
    assert_eq!(items[3]["amount"]["amount"], "-250.00");
}

#[test]
fn import_csv_reports_skipped_rows_on_stderr_only() {
    let out = wfr()
        .args(["--json", "import", "csv", &fixture("activity-messy.csv")])
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(stderr.contains("skipped 3 row"), "stderr said: {stderr}");
    // The contract: stdout is exactly one JSON document, undisturbed by the
    // diagnostic.
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert_eq!(stdout.matches("\"schema\"").count(), 1);
    serde_json::from_str::<Value>(&stdout).expect("stdout parses as a single document");
}

#[test]
fn import_csv_quiet_suppresses_the_skip_note() {
    let out = wfr()
        .args([
            "--json",
            "-q",
            "import",
            "csv",
            &fixture("activity-messy.csv"),
        ])
        .assert()
        .success();
    assert!(out.get_output().stderr.is_empty());
}

#[test]
fn import_csv_filters_by_kind() {
    let v = import(&[
        "--json",
        "import",
        "csv",
        &fixture("activity-investment.csv"),
        "--kind",
        "dividend",
    ]);
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["kind"], "dividend");
}

#[test]
fn import_csv_filters_by_date_range_and_limit() {
    let all = fixture("activity-investment.csv");
    let v = import(&[
        "--json",
        "import",
        "csv",
        &all,
        "--since",
        "2026-01-15",
        "--until",
        "2026-01-31",
    ]);
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 3, "the 01-09 row falls outside the range");

    let v = import(&["--json", "import", "csv", &all, "--limit", "2"]);
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    assert_eq!(v["total"], 4, "total reports the pre-limit count");
}

#[test]
fn import_csv_reads_stdin() {
    let out = wfr()
        .args(["--json", "import", "csv", "-"])
        .write_stdin("Date,Description,Amount\n2026-03-01,Interest earned,1.23\n")
        .assert()
        .success();
    let v: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(v["items"][0]["amount"]["amount"], "1.23");
    assert_eq!(v["items"][0]["kind"], "interest");
}

#[test]
fn import_csv_text_mode_renders_a_table() {
    let out = wfr()
        .args(["import", "csv", &fixture("activity-cash.csv")])
        .assert()
        .success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        text.contains("DATE"),
        "expected a table header, got: {text}"
    );
    assert!(text.contains("2026-01-31"));
    // Text mode must not leak JSON.
    assert!(!text.contains("\"schema\""));
}

#[test]
fn import_csv_missing_file_exits_4() {
    let out = wfr()
        .args(["--json", "import", "csv", "/nonexistent/nope.csv"])
        .assert()
        .code(4);
    let v: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(v["error"]["code"], "not_found");
}

#[test]
fn import_csv_rejects_a_file_that_is_not_an_export() {
    let out = wfr()
        .args(["--json", "import", "csv", "-"])
        .write_stdin("this is not a csv at all\njust some prose\n")
        .assert()
        .code(2);
    let v: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(v["error"]["code"], "usage");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("does not look like a Wealthfront activity export"));
}

#[test]
fn import_csv_strict_fails_on_the_first_bad_row() {
    let out = wfr()
        .args([
            "--json",
            "import",
            "csv",
            &fixture("activity-messy.csv"),
            "--strict",
        ])
        .assert()
        .code(2);
    let v: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert!(v["error"]["message"].as_str().unwrap().contains("--strict"));
}

#[test]
fn import_csv_validates_flags_before_reading_the_file() {
    // A bad range must be a usage error even when the file is also missing —
    // argument validation never depends on I/O.
    wfr()
        .args([
            "--json",
            "import",
            "csv",
            "/nonexistent/nope.csv",
            "--since",
            "not-a-date",
        ])
        .assert()
        .code(2);
    wfr()
        .args([
            "import",
            "csv",
            &fixture("activity-cash.csv"),
            "--since",
            "2026-02-01",
            "--until",
            "2026-01-01",
        ])
        .assert()
        .code(2);
}

// ---------------------------------------------------------------------------
// Network commands: argument validation only. These must fail before any
// request, and must never prompt.
// ---------------------------------------------------------------------------

#[test]
fn api_rejects_a_bad_method_before_touching_the_keychain() {
    wfr()
        .args(["--json", "api", "FETCH", "/v1/accounts"])
        .assert()
        .code(2);
}

#[test]
fn transactions_list_validates_the_range_before_the_network() {
    wfr()
        .args(["--json", "transactions", "list", "--since", "nope"])
        .assert()
        .code(2);
}

/// Opt-in: `auth status` reads keychain items, and `cargo test` rebuilds an
/// ad-hoc-signed binary each run, which macOS treats as a new code identity —
/// putting up a permission dialog per item on every single run. Run
/// deliberately with `WFR_TEST_KEYCHAIN=1 cargo test` for this coverage.
#[test]
fn auth_status_emits_auth_status_v1() {
    if std::env::var("WFR_TEST_KEYCHAIN").as_deref() != Ok("1") {
        return;
    }
    let out = wfr().args(["--json", "auth", "status"]).output().unwrap();
    if !out.status.success() {
        return; // no keychain backend available to answer
    }
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], "auth-status/v1");
    assert_eq!(v["required"], true);
    assert!(
        v.get("session_valid").is_none(),
        "session_valid must be absent unless --verify asked for it"
    );
}
