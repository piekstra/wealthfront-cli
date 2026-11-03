//! `wfr` — Wealthfront from the command line (conforms to piekstra-cli/1).
//!
//! Wealthfront publishes no public API, so most of this CLI wraps a
//! reverse-engineered surface that has never been run against the live site:
//! those commands are marked UNVERIFIED-LIVE in `docs/api.md` and in their own
//! module docs. The exception is `wfr import csv`, which parses the activity
//! CSV export entirely offline and is verified end to end by the test suite.

mod client;
mod commands;
mod config;
mod csv;
mod keychain;
#[cfg(test)]
mod loopback;
mod mcp;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::Shell;
use pk_cli_config::ConfigStore;
use pk_cli_core::info::{AuthInfo, CliInfo};
use pk_cli_core::{output, CliError, CommonArgs, RangeArgs};
use pk_cli_http::ApiArgs;
use pk_cli_selfupdate::{SelfUpdateArgs, Updater};

use commands::auth::AuthCmd;
use commands::import::ImportCsvArgs;
use commands::Ctx;
use config::ConfigCmd;

const BIN: &str = "wfr";
const REPO: &str = "piekstra/wealthfront-cli";

#[derive(Parser, Debug)]
#[command(name = BIN, version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    common: CommonArgs,

    /// Account id to act on (default: the `account` config key).
    #[arg(short, long, global = true, value_name = "ID", env = "WFR_ACCOUNT")]
    account: Option<String>,

    /// Override the config file location.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Credential management and session status.
    #[command(subcommand)]
    Auth(AuthCmd),
    /// Non-secret settings.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Wealthfront accounts.
    #[command(subcommand)]
    Accounts(AccountsCmd),
    /// Every account's balance, rolled up into a household figure (net-worth/v1).
    ///
    /// One row per account — the provider's own current value from the same
    /// VERIFIED-LIVE read `accounts list` uses — summed client-side into
    /// total/assets (and liabilities, only if an account stands negative).
    /// Only a -a/--account typed on the command line narrows it (with a
    /// stderr note); unlike other reads, the WFR_ACCOUNT env var and the
    /// config file's persisted `account` default are deliberately ignored —
    /// ambient state must never silently turn the household figure into one
    /// account's balance.
    NetWorth,
    /// Account activity (transaction-list/v1).
    #[command(subcommand, visible_alias = "activity")]
    Transactions(TransactionsCmd),
    /// Statements and tax documents (documents/v1).
    #[command(subcommand)]
    Documents(DocumentsCmd),
    /// Parse a Wealthfront export offline — no credential, no network.
    #[command(subcommand)]
    Import(ImportCmd),
    /// Raw authenticated passthrough, for discovering real response shapes.
    Api(ApiArgs),
    /// Update to the latest release from GitHub.
    SelfUpdate(SelfUpdateArgs),
    /// Print a shell completion script.
    Completions { shell: Shell },
    /// Machine-readable capability discovery (cli-info/v1).
    Info,
    /// Serve read-only Wealthfront tools to Claude over MCP (stdio).
    ///
    /// For Claude Code (`claude mcp add wealthfront -- wfr mcp`), Claude
    /// Desktop and any MCP client. The tools use the session `wfr auth login
    /// --browser` stored, and never sign in themselves.
    Mcp(pk_cli_mcp::McpArgs),
}

#[derive(Subcommand, Debug)]
enum AccountsCmd {
    /// List accounts.
    #[command(visible_alias = "ls")]
    List(RangeArgs),
    /// Show one account.
    Get { id: String },
}

#[derive(Subcommand, Debug)]
enum TransactionsCmd {
    /// List activity, newest first.
    #[command(visible_alias = "ls")]
    List(RangeArgs),
}

#[derive(Subcommand, Debug)]
enum DocumentsCmd {
    /// List documents, newest first.
    #[command(visible_alias = "ls")]
    List(RangeArgs),
    /// Download one document to a file or directory.
    #[command(visible_alias = "get")]
    Download {
        id: String,
        /// Output file or directory (default: the portal's own filename).
        #[arg(short, long, value_name = "PATH")]
        output: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum ImportCmd {
    /// Parse an activity CSV export into transaction-list/v1.
    Csv(ImportCsvArgs),
}

fn main() {
    // Parsed via explicit `ArgMatches` (not `Cli::parse()`) so the dispatch
    // can ask clap *where* a value came from — `net-worth` narrows only on a
    // `-a` typed on the command line, never on the `WFR_ACCOUNT` env var.
    let matches = Cli::command().get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };
    if let Err(e) = run(&cli, &matches) {
        std::process::exit(output::fail(&e, cli.common.json));
    }
}

/// Was `-a/--account` **typed on the command line** for this invocation, at
/// any level (the flag is global, so clap may record it on the subcommand's
/// matches)? `false` when the value arrived from `WFR_ACCOUNT`
/// (`ValueSource::EnvVariable`) or not at all.
///
/// `net-worth` narrows only on a typed flag: an env var exported in a shell
/// rc is ambient state with the same lifetime as the config default the
/// command already refuses, and a household figure silently narrowed by
/// ambient state is exactly the misreport the honesty rules exist to prevent.
fn account_typed_on_cli(matches: &clap::ArgMatches) -> bool {
    let mut m = matches;
    loop {
        if m.value_source("account") == Some(clap::parser::ValueSource::CommandLine) {
            return true;
        }
        match m.subcommand() {
            Some((_, sub)) => m = sub,
            None => return false,
        }
    }
}

/// The account selection `net-worth` may narrow on: the parsed `-a` value if
/// and only if it was typed on the command line ([`account_typed_on_cli`]).
///
/// This is the dispatcher's whole decision, extracted so the tests exercise
/// the *same function* `run` calls — a refactor that reaches for
/// `cli.account` directly instead would have to bypass it visibly.
fn typed_account(cli: &Cli, matches: &clap::ArgMatches) -> Option<String> {
    account_typed_on_cli(matches)
        .then(|| cli.account.clone())
        .flatten()
}

fn run(cli: &Cli, matches: &clap::ArgMatches) -> Result<(), CliError> {
    let store = ConfigStore::new(BIN).with_override(cli.config.clone());
    let creds = keychain::store();

    // `import`, `completions` and `info` are deliberately handled without
    // building a Ctx: they must work with no config, no keychain and no
    // network, and reading config first would make a broken config file break
    // an offline CSV parse.
    match &cli.command {
        Command::Import(ImportCmd::Csv(args)) => {
            return commands::import::run(args, cli.common.json, cli.common.quiet)
        }
        Command::Completions { shell } => {
            clap_complete::generate(*shell, &mut Cli::command(), BIN, &mut std::io::stdout());
            return Ok(());
        }
        // The tools read the account each call names, never the config
        // file's default, so no config is loaded; listing them reads nothing.
        Command::Mcp(args) => {
            return pk_cli_mcp::run(
                args,
                mcp::WealthfrontTools::new(mcp::LiveSource::new(creds)),
            )
        }
        Command::Info => {
            let info = CliInfo::new(
                BIN,
                env!("CARGO_PKG_VERSION"),
                &format!("https://github.com/{REPO}"),
                AuthInfo {
                    required: true,
                    method: "password".into(),
                    // The verified sign-in (cli-common DESIGN.md §2.2).
                    login_hint: Some(format!("{BIN} auth login --browser")),
                },
                &[
                    "accounts",
                    "net-worth",
                    "transactions",
                    "documents",
                    "import",
                    "api",
                    "mcp",
                ],
            )
            .with_profiles(&[pk_cli_documents::PROFILE]);
            output::json(&serde_json::to_value(&info).unwrap_or_default());
            return Ok(());
        }
        Command::SelfUpdate(args) => {
            return Updater {
                repo: REPO.into(),
                binary: BIN.into(),
                target: env!("BUILD_TARGET").into(),
                current: env!("CARGO_PKG_VERSION").into(),
            }
            .run(args, cli.common.json, cli.common.quiet)
        }
        Command::Config(cmd) => return config::run(cmd, &store, cli.common.json),
        Command::Auth(cmd) => {
            return commands::auth::run(
                cmd,
                &creds,
                &store,
                cli.common.json,
                cli.common.quiet,
                cli.common.interactive(),
                keychain::keeps_real_config(cli.config.is_some()),
            )
        }
        _ => {}
    }

    let cfg: config::Config = store.load()?;
    let ctx = Ctx {
        creds,
        json: cli.common.json,
        quiet: cli.common.quiet,
        // Precedence: flag/env > config file.
        account: cli.account.clone().or(cfg.account.clone()),
    };

    match &cli.command {
        Command::Accounts(AccountsCmd::List(range)) => commands::accounts::list(&ctx, range),
        Command::Accounts(AccountsCmd::Get { id }) => commands::accounts::get(&ctx, id),
        // Only a `-a` typed on the command line narrows the household figure
        // — `WFR_ACCOUNT` (env) and the persisted config default are ambient
        // state and deliberately do not (docs/api.md §3.5).
        Command::NetWorth => commands::networth::show(&ctx, typed_account(cli, matches).as_deref()),
        Command::Transactions(TransactionsCmd::List(range)) => {
            commands::transactions::list(&ctx, range)
        }
        Command::Documents(DocumentsCmd::List(range)) => commands::documents::list(&ctx, range),
        Command::Documents(DocumentsCmd::Download { id, output }) => {
            commands::documents::download(&ctx, id, output.as_deref())
        }
        Command::Api(args) => {
            // Validate before touching the keychain, so a bad method never
            // prompts for credentials.
            let method = args.parsed_method()?;
            let body = args.parsed_body()?;
            let v = ctx.client()?.api(method, &args.path, body)?;
            output::json(&v);
            Ok(())
        }
        // Handled above.
        Command::Auth(_)
        | Command::Config(_)
        | Command::Import(_)
        | Command::SelfUpdate(_)
        | Command::Completions { .. }
        | Command::Mcp(_)
        | Command::Info => unreachable!("dispatched before Ctx construction"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same parse `main` performs, over a full argv — so these tests
    /// exercise the exact `(cli, matches)` pair `run` receives, not a
    /// hand-built stand-in. (A black-box `net-worth` run cannot exist in the
    /// offline suite: the command needs a keychain-backed session, and tests
    /// must never touch the keychain — so the dispatcher decision is pinned
    /// at this seam instead.)
    fn parsed(argv: &[&str]) -> (Cli, clap::ArgMatches) {
        let matches = Cli::command().try_get_matches_from(argv).unwrap();
        let cli = Cli::from_arg_matches(&matches).unwrap();
        (cli, matches)
    }

    /// The flag-vs-env distinction `net-worth` relies on: `-a` typed on the
    /// command line — before or after the subcommand, since the flag is
    /// global — counts as typed; an untyped invocation does not.
    #[test]
    fn only_a_typed_account_flag_counts_as_typed() {
        let (cli, m) = parsed(&["wfr", "-a", "ACCT-XXXX-0001", "net-worth"]);
        assert_eq!(typed_account(&cli, &m).as_deref(), Some("ACCT-XXXX-0001"));
        let (cli, m) = parsed(&["wfr", "net-worth", "-a", "ACCT-XXXX-0001"]);
        assert_eq!(
            typed_account(&cli, &m).as_deref(),
            Some("ACCT-XXXX-0001"),
            "a global flag typed after the subcommand lands on the subcommand's matches"
        );
        let (cli, m) = parsed(&["wfr", "net-worth"]);
        assert_eq!(typed_account(&cli, &m), None);
    }

    /// A login flag the browser branch does not read is refused beside `--browser`,
    /// so a new flag can't be silently ignored: it conflicts, or it joins this list
    /// because the branch reads it.
    #[test]
    fn every_login_flag_the_browser_branch_does_not_read_is_refused() {
        let mut cli = Cli::command();
        let auth = cli.find_subcommand_mut("auth").unwrap();
        let login = auth.find_subcommand_mut("login").unwrap();
        let browser = login
            .get_arguments()
            .find(|a| a.get_id() == "browser")
            .unwrap();
        let refused: Vec<&str> = login
            .get_arg_conflicts_with(browser)
            .iter()
            .map(|a| a.get_id().as_str())
            .collect();
        let read_by_the_browser_branch = ["browser", "fresh_profile", "help"];
        for arg in login.get_arguments() {
            let id = arg.get_id().as_str();
            if arg.is_global_set() || read_by_the_browser_branch.contains(&id) {
                continue;
            }
            assert!(refused.contains(&id), "--browser must conflict with {id}");
        }
    }

    /// `--browser` captures the session and reads only `--fresh-profile`, so clap
    /// refuses it beside every other login flag (exit 2) before `run` reads the
    /// keychain or the network. Parsed only: nothing here runs a login.
    #[test]
    fn browser_login_takes_no_other_credential_source() {
        let parse = |extra: &[&str]| {
            let argv = [&["wfr", "auth", "login"][..], extra].concat();
            Cli::command().try_get_matches_from(argv)
        };
        // Bare `--browser` still parses, though `--channel` has a default.
        assert!(parse(&["--browser"]).is_ok());
        assert!(parse(&["--browser", "--fresh-profile"]).is_ok());
        let refused = [
            &["--stdin"][..],
            &["--from-env", "WFR_PASSWORD"],
            &["--code", "000000"],
            &["--no-verify"],
            &["--overwrite"],
            &["--non-interactive"],
            &["--channel", "totp"],
        ];
        for other in refused {
            let err = parse(&[&["--browser"][..], other].concat()).unwrap_err();
            assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
            assert_eq!(err.exit_code(), 2);
        }
        // The password login keeps its sources, and the code flags.
        assert!(parse(&["--stdin", "--channel", "totp"]).is_ok());
        assert!(parse(&["--from-env", "WFR_PASSWORD"]).is_ok());
        assert!(parse(&["--code", "000000"]).is_ok());
        assert!(parse(&["--no-verify"]).is_ok());
        assert!(parse(&["--overwrite"]).is_ok());
        assert!(parse(&["--non-interactive"]).is_ok());
    }

    /// Set on the child process [`env_account_reaches_the_parse_but_never_narrows_net_worth`]
    /// starts, so the check it runs there knows it was started for it.
    const ENV_ACCOUNT_CHILD: &str = "WFR_TEST_ENV_ACCOUNT_CHILD";

    /// The honesty invariant end to end at the parse seam: a value from
    /// `WFR_ACCOUNT` reaches `cli.account` (so every *other* read honors it)
    /// but must never narrow `net-worth`, while a typed `-a` still does.
    ///
    /// The environment is shared by every test in this process, so the
    /// variable is set only on a child: this test binary, re-run on exactly
    /// [`wfr_account_in_the_environment_never_narrows`]. A black-box run of
    /// `wfr net-worth` cannot show it offline: its first step reads the
    /// session from the keychain, and the narrowing comes after the fetch.
    #[test]
    fn env_account_reaches_the_parse_but_never_narrows_net_worth() {
        let name = "tests::wfr_account_in_the_environment_never_narrows";
        let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", name, "--include-ignored", "--test-threads=1"])
            .env(ENV_ACCOUNT_CHILD, "1")
            .env("WFR_ACCOUNT", "ACCT-XXXX-0002")
            .output()
            .expect("run the test binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stdout}{stderr}");
        assert!(
            stdout.contains("test result: ok. 1 passed"),
            "the child ran the check: {stdout}"
        );
    }

    /// The check [`env_account_reaches_the_parse_but_never_narrows_net_worth`]
    /// runs in a child process with `WFR_ACCOUNT` set. Run on its own, it
    /// has nothing to check and passes.
    #[test]
    #[ignore = "run in a child process with WFR_ACCOUNT set"]
    fn wfr_account_in_the_environment_never_narrows() {
        if std::env::var_os(ENV_ACCOUNT_CHILD).is_none() {
            return;
        }
        let (cli, m) = parsed(&["wfr", "net-worth"]);
        assert_eq!(
            cli.account.as_deref(),
            Some("ACCT-XXXX-0002"),
            "the env var was consumed by the parse"
        );
        assert_eq!(
            typed_account(&cli, &m),
            None,
            "…but env is ambient state and must not narrow the household figure"
        );
        // A literal `-a` beats the env var and narrows.
        let (cli, m) = parsed(&["wfr", "net-worth", "-a", "ACCT-XXXX-0001"]);
        assert_eq!(typed_account(&cli, &m).as_deref(), Some("ACCT-XXXX-0001"));
    }
}
