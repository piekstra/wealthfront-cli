//! Non-secret settings: `~/.config/wfr/config.toml` via `pk-cli-config`.
//!
//! Secrets never land here — the password, the session and any parked
//! MFA state live in the OS keychain under `piekstra.wfr` (see `client.rs`).

use pk_cli_config::ConfigStore;
use pk_cli_core::{output, CliError};
use serde::{Deserialize, Serialize};

pub const KNOWN_KEYS: [&str; 2] = ["username", "account"];

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// The Wealthfront login email. Stored so `auth status` and the keychain
    /// lookup agree on which credential belongs to whom.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Default account id for commands that take `-a/--account`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

#[derive(clap::Subcommand, Debug)]
pub enum ConfigCmd {
    /// Print the resolved config file path.
    Path,
    /// Show the effective configuration.
    Show,
    /// Set a config key (e.g. `config set username you@example.com`).
    Set { key: String, value: String },
    /// Remove a config key.
    Unset { key: String },
}

pub fn run(cmd: &ConfigCmd, store: &ConfigStore, json: bool) -> Result<(), CliError> {
    match cmd {
        ConfigCmd::Path => {
            println!("{}", store.path()?.display());
            Ok(())
        }
        ConfigCmd::Show => {
            let cfg: Config = store.load()?;
            let v = serde_json::to_value(&cfg).unwrap_or_default();
            if json {
                output::json(&v);
            } else {
                output::render(&v);
            }
            Ok(())
        }
        ConfigCmd::Set { key, value } => {
            let mut cfg: Config = store.load()?;
            match key.as_str() {
                "username" => cfg.username = Some(value.clone()),
                "account" => cfg.account = Some(value.clone()),
                other => return Err(unknown_key(other)),
            }
            store.save(&cfg)
        }
        ConfigCmd::Unset { key } => {
            let mut cfg: Config = store.load()?;
            match key.as_str() {
                "username" => cfg.username = None,
                "account" => cfg.account = None,
                other => return Err(unknown_key(other)),
            }
            store.save(&cfg)
        }
    }
}

fn unknown_key(key: &str) -> CliError {
    CliError::Usage(format!(
        "unknown config key `{key}` (known: {})",
        KNOWN_KEYS.join(", ")
    ))
}
