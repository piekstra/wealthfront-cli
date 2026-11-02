//! `wfr mcp`: Wealthfront accounts, activity and documents as MCP tools
//! (cli-common DESIGN.md §1.9, the MCP profile), for Claude Code, Claude
//! Desktop and any MCP client.
//!
//! Three read-only tools over the same reads and mappers the commands use:
//! `wealthfront_accounts` (every account's value and their total, the
//! `net-worth` rollup), `wealthfront_activity` (the activity feed's
//! transactions over a date range) and `wealthfront_documents` (statements
//! and trade confirmations, listed, never downloaded). Every read is a GET:
//! no tool changes anything at Wealthfront.
//!
//! Provider access goes through [`Source`], the per-target seam of
//! cli-common's MCP profile (DESIGN.md §2.3); the tests run every tool
//! offline against the fixtures through it. [`LiveSource`] reads with the
//! session `wfr auth login --browser` stored in the keychain, and only when
//! a tool is called: listing the tools touches no credential. It never
//! signs in: a missing or dead session is an auth error naming that command.

use std::sync::Mutex;

use pk_cli_core::{dates, CliError, Money};
use pk_cli_mcp::{
    parse_args, ListArgs, Page, PageRequest, Server, ToolDef, ToolError, ToolOutput, Toolset,
};
use pk_cli_secrets::CredentialStore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::commands::{documents, networth, overviews, pick_str, transactions, Ctx};

pub const ACCOUNTS_TOOL: &str = "wealthfront_accounts";
pub const ACTIVITY_TOOL: &str = "wealthfront_activity";
pub const DOCUMENTS_TOOL: &str = "wealthfront_documents";

/// What a sign-in failure asks of the user. The verified sign-in is the
/// browser one; the bare `wfr auth login` the profile's standard remedy
/// names has an unverified second-factor step (docs/api.md §3).
const SIGN_IN: &str = "Ask the user to run `wfr auth login --browser` in a terminal, then call \
                       the tool again. Tools never sign in or create credentials themselves";

/// The document types `documents list` returns, as the tools spell them.
const DOCUMENT_TYPES: [&str; 3] = ["statement", "confirm", "green-dot-statement"];

/// Where the tools get Wealthfront's data: the live web API, or fixtures.
#[allow(async_fn_in_trait)] // deliberate: no `Send` bound, as in `Toolset`
pub trait Source {
    /// Every account record (`overviews[]` of `accounts/overviews2`).
    async fn accounts(&self) -> Result<Vec<Value>, CliError>;
    /// One account's activity feed rows, every type, in Wealthfront's order.
    async fn activity(&self, account_id: &str) -> Result<Vec<Value>, CliError>;
    /// Every statement and trade-confirmation record.
    async fn documents(&self) -> Result<Vec<Value>, CliError>;
}

/// The live API, through the same [`Ctx`] and fetchers the commands use.
pub struct LiveSource {
    ctx: Mutex<Ctx>,
}

impl LiveSource {
    pub fn new(creds: CredentialStore) -> Self {
        Self {
            // Quiet: stdout is the protocol. No default account: a tool reads
            // the account its arguments name, never `WFR_ACCOUNT` or the
            // config file's.
            ctx: Mutex::new(Ctx {
                creds,
                json: true,
                quiet: true,
                account: None,
            }),
        }
    }

    /// Run `f` with the context, one read at a time. A successful read writes
    /// a rotated session cookie back to the keychain; two reads at once could
    /// each write a different rotation, and the older one could win.
    fn with_ctx<T>(&self, f: impl FnOnce(&Ctx) -> Result<T, CliError>) -> Result<T, CliError> {
        let ctx = self.ctx.lock().unwrap_or_else(|e| e.into_inner());
        f(&ctx)
    }
}

/// Blocking inside `async fn` is deliberate: the stdio server polls each call
/// on its own blocking thread with no Tokio reactor (pk-cli-mcp's `Toolset`
/// contract), which is where `reqwest::blocking` belongs.
impl Source for LiveSource {
    async fn accounts(&self) -> Result<Vec<Value>, CliError> {
        self.with_ctx(overviews::fetch_records)
    }

    async fn activity(&self, account_id: &str) -> Result<Vec<Value>, CliError> {
        self.with_ctx(|ctx| transactions::fetch_rows(ctx, account_id))
    }

    async fn documents(&self) -> Result<Vec<Value>, CliError> {
        self.with_ctx(documents::fetch_raw)
    }
}

/// The toolset `wfr mcp` serves.
pub struct WealthfrontTools<S: Source> {
    source: S,
}

impl<S: Source> WealthfrontTools<S> {
    pub fn new(source: S) -> Self {
        Self { source }
    }

    #[cfg(test)]
    pub fn source(&self) -> &S {
        &self.source
    }
}

/// A provider failure as a tool error; a sign-in failure names the browser
/// login.
fn tool_err(e: CliError) -> ToolError {
    match e {
        CliError::Auth(m) => ToolError::auth(auth_reason(&m)).with_fix(SIGN_IN),
        other => other.into(),
    }
}

/// Why the read was refused, without the CLI's own remedy (a closing "run
/// `wfr auth login`"): the fix names the one command to ask for, and a
/// second, often different, command in the same error would leave the user
/// to pick.
fn auth_reason(m: &str) -> &str {
    [" — run `", "; run `"]
        .iter()
        .filter_map(|sep| m.find(sep))
        .min()
        .map_or(m, |cut| &m[..cut])
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

// ---- wealthfront_accounts ---------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AccountsArgs {
    /// Only this account (its name or id).
    #[serde(default)]
    pub account: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct AccountsFilter<'a> {
    account: Option<&'a str>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AccountsOut {
    /// Over every matching account, not just this page.
    pub total: String,
    pub assets: String,
    /// Only when an account stands negative.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liabilities: Option<String>,
    /// Accounts Wealthfront sent with no value: listed, in no total.
    #[serde(skip_serializing_if = "is_zero")]
    pub unvalued: usize,
    #[serde(flatten)]
    pub page: Page<AccountItem>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct AccountItem {
    pub name: String,
    /// Wealthfront's account type (PERSONAL_CASH, JOINT_CASH, ...).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

// ---- wealthfront_activity ---------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ActivityArgs {
    /// First day, YYYY-MM-DD. Default: Jan 1 of until's year.
    #[serde(default)]
    pub since: Option<String>,
    /// Last day, YYYY-MM-DD. Default: today.
    #[serde(default)]
    pub until: Option<String>,
    /// Only this account (its name or id).
    #[serde(default)]
    pub account: Option<String>,
    /// deposit, withdrawal, interest, fee, dividend, transfer, buy or sell.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct ActivityFilter<'a> {
    since: &'a str,
    until: &'a str,
    account: Option<&'a str>,
    kind: Option<&'a str>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ActivityOut {
    pub since: String,
    pub until: String,
    /// Transactions in the feed whose date or amount could not be read: in
    /// no item.
    #[serde(skip_serializing_if = "is_zero")]
    pub unreadable: usize,
    #[serde(flatten)]
    pub page: Page<ActivityItem>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct ActivityItem {
    pub date: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Signed: money out is negative.
    pub amount: String,
    pub account: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

// ---- wealthfront_documents --------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocumentsArgs {
    /// statement, confirm (a trade confirmation) or green-dot-statement.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    /// Dated on or after, YYYY-MM-DD.
    #[serde(default)]
    pub since: Option<String>,
    /// Dated on or before, YYYY-MM-DD.
    #[serde(default)]
    pub until: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct DocumentsFilter<'a> {
    kind: Option<&'a str>,
    since: Option<&'a str>,
    until: Option<&'a str>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct DocumentItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    pub name: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// For `wfr documents download <id>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DocumentsOut {
    #[serde(flatten)]
    pub page: Page<DocumentItem>,
}

// ---- the toolset ------------------------------------------------------------

impl<S: Source> Toolset for WealthfrontTools<S> {
    fn server(&self) -> Server {
        Server::new(
            "wfr",
            env!("CARGO_PKG_VERSION"),
            "Wealthfront",
            "wealthfront",
        )
        .instructions(
            "Wealthfront access here is read-only: no tool can trade, transfer or change \
             anything. Wealthfront sign-in is through a browser: the command to ask for is `wfr \
             auth login --browser`. Amounts are USD decimal strings; keep every digit when \
             adding them.",
        )
    }

    fn tools(&self) -> Vec<ToolDef> {
        vec![
            ToolDef::read(
                ACCOUNTS_TOOL,
                "Wealthfront accounts and balances",
                "Lists the user's Wealthfront accounts with each one's current value, and their \
                 total. Use it for balances and what the user has at Wealthfront. Returns total, \
                 assets, liabilities (only when an account is negative) and items with name, \
                 type and balance. Narrow with account.",
            )
            .input::<AccountsArgs>()
            .output::<AccountsOut>(),
            ToolDef::read(
                ACTIVITY_TOOL,
                "Wealthfront activity",
                "Lists Wealthfront transactions in a date range, newest first: deposits, \
                 withdrawals, interest, fees. Use it for what moved in or out over a period. \
                 Items carry date, type, description, signed amount and account. Defaults to \
                 the year to date; narrow with account or type.",
            )
            .input::<ActivityArgs>()
            .output::<ActivityOut>(),
            ToolDef::read(
                DOCUMENTS_TOOL,
                "Wealthfront documents",
                "Lists the user's Wealthfront statements and trade confirmations, newest first, \
                 without downloading them. Use it to see which statements exist. Items carry \
                 date, name and type; tax forms are not listed. Narrow with type or \
                 since/until.",
            )
            .input::<DocumentsArgs>()
            .output::<DocumentsOut>(),
        ]
    }

    async fn call(&self, name: &str, args: Value) -> Result<ToolOutput, ToolError> {
        match name {
            ACCOUNTS_TOOL => self.accounts(parse_args(args)?).await,
            ACTIVITY_TOOL => self.activity(parse_args(args)?).await,
            DOCUMENTS_TOOL => self.documents(parse_args(args)?).await,
            other => Err(ToolError::other(format!("no handler for {other}"))),
        }
    }
}

impl<S: Source> WealthfrontTools<S> {
    async fn accounts(&self, args: AccountsArgs) -> Result<ToolOutput, ToolError> {
        let account = non_empty(args.account.as_deref());
        let page = PageRequest::new(&args.list, &AccountsFilter { account })?;
        let detailed = args.list.format().is_detailed();

        let records = self.source.accounts().await.map_err(tool_err)?;
        let all = account_refs(&records)?;
        let mut sums = Sums::default();
        let mut matched = Vec::new();
        for acct in pick(&all, account)? {
            let balance = overviews::balance_of(acct.record).map(|m| m.amount);
            match &balance {
                Some(amount) => sums.add(&acct.name, amount)?,
                None => sums.unvalued += 1,
            }
            matched.push(AccountItem {
                name: acct.name.clone(),
                kind: overviews::kind_of(acct.record),
                balance,
                id: detailed.then(|| acct.id.clone()),
            });
        }
        ToolOutput::new(&AccountsOut {
            total: Money::from_cents(sums.assets - sums.liabilities).amount,
            assets: Money::from_cents(sums.assets).amount,
            liabilities: (sums.liabilities > 0).then(|| Money::from_cents(sums.liabilities).amount),
            unvalued: sums.unvalued,
            page: page.page(matched, "account")?,
        })
    }

    async fn activity(&self, args: ActivityArgs) -> Result<ToolOutput, ToolError> {
        let (since, until) = window(
            non_empty(args.since.as_deref()),
            non_empty(args.until.as_deref()),
        )?;
        let account = non_empty(args.account.as_deref());
        let kind = non_empty(args.kind.as_deref());
        let page = PageRequest::new(
            &args.list,
            &ActivityFilter {
                since: &since,
                until: &until,
                account,
                kind,
            },
        )?;
        let detailed = args.list.format().is_detailed();

        let records = self.source.accounts().await.map_err(tool_err)?;
        let all = account_refs(&records)?;
        let mut unreadable = 0;
        let mut matched: Vec<ActivityItem> = Vec::new();
        for acct in pick(&all, account)? {
            let rows = self.source.activity(&acct.id).await.map_err(tool_err)?;
            for row in rows.iter().filter(|r| transactions::is_transaction_row(r)) {
                let Some(tx) = transactions::to_transaction(row) else {
                    unreadable += 1;
                    continue;
                };
                if tx.date < since
                    || tx.date > until
                    || kind.is_some_and(|k| {
                        !tx.kind
                            .as_deref()
                            .is_some_and(|x| x.eq_ignore_ascii_case(k))
                    })
                {
                    continue;
                }
                matched.push(ActivityItem {
                    date: tx.date,
                    kind: tx.kind,
                    description: tx.description,
                    amount: tx.amount.amount,
                    account: acct.name.clone(),
                    id: pick_str(row, &["id"]).filter(|_| detailed),
                });
            }
        }
        // Newest first across accounts; a stable sort keeps Wealthfront's
        // order within a day.
        matched.sort_by(|a, b| b.date.cmp(&a.date));
        ToolOutput::new(&ActivityOut {
            since,
            until,
            unreadable,
            page: page.page(matched, "since/until, account or type")?,
        })
    }

    async fn documents(&self, args: DocumentsArgs) -> Result<ToolOutput, ToolError> {
        let kind = document_type(non_empty(args.kind.as_deref()))?;
        let since = date_arg("since", non_empty(args.since.as_deref()))?;
        let until = date_arg("until", non_empty(args.until.as_deref()))?;
        if let (Some(s), Some(u)) = (&since, &until) {
            if s > u {
                return Err(ToolError::usage(format!(
                    "since ({s}) is after until ({u})"
                )));
            }
        }
        let page = PageRequest::new(
            &args.list,
            &DocumentsFilter {
                kind,
                since: since.as_deref(),
                until: until.as_deref(),
            },
        )?;
        let detailed = args.list.format().is_detailed();

        let records = self.source.documents().await.map_err(tool_err)?;
        let mut matched: Vec<DocumentItem> = records
            .iter()
            .filter_map(documents::to_document)
            .map(|d| DocumentItem {
                kind: d.category.as_deref().map(type_word),
                date: d.date,
                name: d.name,
                id: detailed.then_some(d.id),
            })
            .filter(|d| kind.is_none_or(|k| d.kind.as_deref() == Some(k)))
            // As `documents list`: an undated document stays in any window.
            .filter(|d| {
                d.date.as_deref().is_none_or(|x| {
                    since.as_deref().is_none_or(|s| x >= s)
                        && until.as_deref().is_none_or(|u| x <= u)
                })
            })
            .collect();
        // Newest first; undated last.
        matched.sort_by(|a, b| b.date.cmp(&a.date));
        ToolOutput::new(&DocumentsOut {
            page: page.page(matched, "type or since/until")?,
        })
    }
}

/// One account record with the two fields every tool keys on.
struct AccountRef<'a> {
    id: String,
    /// Its display name, else its id.
    name: String,
    record: &'a Value,
}

/// Every record as an [`AccountRef`]. A record without an id is a shape
/// change, never an account to leave out of a total quietly.
fn account_refs(records: &[Value]) -> Result<Vec<AccountRef<'_>>, ToolError> {
    records
        .iter()
        .map(|record| {
            let id = overviews::id_of(record).ok_or_else(|| {
                ToolError::upstream(
                    "a Wealthfront account record carried no id; the response shape may have \
                     changed",
                )
            })?;
            let name = overviews::name_of(record).unwrap_or_else(|| id.clone());
            Ok(AccountRef { id, name, record })
        })
        .collect()
}

/// The accounts `wanted` names (by id, or by name ignoring case), or every
/// account when it names none. An unknown name is not found, listing the
/// names that exist.
fn pick<'r, 'a>(
    all: &'r [AccountRef<'a>],
    wanted: Option<&str>,
) -> Result<Vec<&'r AccountRef<'a>>, ToolError> {
    let Some(wanted) = wanted else {
        return Ok(all.iter().collect());
    };
    let hit: Vec<&AccountRef> = all
        .iter()
        .filter(|a| a.id == wanted || a.name.eq_ignore_ascii_case(wanted))
        .collect();
    if hit.is_empty() {
        let names: Vec<&str> = all.iter().map(|a| a.name.as_str()).collect();
        return Err(ToolError::not_found(format!(
            "no Wealthfront account named `{wanted}`; the accounts are: {}",
            names.join(", ")
        ))
        .with_fix("Call again with one of those names"));
    }
    Ok(hit)
}

/// Exact sums in cents: a float would drift.
#[derive(Default)]
struct Sums {
    assets: i64,
    liabilities: i64,
    unvalued: usize,
}

impl Sums {
    fn add(&mut self, account: &str, amount: &str) -> Result<(), ToolError> {
        let overflow = || {
            ToolError::upstream(format!(
                "could not add the value `{amount}` of account {account}"
            ))
        };
        let cents = networth::to_cents(amount).ok_or_else(overflow)?;
        if cents >= 0 {
            self.assets = self.assets.checked_add(cents).ok_or_else(overflow)?;
        } else {
            let debt = cents.checked_neg().ok_or_else(overflow)?;
            self.liabilities = self.liabilities.checked_add(debt).ok_or_else(overflow)?;
        }
        Ok(())
    }
}

/// Wealthfront's document type as the tools spell it: `GREEN_DOT_STATEMENT`
/// is `green-dot-statement`.
fn type_word(raw: &str) -> String {
    raw.to_ascii_lowercase().replace('_', "-")
}

/// A `type` argument for documents, in the tools' spelling; an unknown one
/// names the known ones.
fn document_type(raw: Option<&str>) -> Result<Option<&'static str>, ToolError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let word = type_word(raw);
    DOCUMENT_TYPES
        .iter()
        .find(|t| **t == word)
        .copied()
        .map(Some)
        .ok_or_else(|| {
            ToolError::usage(format!(
                "`{raw}` is not a Wealthfront document type; the types are: {}. Tax forms are \
                 not listed",
                DOCUMENT_TYPES.join(", ")
            ))
        })
}

fn non_empty(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

/// A date argument, zero-padded (`2026-1-5` is `2026-01-05`) so the string
/// comparisons that filter rows are date comparisons.
fn date_arg(name: &str, v: Option<&str>) -> Result<Option<String>, ToolError> {
    v.map(|d| {
        dates::parse_iso(d).map(dates::fmt_iso).map_err(|_| {
            ToolError::usage(format!("{name} must be a date as YYYY-MM-DD, got `{d}`"))
        })
    })
    .transpose()
}

/// The inclusive window, defaulting to the year to date.
fn window(since: Option<&str>, until: Option<&str>) -> Result<(String, String), ToolError> {
    let since = date_arg("since", since)?;
    let until = date_arg("until", until)?.unwrap_or_else(|| dates::fmt_iso(dates::today()));
    let since = since.unwrap_or_else(|| format!("{}-01-01", &until[..4]));
    if since > until {
        return Err(ToolError::usage(format!(
            "since ({since}) is after until ({until})"
        )));
    }
    Ok((since, until))
}

#[cfg(test)]
mod tests;
