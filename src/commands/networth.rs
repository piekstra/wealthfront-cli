//! `wfr net-worth` — every Wealthfront account's balance, rolled up
//! (`net-worth/v1`).
//!
//! One row per account, taken from the **provider's own** per-account value —
//! `accountValueSummary.totalValue` on `GET /capitan/v1/accounts/overviews2`,
//! the same VERIFIED-LIVE read `accounts list` uses. Both commands read it
//! through the shared `super::overviews` module (envelope + field readers),
//! so they can never disagree about which accounts exist or how each one is
//! read. What no captured `/capitan/v1` endpoint offers is a *household*
//! total, so the cross-account rollup is client-side: integer cents, no
//! floats (docs/api.md §3.5 records the endpoint, the choice, and where a
//! provider-served total would go if one is ever captured).
//!
//! The DTO is the family's `net-worth/v1` shape (`total`, `assets`,
//! `liabilities` omit-if-none, per-account `accounts[]` rows) — the same
//! vocabulary `m1f net-worth` and `rhd net-worth` emit — so an
//! asset-capturing consumer needs one registry row per provider, not
//! per-provider glue.
//!
//! Unlike the other reads, this command's mapping failures are **hard
//! errors**, not counted skips: its contract is completeness, and a household
//! figure quietly missing an account is exactly the misreport the honesty
//! rules exist to prevent.

use pk_cli_core::{output, CliError, Money};
use serde::Serialize;
use serde_json::Value;

use super::{overviews, Ctx};
use crate::client::endpoints;

/// The `net-worth/v1` DTO. `assets` collects the accounts standing positive;
/// an account whose own value is negative lands in `liabilities` instead of
/// silently shrinking "assets" (`overviews2` has no separate margin/borrow
/// shape — a negative per-account value is the only liability signal the
/// captured surface offers, docs/api.md §3.5). `liabilities` is omitted when
/// there is none, per the profile.
#[derive(Debug, Serialize)]
pub struct NetWorth {
    pub total: Money,
    pub assets: Money,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liabilities: Option<Money>,
    pub accounts: Vec<AccountRow>,
}

/// One account's slice of the rollup.
#[derive(Debug, Serialize)]
pub struct AccountRow {
    /// The provider's account id — the same value `wfr accounts list` shows
    /// and `-a` accepts.
    pub account_number: String,
    /// The provider's own account type (`PERSONAL_CASH`, `JOINT_CASH`,
    /// `TAXABLE_INVESTMENT`, …), verbatim.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// This account's current value — `accountValueSummary.totalValue`.
    pub total: Money,
}

/// `typed_account` is the `-a` flag **typed on the command line for this
/// invocation** — never the `WFR_ACCOUNT` env var, and never the config
/// file's persisted `account` default.
///
/// That distinction is deliberate and load-bearing: every other read honoring
/// those defaults narrows harmlessly, but this command's contract is
/// completeness, and ambient state that outlives the invocation — a config
/// key set months ago, an env var exported in a shell rc — silently turning
/// the household figure into one account's balance is exactly the quiet
/// misreport the honesty rules exist to prevent (a narrowed DTO is
/// byte-identical to a genuine single-account household). So only a flag
/// typed at the prompt narrows the rollup (the dispatcher in `main.rs`
/// enforces the flag-vs-env distinction via clap's `ValueSource`; the
/// [`scoped`] tests pin the narrowing semantics), and even that announces
/// itself on stderr.
pub fn show(ctx: &Ctx, typed_account: Option<&str>) -> Result<(), CliError> {
    let rows = overviews::fetch_records(ctx)?;
    let all: Vec<AccountRow> = rows.iter().map(account_row).collect::<Result<_, _>>()?;
    let nw = rollup(scoped(all, typed_account)?)?;
    if let Some(a) = typed_account {
        if !ctx.quiet {
            eprintln!(
                "note: narrowed to account {a} — this is one account's balance, not the \
                 household figure"
            );
        }
    }

    let payload = serde_json::to_value(&nw).unwrap_or_default();
    output::emit(ctx.json, "net-worth", payload, |v| {
        // Lead with the headline figures, then the per-account table.
        let mut head = serde_json::Map::new();
        for k in ["total", "assets", "liabilities"] {
            if let Some(val) = v.get(k) {
                head.insert(k.to_string(), val.clone());
            }
        }
        output::render(&Value::Object(head));
        println!();
        output::table(&output::table_view(
            &output::rows_of(v, "accounts"),
            &["account_number", "type", "total"],
        ));
    });
    Ok(())
}

/// Map one `overviews[]` record onto an [`AccountRow`].
///
/// Pure, so the mapping — including both refusals — is contract-tested
/// offline against the captured fixture. Unlike `accounts list`, a record
/// that cannot be mapped is an error rather than a counted skip: "one of your
/// accounts is missing from the total" must never be a stderr footnote.
fn account_row(v: &Value) -> Result<AccountRow, CliError> {
    let account_number = overviews::id_of(v).ok_or_else(|| {
        CliError::Upstream(format!(
            "an account record carried no id — the shape may have changed; inspect it with \
             `wfr api GET {}` (docs/api.md §3.5)",
            endpoints::ACCOUNTS
        ))
    })?;
    // A missing value is the failure reporting itself, not a $0 account.
    let total = overviews::balance_of(v).ok_or_else(|| {
        CliError::Upstream(format!(
            "account {account_number} carried no value — refusing to report a household total \
             with an account missing from it (docs/api.md §3.5)"
        ))
    })?;
    Ok(AccountRow {
        account_number,
        // The shared reading, so this DTO's `type` and `accounts list`'s
        // `kind` can never disagree about the same account.
        kind: overviews::kind_of(v),
        total,
    })
}

/// Narrow the mapped accounts to an explicit selection, or keep them all.
///
/// Pure, so the scoping semantics — including "no selection means every
/// account" — are pinned offline and can't drift back to honoring the
/// persisted config default.
fn scoped(mut all: Vec<AccountRow>, wanted: Option<&str>) -> Result<Vec<AccountRow>, CliError> {
    if let Some(wanted) = wanted {
        all.retain(|row| row.account_number == wanted);
        if all.is_empty() {
            return Err(CliError::NotFound(format!(
                "no account `{wanted}` in this login — list them with `wfr accounts list`"
            )));
        }
    }
    if all.is_empty() {
        return Err(CliError::Upstream(
            "Wealthfront returned no accounts to value — if this login really has none that is \
             new information; otherwise the overviews shape has changed (docs/api.md §3.5)"
                .into(),
        ));
    }
    Ok(all)
}

/// Sum the per-account values into the household figures.
///
/// Integer cents throughout — no float ever touches a balance. Every total
/// here came through `Money::parse_usd`, which normalizes to exactly two
/// fraction digits, so cents summation is lossless with respect to what the
/// CLI reports (Robinhood's sub-cent lesson does not apply: this provider's
/// amounts are normalized at ingestion, and the per-account rows and the sum
/// therefore carry identical precision). An amount in any other shape did not
/// come from `parse_usd` and is treated as an upstream surprise, never
/// guessed at.
fn rollup(accounts: Vec<AccountRow>) -> Result<NetWorth, CliError> {
    let mut assets: i64 = 0;
    let mut liabilities: i64 = 0;
    for row in &accounts {
        let err = || {
            CliError::Upstream(format!(
                "could not sum the value for account {} — see docs/api.md §3.5",
                row.account_number
            ))
        };
        let v = to_cents(&row.total.amount).ok_or_else(err)?;
        if v >= 0 {
            assets = assets.checked_add(v).ok_or_else(err)?;
        } else {
            let debt = v.checked_neg().ok_or_else(err)?;
            liabilities = liabilities.checked_add(debt).ok_or_else(err)?;
        }
    }
    Ok(NetWorth {
        total: Money::from_cents(assets - liabilities),
        assets: Money::from_cents(assets),
        liabilities: (liabilities > 0).then(|| Money::from_cents(liabilities)),
        accounts,
    })
}

/// Parse a `parse_usd`-normalized amount (`[-]digits.dd`) into signed cents.
/// `None` for anything else — the caller treats that as an upstream surprise
/// rather than guessing.
pub(crate) fn to_cents(amount: &str) -> Option<i64> {
    let (negative, digits) = match amount.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, amount),
    };
    let (int, frac) = digits.split_once('.')?;
    if int.is_empty()
        || frac.len() != 2
        || !int.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let cents = int
        .parse::<i64>()
        .ok()?
        .checked_mul(100)?
        .checked_add(frac.parse::<i64>().ok()?)?;
    Some(if negative { -cents } else { cents })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The captured fixture — synthetic values, live field names — must roll
    /// up end to end: envelope, per-row mapping, and the summed figures.
    #[test]
    fn the_captured_fixture_rolls_up_end_to_end() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/accounts-overviews2.json"
        ))
        .unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        let rows = overviews::unwrap_records(&v).unwrap();
        let all: Vec<AccountRow> = rows
            .iter()
            .map(account_row)
            .collect::<Result<_, _>>()
            .unwrap();
        let nw = rollup(all).unwrap();
        assert_eq!(nw.accounts.len(), 2);
        assert_eq!(nw.accounts[0].account_number, "ACCT-XXXX-0001");
        assert_eq!(
            nw.accounts[0].kind.as_deref(),
            Some("PERSONAL_CASH"),
            "`type` is the provider's own accountType, not the display name"
        );
        assert_eq!(nw.accounts[0].total.amount, "1234.56");
        assert_eq!(nw.accounts[1].total.amount, "5000.00");
        assert_eq!(nw.assets.amount, "6234.56");
        assert_eq!(nw.total.amount, "6234.56");
        assert!(nw.liabilities.is_none(), "no debt renders as absent");
    }

    /// The captured record shape, inline (field names from the 2026-08-18
    /// live capture; values invented).
    fn overview(id: &str, value: f64) -> Value {
        json!({
            "type": "CASH",
            "accountId": id,
            "accountType": "PERSONAL_CASH",
            "accountTypeDisplayName": "Individual",
            "accountDisplayName": "Individual Cash Account",
            "accountValueSummary": {
                "totalValue": value,
                "formattedTotalValue": format!("${value:.2}")
            }
        })
    }

    fn row(number: &str, amount: &str) -> AccountRow {
        AccountRow {
            account_number: number.into(),
            kind: Some("PERSONAL_CASH".into()),
            total: Money::usd(amount),
        }
    }

    #[test]
    fn an_account_row_reads_the_shared_account_fields() {
        let r = account_row(&overview("ACCT-XXXX-0001", 1234.56)).unwrap();
        assert_eq!(r.account_number, "ACCT-XXXX-0001");
        assert_eq!(r.kind.as_deref(), Some("PERSONAL_CASH"));
        assert_eq!(r.total.amount, "1234.56");
        assert_eq!(r.total.currency, "USD");
    }

    /// A record without an id, or without a value, is a loud upstream error —
    /// never a skipped row. A household figure missing an account must not be
    /// a stderr footnote.
    #[test]
    fn an_unmappable_record_is_a_hard_error_not_a_skip() {
        let mut no_id = overview("ACCT-XXXX-0001", 1.0);
        no_id.as_object_mut().unwrap().remove("accountId");
        let err = account_row(&no_id).unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("carried no id"));

        let mut no_value = overview("ACCT-XXXX-0001", 1.0);
        no_value
            .as_object_mut()
            .unwrap()
            .remove("accountValueSummary");
        let err = account_row(&no_value).unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("ACCT-XXXX-0001"));
    }

    /// The scoping contract: no explicit selection means **every** account.
    /// This is what keeps the config file's persisted `account` default —
    /// which the dispatcher never passes in — from silently narrowing the
    /// household figure to one account's balance.
    #[test]
    fn no_explicit_selection_keeps_every_account() {
        let all = || vec![row("ACCT-XXXX-0001", "1.00"), row("ACCT-XXXX-0002", "2.00")];
        assert_eq!(scoped(all(), None).unwrap().len(), 2);
        // An explicit selection narrows to exactly that account...
        let one = scoped(all(), Some("ACCT-XXXX-0002")).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].account_number, "ACCT-XXXX-0002");
        // ...and an unknown one is not-found (exit 4), never an empty $0 DTO.
        assert_eq!(
            scoped(all(), Some("ACCT-XXXX-9999"))
                .unwrap_err()
                .exit_code(),
            4
        );
    }

    /// No accounts at all is an upstream surprise, not a $0 household.
    #[test]
    fn an_empty_account_listing_is_a_loud_upstream_error() {
        assert_eq!(scoped(Vec::new(), None).unwrap_err().exit_code(), 5);
    }

    #[test]
    fn the_rollup_sums_accounts_and_omits_absent_liabilities() {
        let nw = rollup(vec![
            row("ACCT-XXXX-0001", "1234.56"),
            row("ACCT-XXXX-0002", "5000.00"),
        ])
        .unwrap();
        assert_eq!(nw.total.amount, "6234.56");
        assert_eq!(nw.assets.amount, "6234.56");
        assert!(
            nw.liabilities.is_none(),
            "no debt renders as absent, not $0"
        );
        assert_eq!(nw.accounts.len(), 2);
    }

    /// An account standing negative is a liability, not a quiet subtraction
    /// from "assets".
    #[test]
    fn a_negative_account_lands_in_liabilities() {
        let nw = rollup(vec![
            row("ACCT-XXXX-0001", "2000.00"),
            row("ACCT-XXXX-0002", "-150.25"),
        ])
        .unwrap();
        assert_eq!(nw.assets.amount, "2000.00");
        assert_eq!(nw.liabilities.as_ref().unwrap().amount, "150.25");
        assert_eq!(nw.total.amount, "1849.75");
    }

    #[test]
    fn an_unparseable_amount_fails_the_rollup_loudly() {
        let err = rollup(vec![row("ACCT-XXXX-0001", "n/a")]).unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("ACCT-XXXX-0001"));
    }

    #[test]
    fn the_dto_serializes_the_family_shape() {
        let nw = rollup(vec![
            row("ACCT-XXXX-0001", "2000.00"),
            row("ACCT-XXXX-0002", "-1.00"),
        ])
        .unwrap();
        let v = serde_json::to_value(&nw).unwrap();
        // `output::emit` adds the schema tag; the payload carries the figures.
        assert_eq!(v["total"]["amount"], "1999.00");
        assert_eq!(v["assets"]["amount"], "2000.00");
        assert_eq!(v["liabilities"]["amount"], "1.00");
        assert_eq!(v["accounts"][0]["account_number"], "ACCT-XXXX-0001");
        assert_eq!(v["accounts"][0]["type"], "PERSONAL_CASH");
        assert_eq!(v["accounts"][0]["total"]["amount"], "2000.00");
    }

    /// `to_cents` accepts exactly the `parse_usd`-normalized shape and
    /// rejects the rest — anything else did not come from this CLI's money
    /// path and must surface as an upstream surprise, not a guess.
    #[test]
    fn to_cents_parses_normalized_amounts_and_rejects_the_rest() {
        assert_eq!(to_cents("1234.56"), Some(123_456));
        assert_eq!(to_cents("0.00"), Some(0));
        assert_eq!(to_cents("-0.05"), Some(-5), "sign survives |v| < 1");
        assert_eq!(to_cents("-250.00"), Some(-25_000));
        assert_eq!(to_cents("12"), None, "parse_usd always emits decimals");
        assert_eq!(to_cents("12.5"), None);
        assert_eq!(to_cents("12.345"), None);
        assert_eq!(to_cents("$12.00"), None);
        assert_eq!(to_cents("n/a"), None);
        assert_eq!(to_cents(""), None);
        assert_eq!(to_cents(".50"), None);
    }
}
