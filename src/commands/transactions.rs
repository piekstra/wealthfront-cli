//! `wfr transactions list` — account activity.
//!
//! CAPTURED-LIVE (2026-08-18): `GET /capitan/v1/activities?account_id=…` returns
//! `{"activities": [{type, headline, body, date, id, url, …}]}` — a *display*
//! feed that mixes real transactions (`type` prefixed `TXN_`, e.g.
//! `TXN_DEPOSIT`, `TXN_WITHDRAWAL`, `TXN_INTEREST`) with promotional and invite
//! rows. Non-`TXN_` rows are skipped, so the "dropped" note counts only real
//! transactions.
//!
//! **Amounts are not structured.** The feed carries no amount field; the value
//! is embedded in the `body` sentence ("…in the amount of $12.34."), so we pull
//! it out of the text and apply the account-perspective sign by type (§6): money
//! out — withdrawals, fees — is negative; deposits and interest are positive.
//! Every `TXN_` row observed carried a `$` amount in `body`, but this is text
//! parsing, so a row whose amount can't be read is dropped and counted rather
//! than guessed. For per-lot structured data, `wfr import csv` / a future
//! `import qfx` remain the cleaner source.
//!
//! Emits the same `transaction-list/v1` shape as `wfr import csv`.

use pk_cli_core::{output, CliError, Money, Paged, RangeArgs};
use pk_cli_utility::Transaction;
use serde_json::Value;

use super::{note_dropped, pick_str, records, Ctx};
use crate::client::endpoints;
use crate::commands::import::canonical_kind;
use crate::csv;

const DATE_KEYS: [&str; 3] = ["date", "created_at", "transactionDate"];
const DESC_KEYS: [&str; 3] = ["headline", "description", "body"];

/// Only `TXN_*` activities are transactions; blog/invite rows return `None`.
pub(crate) fn to_transaction(v: &Value) -> Option<Transaction> {
    let ty = pick_str(v, &["type"])?;
    let bare = ty.strip_prefix("TXN_")?; // skip PROMOTIONAL_BLOG, INVITE_*, …
    let raw_date = pick_str(v, &DATE_KEYS)?;
    let head = raw_date.split(['T', ' ']).next().unwrap_or(&raw_date);
    let date = csv::parse_date(head)?;
    let kind = canonical_activity_kind(bare);
    // Amount is in the body sentence; drop (and count) a row we can't read.
    let amount = pick_str(v, &["body"]).and_then(|b| amount_from_text(&b, &kind))?;
    let description = pick_str(v, &DESC_KEYS);
    Some(Transaction {
        date,
        amount,
        description,
        kind: Some(kind),
    })
}

/// `DEPOSIT` → `deposit`, canonicalized against the family vocabulary; an
/// unknown activity word keeps its lowercased self.
fn canonical_activity_kind(bare: &str) -> String {
    let lower = bare.to_ascii_lowercase();
    canonical_kind(&lower).unwrap_or(lower)
}

/// Pull the first `$1,234.56` out of the body sentence, then sign it by kind:
/// money out (withdrawal, fee) negative; everything else positive (§6).
fn amount_from_text(body: &str, kind: &str) -> Option<Money> {
    let start = body.find('$')?;
    let rest = &body[start..];
    let end = rest[1..]
        .find(|c: char| !(c.is_ascii_digit() || c == ',' || c == '.'))
        .map(|i| i + 1)
        .unwrap_or(rest.len());
    // Trim the sentence-ending period ("…$12.34." → "$12.34") before parsing.
    let money = Money::parse_usd(rest[..end].trim_end_matches('.'))?;
    if matches!(kind, "withdrawal" | "fee") {
        // Accounting parentheses parse as negative (Money::parse_usd handles it).
        Money::parse_usd(&format!("({})", money.amount))
    } else {
        Some(money)
    }
}

fn rows_of_response(raw: &Value, path: &str) -> Result<Vec<Value>, CliError> {
    records(
        raw,
        &["activities", "transfers", "transactions"],
        "transaction",
        path,
    )
}

/// One account's activity feed rows, every type: one authenticated read,
/// one envelope unwrap. Shared with the MCP tools.
pub(crate) fn fetch_rows(ctx: &Ctx, account: &str) -> Result<Vec<Value>, CliError> {
    let path = endpoints::ACTIVITIES.replace("{account}", account);
    let raw = ctx.client()?.get_json(&path)?;
    rows_of_response(&raw, &path)
}

/// Whether a feed row is a transaction (`TXN_*`) rather than a blog or
/// invite row.
pub(crate) fn is_transaction_row(row: &Value) -> bool {
    pick_str(row, &["type"]).is_some_and(|t| t.starts_with("TXN_"))
}

pub fn list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    range.validate()?;
    let account = ctx.account_id()?;
    let all_rows = fetch_rows(ctx, account)?;
    // Count only transaction rows, so intentionally-skipped blog rows don't
    // trip the "records dropped" smoke alarm.
    let txn_rows: Vec<&Value> = all_rows.iter().filter(|r| is_transaction_row(r)).collect();
    let mut items: Vec<Transaction> = txn_rows.iter().filter_map(|v| to_transaction(v)).collect();
    note_dropped(ctx.quiet, "transaction", txn_rows.len(), items.len());

    if let Some(since) = &range.since {
        items.retain(|t| t.date.as_str() >= since.as_str());
    }
    if let Some(until) = &range.until {
        items.retain(|t| t.date.as_str() <= until.as_str());
    }
    let total = items.len() as u64;
    if let Some(n) = range.limit {
        items.truncate(n as usize);
    }

    let mut paged = Paged::new("transaction", items);
    paged.total = Some(total);
    if ctx.json {
        output::json(&serde_json::to_value(&paged).unwrap_or_default());
    } else {
        let v = serde_json::to_value(&paged).unwrap_or_default();
        let rows = output::rows_of(&v, "items");
        output::table(&output::table_view(
            &rows,
            &["date", "amount", "kind", "description"],
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_a_txn_deposit_with_amount_from_body() {
        let v = json!({
            "type": "TXN_DEPOSIT",
            "headline": "Deposit",
            "body": "We received your deposit in the amount of $1,250.00.",
            "date": "2026-01-05"
        });
        let t = to_transaction(&v).unwrap();
        assert_eq!(t.date, "2026-01-05");
        assert_eq!(t.amount.amount, "1250.00", "amount parsed out of the body");
        assert_eq!(t.kind.as_deref(), Some("deposit"));
    }

    #[test]
    fn withdrawal_amount_is_negative() {
        let v = json!({
            "type": "TXN_WITHDRAWAL",
            "headline": "Withdrawal",
            "body": "We completed your withdrawal in the amount of $40.00.",
            "date": "2026-02-01"
        });
        let t = to_transaction(&v).unwrap();
        assert_eq!(t.kind.as_deref(), Some("withdrawal"));
        assert_eq!(
            t.amount.amount, "-40.00",
            "money out is negative (account view)"
        );
    }

    #[test]
    fn interest_is_positive() {
        let v = json!({
            "type": "TXN_INTEREST",
            "headline": "Interest",
            "body": "You received interest in the amount of $0.15.",
            "date": "2026-02-28"
        });
        assert_eq!(to_transaction(&v).unwrap().amount.amount, "0.15");
    }

    #[test]
    fn non_transaction_feed_rows_are_skipped() {
        assert!(to_transaction(&json!({
            "type": "PROMOTIONAL_BLOG", "headline": "Read this", "body": "no money here", "date": "2026-01-01"
        }))
        .is_none());
        assert!(
            to_transaction(&json!({ "type": "INVITE_SIGNUP", "date": "2026-01-01" })).is_none()
        );
    }

    #[test]
    fn finds_the_activities_envelope() {
        let raw = json!({ "activities": [
            { "type": "TXN_INTEREST", "headline": "Interest", "body": "interest of $1.00.", "date": "2026-01-01" }
        ] });
        assert_eq!(rows_of_response(&raw, "/x").unwrap().len(), 1);
    }

    #[test]
    fn unrecognized_envelope_errors_rather_than_reporting_no_activity() {
        let err = rows_of_response(&json!({ "surprise": {} }), "/x").unwrap_err();
        assert!(matches!(err, CliError::Upstream(_)));
    }
}
