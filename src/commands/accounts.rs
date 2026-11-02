//! `wfr accounts list|get` — the account inventory.
//!
//! A view over the shared `overviews2` reading (`super::overviews`), which
//! owns the endpoint, envelope, and field readers — see that module. This
//! command's own policy: a record that fails to map is skipped and counted
//! on stderr (`note_dropped`), because an inventory listing degrades
//! gracefully; the `net-worth` rollup over the same reading does not.

use pk_cli_core::{output, CliError, Money, Paged, RangeArgs};
use serde::Serialize;
use serde_json::Value;

use super::{note_dropped, overviews, Ctx};

/// One Wealthfront account (`account/v1`).
///
/// Provider-shaped rather than a family profile: there is no `accounts`
/// domain profile, and inventing one from a single unverified provider would
/// fail the PROFILES.md bar on every count.
#[derive(Debug, Serialize)]
pub struct Account {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<Money>,
}

fn to_account(v: &Value) -> Option<Account> {
    let id = overviews::id_of(v)?;
    // A nameless account still lists — falling back to the id beats dropping
    // the row, since the id is what every other command needs.
    let name = overviews::name_of(v).unwrap_or_else(|| id.clone());
    Some(Account {
        id,
        name,
        kind: overviews::kind_of(v),
        balance: overviews::balance_of(v),
    })
}

fn fetch(ctx: &Ctx) -> Result<Vec<Account>, CliError> {
    let rows = overviews::fetch_records(ctx)?;
    let mapped: Vec<Account> = rows.iter().filter_map(to_account).collect();
    note_dropped(ctx.quiet, "account", rows.len(), mapped.len());
    Ok(mapped)
}

pub fn list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    range.validate()?;
    let mut items = fetch(ctx)?;
    let total = items.len() as u64;
    if let Some(n) = range.limit {
        items.truncate(n as usize);
    }
    let mut paged = Paged::new("account", items);
    paged.total = Some(total);
    if ctx.json {
        output::json(&serde_json::to_value(&paged).unwrap_or_default());
    } else {
        let v = serde_json::to_value(&paged).unwrap_or_default();
        let rows = output::rows_of(&v, "items");
        output::table(&output::table_view(
            &rows,
            &["id", "name", "kind", "balance"],
        ));
    }
    Ok(())
}

pub fn get(ctx: &Ctx, id: &str) -> Result<(), CliError> {
    let found = fetch(ctx)?
        .into_iter()
        .find(|a| a.id == id)
        .ok_or_else(|| CliError::NotFound(format!("no account with id `{id}`")))?;
    let v = serde_json::to_value(&found).unwrap_or_default();
    if ctx.json {
        output::json(&v);
    } else {
        output::kv(&v, 0);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_a_plausible_account_record() {
        let v = json!({
            "id": "acct-0000",
            "displayName": "Individual Investment",
            "accountType": "TAXABLE_INVESTMENT",
            "totalValue": 1234.5
        });
        let a = to_account(&v).unwrap();
        assert_eq!(a.id, "acct-0000");
        assert_eq!(a.name, "Individual Investment");
        assert_eq!(a.kind.as_deref(), Some("TAXABLE_INVESTMENT"));
        assert_eq!(a.balance.unwrap().amount, "1234.50");
    }

    #[test]
    fn maps_the_captured_overviews2_shape() {
        // Field names and nesting from the 2026-08-18 live capture.
        let v = json!({
            "accountId": "acct-XXXX",
            "accountType": "TAXABLE_INVESTMENT",
            "accountTypeDisplayName": "Individual",
            "accountDisplayName": "My Investing",
            "accountValueSummary": {
                "totalValue": 100.0,
                "formattedTotalValue": "$1,234.56"
            }
        });
        let a = to_account(&v).unwrap();
        assert_eq!(a.id, "acct-XXXX");
        assert_eq!(a.name, "My Investing", "accountDisplayName wins");
        assert_eq!(a.kind.as_deref(), Some("TAXABLE_INVESTMENT"));
        assert_eq!(
            a.balance.unwrap().amount,
            "1234.56",
            "balance comes from accountValueSummary.formattedTotalValue"
        );
    }

    #[test]
    fn account_without_an_id_is_dropped_not_faked() {
        assert!(to_account(&json!({ "displayName": "Nameless" })).is_none());
    }

    #[test]
    fn missing_optional_fields_are_omitted_not_nulled() {
        let a = to_account(&json!({ "id": "x" })).unwrap();
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["name"], "x", "name falls back to the id");
        assert!(v.get("kind").is_none());
        assert!(v.get("balance").is_none());
    }
}
