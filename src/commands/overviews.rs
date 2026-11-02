//! The shared `/capitan/v1/accounts/overviews2` reading, in one place.
//!
//! Both `accounts list|get` and `net-worth` are views over the same
//! CAPTURED-LIVE (2026-08-18) endpoint —
//! `{"overviews": [{accountId, accountType, accountDisplayName,
//! accountValueSummary: {totalValue, formattedTotalValue, …}, …}]}` — and
//! they must never disagree about **which accounts exist** or **how each
//! field is read**. So the envelope unwrap and the per-record field readers
//! live here, owned once; each command keeps only its own mapping *policy*
//! (skip-and-note for the inventory listing, hard error for the household
//! rollup), which is the part that legitimately differs.

use pk_cli_core::{CliError, Money};
use serde_json::Value;

use super::{pick_money, pick_str, records, Ctx};
use crate::client::endpoints;

/// Key spellings to try, widest plausible set first. Recorded here rather than
/// inline so a live capture can be diffed against them.
const ID_KEYS: [&str; 4] = ["accountId", "id", "account_id", "externalId"];
const NAME_KEYS: [&str; 5] = [
    "accountDisplayName",
    "name",
    "displayName",
    "nickname",
    "accountTypeDisplayName",
];
const KIND_KEYS: [&str; 5] = [
    "accountType",
    "accountTypeDisplayName",
    "type",
    "category",
    "productType",
];
/// Inside `accountValueSummary`: the formatted string first (carries `$` and
/// commas that `Money::parse_usd` handles), the raw number second.
const VALUE_SUMMARY_KEYS: [&str; 2] = ["formattedTotalValue", "totalValue"];
/// Top-level fallbacks, if a record ever lacks `accountValueSummary`.
const BALANCE_KEYS: [&str; 4] = ["balance", "totalValue", "value", "marketValue"];

/// Fetch the account records: one authenticated read, one envelope unwrap.
pub(crate) fn fetch_records(ctx: &Ctx) -> Result<Vec<Value>, CliError> {
    unwrap_records(&ctx.client()?.get_json(endpoints::ACCOUNTS)?)
}

/// Unwrap the `overviews[]` envelope. Pure, so the envelope contract is
/// pinned offline by the fixture tests; an unrecognized envelope is a loud
/// error (via [`records`]), never an empty account list.
pub(crate) fn unwrap_records(raw: &Value) -> Result<Vec<Value>, CliError> {
    records(
        raw,
        &["overviews", "accounts"],
        "account",
        endpoints::ACCOUNTS,
    )
}

/// The account id.
pub(crate) fn id_of(v: &Value) -> Option<String> {
    pick_str(v, &ID_KEYS)
}

/// The human-facing account name.
pub(crate) fn name_of(v: &Value) -> Option<String> {
    pick_str(v, &NAME_KEYS)
}

/// The provider's own account type (`PERSONAL_CASH`, `TAXABLE_INVESTMENT`, …),
/// passed through verbatim.
pub(crate) fn kind_of(v: &Value) -> Option<String> {
    pick_str(v, &KIND_KEYS)
}

/// The account's current value: the nested `accountValueSummary` first, then a
/// top-level money field for robustness.
pub(crate) fn balance_of(v: &Value) -> Option<Money> {
    v.get("accountValueSummary")
        .and_then(|s| pick_money(s, &VALUE_SUMMARY_KEYS))
        .or_else(|| pick_money(v, &BALANCE_KEYS))
}
