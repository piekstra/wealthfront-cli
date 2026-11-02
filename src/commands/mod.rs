//! Command implementations, plus the tolerant JSON field-picking the
//! reverse-engineered reads depend on.
//!
//! Because no capture pins Wealthfront's response shapes (see `docs/api.md`),
//! every read below resolves its fields through [`pick`] against a list of
//! plausible key spellings. Two rules keep that from becoming a lie:
//!
//! 1. A field that cannot be resolved is **omitted**, per the family's
//!    omit-don't-null rule — never defaulted to an empty string.
//! 2. A response whose *records* cannot be located at all is a hard
//!    [`CliError::Upstream`] naming the passthrough command to run, rather
//!    than an empty list. An empty table is indistinguishable from "you have
//!    no accounts", which is exactly the silent failure this CLI must not ship.

pub mod accounts;
pub mod auth;
pub mod documents;
pub mod import;
pub mod networth;
pub mod overviews;
pub mod transactions;

use pk_cli_core::{CliError, Money};
use pk_cli_secrets::CredentialStore;
use serde_json::Value;

use crate::client::Wf;

/// Shared state for authenticated commands.
pub struct Ctx {
    pub creds: CredentialStore,
    pub json: bool,
    pub quiet: bool,
    pub account: Option<String>,
}

impl Ctx {
    /// A client backed by the cached session.
    ///
    /// There is deliberately **no automatic re-login**. Wealthfront's second
    /// factor cannot be automated, so a background re-auth would either hang
    /// waiting for a code or burn one without the user asking. An expired
    /// session is an error telling the user to log in, and that is the whole
    /// policy.
    pub fn client(&self) -> Result<Wf, CliError> {
        Wf::from_cached_session(&self.creds)
    }

    /// The account to act on: `--account`, else config, else an error naming
    /// how to discover one.
    pub fn account_id(&self) -> Result<&str, CliError> {
        self.account.as_deref().ok_or_else(|| {
            CliError::Usage(
                "no account selected — pass `-a <ID>`, or run `wfr config set account <ID>` \
                 (list them with `wfr accounts list`)"
                    .into(),
            )
        })
    }
}

/// Warn when the mapper silently dropped records.
///
/// Dropping a record is the right behavior — a row with no id or no date
/// cannot become a DTO — but doing it *quietly* is how an unverified mapping
/// turns "47 transactions" into "3 transactions" and nobody notices. While
/// the response shapes remain UNVERIFIED-LIVE this is the CLI's own smoke
/// alarm, and the number it prints is the first thing to chase.
pub fn note_dropped(quiet: bool, noun: &str, raw: usize, mapped: usize) {
    if quiet || mapped >= raw {
        return;
    }
    eprintln!(
        "note: {} of {raw} {noun} record(s) did not match any known field spelling and were \
         skipped — the mapping is UNVERIFIED-LIVE; compare `wfr api GET <path>` against \
         src/commands/{noun}s.rs",
        raw - mapped
    );
}

/// First present key from `keys`.
pub fn pick<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|k| v.get(*k).filter(|x| !x.is_null()))
}

/// First *usable* key as a trimmed non-empty string. Numbers are accepted and
/// stringified, because providers routinely change an id from `12345` to
/// `"12345"` between endpoints.
///
/// Note "usable", not "present": the fallback continues past a key that
/// exists but holds `""` or `null`. Providers emit an empty string far more
/// often than they omit the field, so stopping at the first *present* key
/// would let `{"name": "", "displayName": "Cash"}` resolve to nothing — the
/// fallback list would be decorative.
pub fn pick_str(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| {
        let s = match v.get(*k)? {
            Value::String(s) => s.trim().to_string(),
            Value::Number(n) => n.to_string(),
            _ => return None,
        };
        (!s.is_empty()).then_some(s)
    })
}

/// First usable key as [`Money`], accepting a bare number, a decimal string
/// (including a `$` prefix), or a nested `{amount, currency}` object.
///
/// Same fall-through rule as [`pick_str`]: a key holding an unparseable value
/// does not stop the search.
pub fn pick_money(v: &Value, keys: &[&str]) -> Option<Money> {
    keys.iter().find_map(|k| match v.get(*k)? {
        Value::Number(n) => Money::parse_usd(&n.to_string()),
        Value::String(s) => Money::parse_usd(s),
        obj @ Value::Object(_) => match pick(obj, &["amount", "value"])? {
            Value::Number(n) => Money::parse_usd(&n.to_string()),
            Value::String(s) => Money::parse_usd(s),
            _ => None,
        },
        _ => None,
    })
}

/// Locate the record array in a response whose envelope is unknown.
///
/// Tries the common envelope keys, then the bare array. Returns an error —
/// never an empty vec — when nothing matches, so a shape change surfaces as a
/// loud failure instead of a plausible-looking empty result.
pub fn records(v: &Value, keys: &[&str], what: &str, probe: &str) -> Result<Vec<Value>, CliError> {
    if let Some(arr) = v.as_array() {
        return Ok(arr.clone());
    }
    for k in keys
        .iter()
        .chain(["items", "data", "results", "content"].iter())
    {
        if let Some(arr) = v.get(*k).and_then(Value::as_array) {
            return Ok(arr.clone());
        }
    }
    Err(CliError::Upstream(format!(
        "could not find the {what} list in Wealthfront's response — the shape is UNVERIFIED-LIVE. \
         Inspect it with `wfr api GET {probe}` and correct the mapping in src/commands/."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pick_str_takes_the_first_present_key() {
        let v = json!({ "displayName": "Cash", "name": "" });
        assert_eq!(
            pick_str(&v, &["name", "displayName"]).as_deref(),
            Some("Cash")
        );
    }

    #[test]
    fn pick_str_stringifies_numeric_ids() {
        let v = json!({ "id": 12345 });
        assert_eq!(pick_str(&v, &["id"]).as_deref(), Some("12345"));
    }

    #[test]
    fn pick_str_skips_null_and_blank() {
        let v = json!({ "a": null, "b": "   ", "c": "ok" });
        assert_eq!(pick_str(&v, &["a", "b", "c"]).as_deref(), Some("ok"));
    }

    #[test]
    fn pick_money_falls_through_an_unparseable_value() {
        let v = json!({ "amount": "n/a", "value": "$12.00" });
        assert_eq!(
            pick_money(&v, &["amount", "value"]).unwrap().amount,
            "12.00"
        );
    }

    #[test]
    fn pick_money_accepts_the_three_shapes() {
        assert_eq!(
            pick_money(&json!({ "b": 1234.5 }), &["b"]).unwrap().amount,
            "1234.50"
        );
        assert_eq!(
            pick_money(&json!({ "b": "$1,234.50" }), &["b"])
                .unwrap()
                .amount,
            "1234.50"
        );
        assert_eq!(
            pick_money(
                &json!({ "b": { "amount": "10.00", "currency": "USD" } }),
                &["b"]
            )
            .unwrap()
            .amount,
            "10.00"
        );
    }

    #[test]
    fn records_finds_common_envelopes_and_bare_arrays() {
        let probe = "/api/accounts";
        assert_eq!(
            records(&json!([{ "id": 1 }]), &["accounts"], "account", probe)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            records(
                &json!({ "accounts": [{ "id": 1 }] }),
                &["accounts"],
                "account",
                probe
            )
            .unwrap()
            .len(),
            1
        );
        assert_eq!(
            records(
                &json!({ "items": [{ "id": 1 }] }),
                &["accounts"],
                "account",
                probe
            )
            .unwrap()
            .len(),
            1
        );
    }

    #[test]
    fn records_errors_rather_than_returning_empty() {
        // The important one: an unrecognized envelope must not look like
        // "you have no accounts".
        let err = records(
            &json!({ "surprise": {} }),
            &["accounts"],
            "account",
            "/api/accounts",
        )
        .unwrap_err();
        assert!(matches!(err, CliError::Upstream(_)));
        assert!(err.to_string().contains("UNVERIFIED-LIVE"));
    }
}
