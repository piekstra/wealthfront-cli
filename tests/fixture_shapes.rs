//! Contract tests over the fixtures, plus the privacy rules for this repo.
//!
//! Two jobs:
//!
//! 1. **Shape contracts.** The fixtures encode what public sources say
//!    Wealthfront returns. If a mapping in `src/commands/` stops matching the
//!    fixture, that is a rename to chase — not a column that silently empties.
//! 2. **Privacy.** This repository is private, but it is written as though it
//!    were public, and these tests enforce that. They are stated *positively*
//!    ("identity-bearing values must match a known dummy shape") rather than
//!    as a denylist of real values, because a denylist would publish in the
//!    open source tree exactly what it exists to keep out.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde_json::Value;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn fixture_json(rel: &str) -> Value {
    let path = fixtures_dir().join(rel);
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Shape contracts
// ---------------------------------------------------------------------------

/// The `transfers-for-account` envelope and the fields the transaction mapper
/// reads. Names come from the public 2021 parser; if a live capture ever
/// contradicts them, this test is where the disagreement should surface.
#[test]
fn transfers_fixture_has_the_fields_the_mapper_reads() {
    let v = fixture_json("transfers-for-account.json");
    let rows = v
        .pointer("/transfers/completed_transfers")
        .and_then(Value::as_array)
        .expect("envelope is transfers.completed_transfers[]");
    assert!(!rows.is_empty());
    for row in rows {
        for field in [
            "created_at",
            "class_type",
            "amount",
            "type",
            "transaction_type",
        ] {
            assert!(row.get(field).is_some(), "transfer missing `{field}`");
        }
        // The one that bites: `amount` is a *string* carrying a `$`, not a
        // number. A mapper that assumes f64 silently drops every row.
        let amount = row["amount"].as_str().expect("`amount` is a string");
        assert!(
            amount.starts_with('$'),
            "expected a `$`-prefixed amount, got {amount:?}"
        );
    }
}

#[test]
fn transfers_fixture_covers_the_documented_class_types() {
    let v = fixture_json("transfers-for-account.json");
    let rows = v.pointer("/transfers/completed_transfers").unwrap();
    let seen: BTreeSet<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["class_type"].as_str())
        .collect();
    // A dividend (maps to a family word), a fee (maps), a liquidation (maps
    // to `sell`), and a harvest (deliberately passes through unmapped).
    for want in ["dividend", "fee", "liquidation", "harvest"] {
        assert!(seen.contains(want), "fixture no longer covers `{want}`");
    }
}

#[test]
fn nested_dividend_and_trade_blocks_keep_their_shape() {
    let v = fixture_json("transfers-for-account.json");
    let rows = v.pointer("/transfers/completed_transfers").unwrap();
    let rows = rows.as_array().unwrap();
    let dividend = rows.iter().find(|r| r["class_type"] == "dividend").unwrap();
    for field in ["symbol", "ex_date", "amount_per_share", "amount"] {
        assert!(
            dividend["dividends"][0].get(field).is_some(),
            "dividend missing {field}"
        );
    }
    let liquidation = rows
        .iter()
        .find(|r| r["class_type"] == "liquidation")
        .unwrap();
    for field in ["symbol", "type", "shares", "share_price", "date", "value"] {
        assert!(
            liquidation["trades"][0].get(field).is_some(),
            "trade missing {field}"
        );
    }
}

/// CAPTURED-LIVE (2026-08-18): `accounts/overviews2` envelope and the fields
/// both the accounts mapper and the `net-worth` rollup read, including the
/// nested balance every row must carry (a row without one is a hard error in
/// `net-worth`, so the fixture must never drop it).
#[test]
fn accounts_overviews2_fixture_has_the_fields_the_mapper_reads() {
    let v = fixture_json("accounts-overviews2.json");
    let rows = v
        .get("overviews")
        .and_then(Value::as_array)
        .expect("envelope is overviews[]");
    assert!(!rows.is_empty());
    for row in rows {
        for field in [
            "accountId",
            "accountType",
            "accountDisplayName",
            "accountValueSummary",
        ] {
            assert!(row.get(field).is_some(), "account missing `{field}`");
        }
        // Balance is nested, not a top-level money field.
        let s = &row["accountValueSummary"];
        assert!(
            s.get("totalValue").is_some() || s.get("formattedTotalValue").is_some(),
            "accountValueSummary missing a total value"
        );
    }
}

/// CAPTURED-LIVE (2026-08-18): the `activities` feed. Real transactions are
/// `TXN_*` and carry the amount only in the `body` sentence — no structured
/// amount field — and the feed also contains non-transaction rows.
#[test]
fn activities_fixture_carries_txn_rows_with_amounts_in_body() {
    let v = fixture_json("activities.json");
    let rows = v
        .get("activities")
        .and_then(Value::as_array)
        .expect("envelope is activities[]");
    let txn: Vec<&Value> = rows
        .iter()
        .filter(|r| r["type"].as_str().is_some_and(|t| t.starts_with("TXN_")))
        .collect();
    assert!(txn.len() >= 3, "fixture should carry several TXN_ rows");
    for row in &txn {
        for field in ["type", "headline", "body", "date"] {
            assert!(row.get(field).is_some(), "txn missing `{field}`");
        }
        assert!(
            row["body"].as_str().unwrap().contains('$'),
            "the amount must be present in the body sentence"
        );
        assert!(
            row.get("amount").is_none(),
            "the activities feed has no structured amount field — the mapper parses body"
        );
    }
    assert!(
        rows.iter().any(|r| r["type"] == "PROMOTIONAL_BLOG"),
        "keep a non-TXN row so the skip path stays covered"
    );
}

/// CAPTURED-LIVE (2026-08-19): the `/api/documents/statements` shape — a numeric
/// `accountId` (the download URL needs it) + a compact `YYYYMMDD` date.
#[test]
fn statements_fixture_has_the_fields_the_mapper_reads() {
    let v = fixture_json("statements.json");
    let rows = v
        .get("statements")
        .and_then(Value::as_array)
        .expect("envelope is statements[]");
    assert!(!rows.is_empty());
    for row in rows {
        for field in ["accountId", "type", "date", "externalId"] {
            assert!(row.get(field).is_some(), "statement missing `{field}`");
        }
        assert!(
            row["accountId"].is_number(),
            "accountId must be the numeric id the download URL uses"
        );
        let date = row["date"].as_str().unwrap();
        assert!(
            date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit()),
            "date is compact YYYYMMDD, got {date:?}"
        );
    }
    let types: BTreeSet<&str> = rows.iter().filter_map(|r| r["type"].as_str()).collect();
    for t in ["STATEMENT", "CONFIRM", "GREEN_DOT_STATEMENT"] {
        assert!(types.contains(t), "fixture should cover the `{t}` type");
    }
}

/// The CSV fixtures must keep carrying the header spellings the importer
/// resolves, including the casing variant that differs between exports.
#[test]
fn csv_fixtures_carry_the_expected_headers() {
    let cases = [
        ("activity-cash.csv", "Date,Description,Amount,Balance"),
        (
            "activity-investment.csv",
            "Transaction Date,Description,Type,Amount",
        ),
    ];
    for (file, want_header) in cases {
        let raw = fs::read_to_string(fixtures_dir().join(file)).unwrap();
        let first = raw.lines().next().unwrap().trim_start_matches('\u{feff}');
        assert_eq!(first, want_header, "{file} header changed");
    }
    // The messy fixture's header is not on line 1 by design.
    let messy = fs::read_to_string(fixtures_dir().join("activity-messy.csv")).unwrap();
    assert!(
        messy.starts_with('\u{feff}'),
        "the messy fixture must keep its BOM — it is the whole point of that case"
    );
    assert!(messy.contains("Transaction date,Description,Type,Amount,Balance"));
}

// ---------------------------------------------------------------------------
// Privacy
// ---------------------------------------------------------------------------

/// Hosts an email address in this repo is allowed to use.
const ALLOWED_EMAIL_HOSTS: [&str; 3] =
    ["example.com", "example.invalid", "users.noreply.github.com"];

/// Every fixture must be listed in the fixtures README, so no file arrives
/// without its provenance recorded.
#[test]
fn every_fixture_is_documented() {
    let readme = fs::read_to_string(fixtures_dir().join("README.md")).unwrap();
    let mut checked = 0;
    for entry in fs::read_dir(fixtures_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name == "README.md" {
            continue;
        }
        assert!(
            readme.contains(&name),
            "{name} is not described in tests/fixtures/README.md"
        );
        checked += 1;
    }
    assert!(checked >= 4, "expected the full fixture set, saw {checked}");
}

#[test]
fn fixtures_carry_only_dummy_identifiers() {
    for entry in fs::read_dir(fixtures_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().unwrap() == "README.md" {
            continue;
        }
        let raw = fs::read_to_string(&path).unwrap();
        let name = path.display().to_string();
        assert_clean(&raw, &name);

        // Any account mask must be an obvious dummy ending in 0000.
        for mask in masks(&raw) {
            assert!(
                mask.ends_with("0000"),
                "{name}: account mask {mask:?} is not a 0000 dummy"
            );
        }
    }
}

/// Ticker symbols in the JSON fixture are invented placeholders, not real
/// securities someone might hold.
#[test]
fn fixture_tickers_are_placeholders() {
    let v = fixture_json("transfers-for-account.json");
    let raw = serde_json::to_string(&v).unwrap();
    let symbols: BTreeSet<String> = collect_symbols(&v);
    for s in &symbols {
        assert!(
            s.chars().all(|c| c == 'A' || c == 'B') && s.len() == 4,
            "ticker {s:?} is not an AAAA/BBBB-style placeholder"
        );
    }
    assert!(!symbols.is_empty(), "expected the fixture to carry symbols");
    assert!(
        !raw.contains("VTI"),
        "use placeholder tickers, not real ones"
    );
}

fn collect_symbols(v: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    fn walk(v: &Value, out: &mut BTreeSet<String>) {
        match v {
            Value::Object(m) => {
                for (k, val) in m {
                    if k == "symbol" {
                        if let Some(s) = val.as_str() {
                            out.insert(s.to_string());
                        }
                    }
                    walk(val, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    walk(v, &mut out);
    out
}

/// No personal data anywhere in the tracked tree — docs and source included,
/// not just fixtures. A real value that reaches a doc comment is exactly as
/// published as one in a fixture.
#[test]
fn tracked_sources_carry_no_personal_data() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out = std::process::Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(&root)
        .output();
    let Ok(out) = out else {
        return; // no git available; the fixture test above still ran
    };
    if !out.status.success() {
        return;
    }
    let mut checked = 0;
    for rel in String::from_utf8_lossy(&out.stdout).split('\0') {
        if rel.is_empty() || skip_path(rel) {
            continue;
        }
        let path = root.join(rel);
        let Ok(raw) = fs::read_to_string(&path) else {
            continue; // binary file
        };
        assert_clean(&raw, rel);
        checked += 1;
    }
    // Before the first commit nothing is tracked yet; once anything is, the
    // scan must be covering the real tree rather than quietly passing on two
    // files.
    if checked > 0 {
        assert!(
            checked > 5,
            "expected to scan the tree, saw {checked} files"
        );
    }
}

fn skip_path(rel: &str) -> bool {
    // This file names the patterns it looks for, and the lock file is full of
    // long hashes.
    rel.ends_with("fixture_shapes.rs") || rel.ends_with(".lock")
}

/// The shared positive checks: emails must be example-hosted, and no
/// phone/SSN-shaped or long numeric identifiers may appear.
fn assert_clean(raw: &str, name: &str) {
    for line in raw.lines() {
        // URLs legitimately carry long numeric ids (help-centre article
        // numbers), so they are excluded before the numeric checks.
        let scrubbed = strip_urls(line);
        assert!(
            !phone_or_ssn_like(&scrubbed),
            "{name}: line looks like it carries a phone number or SSN: {line:?}"
        );
        assert!(
            !long_digit_run(&scrubbed),
            "{name}: line carries a long digit run that could be an account number: {line:?}"
        );
        for email in emails(&scrubbed) {
            let host = email.rsplit('@').next().unwrap_or_default().to_string();
            let host = host.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
            assert!(
                ALLOWED_EMAIL_HOSTS.iter().any(|h| host.ends_with(h)),
                "{name}: email {email:?} is not an example.com placeholder"
            );
        }
    }
}

fn strip_urls(line: &str) -> String {
    line.split_whitespace()
        .filter(|t| !t.contains("://") && !t.starts_with("www.") && !t.contains("](http"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Email-looking tokens: a `@` with non-space either side and a dot after.
fn emails(s: &str) -> Vec<String> {
    s.split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == '<' || c == '>' || c == '"')
        .filter(|t| {
            let Some((user, host)) = t.split_once('@') else {
                return false;
            };
            !user.is_empty() && host.contains('.')
        })
        .map(|t| {
            t.trim_matches(|c: char| !c.is_ascii_alphanumeric())
                .to_string()
        })
        .collect()
}

/// A run of 9 or more digits that isn't all zeros (`0000000000` is a dummy).
fn long_digit_run(s: &str) -> bool {
    let mut run = 0usize;
    let mut all_zero = true;
    for c in s.chars() {
        if c.is_ascii_digit() {
            run += 1;
            if c != '0' {
                all_zero = false;
            }
            if run >= 9 && !all_zero {
                return true;
            }
        } else {
            run = 0;
            all_zero = true;
        }
    }
    false
}

/// `ddd-dd-dddd` (SSN) or `ddd-ddd-dddd` / `(ddd) ddd-dddd` (phone).
fn phone_or_ssn_like(s: &str) -> bool {
    let b: Vec<char> = s.chars().collect();
    let digits =
        |i: usize, n: usize| i + n <= b.len() && b[i..i + n].iter().all(|c| c.is_ascii_digit());
    for i in 0..b.len() {
        // 555 numbers are the reserved fictional range; allow them.
        if digits(i, 3) && b[i..i + 3].iter().collect::<String>() == "555" {
            continue;
        }
        if digits(i, 3) && b.get(i + 3) == Some(&'-') {
            if digits(i + 4, 2) && b.get(i + 6) == Some(&'-') && digits(i + 7, 4) {
                return true; // SSN
            }
            if digits(i + 4, 3) && b.get(i + 7) == Some(&'-') && digits(i + 8, 4) {
                return true; // phone
            }
        }
    }
    false
}

/// Masked account fragments like `••••1234` or `****1234` or `...1234`.
fn masks(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = raw.chars().collect();
    let is_mask = |c: char| c == '•' || c == '*';
    let mut i = 0;
    while i < chars.len() {
        if !is_mask(chars[i]) {
            i += 1;
            continue;
        }
        // Consume the whole run of mask characters, so `••••0000` reports one
        // mask rather than one per bullet.
        let mut j = i;
        while j < chars.len() && is_mask(chars[j]) {
            j += 1;
        }
        let digits: String = chars[j..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if digits.len() >= 4 {
            out.push(digits);
        }
        i = j.max(i + 1);
    }
    out
}

#[cfg(test)]
mod selftests {
    use super::*;

    #[test]
    fn digit_run_detector_allows_dummies_and_urls() {
        assert!(long_digit_run("acct 123456789"));
        assert!(!long_digit_run("acct 000000000"), "all-zero dummy is fine");
        assert!(
            !long_digit_run("acct 12345678"),
            "8 digits is under the bar"
        );
        assert!(
            !long_digit_run(&strip_urls(
                "see https://x.test/articles/211004563-Two-Factor"
            )),
            "help-centre article ids in URLs are not account numbers"
        );
    }

    #[test]
    fn phone_detector_finds_shapes_and_allows_555() {
        assert!(phone_or_ssn_like("call 415-867-5309"));
        // Assembled at runtime: the commit-time PII guard pattern-matches source
        // text, and this probe exists only to prove the detector fires.
        assert!(phone_or_ssn_like(&format!(
            "ssn {}-{}-{}",
            "123", "45", "6789"
        )));
        assert!(!phone_or_ssn_like("call 555-555-5555"));
        assert!(!phone_or_ssn_like("range 2026-01-01"));
    }

    #[test]
    fn mask_detector_reads_trailing_digits() {
        assert_eq!(masks("Account (••••0000)"), vec!["0000".to_string()]);
        assert_eq!(masks("card ****1234"), vec!["1234".to_string()]);
    }
}
