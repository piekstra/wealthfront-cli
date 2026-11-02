//! `wfr import csv <FILE>` — turn a Wealthfront activity CSV export into the
//! family transaction DTO (`transaction-list/v1`).
//!
//! This is the one command in this CLI that is verified end to end offline:
//! it needs no credential, no network, and no live session, so its behavior is
//! pinned by fixtures rather than asserted from a capture. Everything the
//! reverse-engineered HTTP surface cannot promise, this can.
//!
//! Two conventions are worth stating up front because both are easy to get
//! silently wrong:
//!
//! **Sign is account-perspective, passed through unchanged.** Money into the
//! account (deposits, dividends, interest) is positive; money out (withdrawals,
//! fees) is negative — exactly as the export writes it. Note this is the
//! *opposite* of the `utility/v1` reading of [`Transaction`], where a charge
//! you owe is positive. Inverting it here would be defensible for a bill but
//! nonsense for a brokerage account, so the export's own convention wins and
//! is documented rather than "corrected". See `docs/api.md`.
//!
//! **`Balance` is deliberately dropped.** The export's running balance is a
//! property of the statement's ordering, not of the transaction, and the
//! family `Transaction` has no field for it. Keeping it would mean emitting a
//! number that goes wrong the moment a caller filters or sorts the list.

use clap::Args;
use pk_cli_core::{output, CliError, Paged, RangeArgs};
use pk_cli_utility::Transaction;

use crate::csv;

#[derive(Args, Debug)]
pub struct ImportCsvArgs {
    /// Path to the activity CSV export, or `-` to read stdin.
    #[arg(value_name = "FILE")]
    pub file: String,

    #[command(flatten)]
    pub range: RangeArgs,

    /// Only rows of this kind (e.g. `dividend`, `interest`, `fee`).
    #[arg(long, value_name = "KIND")]
    pub kind: Option<String>,

    /// Fail on the first unimportable row instead of skipping it.
    #[arg(long)]
    pub strict: bool,
}

/// Where each field lives in the export's header row.
#[derive(Debug, PartialEq)]
struct Columns {
    date: usize,
    amount: usize,
    description: Option<usize>,
    kind: Option<usize>,
}

/// Header spellings seen across the cash and investment exports, in
/// preference order. The export is not consistent between account types, and
/// has shipped both `Transaction date` and `Transaction Date`, so matching is
/// case- and whitespace-insensitive (see [`csv::norm_header`]).
const DATE_HEADERS: [&str; 5] = [
    "date",
    "transaction date",
    "trade date",
    "post date",
    "settlement date",
];
const DESC_HEADERS: [&str; 4] = ["description", "transaction", "details", "memo"];
const KIND_HEADERS: [&str; 3] = ["type", "transaction type", "category"];

/// Locate the header row and resolve column positions.
///
/// Scans the first records rather than assuming line 1, because exports that
/// have been through a spreadsheet often carry a title or an account label
/// above the real header. A row qualifies as the header when it names both a
/// date and an amount column — the two fields a [`Transaction`] cannot be
/// built without.
fn find_header(records: &[Vec<String>]) -> Option<(usize, Columns)> {
    for (i, record) in records.iter().take(25).enumerate() {
        if csv::is_blank(record) {
            continue;
        }
        let headers: Vec<String> = record.iter().map(|h| csv::norm_header(h)).collect();
        let find = |names: &[&str]| {
            names
                .iter()
                .find_map(|want| headers.iter().position(|h| h == want))
        };
        let (Some(date), Some(amount)) = (find(&DATE_HEADERS), find(&["amount"])) else {
            continue;
        };
        return Some((
            i,
            Columns {
                date,
                amount,
                description: find(&DESC_HEADERS),
                kind: find(&KIND_HEADERS),
            },
        ));
    }
    None
}

/// Canonicalize the activity type into a small family vocabulary, falling
/// back to the provider's own wording.
///
/// Unrecognized types **pass through** (lowercased) rather than becoming
/// `other`. A closed set would quietly collapse activity this CLI has never
/// seen — and since the whole point of importing is tax categorization, losing
/// the distinction between an unknown credit and a dividend is the expensive
/// failure. Callers can therefore see a `kind` this code has no opinion about.
///
/// Wealthfront's own `class_type` vocabulary includes `harvest` (tax-loss
/// harvesting), `index-optimization` and `other-investment`, none of which map
/// onto a family word. Those pass through verbatim on purpose: `harvest` in
/// particular is precisely the row a tax workflow is looking for, and
/// flattening it to `sell` would hide it.
///
/// Shared with the live `transactions list` path so `--kind dividend` means
/// the same thing whichever surface produced the list.
pub fn canonical_kind(raw: &str) -> Option<String> {
    let s = csv::norm_header(raw);
    if s.is_empty() {
        return None;
    }
    // Order matters: the first match wins, so more specific words lead.
    // "Dividend Reinvestment" is dividend income before it is a purchase.
    const RULES: [(&str, &str); 13] = [
        ("dividend", "dividend"),
        ("interest", "interest"),
        ("advisory", "fee"),
        ("fee", "fee"),
        ("deposit", "deposit"),
        ("funding", "deposit"),
        ("withdraw", "withdrawal"),
        ("transfer", "transfer"),
        ("purchase", "buy"),
        ("buy", "buy"),
        ("liquidation", "sell"),
        ("sale", "sell"),
        ("sell", "sell"),
    ];
    for (needle, canon) in RULES {
        if s.contains(needle) {
            return Some(canon.to_string());
        }
    }
    Some(s)
}

/// Why a row was not importable, for the skip report.
struct Skip {
    line: usize,
    reason: String,
}

/// Parse the whole document into transactions, plus the rows that could not
/// be made into one.
fn rows(
    records: &[Vec<String>],
    header_at: usize,
    cols: &Columns,
) -> (Vec<Transaction>, Vec<Skip>) {
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    for (offset, record) in records.iter().enumerate().skip(header_at + 1) {
        // Line numbers are 1-based and counted in records, which is what a
        // reader sees when the file has no embedded newlines; a quoted
        // multi-line cell makes this an approximation, so the message says
        // "row" rather than claiming a file line.
        let line = offset + 1;
        if csv::is_blank(record) {
            continue;
        }
        // Short rows are normal: exports drop trailing empty cells.
        let cell = |i: usize| record.get(i).map(String::as_str).unwrap_or("").trim();

        let Some(date) = csv::parse_date(cell(cols.date)) else {
            // A row without a parseable date is a section header, a totals
            // footer, or junk — never a transaction. Counted, not fatal.
            skipped.push(Skip {
                line,
                reason: format!("no usable date in {:?}", cell(cols.date)),
            });
            continue;
        };
        let Some(amount) = csv::parse_amount(cell(cols.amount)) else {
            skipped.push(Skip {
                line,
                reason: format!("no usable amount in {:?}", cell(cols.amount)),
            });
            continue;
        };
        let description = cols
            .description
            .map(cell)
            .filter(|d| !d.is_empty())
            .map(str::to_string);
        // Prefer the declared type; infer from the description only when the
        // export carries no type column at all.
        let kind = cols
            .kind
            .map(cell)
            .and_then(canonical_kind)
            .or_else(|| description.as_deref().and_then(inferred_kind));

        items.push(Transaction {
            date,
            amount,
            description,
            kind,
        });
    }
    (items, skipped)
}

/// Best-effort kind for exports with no `Type` column: match the same
/// vocabulary against the description, and stay silent when nothing matches
/// rather than guessing.
fn inferred_kind(description: &str) -> Option<String> {
    let canon = canonical_kind(description)?;
    // `canonical_kind` passes unknown text through verbatim; for a free-text
    // description that would put the whole memo line in `kind`, so only keep
    // it when it actually landed on a known word.
    const KNOWN: [&str; 8] = [
        "dividend",
        "interest",
        "fee",
        "deposit",
        "withdrawal",
        "transfer",
        "buy",
        "sell",
    ];
    KNOWN.contains(&canon.as_str()).then_some(canon)
}

pub fn run(args: &ImportCsvArgs, json: bool, quiet: bool) -> Result<(), CliError> {
    // Validate before touching the filesystem, so bad flags never depend on
    // the file existing.
    args.range.validate()?;

    let raw = if args.file == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| CliError::Usage(format!("reading stdin: {e}")))?;
        buf
    } else {
        std::fs::read_to_string(&args.file).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                CliError::NotFound(format!("no such file: {}", args.file))
            }
            _ => CliError::Usage(format!("reading {}: {e}", args.file)),
        })?
    };

    let records = csv::parse(&raw);
    let Some((header_at, cols)) = find_header(&records) else {
        return Err(CliError::Usage(format!(
            "{} does not look like a Wealthfront activity export: no header row with a date \
             column and an `Amount` column in the first 25 rows",
            if args.file == "-" {
                "stdin"
            } else {
                &args.file
            }
        )));
    };

    let (mut items, skipped) = rows(&records, header_at, &cols);

    if args.strict {
        if let Some(first) = skipped.first() {
            return Err(CliError::Usage(format!(
                "row {}: {} (--strict)",
                first.line, first.reason
            )));
        }
    }

    // Filters, then the limit slice — so `--limit` counts what the caller
    // asked for, not what was read.
    if let Some(want) = &args.kind {
        let want = want.to_ascii_lowercase();
        items.retain(|t| t.kind.as_deref() == Some(want.as_str()));
    }
    if let Some(since) = &args.range.since {
        items.retain(|t| t.date.as_str() >= since.as_str());
    }
    if let Some(until) = &args.range.until {
        items.retain(|t| t.date.as_str() <= until.as_str());
    }

    let total = items.len() as u64;
    if let Some(n) = args.range.limit {
        items.truncate(n as usize);
    }

    if !quiet && !skipped.is_empty() {
        // Diagnostics on stderr only — stdout stays a single clean DTO.
        eprintln!(
            "skipped {} row(s) that are not transactions (e.g. row {}: {})",
            skipped.len(),
            skipped[0].line,
            skipped[0].reason
        );
    }

    let mut paged = Paged::new("transaction", items);
    paged.total = Some(total);
    if json {
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

    fn cols_of(doc: &str) -> Option<(usize, Columns)> {
        find_header(&csv::parse(doc))
    }

    #[test]
    fn finds_a_plain_header() {
        let (at, cols) = cols_of("Date,Description,Amount,Balance\n").unwrap();
        assert_eq!(at, 0);
        assert_eq!(cols.date, 0);
        assert_eq!(cols.description, Some(1));
        assert_eq!(cols.amount, 2);
        assert_eq!(cols.kind, None);
    }

    #[test]
    fn finds_a_header_under_a_preamble() {
        let doc = "Wealthfront Activity Export\n\nTransaction Date,Description,Type,Amount\n";
        let (at, cols) = cols_of(doc).unwrap();
        assert_eq!(at, 2, "header is the third record, not the first");
        assert_eq!(cols.kind, Some(2));
        assert_eq!(cols.amount, 3);
    }

    #[test]
    fn header_match_is_case_insensitive() {
        // The bug this guards: `Transaction Date` vs `Transaction date`
        // parsing fine and then reporting every row as missing a date.
        let (_, cols) = cols_of("TRANSACTION DATE,DESCRIPTION,AMOUNT\n").unwrap();
        assert_eq!(cols.date, 0);
        assert_eq!(cols.amount, 2);
    }

    #[test]
    fn rejects_a_file_with_no_amount_column() {
        assert!(cols_of("Date,Description,Balance\n").is_none());
    }

    #[test]
    fn kind_canonicalizes_known_types_and_passes_others_through() {
        assert_eq!(canonical_kind("Dividend").as_deref(), Some("dividend"));
        assert_eq!(
            canonical_kind("Dividend Reinvestment").as_deref(),
            Some("dividend"),
            "reinvested dividends are dividend income first"
        );
        assert_eq!(canonical_kind("Advisory Fee").as_deref(), Some("fee"));
        assert_eq!(
            canonical_kind("  WITHDRAWAL ").as_deref(),
            Some("withdrawal")
        );
        assert_eq!(
            canonical_kind("Tax Withholding").as_deref(),
            Some("tax withholding"),
            "unknown types keep the provider's own wording"
        );
        assert_eq!(canonical_kind("   ").as_deref(), None);
    }

    #[test]
    fn inferred_kind_only_fires_on_known_words() {
        assert_eq!(
            inferred_kind("Monthly interest payment").as_deref(),
            Some("interest")
        );
        assert_eq!(
            inferred_kind("Something entirely unrelated"),
            None,
            "a free-text memo must not become the kind"
        );
    }

    #[test]
    fn rows_skip_non_transactions_without_failing() {
        let doc = "Date,Description,Amount\n\
                   2026-01-05,Deposit,100.00\n\
                   ,Total,100.00\n\
                   Ending Balance,,\n";
        let records = csv::parse(doc);
        let (at, cols) = find_header(&records).unwrap();
        let (items, skipped) = rows(&records, at, &cols);
        assert_eq!(items.len(), 1);
        assert_eq!(skipped.len(), 2, "totals and balance footers are skipped");
    }

    #[test]
    fn amount_sign_is_passed_through_from_the_export() {
        let doc = "Date,Description,Type,Amount\n\
                   2026-01-05,Deposit,Deposit,250.00\n\
                   2026-01-31,Advisory fee,Fee,-1.42\n";
        let records = csv::parse(doc);
        let (at, cols) = find_header(&records).unwrap();
        let (items, _) = rows(&records, at, &cols);
        assert_eq!(items[0].amount.amount, "250.00", "money in stays positive");
        assert_eq!(items[1].amount.amount, "-1.42", "money out stays negative");
        assert_eq!(items[1].kind.as_deref(), Some("fee"));
    }
}
