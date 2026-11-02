//! A small, total RFC 4180 CSV reader plus the field normalizers the
//! Wealthfront activity export needs.
//!
//! Why hand-rolled rather than a CSV crate: the family style keeps parsing
//! dependency-free and total (see `pk-cli-scrape` for the same choice on the
//! HTML side), and the whole grammar is a 40-line state machine. Nothing here
//! panics or allocates unboundedly on hostile input — a truncated quote yields
//! the fields parsed so far rather than an error, because a half-written
//! export should still import the rows that are intact.
//!
//! The normalizers exist because the export is looser than it looks: amounts
//! arrive with currency symbols, thousands separators, accounting parentheses
//! and (from some spreadsheet round-trips) trailing minus signs; dates arrive
//! in at least four shapes. Both delegate to `pk_cli_core` where a helper
//! already exists and only extend it where the export needs more.

use pk_cli_core::{dates, dates::Civil, Money};

/// Parse a CSV document into records of fields.
///
/// Handles quoted fields, `""` escapes, embedded commas and newlines, and
/// CRLF or LF line endings. A leading UTF-8 BOM is stripped — Wealthfront's
/// export carries one often enough that not handling it is the single most
/// likely cause of a "file has no Date column" report, because the BOM binds
/// to the first header cell and renames `Date` to `\u{feff}Date`.
pub fn parse(input: &str) -> Vec<Vec<String>> {
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();
    // True once the current record has seen any character at all, so a
    // trailing newline at end of file doesn't manufacture a phantom record.
    let mut started = false;

    while let Some(c) = chars.next() {
        started = true;
        if in_quotes {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => in_quotes = false,
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.trim().is_empty() => {
                // Opening quote. Anything already in `field` is leading
                // whitespace, which the export sometimes emits before a
                // quoted cell; drop it rather than smuggling it inside.
                field.clear();
                in_quotes = true;
            }
            '"' => field.push('"'),
            ',' => record.push(std::mem::take(&mut field)),
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
                started = false;
            }
            '\n' => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
                started = false;
            }
            _ => field.push(c),
        }
    }
    if started || !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    records
}

/// True when a record carries no data at all — every cell blank.
///
/// Blank records are structural noise (spreadsheet round-trips leave them
/// between sections), not rows worth reporting as errors.
pub fn is_blank(record: &[String]) -> bool {
    record.iter().all(|f| f.trim().is_empty())
}

/// Normalize a header cell for matching: trim, strip a stray BOM, casefold,
/// and collapse internal whitespace.
///
/// Case-insensitivity is load-bearing. The export has shipped both
/// `Transaction date` and `Transaction Date`; matching one spelling exactly
/// means the other parses its header fine and then reports every single row
/// as "missing date", which reads like a corrupt file rather than a casing
/// mismatch.
pub fn norm_header(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('\u{feff}')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// Parse a Wealthfront amount cell into [`Money`].
///
/// Delegates the bulk to [`Money::parse_usd`] (currency symbols, thousands
/// separators, accounting parentheses) and only pre-normalizes the one shape
/// it does not cover: a trailing minus, `12.34-`, which spreadsheet exports
/// produce and which would otherwise silently import as a **positive** number
/// — a sign error that survives all the way into a tax total.
pub fn parse_amount(raw: &str) -> Option<Money> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let s = s
        .strip_suffix('-')
        .map(|v| format!("-{v}"))
        .unwrap_or_else(|| s.to_string());
    let s = s.strip_prefix('+').unwrap_or(&s).to_string();
    // Reject cells with no digit at all ("n/a", "—") rather than letting
    // `parse_usd` decide; a dash-only cell is missing data, not zero.
    if !s.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    Money::parse_usd(&s)
}

/// Parse the date shapes the export has been observed to use, returning ISO
/// `YYYY-MM-DD`.
///
/// Accepted: `YYYY-MM-DD`, `MM/DD/YYYY`, `M/D/YY`, `MM-DD-YYYY`, and
/// `Month DD, YYYY` (full or three-letter English month). All are month-first;
/// there is deliberately no DD/MM support, because guessing between the two
/// silently corrupts every date before the 13th of a month.
pub fn parse_date(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // ISO first: unambiguous, and the cheapest to reject.
    if let Ok(c) = dates::parse_iso(s) {
        return valid(c).then(|| dates::fmt_iso(c));
    }
    // The shared MM/DD/YYYY helper is strict about a 4-digit year, so it
    // handles the common case; `numeric` below covers 2-digit years and the
    // dash-separated variant.
    if let Some(c) = dates::parse_mm_slash_dd_yyyy(s) {
        return valid(c).then(|| dates::fmt_iso(c));
    }
    if let Some(c) = numeric(s).or_else(|| month_name(s)) {
        return valid(c).then(|| dates::fmt_iso(c));
    }
    None
}

/// `M/D/YY`, `M/D/YYYY`, `MM-DD-YYYY` — month-first numeric with either
/// separator and a 2- or 4-digit year.
fn numeric(s: &str) -> Option<Civil> {
    let sep = if s.contains('/') { '/' } else { '-' };
    let parts: Vec<&str> = s.split(sep).collect();
    if parts.len() != 3
        || !parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    let m: u32 = parts[0].parse().ok()?;
    let d: u32 = parts[1].parse().ok()?;
    let y: i64 = parts[2].parse().ok()?;
    // A 2-digit year is expanded into the 2000s. Wealthfront launched in 2008
    // and these are account statements, so there is no 1900s case to get
    // wrong; a 4-digit year is passed through untouched.
    let y = match parts[2].len() {
        2 => 2000 + y,
        4 => y,
        _ => return None,
    };
    Some((y, m, d))
}

/// `January 5, 2026` / `Jan 5 2026` — the comma is optional.
fn month_name(s: &str) -> Option<Civil> {
    const MONTHS: [&str; 12] = [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ];
    let cleaned = s.replace(',', " ");
    let parts: Vec<&str> = cleaned.split_whitespace().collect();
    if parts.len() != 3 {
        return None;
    }
    let word = parts[0].to_ascii_lowercase();
    let m = MONTHS
        .iter()
        .position(|full| *full == word || full.starts_with(&word) && word.len() == 3)?
        as u32
        + 1;
    let d: u32 = parts[1].parse().ok()?;
    let y: i64 = parts[2].parse().ok()?;
    (parts[2].len() == 4).then_some((y, m, d))
}

/// Reject impossible calendar dates (Feb 30, month 13) that the shape parsers
/// above would otherwise wave through.
fn valid((y, m, d): Civil) -> bool {
    if !(1..=12).contains(&m) || d == 0 {
        return false;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let len = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if leap => 29,
        _ => 28,
    };
    d <= len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_plain_records() {
        let got = parse("a,b,c\n1,2,3\n");
        assert_eq!(got, vec![vec!["a", "b", "c"], vec!["1", "2", "3"]]);
    }

    #[test]
    fn no_phantom_record_from_trailing_newline() {
        assert_eq!(parse("a,b\n").len(), 1);
        assert_eq!(parse("a,b\n\n").len(), 2, "a blank line is a real record");
    }

    #[test]
    fn handles_crlf() {
        assert_eq!(
            parse("a,b\r\n1,2\r\n"),
            vec![vec!["a", "b"], vec!["1", "2"]]
        );
    }

    #[test]
    fn strips_bom_so_first_header_matches() {
        let got = parse("\u{feff}Date,Amount\n2026-01-02,1.00\n");
        assert_eq!(got[0][0], "Date");
    }

    #[test]
    fn quoted_fields_keep_commas_quotes_and_newlines() {
        let got = parse("\"Smith, Jane\",\"a \"\"quote\"\"\",\"two\nlines\"\n");
        assert_eq!(got[0][0], "Smith, Jane");
        assert_eq!(got[0][1], "a \"quote\"");
        assert_eq!(got[0][2], "two\nlines");
    }

    #[test]
    fn unterminated_quote_keeps_what_it_parsed() {
        // Truncated download: keep the intact prefix rather than erroring out.
        let got = parse("a,b\n1,\"unterminated");
        assert_eq!(got.len(), 2);
        assert_eq!(got[1][1], "unterminated");
    }

    #[test]
    fn header_normalization_is_case_and_space_insensitive() {
        assert_eq!(norm_header("  Transaction   Date "), "transaction date");
        assert_eq!(norm_header("\u{feff}Date"), "date");
    }

    #[test]
    fn amounts_cover_the_export_shapes() {
        assert_eq!(parse_amount("$1,234.50").unwrap().amount, "1234.50");
        assert_eq!(parse_amount("-$25.00").unwrap().amount, "-25.00");
        assert_eq!(parse_amount("(12.34)").unwrap().amount, "-12.34");
        assert_eq!(parse_amount("12.34-").unwrap().amount, "-12.34");
        assert_eq!(parse_amount("+40").unwrap().amount, "40.00");
        assert_eq!(parse_amount("0.07").unwrap().amount, "0.07");
    }

    #[test]
    fn amounts_reject_non_numeric_cells() {
        for cell in ["", "  ", "n/a", "—", "-"] {
            assert!(parse_amount(cell).is_none(), "{cell:?} should not parse");
        }
    }

    #[test]
    fn dates_cover_the_export_shapes() {
        for (input, want) in [
            ("2026-01-05", "2026-01-05"),
            ("01/05/2026", "2026-01-05"),
            ("1/5/26", "2026-01-05"),
            ("01-05-2026", "2026-01-05"),
            ("January 5, 2026", "2026-01-05"),
            ("Jan 5 2026", "2026-01-05"),
        ] {
            assert_eq!(parse_date(input).as_deref(), Some(want), "input {input}");
        }
    }

    #[test]
    fn dates_reject_impossible_and_unparseable() {
        for bad in [
            "",
            "not a date",
            "2026-02-30",
            "13/01/2026",
            "2/30/2026",
            "Total",
        ] {
            assert!(parse_date(bad).is_none(), "{bad:?} should not parse");
        }
    }
}
