//! `wfr documents list|download` — statements and trade confirmations
//! (documents/v1).
//!
//! CAPTURED-LIVE (2026-08-19): `GET /api/documents/statements` returns
//! `{"statements": [{accountId (numeric), type, date, externalId}]}` — every
//! monthly statement (`STATEMENT`), trade confirmation (`CONFIRM`) and cash
//! statement (`GREEN_DOT_STATEMENT`). There is no bulk download; a single PDF is
//! fetched from `/documents/{accountId}/document/{externalId}` (the **numeric**
//! account id, which is why this Rails endpoint is used rather than
//! `/capitan/v1/documents/account-statements`, whose id is the `ACCA-…` form the
//! download rejects). Tax forms live at `/capitan/v1/documents/user`, usually
//! empty; that surface is not wired here.
//!
//! Downloads are gated on a `%PDF` magic-number check (see `client::download`)
//! rather than on the HTTP status, because an expired session answers a
//! download with 200 and a login page. Without that check this command would
//! cheerfully write an HTML error page to a `.pdf` and report success.

use std::path::{Path, PathBuf};

use pk_cli_core::{output, CliError, Paged, RangeArgs};
use pk_cli_documents::{Document, SavedDocument};
use serde_json::Value;

use super::{note_dropped, pick_str, records, Ctx};
use crate::client::endpoints;
use crate::csv;

/// `externalId` is the document key and download id; the rest are fallbacks.
const ID_KEYS: [&str; 4] = ["externalId", "id", "documentId", "uuid"];
const NAME_KEYS: [&str; 4] = ["name", "title", "displayName", "description"];
const DATE_KEYS: [&str; 4] = ["date", "created_at", "createdAt", "postedDate"];
const CATEGORY_KEYS: [&str; 3] = ["type", "category", "documentType"];
const ACCOUNT_KEYS: [&str; 2] = ["accountId", "account_id"];
const FILE_KEYS: [&str; 3] = ["fileName", "file_name", "filename"];

pub(crate) fn fetch_raw(ctx: &Ctx) -> Result<Vec<Value>, CliError> {
    let raw = ctx.client()?.get_json(endpoints::DOCUMENTS)?;
    records(
        &raw,
        &["statements", "documents"],
        "document",
        endpoints::DOCUMENTS,
    )
}

pub(crate) fn to_document(v: &Value) -> Option<Document> {
    let id = pick_str(v, &ID_KEYS)?;
    let date = pick_str(v, &DATE_KEYS).and_then(|d| normalize_date(&d));
    // Statements carry no name/filename, so synthesize a readable label.
    let name = pick_str(v, &NAME_KEYS).unwrap_or_else(|| synth_name(v, date.as_deref(), &id));
    let mut doc = Document::new(id, name);
    doc.date = date;
    doc.category = pick_str(v, &CATEGORY_KEYS);
    doc.file = pick_str(v, &FILE_KEYS);
    Some(doc)
}

/// Statements date as compact `YYYYMMDD`; reshape to ISO before the parser
/// (which also accepts the `YYYY-MM-DD` / timestamp forms other records use).
fn normalize_date(raw: &str) -> Option<String> {
    let head = raw.split(['T', ' ']).next().unwrap_or(raw);
    if head.len() == 8 && head.bytes().all(|b| b.is_ascii_digit()) {
        csv::parse_date(&format!("{}-{}-{}", &head[0..4], &head[4..6], &head[6..8]))
    } else {
        csv::parse_date(head)
    }
}

/// e.g. `STATEMENT 2026-01-31` / `CONFIRM 2026-01-15`; falls back to the id.
fn synth_name(v: &Value, date: Option<&str>, id: &str) -> String {
    match (pick_str(v, &CATEGORY_KEYS), date) {
        (Some(t), Some(d)) => format!("{t} {d}"),
        (Some(t), None) => t,
        _ => id.to_string(),
    }
}

pub fn list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    range.validate()?;
    let rows = fetch_raw(ctx)?;
    let mut items: Vec<Document> = rows.iter().filter_map(to_document).collect();
    note_dropped(ctx.quiet, "document", rows.len(), items.len());
    // Newest first, per the profile. Documents with no date sort last rather
    // than being dropped.
    items.sort_by(|a, b| b.date.cmp(&a.date));
    if let Some(since) = &range.since {
        items.retain(|d| d.date.as_deref().is_none_or(|x| x >= since.as_str()));
    }
    if let Some(until) = &range.until {
        items.retain(|d| d.date.as_deref().is_none_or(|x| x <= until.as_str()));
    }
    let total = items.len() as u64;
    if let Some(n) = range.limit {
        items.truncate(n as usize);
    }
    let mut paged = Paged::new("document", items);
    paged.total = Some(total);
    if ctx.json {
        output::json(&serde_json::to_value(&paged).unwrap_or_default());
    } else {
        let v = serde_json::to_value(&paged).unwrap_or_default();
        let rows = output::rows_of(&v, "items");
        output::table(&output::table_view(
            &rows,
            &["id", "date", "category", "name"],
        ));
    }
    Ok(())
}

/// Choose the output path: an explicit file, a file inside an explicit
/// directory, or a filename derived from the document in the working directory.
fn target(doc: &Document, out: Option<&Path>) -> PathBuf {
    let leaf = doc
        .file
        .clone()
        .unwrap_or_else(|| format!("{}.pdf", sanitize(&doc.id)));
    match out {
        Some(p) if p.is_dir() => p.join(leaf),
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(leaf),
    }
}

/// Keep a provider id from escaping the target directory or breaking a shell.
fn sanitize(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

pub fn download(ctx: &Ctx, id: &str, out: Option<&Path>) -> Result<(), CliError> {
    // The download URL needs the numeric account id, which lives on the record —
    // so look the document up in the raw list rather than the mapped DTO.
    let rows = fetch_raw(ctx)?;
    let rec = rows
        .iter()
        .find(|r| pick_str(r, &ID_KEYS).as_deref() == Some(id))
        .ok_or_else(|| CliError::NotFound(format!("no document with id `{id}`")))?;
    let account = pick_str(rec, &ACCOUNT_KEYS).ok_or_else(|| {
        CliError::Upstream(format!(
            "document `{id}` carries no account id to build its URL"
        ))
    })?;
    let doc = to_document(rec)
        .ok_or_else(|| CliError::Upstream("could not map the document record".into()))?;
    let path = endpoints::DOCUMENT
        .replace("{account}", &account)
        .replace("{id}", id);
    // `download` refuses anything that isn't a real PDF, so reaching the next
    // line means bytes worth writing.
    let bytes = ctx.client()?.download(&path)?;
    let dest = target(&doc, out);
    std::fs::write(&dest, &bytes)
        .map_err(|e| CliError::Other(format!("writing {}: {e}", dest.display())))?;
    let saved = SavedDocument::from_document(&doc, dest.display().to_string(), bytes.len() as u64);
    let v = serde_json::to_value(&saved).unwrap_or_default();
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
    fn maps_a_captured_statement_record() {
        // Field names from the 2026-08-19 live capture; accountId is numeric.
        let d = to_document(&json!({
            "accountId": 3000000,
            "type": "STATEMENT",
            "date": "20260131",
            "externalId": "DOCA-XXXX-0000-0000"
        }))
        .unwrap();
        assert_eq!(d.id, "DOCA-XXXX-0000-0000", "id is the externalId");
        assert_eq!(
            d.date.as_deref(),
            Some("2026-01-31"),
            "compact YYYYMMDD is reshaped to ISO"
        );
        assert_eq!(d.category.as_deref(), Some("STATEMENT"));
        assert_eq!(
            d.name, "STATEMENT 2026-01-31",
            "name synthesized from type+date"
        );
    }

    #[test]
    fn document_without_an_id_is_dropped() {
        assert!(to_document(&json!({ "type": "STATEMENT" })).is_none());
    }

    #[test]
    fn download_url_uses_numeric_account_and_external_id() {
        // Build the path the same way `download` does.
        let path = endpoints::DOCUMENT
            .replace("{account}", "3000000")
            .replace("{id}", "DOCA-XXXX-0000-0000");
        assert_eq!(path, "/documents/3000000/document/DOCA-XXXX-0000-0000");
    }

    #[test]
    fn target_prefers_explicit_path_then_id_filename() {
        let doc = Document::new("DOCA-XXXX-0000-0000", "STATEMENT 2026-01-31");
        assert_eq!(
            target(&doc, Some(Path::new("/tmp/out.pdf"))),
            PathBuf::from("/tmp/out.pdf")
        );
        // No portal filename: fall back to a sanitized id.
        assert_eq!(target(&doc, None), PathBuf::from("DOCA-XXXX-0000-0000.pdf"));
    }

    #[test]
    fn sanitize_strips_path_traversal() {
        assert_eq!(sanitize("../../etc/passwd"), "------etc-passwd");
        assert!(!sanitize("../../etc/passwd").contains('/'));
    }
}
