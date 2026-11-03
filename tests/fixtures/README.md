# Test fixtures — synthetic, not captures

**Every file here was written by hand. None is a capture of a real
Wealthfront account, and no real Wealthfront data has ever been committed to
this repository.** The `values` are all invented; only the *shapes* are real.

A first-party live capture on 2026-08-18 did authenticate against the site and
observe the real response shapes (that is where the `accounts-overviews2` and
`activities` structures come from). But the capture recorded **field names
only**, never values, and these fixtures were written by hand from those names
with invented data — no real record was scrubbed into the tree. The privacy
tests in `fixture_shapes.rs` enforce that over every tracked file.

The values are therefore all invented: `AAAA`/`BBBB` are not real tickers,
`ACCT-XXXX-0001` is not a real account id, `••••0000` is not a real account
mask, and the amounts are round numbers chosen to exercise parsing rather than
to resemble anyone's balance.

## Provenance of the *shapes*

Synthetic values, but not invented structure — the shapes come from public
sources so the contract tests are worth something:

| Fixture | Shape source |
|---|---|
| `transfers-for-account.json` | The response schema of the `transfers-for-account` XHR, as read off the public parser in [KrauseFx/wealthfront-tax-info-exporter](https://github.com/KrauseFx/wealthfront-tax-info-exporter) (`generate_tax_documents.rb`), which was written against a real 2021 capture. Envelope `transfers.completed_transfers[]`; per-record `created_at`, `class_type`, `amount` (a **string** with a `$` prefix), `type`, `transaction_type`; nested `dividends[]` and `trades[]`; `your_fee`/`period` on fee records. Retained as the likely **investment-account** activity shape; the live CLI reads `activities` (below) for cash accounts. |
| `accounts-overviews2.json` | **CAPTURED-LIVE 2026-08-18** field names from `GET /capitan/v1/accounts/overviews2`. Envelope `overviews[]`; per-record `accountId`, `accountType`, `accountDisplayName`, and a nested `accountValueSummary` whose `totalValue`/`formattedTotalValue` carry the balance. Read by both `accounts list` and the `net-worth` rollup (whose fixture-driven contract test pins the summed figures). |
| `login-page-with-challenge-words.html` | Hand-written, not modelled on any capture: a login page whose title is ordinary and whose meta tag, script and body hold a challenge's words. Only a `<title>` may name a bot check (`html_reads_as_edge_block`) |
| `activities.json` | **CAPTURED-LIVE 2026-08-18** field names from `GET /capitan/v1/activities?account_id=…`. Envelope `activities[]`; a display feed mixing real transactions (`type` prefixed `TXN_`, with the amount only inside the `body` sentence) with `PROMOTIONAL_BLOG` / `INVITE_*` rows the mapper skips. |
| `statements.json` | **CAPTURED-LIVE 2026-08-19** field names from `GET /api/documents/statements`. Envelope `statements[]`; per-record numeric `accountId` (the download URL `/documents/{accountId}/document/{externalId}` needs it), `type` (`STATEMENT`/`CONFIRM`/`GREEN_DOT_STATEMENT`), a compact `YYYYMMDD` `date`, and `externalId`. |
| `activity-cash.csv` | The cash-account activity CSV export: `Date,Description,Amount,Balance`. |
| `activity-investment.csv` | The investment-account variant: `Transaction Date,Description,Type,Amount`. |
| `activity-messy.csv` | Same format, carrying every awkward case observed in real exports at once — see below. |

The CSV header sets come from a working Wealthfront CSV parser written for a
previous project against real exports. Only the *format knowledge* (which
column names exist, which date and amount spellings appear) was carried over;
no data rows were, and the files in that project were never opened here.

**Explicitly rejected as a source:** the `Date,Symbol,Type,Quantity,Price,Amount`
header set published by pocketportfolio.app under the title "Wealthfront CSV
Export". That is that tool's own generic import schema — the page advertises
"auto-detection for 20+ brokers" and never demonstrates a real Wealthfront
file. Adopting it would have hard-coded a format Wealthfront does not emit.

## What `activity-messy.csv` deliberately contains

Each of these broke, or would have broken, a real parser:

- a UTF-8 **BOM** on the first byte (binds to the first header cell and
  renames `Date` to `\u{feff}Date`)
- two **preamble lines** and a blank line above the real header row
- `Transaction date` vs `Transaction Date` — **casing** that differs from the
  other exports
- a **quoted date containing a comma** (`"January 31, 2026"`)
- **quoted descriptions containing commas** and an em dash
- four date spellings in one file: `Month DD, YYYY`, `M/D/YY`, `MM-DD-YYYY`,
  `YYYY-MM-DD`
- four amount spellings: **trailing minus** (`2.08-`), `$`-prefixed,
  thousands separators, **accounting parentheses** (`(250.00)`)
- a **blank row** mid-file
- an **impossible date** (`2026-13-45`) that must be skipped, not imported
- a **totals footer** and an **ending-balance footer**

## Policy

- Fixtures are synthetic. If a real capture is ever taken, it is scrubbed
  *before* it touches the working tree — never committed "to scrub later". A
  live session cookie or pre-signed URL is a working credential.
- Identity-bearing values use obvious dummies: `0000` masks, `AAAA`-style
  tickers, `example.com` / `example.invalid` hosts.
- `tests/fixture_shapes.rs` enforces this positively — it asserts fixtures
  match known dummy shapes rather than listing real values to exclude, since
  a denylist would publish exactly what it exists to keep out.
