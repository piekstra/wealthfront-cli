//! The `wfr mcp` tools, offline: every tool runs in process against the
//! synthetic fixtures through the `Source` seam, mapped by the commands' own
//! mappers, and cli-common's conformance helper checks the definitions and
//! every result's shape and size.

use std::sync::Mutex;

use pk_cli_core::CliError;
use pk_cli_mcp::conformance::{assert_conforms, assert_fits, call, definition_size};
use pk_cli_mcp::CallToolResult;
use serde_json::{json, Value};

use super::*;

fn fixture(raw: &str) -> Value {
    serde_json::from_str(raw).expect("fixture parses")
}

const INDIVIDUAL: &str = "ACCT-XXXX-0001";
const JOINT: &str = "ACCT-XXXX-0002";

struct Fixtures {
    accounts: Vec<Value>,
    /// The activities fixture: the individual account's feed.
    activity: Vec<Value>,
    /// The joint account's feed: one deposit, and one transaction whose
    /// amount cannot be read.
    joint_activity: Vec<Value>,
    documents: Vec<Value>,
    /// Every source call, as `method:arg`.
    calls: Mutex<Vec<String>>,
    /// When set, every call fails with this.
    fail: Mutex<Option<CliError>>,
}

impl Fixtures {
    fn new() -> Self {
        let accounts = fixture(include_str!(
            "../../tests/fixtures/accounts-overviews2.json"
        ));
        let activity = fixture(include_str!("../../tests/fixtures/activities.json"));
        let documents = fixture(include_str!("../../tests/fixtures/statements.json"));
        Self {
            accounts: overviews::unwrap_records(&accounts).unwrap(),
            activity: activity["activities"].as_array().unwrap().clone(),
            joint_activity: vec![
                json!({
                    "type": "TXN_DEPOSIT", "headline": "Deposit",
                    "body": "We received your deposit in the amount of $500.00.",
                    "date": "2026-01-20", "id": "ACT-XXXX-0006"
                }),
                json!({
                    "type": "TXN_DEPOSIT", "headline": "Deposit",
                    "body": "We received your deposit.",
                    "date": "2026-01-21", "id": "ACT-XXXX-0007"
                }),
            ],
            documents: documents["statements"].as_array().unwrap().clone(),
            calls: Mutex::new(Vec::new()),
            fail: Mutex::new(None),
        }
    }

    fn record(&self, call: String) -> Result<(), CliError> {
        self.calls.lock().unwrap().push(call);
        match self.fail.lock().unwrap().as_ref() {
            None => Ok(()),
            Some(e) => Err(e.clone()),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Source for Fixtures {
    async fn accounts(&self) -> Result<Vec<Value>, CliError> {
        self.record("accounts".into())?;
        Ok(self.accounts.clone())
    }

    async fn activity(&self, account_id: &str) -> Result<Vec<Value>, CliError> {
        self.record(format!("activity:{account_id}"))?;
        Ok(match account_id {
            INDIVIDUAL => self.activity.clone(),
            JOINT => self.joint_activity.clone(),
            _ => Vec::new(),
        })
    }

    async fn documents(&self) -> Result<Vec<Value>, CliError> {
        self.record("documents".into())?;
        Ok(self.documents.clone())
    }
}

fn tools() -> WealthfrontTools<Fixtures> {
    WealthfrontTools::new(Fixtures::new())
}

fn with_accounts(extra: Vec<Value>) -> WealthfrontTools<Fixtures> {
    let mut fixtures = Fixtures::new();
    fixtures.accounts.extend(extra);
    WealthfrontTools::new(fixtures)
}

fn err(r: &CallToolResult) -> &str {
    assert!(r.is_error(), "expected an error, got {}", r.text());
    assert!(r.structured().is_none());
    r.text()
}

fn field(items: &Value, key: &str) -> Vec<String> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i[key].as_str().unwrap_or("-").to_string())
        .collect()
}

// ---- the definitions --------------------------------------------------------

#[test]
fn the_tools_conform_to_the_mcp_profile() {
    assert_conforms(&tools());
}

#[test]
fn the_definitions_stay_small() {
    let t = tools();
    let mut total = 0;
    for name in [ACCOUNTS_TOOL, ACTIVITY_TOOL, DOCUMENTS_TOOL] {
        let size = definition_size(&t, name);
        eprintln!("{name}: {size} characters");
        assert!(size < 2_500, "{name} takes {size} characters");
        total += size;
    }
    eprintln!("total: {total} characters");
    assert!(total <= 8_000, "the definitions take {total} characters");
}

#[test]
fn listing_and_describing_the_tools_reads_nothing() {
    let t = tools();
    let _ = t.tools();
    let _ = t.server();
    assert!(t.source().calls().is_empty());
}

// ---- wealthfront_accounts ---------------------------------------------------

#[test]
fn accounts_are_named_valued_and_totalled() {
    let t = tools();
    let r = call(&t, ACCOUNTS_TOOL, json!({}));
    let out = assert_fits(&t, ACCOUNTS_TOOL, &r);
    assert_eq!(out["total"], "6234.56");
    assert_eq!(out["assets"], "6234.56");
    assert!(out.get("liabilities").is_none());
    assert!(out.get("unvalued").is_none());
    assert_eq!(
        field(&out["items"], "name"),
        ["Individual Cash Account", "Joint Cash Account"]
    );
    assert_eq!(field(&out["items"], "balance"), ["1234.56", "5000.00"]);
    assert_eq!(
        field(&out["items"], "type"),
        ["PERSONAL_CASH", "JOINT_CASH"]
    );
    assert!(out["items"][0].get("id").is_none(), "concise");
    assert_eq!(out["returned"], 2);
    assert_eq!(t.source().calls(), ["accounts"]);
}

#[test]
fn detailed_accounts_add_their_ids() {
    let t = tools();
    let r = call(&t, ACCOUNTS_TOOL, json!({"response_format": "detailed"}));
    let out = assert_fits(&t, ACCOUNTS_TOOL, &r);
    assert_eq!(field(&out["items"], "id"), [INDIVIDUAL, JOINT]);
}

#[test]
fn an_account_is_named_not_numbered_and_narrows_the_total() {
    let t = tools();
    let r = call(&t, ACCOUNTS_TOOL, json!({"account": "joint cash account"}));
    let out = assert_fits(&t, ACCOUNTS_TOOL, &r);
    assert_eq!(field(&out["items"], "name"), ["Joint Cash Account"]);
    assert_eq!(out["total"], "5000.00");
    let r = call(&t, ACCOUNTS_TOOL, json!({"account": INDIVIDUAL}));
    let out = assert_fits(&t, ACCOUNTS_TOOL, &r);
    assert_eq!(out["total"], "1234.56");
}

#[test]
fn an_unknown_account_lists_the_names_that_exist() {
    let t = tools();
    let text = err(&call(&t, ACCOUNTS_TOOL, json!({"account": "Rainy Day"}))).to_string();
    assert!(text.starts_with("not_found:"), "{text}");
    assert!(
        text.contains("Individual Cash Account, Joint Cash Account"),
        "{text}"
    );
}

#[test]
fn a_negative_account_is_a_liability_and_an_unvalued_one_is_counted_apart() {
    let t = with_accounts(vec![
        json!({
            "accountId": "ACCT-XXXX-0003", "accountType": "TAXABLE_INVESTMENT",
            "accountDisplayName": "Margin Test",
            "accountValueSummary": {"totalValue": -34.56, "formattedTotalValue": "-$34.56"}
        }),
        json!({"accountId": "ACCT-XXXX-0004", "accountDisplayName": "Pending Open"}),
    ]);
    let r = call(&t, ACCOUNTS_TOOL, json!({}));
    let out = assert_fits(&t, ACCOUNTS_TOOL, &r);
    assert_eq!(out["assets"], "6234.56");
    assert_eq!(out["liabilities"], "34.56");
    assert_eq!(out["total"], "6200.00");
    assert_eq!(out["unvalued"], 1);
    let pending = &out["items"][3];
    assert_eq!(pending["name"], "Pending Open");
    assert!(pending.get("balance").is_none(), "{pending}");
}

/// A record with no id is a shape change: a total that quietly left it out
/// would be a wrong figure.
#[test]
fn an_account_without_an_id_fails_the_call() {
    let t = with_accounts(vec![json!({"accountDisplayName": "Nameless"})]);
    let text = err(&call(&t, ACCOUNTS_TOOL, json!({}))).to_string();
    assert!(text.starts_with("upstream:"), "{text}");
}

#[test]
fn accounts_page_with_a_cursor_bound_to_the_filters() {
    let t = tools();
    let first = call(&t, ACCOUNTS_TOOL, json!({"limit": 1}));
    let out = assert_fits(&t, ACCOUNTS_TOOL, &first);
    assert_eq!(field(&out["items"], "name"), ["Individual Cash Account"]);
    assert_eq!(out["total"], "6234.56", "the total is not the page's");
    let cursor = out["next_cursor"].as_str().unwrap().to_string();

    let second = call(&t, ACCOUNTS_TOOL, json!({"limit": 1, "cursor": cursor}));
    let out = assert_fits(&t, ACCOUNTS_TOOL, &second);
    assert_eq!(field(&out["items"], "name"), ["Joint Cash Account"]);
    assert!(out.get("next_cursor").is_none());

    let other = call(
        &t,
        ACCOUNTS_TOOL,
        json!({"limit": 1, "cursor": cursor, "account": "Joint Cash Account"}),
    );
    assert!(err(&other).starts_with("usage:"));
}

// ---- wealthfront_activity ---------------------------------------------------

/// Two rows that say the same thing and hold no id, split by a page boundary: both are seen.
#[test]
fn identical_rows_with_no_id_are_both_seen_across_a_page_boundary() {
    let mut fixtures = Fixtures::new();
    let mut row = fixtures.activity[0].clone();
    row.as_object_mut().unwrap().remove("id");
    fixtures.activity = vec![row.clone(), row];
    fixtures.joint_activity.clear();
    let t = WealthfrontTools::new(fixtures);
    let args = json!({"since": "2026-01-01", "until": "2026-12-31", "limit": 1});
    let r = call(&t, ACTIVITY_TOOL, args.clone());
    let first = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(first["returned"], 1);
    let mut next = args;
    next["cursor"] = first["next_cursor"].clone();
    let r = call(&t, ACTIVITY_TOOL, next);
    let second = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(second["returned"], 1);
    assert!(second["next_cursor"].is_null());
}

/// A count of rows would show the first page's last row again.
#[test]
fn an_activity_row_that_arrives_between_pages_repeats_nothing() {
    let args = json!({
        "since": "2026-01-01",
        "until": "2026-12-31",
        "limit": 2,
        "response_format": "detailed",
    });
    let t = tools();
    let r = call(&t, ACTIVITY_TOOL, args.clone());
    let first = assert_fits(&t, ACTIVITY_TOOL, &r);
    let seen = first["items"][1]["description"].clone();

    let mut fixtures = Fixtures::new();
    let mut newer = fixtures.activity[0].clone();
    newer["id"] = json!("dummy-newer-row");
    fixtures.activity.insert(0, newer);
    let t = WealthfrontTools::new(fixtures);
    let mut next = args;
    next["cursor"] = first["next_cursor"].clone();
    let r = call(&t, ACTIVITY_TOOL, next);
    let second = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_ne!(second["items"][0]["description"], seen);
}

#[test]
fn activity_is_newest_first_across_accounts_with_signed_amounts() {
    let t = tools();
    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(out["since"], "2026-01-01");
    assert_eq!(
        field(&out["items"], "date"),
        ["2026-02-01", "2026-01-31", "2026-01-20", "2026-01-05"]
    );
    assert_eq!(
        field(&out["items"], "type"),
        ["withdrawal", "interest", "deposit", "deposit"]
    );
    assert_eq!(
        field(&out["items"], "amount"),
        ["-40.00", "0.15", "500.00", "1250.00"]
    );
    assert_eq!(
        field(&out["items"], "account"),
        [
            "Individual Cash Account",
            "Individual Cash Account",
            "Joint Cash Account",
            "Individual Cash Account"
        ]
    );
    // The blog and invite rows are not transactions; the joint deposit with
    // no amount is counted, not guessed.
    assert_eq!(out["unreadable"], 1);
    assert!(out["items"][0].get("id").is_none(), "concise");
    assert_eq!(
        t.source().calls(),
        [
            "accounts",
            "activity:ACCT-XXXX-0001",
            "activity:ACCT-XXXX-0002"
        ]
    );
}

#[test]
fn activity_narrows_by_window_account_and_type() {
    let t = tools();
    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-01-01", "until": "2026-01-31", "type": "DEPOSIT"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(field(&out["items"], "date"), ["2026-01-20", "2026-01-05"]);

    let t = tools();
    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31", "account": "Individual Cash Account"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(out["returned"], 3);
    assert!(out.get("unreadable").is_none());
    assert_eq!(t.source().calls(), ["accounts", "activity:ACCT-XXXX-0001"]);
}

#[test]
fn detailed_activity_adds_the_feed_ids() {
    let t = tools();
    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-02-01", "until": "2026-02-28", "response_format": "detailed"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(field(&out["items"], "id"), ["ACT-XXXX-0003"]);
}

#[test]
fn activity_defaults_to_the_year_to_date() {
    let t = tools();
    let r = call(&t, ACTIVITY_TOOL, json!({"until": "2026-08-31"}));
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(out["since"], "2026-01-01");
    let today = dates::fmt_iso(dates::today());
    let r = call(&t, ACTIVITY_TOOL, json!({}));
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(out["until"], today);
    assert_eq!(out["since"], format!("{}-01-01", &today[..4]));
}

#[test]
fn bad_dates_fail_before_any_read() {
    let t = tools();
    for args in [
        json!({"since": "01/05/2026"}),
        json!({"until": "2026-13-01"}),
        json!({"since": "2026-09-01", "until": "2026-08-01"}),
    ] {
        let text = err(&call(&t, ACTIVITY_TOOL, args.clone())).to_string();
        assert!(text.starts_with("usage:"), "{args}: {text}");
    }
    let text = err(&call(
        &t,
        DOCUMENTS_TOOL,
        json!({"since": "2026-09-01", "until": "2026-08-01"}),
    ))
    .to_string();
    assert!(text.starts_with("usage:"), "{text}");
    let text = err(&call(&t, DOCUMENTS_TOOL, json!({"until": "2026-1-x"}))).to_string();
    assert!(text.contains("YYYY-MM-DD"), "{text}");
    assert!(t.source().calls().is_empty());
}

/// An unpadded date compares as a string, so it is padded first:
/// `"2026-8-5" < "2026-08-01"` as text, though 5 August is later.
#[test]
fn unpadded_dates_are_padded_before_any_comparison() {
    let (s, u) = window(Some("2026-8-5"), Some("2026-08-31")).unwrap();
    assert_eq!((s.as_str(), u.as_str()), ("2026-08-05", "2026-08-31"));
    let (s, _) = window(None, Some("2026-3-1")).unwrap();
    assert_eq!(s, "2026-01-01");
}

// ---- wealthfront_documents --------------------------------------------------

#[test]
fn documents_list_names_and_types_newest_first() {
    let t = tools();
    let r = call(&t, DOCUMENTS_TOOL, json!({}));
    let out = assert_fits(&t, DOCUMENTS_TOOL, &r);
    assert_eq!(
        field(&out["items"], "date"),
        ["2026-01-31", "2026-01-15", "2026-01-14"]
    );
    assert_eq!(
        field(&out["items"], "type"),
        ["statement", "confirm", "green-dot-statement"]
    );
    assert_eq!(out["items"][0]["name"], "STATEMENT 2026-01-31");
    assert!(out["items"][0].get("id").is_none(), "concise");
    // The numeric account id the download URL needs never leaves.
    assert!(!r.text().contains("3000000"), "{}", r.text());
    assert_eq!(t.source().calls(), ["documents"]);
}

#[test]
fn documents_narrow_by_type_and_window_with_ids_on_request() {
    let t = tools();
    let r = call(
        &t,
        DOCUMENTS_TOOL,
        json!({"type": "CONFIRM", "response_format": "detailed"}),
    );
    let out = assert_fits(&t, DOCUMENTS_TOOL, &r);
    assert_eq!(field(&out["items"], "type"), ["confirm"]);
    assert_eq!(out["items"][0]["id"], "DOCB-XXXX-0000-0002");

    let r = call(
        &t,
        DOCUMENTS_TOOL,
        json!({"since": "2026-01-15", "until": "2026-01-31"}),
    );
    let out = assert_fits(&t, DOCUMENTS_TOOL, &r);
    assert_eq!(field(&out["items"], "date"), ["2026-01-31", "2026-01-15"]);

    let r = call(&t, DOCUMENTS_TOOL, json!({"type": "green_dot_statement"}));
    let out = assert_fits(&t, DOCUMENTS_TOOL, &r);
    assert_eq!(out["returned"], 1);
}

#[test]
fn an_unknown_document_type_names_the_known_ones() {
    let t = tools();
    let text = err(&call(&t, DOCUMENTS_TOOL, json!({"type": "1099"}))).to_string();
    assert!(text.starts_with("usage:"), "{text}");
    assert!(
        text.contains("statement, confirm, green-dot-statement"),
        "{text}"
    );
    assert!(text.contains("Tax forms are not listed"), "{text}");
    assert!(t.source().calls().is_empty());
}

// ---- errors -----------------------------------------------------------------

#[test]
fn a_missing_session_asks_for_the_browser_login_in_a_terminal() {
    let t = tools();
    *t.source().fail.lock().unwrap() = Some(CliError::Auth(
        "no Wealthfront session stored — run `wfr auth login`".into(),
    ));
    for name in [ACCOUNTS_TOOL, ACTIVITY_TOOL, DOCUMENTS_TOOL] {
        let text = err(&call(&t, name, json!({}))).to_string();
        assert!(text.starts_with("auth:"), "{name}: {text}");
        assert!(
            text.contains("Ask the user to run `wfr auth login --browser` in a terminal"),
            "{name}: {text}"
        );
        assert!(text.contains("never sign in"), "{name}: {text}");
        // The CLI's own remedy is dropped: one command to ask for, not two.
        assert!(!text.contains("`wfr auth login`"), "{name}: {text}");
    }
}

#[test]
fn an_auth_error_keeps_its_reason_and_drops_the_cli_s_remedy() {
    for (message, reason) in [
        ("no Wealthfront session stored — run `wfr auth login`", "no Wealthfront session stored"),
        ("Wealthfront returned HTML where JSON was expected (session expired) — run `wfr auth login`", "Wealthfront returned HTML where JSON was expected (session expired)"),
    ] {
        assert_eq!(tool_err(CliError::Auth(message.into())).message(), reason);
    }
    assert_eq!(tool_err(CliError::Auth("401".into())).message(), "401");
}

#[test]
fn a_provider_failure_is_upstream_not_the_arguments() {
    let t = tools();
    *t.source().fail.lock().unwrap() = Some(CliError::Upstream("HTTP 503".into()));
    let text = err(&call(&t, ACCOUNTS_TOOL, json!({}))).to_string();
    assert!(text.starts_with("upstream:"), "{text}");
    assert!(!text.contains("auth login"), "{text}");
}

#[test]
fn the_instructions_name_the_browser_login_and_read_only_access() {
    let text = pk_cli_mcp::instructions(&tools());
    assert!(text.contains("`wfr auth login --browser`"), "{text}");
    assert!(text.contains("read-only"), "{text}");
}
