# AGENTS.md — working on wfr

Canonical guide for humans and agents. `CLAUDE.md` points here.

## What this repo is

A [piekstra CLI family](https://github.com/piekstra/cli-common) member
(`piekstra-cli/1`) for Wealthfront. Rust, clap-derive, `pk-cli-*` crates pinned
to tag **v0.15.1**. Binary is `wfr`; crate is `wealthfront-cli`.

**Read-only.** Nothing here moves money or mutates the account. If that ever
changes, the claim in README, SECURITY.md and this file must change in the
*same commit* as the first write.

## The one thing to understand first

The surface is split, and the split is not cosmetic:

- **`import csv` is verified.** No network, no credential. Its behavior is
  pinned by fixtures and tested end to end. Treat it as the polished piece; it
  is what actually works.
- **Reads and browser login both VERIFIED-LIVE.** A first-party capture on
  2026-08-18 verified `wfr accounts list` / `transactions list` / `api` end to
  end against `/capitan/v1/accounts/overviews2` and `/capitan/v1/activities`.
  Authenticated calls need the session cookies **plus `x-csrf-token`** (the
  URL-decoded `xsrf` cookie; `client.rs::csrf_token` — `docs/api.md` §3.4).
  Obtaining the session works two ways. **`wfr auth login --browser`**
  (`browser_capture` in `src/commands/auth.rs`, on cli-common's
  `pk-cli-browser`) launches a plain Chrome (no automation flags →
  reCAPTCHA-safe), the owner signs in, and the CLI reads the wealthfront.com
  jar, confirms it with `GET /capitan/v1/me` before the tab closes, and stores
  it (`docs/api.md` §3.6). VERIFIED-LIVE with the embedded capture it replaced;
  the shared-crate build awaits the owner's next sign-in. **`wfr auth login` (bare HTTP) also reaches credential validation
  + 2FA as of 2026-08-31** — the earlier "reCAPTCHA needs a browser" claim was
  wrong: a tokenless POST with the `login_xsrf` handshake reaches the login, and
  a wrong password now returns a credentials error, not a session error
  (`docs/api.md`, 2026-08-31 diagnosis + §3.1). The **app-specific password is
  still rejected** by the web login (§3.3). The bare-HTTP path's MFA *verify*
  body shape is UNVERIFIED-LIVE — it needs the owner's one real login (SMS) via
  the existing `--code <CODE>` resume; `--browser` is the guaranteed fallback.
  `wfr documents list`/`download`
  are also VERIFIED-LIVE (2026-08-19) against `/api/documents/statements` +
  `/documents/{account}/document/{externalId}`. The 2021
  `transfers-for-account` endpoint now **404s** — investment-account activity
  has no captured shape, but this owner has only cash accounts (whose activity
  is the `activities` feed), so nothing is missing for them.
- **`net-worth` is VERIFIED-LIVE (2026-08-24 owner smoke), and adds no endpoint.** It
  re-reads the VERIFIED-LIVE `overviews2` accounts endpoint through the same
  shared field readers as `accounts list` and rolls the balances up into the
  family `net-worth/v1` DTO (`docs/api.md` §3.5) — the shape `m1f net-worth`
  and `rhd net-worth` also emit, so asset-capturing consumers (tax-cli) need
  one registry row per provider. Delete this marker once the owner has run it
  against a live session.

Do not quietly upgrade a guess to a fact. If you confirm something live,
update `docs/api.md`, delete the specific UNVERIFIED-LIVE marker you earned,
and say what you captured.

## Credential loop — do not burn codes

**Wealthfront requires 2FA on every account and offers no way to disable it.**
Logging in costs a rate-limited SMS code, and codes cannot be obtained
unattended. Therefore:

- The test suite is **fully offline** and must stay that way. No network, no
  keychain, no credential. Keychain-touching assertions are behind
  `WFR_TEST_KEYCHAIN=1`.
- **Ask before triggering a live login.** Don't run `auth login` against the
  real site "just to see".
- `--channel totp` costs nothing (the code is generated on the user's device).
  Prefer it over `sms` for any experiment.
- The **app-specific password** experiment (`docs/api.md` §3) is **answered**
  (2026-08-13): HTTP Basic Auth with it 404'd, and the real web login **rejects
  it** ("Invalid email address or password", §3.3) — it is an aggregator-linking
  credential, not a web-login one. Don't re-present it as an open first step or
  re-spend a login attempt on it; a real `wfr` login needs the real password +
  2FA, via either the bare-HTTP `wfr auth login` (fixed 2026-08-31 — no browser
  needed to reach 2FA) or `wfr auth login --browser` (§3.1–3.2, §10).

## Layout

| Path | Role |
|---|---|
| `src/main.rs` | clap tree, dispatch, exit-code mapping |
| `src/commands/auth.rs` | `auth login` (password + parked MFA, and `--browser`: the `pk-cli-browser` capture and its `/capitan/v1/me` confirm), `status`, `logout`, `set-credential` |
| `src/client.rs` | HTTP, session (`x-csrf-token`), login `login_xsrf` handshake + MFA, `endpoints` — login **CAPTURED-LIVE & bare-HTTP-reachable** (2026-08-31), `me`/`accounts`/`activities`/`documents` reads all **VERIFIED-LIVE** |
| `src/keychain.rs` | the four keychain account names and why each exists |
| `src/config.rs` | non-secret settings |
| `src/csv.rs` | RFC 4180 reader + amount/date normalizers |
| `src/commands/import.rs` | the verified CSV importer |
| `src/commands/{accounts,transactions,documents}.rs` | all read the **VERIFIED-LIVE** API (accounts, activity, statements + downloads) |
| `src/commands/overviews.rs` | the shared `overviews2` reading (envelope + field readers) that `accounts` and `net-worth` are both views over |
| `src/commands/networth.rs` | `net-worth/v1` rollup of the shared overviews reading — **VERIFIED-LIVE** (2026-08-24 owner smoke) |
| `src/commands/mod.rs` | tolerant JSON field-picking shared by those reads |
| `src/loopback.rs` | test-only: the std loopback HTTP server the unit tests answer the client's requests from |
| `src/mcp.rs` | `wfr mcp`: the MCP tools over a `Source` seam |
| `packaging/mcpb/` | the Claude Desktop extension manifest |

## Rules that are easy to get wrong here

**Reuse before you write.** `pk_cli_core` already owns dates (`parse_iso`,
`fmt_iso`), money (`Money::parse_usd` — it handles `$`, commas and accounting
parentheses), output (`emit`, `table_view`, `kv`, `table`, `json`, `fail`),
paging (`Paged`) and range flags (`RangeArgs`). `src/csv.rs` extends
`parse_usd` for exactly one case it does not cover (trailing minus) and
delegates the rest. Don't fork these. The browser sign-in is
`pk_cli_browser`'s: wfr only names the host, the cookies and the confirm read.
If it ever needs something the crate cannot express, add it to cli-common
rather than embedding DevTools code here again.

**One JSON document per invocation.** If a command already emitted its DTO and
then needs a nonzero exit, `std::process::exit` directly — returning an error
appends a second document. `auth status --verify` is the live example.

**Validate before touching keychain or network,** so `--help` and bad input
never prompt or hang. `import csv` validates its range flags before it even
opens the file; `api` parses the method before building a client.

**Omit, don't null.** A field the mapper cannot resolve is absent from the DTO.

**Never report success from a status code.** Downloads require the `%PDF`
magic number. Logins require a positive signal, and *rejection is checked
first* — a rejected login often renders an MFA-shaped page, and testing for
the code prompt first makes the CLI ask for a code nobody sent.
`GET /capitan/v1/me` counts as signed in only when it answers a JSON object
(`Wf::me`). A 200 that is empty, `null` or any other JSON value is an upstream
error (exit 5), for the browser confirm, the password login and
`auth status --verify` alike: a visitor's answer is a 401, not an empty 200.

**Records that fail to map are counted on stderr** (`note_dropped`). An
unrecognized *envelope* is a hard error, never an empty list — "no accounts"
and "the shape changed" must not look identical.

## MCP tools

`wfr mcp` (src/mcp.rs) serves three read-only tools under cli-common's MCP
profile (DESIGN.md §1.9): `wealthfront_accounts` (each account's value and
their total), `wealthfront_activity` (the feed's transactions over a date
range) and `wealthfront_documents` (statements and trade confirmations,
listed, never downloaded). They read through the `Source` trait;
`LiveSource` wraps the same `Ctx` and fetchers the commands use, one read at
a time, because each successful read writes a rotated session cookie back to
the keychain and two at once could leave the older rotation stored. The
tools never sign in: an auth error asks the user to run `wfr auth login
--browser` in a terminal (the profile's standard remedy names plain `auth
login`, whose second-factor step is unverified).

- Tests: `src/mcp/tests.rs` runs every tool in process over the fixtures
  through a fixture `Source` and cli-common's conformance helper;
  `tests/mcp_stdio.rs` drives the binary over stdio without reading the
  keychain; `tests/packaging.rs` holds `packaging/mcpb/manifest.json` to the
  binary.
- Budget: the definitions stay under 8,000 characters together
  (`the_definitions_stay_small` prints each size). Shorten a description
  before adding a field.
- Releases attach `wfr-<version>.mcpb`, a Claude Desktop extension with no
  settings: it reads the keychain session.

## Tests

Offline, no mocking library. `assert_cmd` + `predicates`, plus
`pk-cli-browser`'s `test-util` feature, nothing else. The feature is a
dev-dependency only, so `cargo tree -e normal` shows `pk-cli-browser` without
it and the binary is built without it.

- `tests/cli_surface.rs` — black-box: every command's `--help` renders (this is
  what catches a subcommand flag colliding with a global like `-a`/`-q`), exit
  codes, the `--json` error DTO, `info`, completions, and the full `import csv`
  behavior end to end.
- `tests/fixture_shapes.rs` — contract tests over the fixtures, plus the
  privacy rules (below).
- Unit tests inline in `#[cfg(test)] mod tests`.

**Tests never set or remove an environment variable.** The process
environment is shared by every test, and they run in parallel. `clippy.toml`
disallows `std::env::set_var` and `std::env::remove_var`, so `make lint` fails
on a new use. Pass the value to the pure function that decides on it instead,
as `client::base_from` takes `WFR_BASE_URL`'s. Where only a real parse shows
the behavior, set the variable on a child process: the `WFR_ACCOUNT` test
re-runs one unit test in this test binary with the variable set
(`env_account_reaches_the_parse_but_never_narrows_net_worth`). `wfr
net-worth` itself cannot show it offline, because it reads the session from
the keychain before it narrows.

**HTTP paths run against `src/loopback.rs`,** a std-only server on 127.0.0.1
that records each request. Point the client at it with an explicit base
(`Wf::with_base`, `Wf::from_bundle_at`).

**The browser login's confirm hook is tested without a browser.**
`Captured::for_test` (the `test-util` feature) builds the capture the crate
would hand over, and `confirm_session_with` takes the client that makes the
`/capitan/v1/me` read, so each `Confirm` outcome is pinned against the loopback
server: no jar fails before any read, a JSON object is `Ready` and the read
sends the jar with `x-csrf-token`, a signed-out answer is `NotYet`, and
anything else (an empty or `null` 200 included) ends the wait as exit 5.

## Fixtures and privacy

**Fixtures here are synthetic, not scrubbed captures.** No real Wealthfront
data has ever been in this repo. The *shapes* come from public sources; the
values are invented. See `tests/fixtures/README.md`.

The repo is private but written as though public, and
`tests/fixture_shapes.rs` enforces that over **all git-tracked files**, not
just fixtures — a real value in a doc comment is exactly as published as one in
a fixture. Rules are stated *positively* (identity-bearing values must match a
known dummy shape) rather than as a denylist, because a denylist publishes
what it exists to hide.

If you ever take a real capture: scrub it **before** it reaches the working
tree. A live session cookie or a pre-signed URL is a working credential, and
`git` remembers.

## macOS signing

`cargo install` ad-hoc signs, minting a new code identity each time, and macOS
scopes keychain "Always Allow" grants to that identity — so every reinstall
silently revokes the grant and the next run prompts again. `make install` and
`make dev` re-sign with the stable shared identity from
`cli-common/scripts/dev-sign.sh`. Verify with `codesign -dv $(which wfr)`:
you want `pk-cli-codesign`, not `Signature=adhoc`. **`self-update` installs the
release asset, which is NOT dev-signed** — after it, re-run `make install` or
expect keychain prompts.

**The headless manifestation is an infinite silent hang, not a prompt.** A
keychain approval dialog raised for a process spawned from a non-TTY shell
blocks with no terminal output at all (the 2026-09-01 login hang: 5+ minutes,
no output, no SMS — killed; `docs/api.md`, 2026-09-01 follow-up). `auth login`
therefore (a) performs **no pre-network keychain read at all** on a headless
run — neither the stored password nor device trust — where "headless" is
`--stdin`, `--from-env`, `--overwrite`, or a piped (non-TTY) stdin with no
flags, (b) announces every keychain access on stderr *before* making it, so the
last line names what is blocking, and (c) stores the password only after the
provider accepts it. Keep those properties when touching the login flow; the
regression tests are `headless_login_with_piped_stdin_never_prompts_or_hangs`
and `bare_piped_stdin_without_flags_is_headless_too`.

## CI

Linux only, on purpose. The suite is entirely offline, so a macOS runner would
cost ~10x and exercise nothing extra. Releases are cut by pushing a `v*` tag
whose version matches `Cargo.toml` and `packaging/mcpb/manifest.json`
(`.github/workflows/release.yml` refuses a mismatch). They build both Apple
targets, `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc` as
`wfr-<target>.tar.gz` (the names `self-update` expects), plus
`wfr-<version>.mcpb`. A pull request that changes the workflow, `packaging/`,
`Cargo.toml` or `Cargo.lock` runs the same builds as a dry run.

Two jobs, both on `ubuntu-latest` with a read-only token. `verify` is fmt,
clippy, tests and the smoke run (`make verify`). `security` runs `cargo audit`,
which reads the whole lockfile, including entries behind features wfr does not
enable. It also runs `cargo deny check` against `deny.toml`, and gitleaks over
the full history. The tool versions are pinned (cargo-audit 0.22.2, cargo-deny
0.20.2, and gitleaks 8.24.3 by SHA-256). Mirror both jobs locally before
pushing: `make verify`, `cargo audit` and `cargo deny check`. Fix an advisory
with a minimal `cargo update -p <crate> --precise <version>`, in its own
commit.

## Definition of done

`make verify` green, CI green, dogfooded through the **installed** binary
(`make install` — a stale `~/.cargo/bin/wfr` will happily serve old behavior),
`--json` and human output in sync, `docs/api.md` matching reality including its
honesty labels, and no personal data anywhere in the diff.

For the MCP tools, drive the installed `wfr mcp` over stdio with JSON-RPC
lines (`initialize`, `tools/list`, `tools/call`); `wfr mcp --list-tools`
prints the definitions without a credential. To see the sign-in error
without opening the real session, set `WFR_KEYCHAIN_SERVICE` to a service
that holds nothing: a missing keychain item is read without a prompt and
fails as "not logged in". The variable only renames which entry is read; it
never carries a session.
