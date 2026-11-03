# wfr — Wealthfront from the command line

A [piekstra CLI family](https://github.com/piekstra/cli-common) member for
[Wealthfront](https://www.wealthfront.com). Rust, keychain-secured, `--json` on
every command, agent-friendly.

Conforms to `piekstra-cli` spec v1. Read-only: nothing in this CLI moves money
or changes anything in your account.

Unofficial; not affiliated with or endorsed by Wealthfront.

## Honest status

Wealthfront publishes **no public API**. This CLI wraps the reverse-engineered
web API; a first-party live capture on **2026-08-18** authenticated and verified
the reads end to end. The important nuance: **the reads work once a session
cookie is in the keychain, and the verified way to get one is a browser
sign-in** — `wfr auth login --browser`, with the real password + 2FA (the
app-specific password is rejected, [`docs/api.md`](docs/api.md) §3.3). That
splits the surface in three:

| Command | Status |
|---|---|
| `wfr import csv <FILE>` | **Verified offline.** Parses the activity CSV export with no credential and no network. Covered end to end by the test suite. |
| `wfr accounts list`, `transactions list`, `api`, `auth status --verify` | **VERIFIED-LIVE (2026-08-18).** Read the real `/capitan/v1/` API (accounts, activity) using the stored session cookies + the `x-csrf-token` derived from the `xsrf` cookie. They work whenever a valid session is in the keychain. |
| `wfr auth login --browser` | **VERIFIED-LIVE (2026-08-18)** with the Chrome capture this repo used to embed; it now runs on cli-common's shared `pk-cli-browser`, which makes the same reads and awaits the owner's next live sign-in. Opens a real Chrome window so you sign in (password + 2FA); the CLI reads the wealthfront.com cookies over the DevTools protocol, confirms them with `GET /capitan/v1/me` before the tab closes, and stores them ([`docs/api.md`](docs/api.md) §3.6). The bare-HTTP `wfr auth login` (no browser) reaches 2FA too since 2026-08-31, but its code step is UNVERIFIED-LIVE ([`docs/api.md`](docs/api.md), the 2026-08-31 diagnosis). |
| `wfr documents list`, `documents download` | **VERIFIED-LIVE (2026-08-19).** Lists your statements + trade confirmations (`/api/documents/statements`) and downloads a document PDF (`/documents/{account}/document/{externalId}`, gated on `%PDF`). |
| `wfr net-worth` | **VERIFIED-LIVE (2026-08-24).** Rolls the VERIFIED-LIVE accounts read (`/capitan/v1/accounts/overviews2`) into the family `net-worth/v1` DTO — household `total`/`assets` (and `liabilities`, only if an account stands negative) plus per-account rows. Smoked against a live session: three real accounts (PERSONAL_CASH/JOINT_CASH/JOINT), total equal to their sum ([`docs/api.md`](docs/api.md) §3.5). |

If you want Wealthfront data with no login at all, `import csv` today (and see
[`docs/api.md`](docs/api.md) §10 for the future `import qfx`). Otherwise
`wfr auth login --browser` gets you a live session, then the reads above work.

## Install

```sh
cargo install --git https://github.com/piekstra/wealthfront-cli --locked
# or, from a clone:
make install
```

## The verified part: importing a CSV export

Wealthfront's Cash Account CSV export (Activity → export) becomes the family
`transaction-list/v1` shape:

```sh
wfr import csv ~/Downloads/activity.csv
wfr --json import csv ~/Downloads/activity.csv | jq '.items[] | select(.kind == "dividend")'
wfr import csv activity.csv --kind interest --since 2026-01-01 --until 2026-12-31
cat activity.csv | wfr --json import csv -
```

```json
{
  "schema": "transaction-list/v1",
  "items": [
    { "date": "2026-01-31",
      "amount": { "amount": "4.11", "currency": "USD" },
      "description": "Interest earned",
      "kind": "interest" }
  ],
  "total": 1
}
```

It handles what real exports actually contain: a UTF-8 BOM, preamble lines
above the header, `Transaction date` vs `Transaction Date`, quoted fields with
embedded commas, four date spellings, `$1,234.56` / `(250.00)` / `2.08-`
amounts, blank rows, and totals footers. Rows that are not transactions are
skipped and **counted on stderr** — never silently dropped. `--strict` turns
the first such row into a failure instead.

Two conventions worth knowing:

- **Sign is account-perspective:** money in is positive, money out negative,
  exactly as the export writes it.
- **Unknown activity types pass through verbatim.** `harvest` stays `harvest`
  rather than being flattened into `sell`, because that distinction is the
  whole point at tax time.

## Signing in and reading your data

The verified sign-in opens a real browser; the reads then run over plain HTTP
against the live API:

```sh
wfr config set username you@example.com
wfr auth login --browser             # opens Chrome; sign in (password + 2FA); session captured
wfr auth status --verify             # confirms the stored session is live

wfr accounts list                    # VERIFIED-LIVE
wfr net-worth --json                 # every account's balance rolled up (net-worth/v1)
wfr transactions list -a <ACCOUNT_ID> --since 2026-01-01   # VERIFIED-LIVE
wfr documents list                   # VERIFIED-LIVE: statements + trade confirmations
wfr documents download <ID> -o ~/Documents/   # VERIFIED-LIVE: writes the document PDF

wfr api GET /capitan/v1/accounts     # real API base (needs a live session)
```

`--browser` opens Chrome at the Wealthfront login and waits up to 10 minutes
while you sign in; Ctrl-C cancels. Once `GET /capitan/v1/me` accepts the window's
wealthfront.com cookies, the tab closes, Chrome quits, and the cookies are stored
as the keychain `session`. Set `WFR_CHROME` to a Chrome binary outside the
standard install paths. The mechanism is cli-common's `pk-cli-browser`
([`docs/api.md`](docs/api.md) §3.6).

**The profile is kept.** Chrome runs in a profile `wfr` keeps on disk, owner-only
(`0700`), at `~/Library/Application Support/piekstra.wfr/browser-profile` on
macOS and `$XDG_DATA_HOME/piekstra.wfr/browser-profile` (or under
`~/.local/share`) on Linux. Wealthfront's own cookies stay there between
sign-ins, so a later `--browser` asks for less, often nothing: the window opens,
the app loads signed in, the session is read and the window closes. On Windows
every sign-in uses a scratch profile.

That is a trade: far fewer sign-ins, for a full Chrome profile on disk. Besides
Wealthfront's cookies, it holds browsing history with full URLs including query
strings, the HTTP cache and site storage. Chrome's cookie encryption does not
cover those, so `0700` is their only protection, and the directory is one
ordinary backups usually include. On Linux with no desktop keyring, Chrome
encrypts cookies with a fixed, publicly known key, so `0700` is all that protects
the session cookie too: use `--fresh-profile` there. See
[SECURITY.md](SECURITY.md).

- `wfr auth login --browser --fresh-profile` signs in through a scratch profile
  deleted afterwards, and leaves the kept one alone. Wealthfront sees a new
  device, so expect its full sign-in.
- `wfr auth logout` removes the kept profile too, so the next sign-in starts
  signed out. Every step is attempted: if one fails, or a sign-in or a Chrome is
  using the profile, the rest is still cleared, and the error says what was
  cleared and what remains, with the first failure's exit code. Fix that and log
  out again.
- A sign-in that fails once Chrome may have used the kept profile, Ctrl-C
  included, leaves it in place, possibly signed in, and its error says so. `wfr
  auth logout` removes it, and clears the stored session too. `wfr auth status`
  does not report the profile.

Wealthfront requires two-factor authentication on **every** account with no way
to disable it. A login that needs a code parks its in-flight session in the
keychain, so `--code` resumes exactly the session that requested the code —
a fresh login would present it against a session that never asked, and be
rejected. See [`docs/api.md`](docs/api.md) §3.

`wfr api` is the important one while the surface is unverified: it is how you
discover the real response shapes, and every mapping in `src/commands/` is
meant to be corrected from what it prints.

## Use with Claude

`wfr mcp` serves three read-only tools over MCP, so Claude can answer
questions about your own Wealthfront accounts. There is no hosted service:
the tools run on your computer, in your copy of `wfr`, and call Wealthfront's
web API directly with the session `wfr auth login --browser` stored in your
OS keychain.

| Tool | Answers |
| --- | --- |
| `wealthfront_accounts` | What is each account worth, and what is the total? Each account's name, type and current value, with the total over them, narrowed by `account` (its name) |
| `wealthfront_activity` | What moved in or out over a period? Deposits, withdrawals, interest, fees and the rest of the activity feed's transactions by `since`/`until` dates (year to date by default), `account` and `type` |
| `wealthfront_documents` | Which statements exist? Statements and trade confirmations by `type` (`statement`, `confirm`, `green-dot-statement`) and `since`/`until`; never downloaded (`wfr documents download` does that). Tax forms are not in this list |

Results are concise by default (`response_format: "detailed"` adds ids), 25
records a page with a cursor for more, and never larger than about 32,000
characters. Accounts are named, not numbered. Descriptions come from
Wealthfront; the server tells Claude to treat them as data, not
instructions. There is no holdings tool: no `wfr` command reads positions yet.

**Sign in first.** Wealthfront sign-in is through a browser, so no settings
form can hold it. Install `wfr` and run `wfr auth login --browser` in a
terminal (see [Signing in](#signing-in-and-reading-your-data)). Both ways of
connecting Claude below then use that session from the OS keychain (service
`piekstra.wfr`), writing a rotated cookie back as the commands do. If the
session is missing or has lapsed, the tools say so and ask you to run
`wfr auth login --browser` in a terminal; they never sign in by themselves.

**Claude Code.** Add the `wealthfront-cli` plugin from the
[piekstra plugin marketplace](https://github.com/piekstra/claude-plugins):

```console
$ claude plugin marketplace add piekstra/claude-plugins
$ claude plugin install wealthfront-cli@piekstra-plugins
```

or register the server yourself:

```console
$ claude mcp add wealthfront -- wfr mcp
```

**Claude Desktop.** Download `wfr-<version>.mcpb` from the
[latest release](https://github.com/piekstra/wealthfront-cli/releases/latest)
and open it. It asks for nothing: the bundled `wfr` reads the session your
installed `wfr` stored. On macOS the bundled binary is a different program
to the keychain, so its first call raises a keychain prompt for the
`piekstra.wfr` item; choose **Always Allow**, or every call will ask again.

Any other MCP client that launches a local server can run `wfr mcp`.

## Standard surface

```
wfr auth login|status|logout|set-credential
wfr config path|show|set|unset
wfr accounts list|get <ID>
wfr net-worth                  (net-worth/v1 rollup; only a typed -a narrows —
                                WFR_ACCOUNT and the config default don't)
wfr transactions list          (alias: activity)
wfr documents list|download <ID>
wfr import csv <FILE>
wfr api <METHOD> <PATH> [--data JSON]
wfr mcp [--list-tools]         (read-only tools for Claude; see Use with Claude)
wfr self-update [--check] [-y]
wfr completions <shell>
wfr info
```

Global flags: `--json`, `-v/--verbose`, `-q/--quiet`, `--no-color`,
`-a/--account`, `--config`.

Exit codes: `0` ok · `2` usage · `3` auth · `4` not found · `5` upstream ·
`6` confirmation required.

## Security

Secrets live only in the macOS keychain under `piekstra.wfr` — never in argv,
never in a file, never in a log. Four entries: `password`, `session`,
`pending-login`, `device`. See [SECURITY.md](SECURITY.md).

## Development

```sh
make verify     # fmt-check + lint + test + smoke — the CI gate
make install
```

The test suite is **fully offline**: no network, no keychain, no credential.
That is deliberate — logging in costs a rate-limited SMS code, so a suite that
needed one would be a suite nobody could run. See [AGENTS.md](AGENTS.md).

## License

MIT
