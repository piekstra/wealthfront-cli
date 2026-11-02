# Contributing

Start with **[AGENTS.md](AGENTS.md)** — it is the canonical guide. This file is
the short version of the mechanics.

## Setup

```sh
cargo build
make verify      # fmt-check + lint + test + smoke — the CI gate
make install     # installs and re-signs (see AGENTS.md on macOS signing)
```

## Before you push

`make verify` must be green. It runs exactly what CI runs, so a green local run
predicts a green CI run.

## House rules

- `--json` valid on every command; one DTO on stdout, schema-tagged; text to
  stdout, diagnostics to stderr; **exactly one JSON document per invocation**.
- Exit codes: `0` ok · `2` usage · `3` auth · `4` not found · `5` upstream ·
  `6` confirmation required.
- ISO `YYYY-MM-DD` on every date flag. `--limit`/`--since`/`--until` come from
  `RangeArgs`; do not invent new pagination flags.
- Secrets only via keychain, `--stdin`, or `--from-env`. Never argv.
- Validate arguments before touching the keychain or the network.
- Reuse `pk-cli-*` before writing a helper — dates, money, output, paging and
  range flags all already exist.

## Tests are offline, always

No network, no keychain, no credential. Logging in to Wealthfront costs a
rate-limited SMS code; a suite that needed one would be a suite nobody could
run. Keychain-touching assertions go behind `WFR_TEST_KEYCHAIN=1`.

Add tests with the change:

- a black-box case in `tests/cli_surface.rs` for a new command or flag,
- a contract assertion in `tests/fixture_shapes.rs` if you touch a mapping,
- unit tests inline for parsing logic.

## Fixtures

Synthetic only. Never commit a real capture — a session cookie or a pre-signed
URL is a working credential, and git remembers. Document any new fixture in
`tests/fixtures/README.md`; a test enforces that.

## If you confirm something live

The HTTP surface is UNVERIFIED-LIVE. When you capture real requests:

1. correct `src/client.rs::endpoints` and the key lists in `src/commands/`,
2. update `docs/api.md` — including removing the specific UNVERIFIED-LIVE
   labels you have earned the right to remove, and adding what surprised you to
   the Traps section,
3. scrub captures into synthetic fixtures before they reach the working tree.
