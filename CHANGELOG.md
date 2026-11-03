# Changelog

## v0.3.3 — 2026-11-03

Built on cli-common v0.20.0.

- A `wfr auth login --browser` that runs out of time before you finish signing in
  now says what `GET /capitan/v1/me` answered, where it used to say only "answered
  as signed out". Still exit 3.
- A read that can't decide no longer ends the sign-in, and an edge block no longer
  reads as a dead session. That is a 429, a 5xx, a dropped connection, an edge
  block's page (an HTML 403, or a page behind a 200 titled as a challenge), or a 200
  that is empty, `null` or not JSON. The window stays open, since the session cookies
  do not survive the stop, and cli-common asks again after a backoff of 6 s, doubling
  to 60 s, or longer if Wealthfront's `Retry-After` asks. Its first such answer prints
  one status line, unless `-q`, saying Ctrl-C ends the wait. **A wait that runs out on
  it is exit 5**, not exit 3 as an edge block was, because signing in again fixes
  nothing. A 404 still ends the sign-in at once, since no later poll can change it.
- A 200 alone no longer accepts a session, on any path. `GET /capitan/v1/me` must
  show a non-empty `emailAddress` or `userIdExternalized`. In a browser sign-in a
  parseable answer without one keeps the wait going, where it used to end it. The
  password login and `auth status --verify` report it as exit 5, as before.
- `wfr auth login --json` used to run and print nothing on stdout. It now prints
  `auth-login/v1` on every path that stores a session, with `verified: true`. Every
  path stores a session only after that read showed an account, so it is never
  `false`.
- Outside a sign-in, a 403's HTML page, or a page behind a 200 titled as a challenge,
  names itself as a possible bot check or edge block (exit 3): a new sign-in may not
  clear it, so wait or try another network. Any other 403 names both causes. Exit
  codes are unchanged. The text holds a status, never a cookie value or the page.
- `wfr auth login --help` no longer offers `--no-verify`, which no login path
  reads. It still parses without `--browser`, so a script that passes it does not
  break.

## v0.3.2 — 2026-11-03

`wfr auth login --browser` now refuses every login flag it does not read, with
exit 2 and the flag named on stderr. Each of these used to parse and be ignored.
A script that passes one beside `--browser` must drop it:

- `--code`: the browser sign-in ran, and a parked login stayed parked.
- `--no-verify`, `--overwrite`, `--non-interactive` and `--channel`: the sign-in
  ran the same with or without them.

`--stdin` and `--from-env` were already refused. `--fresh-profile` stays allowed.
These flags still parse without `--browser`.

## v0.3.1 — 2026-11-03

Moves to cli-common v0.19.0. The minimum Rust version is now 1.89.

- A sign-in in the kept profile now asks Chrome to quit before stopping it, so a
  remember-this-device cookie set just before the window closes is on disk for
  the next sign-in. Measured by cli-common in headless Chrome only: on v0.16.0 a
  cookie written just before the close survived 6 of 40 runs, and on v0.19.0 40
  of 40. A stuck Chrome can hold `wfr` for up to 11 s, up from 6 s.
- `wfr auth status` reports `browser_profile` within `auth-status/v1`: whether a
  profile is kept, not whether it is signed in. A profile that needs repair is a
  warning on stderr and leaves the field out.
- While `WFR_KEYCHAIN_SERVICE` names a service, `wfr auth status` reads nothing
  about the real profile, leaves `browser_profile` out and says so on stderr.
- `wfr auth login --fresh-profile` without `--browser` is a usage error (exit 2)
  whichever other flag is beside it. It used to parse beside `--stdin` or
  `--from-env`, and the flag was ignored.

## v0.3.0 — 2026-11-03

Moves to cli-common v0.16.0. A browser sign-in now runs in a profile `wfr`
keeps, where it used to run in a scratch profile deleted after every sign-in.

- `wfr auth login --browser` keeps its Chrome profile on disk, owner-only
  (`0700`), at `~/Library/Application Support/piekstra.wfr/browser-profile` on
  macOS and `$XDG_DATA_HOME/piekstra.wfr/browser-profile` (or under
  `~/.local/share`) on Linux, so Wealthfront's own cookies carry over and later
  sign-ins need less input. Windows still uses a scratch profile every time.
- `wfr auth login --browser --fresh-profile` runs one sign-in in a scratch
  profile, and leaves the kept one alone.
- `wfr auth logout` also removes the kept profile, as its last step. It exits 1
  with the crate's message while a sign-in or a Chrome is using the profile, or
  when the path is a symlink or another user's; the keychain items are cleared
  by then, and the error and `auth logout --help` say so.
- `wfr auth logout` attempts every step even when one fails or the config can't
  be parsed, and says what was cleared and what remains, with the first
  failure's exit code. `--forget` clears a config that can't be parsed.
- `GET /capitan/v1/me` answering `{}` no longer counts as signed in.
- While `WFR_KEYCHAIN_SERVICE` names a service, `wfr auth logout` leaves the
  real profile and config in place and `wfr auth login --browser` uses a scratch
  profile, and each says so.
- A `--browser` failure once Chrome may have used the kept profile says the
  profile stays and that `wfr auth logout` removes it.
- SECURITY.md and the README state what the kept profile holds: it is a full
  Chrome profile, with history, HTTP cache and site storage outside Chrome's
  cookie encryption, `0700` as their only protection, in a directory backups
  usually include. On Linux with no desktop keyring the session cookie has only
  `0700` too.
