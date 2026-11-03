# Changelog

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
- While `WFR_KEYCHAIN_SERVICE` names a service, `wfr auth logout` leaves the real
  profile in place and `wfr auth login --browser` uses a scratch profile, and each
  says so.
- Every `--browser` failure in the kept profile says the profile stays and that
  `wfr auth logout` removes it.
- SECURITY.md and the README state what the kept profile holds: it is a full
  Chrome profile, with history, HTTP cache and site storage outside Chrome's
  cookie encryption, `0700` as their only protection, in a directory backups
  usually include. On Linux with no desktop keyring the session cookie has only
  `0700` too.
