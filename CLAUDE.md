# CLAUDE.md

See **[AGENTS.md](AGENTS.md)** — it is the canonical guide for this repo.

Three things that bite immediately:

- **Logging in costs a rate-limited SMS code**, and Wealthfront's 2FA cannot be
  disabled. The test suite is offline for that reason — keep it that way, and
  don't trigger `auth login` against the live site just to test unless you mean
  to. `--channel totp` is free; prefer it.
- **Reads and browser login both VERIFIED-LIVE.** As of 2026-08-18 `wfr accounts
  list` / `transactions list` / `api` read the real `/capitan/v1/` API given a
  session — auth needs the session cookies **plus `x-csrf-token`** (URL-decoded
  `xsrf` cookie, `docs/api.md` §3.4). Getting the session is **`wfr auth login
  --browser`** (`src/commands/auth.rs`, on cli-common's `pk-cli-browser`):
  launches a plain Chrome (reCAPTCHA-safe), you sign in, it captures, confirms
  and stores the session (`docs/api.md` §3.6; the shared-crate build awaits the
  owner's next live sign-in). The bare-HTTP `wfr auth login` reaches 2FA too
  (2026-08-31), but its code step is UNVERIFIED-LIVE, so `--browser` is the
  verified path; the **app-specific password is rejected** either way. `wfr
  documents list`/`download` are VERIFIED-LIVE too (2026-08-19,
  `/api/documents/statements`). Don't present a guessed/uncaptured endpoint as
  working — but almost everything is captured now.
- **Fixtures are synthetic and the privacy tests scan every tracked file**, not
  just `tests/fixtures/`. Never commit a real capture.
