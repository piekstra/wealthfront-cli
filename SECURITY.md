# Security

## Scope

`wfr` is **read-only**. It lists accounts, activity and documents, downloads
document files, and parses CSV exports. It does not move money, place trades,
or change account settings. If that ever changes, this file and the README
claim must change in the same commit as the first write.

## Where secrets live

Only in the OS keychain, under the service `piekstra.wfr`:

| Account | Contents |
|---|---|
| `password` | Wealthfront login password (or app-specific password) |
| `session` | authenticated session cookie bundle |
| `pending-login` | an in-flight login parked mid-MFA |
| `device` | remember-this-device token, if the site issues one |

Secrets enter only via an interactive prompt, `--stdin`, or `--from-env <VAR>`
— **never** as a command-line argument, never from a config file, never
written to a log. `--verbose` does not print secrets, cookies, or full account
numbers.

`wfr auth logout` clears the session and any parked login; `--forget` also
removes the stored password, device token, and config identity.

## Browser sign-in

`wfr auth login --browser` runs cli-common's `pk-cli-browser`
([cli-common DESIGN.md §2.2](https://github.com/piekstra/cli-common/blob/v0.14.0/DESIGN.md)).
You type the password and the 2FA code on Wealthfront's own page in a Chrome
window; they never pass through `wfr`. While the window is open:

- **The debug port has no authentication.** Chrome is launched with a
  DevTools port, and anything that can reach `127.0.0.1:<port>` or read the
  profile's `DevToolsActivePort` file can read every cookie in the window. So
  the profile is created `0700`, exclusively (an existing path is refused,
  never adopted), under an unpredictable name in the temp dir. It is deleted
  on every exit, Ctrl-C included; a second Ctrl-C kills Chrome and deletes it
  at once. A profile that cannot be removed is reported on stderr even under
  `-q`, since it may hold the session.
- **Only Wealthfront's cookies are read.** Pages count only on exactly
  `www.wealthfront.com` over `https`. The stored session is the cookies the
  browser would send to `wealthfront.com` or a host under it, matched label
  for label: `notwealthfront.com`, `wealthfront.com.evil.example` and punycode
  look-alikes never match. Nothing is evaluated in any page.
- **The candidate session goes to one place:** `GET /capitan/v1/me` on
  `www.wealthfront.com`, once per poll, through the same client as every read,
  to confirm the sign-in before the tab closes.
- **The session is never logged, put on a command line, or written to disk**
  outside Chrome's own profile. Messages name hosts and cookie names only. The
  session is stored only as the keychain `session` item.

## The MCP server

`wfr mcp` serves read-only tools to an MCP client (Claude Code, Claude
Desktop) over stdio, on this machine only; it opens no port. It uses the
session already in the keychain, exactly as the commands do, writing a
rotated cookie back in place, and never signs in: a missing or lapsed session
is an error asking the user to run `wfr auth login --browser` in a terminal.
No tool downloads a document or emits the numeric account id its download
URL needs. The Claude Desktop extension (`.mcpb`) takes no settings and so
holds no credential of its own; on macOS its bundled binary needs the user's
approval, once, to read the `piekstra.wfr` keychain item.

`WFR_KEYCHAIN_SERVICE` renames the keychain service read and written, for
tests and for checking the error paths against an empty service. It carries
no secret.

## App-specific password — not usable for wfr's own login

Wealthfront issues **read-only app-specific passwords** for third-party
linking (Settings → Security → "Link Wealthfront to other apps"). It is
read-only by construction and can be revoked independently without touching
your login. Note (2026-08-13): the app-specific password is **rejected by the
web login** ("Invalid email address or password", `docs/api.md` §3.3) — it is an
aggregator-linking credential, not a `wfr` login credential. A real `wfr` login
needs the real password + 2FA, entered on Wealthfront's own page through the
browser sign-in above, so there is no reason to store the app-specific password
for `wfr`.

## Verified and unverified surface

`docs/api.md` labels every endpoint with what is known about it. In short:

- **VERIFIED-LIVE:** `accounts list`, `net-worth`, `transactions list`,
  `documents list`/`download`, `api` and `auth status --verify` read the real
  API with a stored session (2026-08-18 to 2026-08-24). `wfr auth login
  --browser` was verified on 2026-08-18 with the capture this repo used to
  embed; the `pk-cli-browser` build that replaced it awaits the owner's next
  sign-in.
- **UNVERIFIED-LIVE:** the bare-HTTP `wfr auth login` reaches credential
  validation and 2FA (2026-08-31), but the body of its code-verify request has
  not been confirmed against a real login. The device-trust token has not been
  observed, and investment-account activity has no captured endpoint (the
  2021 `transfers-for-account` path 404s).

Practical consequences:

- Credentials and the session go only to `https://www.wealthfront.com`
  (`client::BASE`, a compile-time constant; no config key changes it) or to a
  loopback address. The `WFR_BASE_URL` environment variable is the one runtime
  override. It exists so the offline tests can drive the real login code
  against a fake server, and it is refused unless it is a plain `http` or
  `https` URL on `127.0.0.1`, `localhost` or `[::1]` with no user info. It
  applies to every Wealthfront request `wfr` makes, including the browser
  sign-in's confirm read; the Chrome window always opens `www.wealthfront.com`.
- Treat a success from an UNVERIFIED-LIVE path with suspicion until it has been
  confirmed against a real capture.

## Automation and terms of service

Wealthfront publishes no public API. This CLI automates a private surface,
which may conflict with Wealthfront's terms of service and can break without
notice. That is a decision to make knowingly.

## Reporting

This is a personal, private repository. Report issues directly to the owner.
Please do not include real account numbers, session cookies, pre-signed URLs,
or statement contents in an issue — a pre-signed URL is a live credential.
