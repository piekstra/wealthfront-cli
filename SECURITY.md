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

The one exception is the browser profile a `--browser` sign-in keeps (below),
where Wealthfront's session cookies also sit.

`wfr auth logout` clears the session and any parked login, and removes the kept
browser profile (below); `--forget` also removes the stored password, device
token, and config identity.

## Browser sign-in

`wfr auth login --browser` runs cli-common's `pk-cli-browser` ([cli-common
DESIGN.md §2.2](https://github.com/piekstra/cli-common/blob/v0.19.0/DESIGN.md)).
You type the password and the 2FA code on Wealthfront's own page in a Chrome
window; they never pass through `wfr`. While the window is open:

- **The debug port has no authentication.** Chrome is launched with a DevTools
  port, and anything that can reach `127.0.0.1:<port>` or read the profile's
  `DevToolsActivePort` file can read every cookie in the window. So the profile
  is owner-only (below), and Chrome is stopped on every exit (a kept profile's
  is asked to quit first, so a cookie set just before the close is on disk),
  Ctrl-C included; a second Ctrl-C kills it at once.
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

**The browser profile stays on disk between sign-ins**, so Wealthfront remembers
the device. It lives at
`~/Library/Application Support/piekstra.wfr/browser-profile` on macOS
(`$XDG_DATA_HOME/piekstra.wfr/browser-profile`, or under `~/.local/share`, on
Linux). It is a full Chrome profile, so it holds more than the session:

- **Cookies**, Wealthfront's session among them. Chrome encrypts these at rest,
  on macOS with the "Chrome Safe Storage" key in the login keychain and on Linux
  with the desktop keyring. **On Linux with no desktop keyring it falls back to a
  fixed, publicly known key**, so there the session cookie is effectively
  unencrypted and `0700` is its only protection. Use `--fresh-profile` on such a
  machine.
- **Browsing history with full URLs including query strings, the HTTP cache and
  site storage** (`localStorage`, IndexedDB). Chrome's cookie encryption does not
  cover these, and the directory's `0700` mode is their only protection. The
  cache can hold what Wealthfront's pages loaded during a sign-in.
- **It sits where ordinary backups look.** Time Machine and home-directory
  backups usually include this directory, so a copy can outlive the profile, and
  `wfr auth logout` cannot reach a backup. Exclude the directory from backups, or
  use `--fresh-profile`, if that matters to you.

So:

- The profile is created `0700`, and a launch is refused when it is a symlink,
  is not your user's or is not `0700`.
- One sign-in uses it at a time. A second, or a launch while a Chrome still runs
  in it, is refused (exit 1).
- `wfr auth logout` removes it, and refuses while it is in use or when it is a
  symlink or another user's. Every step of a logout is attempted, so a refusal
  or a failed keychain or config step leaves the rest done. The error says what
  was cleared and what remains, names the path and says how to finish, with the
  first failure's exit code. A logout does not parse the config, so a file that
  can't be parsed stops nothing, and `--forget` removes it.
- A sign-in that fails once Chrome may have used it leaves it in place, possibly
  signed in: a timeout, a closed window, Ctrl-C, a confirm read that ends the
  wait, a keychain write that fails after the capture. The error says so and
  names `wfr auth logout`, which removes it and clears the stored session too. A
  second Ctrl-C kills Chrome with no such message. A launch refused before
  Chrome uses it (no Chrome, a profile in use or needing repair) says nothing
  about it, since `auth logout` would refuse the same profile. `wfr auth status`
  reports whether one is kept, not whether it is signed in.
- A session cookie left in it from an earlier sign-in is not trusted alone: only
  a `GET /capitan/v1/me` that answers a non-empty account object accepts a
  session, so an unverified session cannot replace a working one.
- `--fresh-profile` runs one sign-in in a scratch profile instead, created
  `0700`, exclusively (an existing path is refused, never adopted), under an
  unpredictable name in the temp dir, and removed when the window closes. One
  that cannot be removed is reported on stderr even under `-q`, since it may
  hold the session.
- Windows has no kept profile: every sign-in there uses a scratch one.

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

`WFR_KEYCHAIN_SERVICE` renames the keychain service read and written, for tests
and for checking the error paths against an empty service. It carries no secret.
A service it names is a test namespace, and must not read or change the real
kept browser profile or the real config. While it names one, `wfr auth logout`
clears that service, leaves the real profile in place and says so, `wfr auth
login --browser` uses a scratch profile, as with `--fresh-profile`, and says so
in one line on stderr, `auth logout --forget` leaves the real config and says
so, and `wfr auth status` reads nothing about the real profile, leaves
`browser_profile` out and says so. A `--config` you name is still cleared. A
blank value names no service.

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
