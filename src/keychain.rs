//! Keychain account names under the service `piekstra.wfr`, and the store
//! that reads them.
//!
//! Four opaque strings, never a serialized struct — the family pattern is one
//! secret per account so a rotation or a partial logout can delete exactly one
//! thing. The *why* for each lives here rather than at the call sites.

use pk_cli_secrets::CredentialStore;

/// The Wealthfront login password.
pub const PASSWORD_ACCOUNT: &str = "password";

/// The authenticated session cookie bundle (`"k=v; k=v"`). Rewritten whenever
/// the site rotates a cookie, so the cached copy cannot go stale while
/// Wealthfront still considers the session live.
pub const SESSION_ACCOUNT: &str = "session";

/// An in-flight login parked mid-MFA.
///
/// `auth login` on an untrusted device sends a code and stores *the session
/// that requested it* here, so `wfr auth login --code <CODE>` resumes that
/// session. A second invocation that started a fresh login would present the
/// code against a session that never asked for one, and the site would reject
/// a code the user is holding and can see is correct — an infuriating and
/// completely opaque failure.
pub const PENDING_ACCOUNT: &str = "pending-login";

/// A remember-this-device token, when the site issues one, so later logins
/// skip the second factor. UNVERIFIED-LIVE: no capture confirms Wealthfront
/// issues one or what it is called.
pub const DEVICE_ACCOUNT: &str = "device";

/// Renames the keychain service read and written, for the test suite and for
/// dogfooding the error paths: pointed at a service that holds nothing, a
/// command reads a *missing* item, which needs no user approval and fails as
/// "not logged in", where the real service would open the user's actual
/// session (and, from the ad-hoc-signed binary `cargo test` builds, raise a
/// macOS keychain prompt). It names which entry is read; it never carries a
/// session.
pub const SERVICE_ENV: &str = "WFR_KEYCHAIN_SERVICE";

/// The credential store every command uses: `piekstra.wfr`, unless
/// [`SERVICE_ENV`] names another service.
pub fn store() -> CredentialStore {
    store_for(std::env::var(SERVICE_ENV).ok().as_deref())
}

/// [`store`]'s decision, given the variable's value, so a test can check it
/// without setting the process environment every test shares.
fn store_for(service: Option<&str>) -> CredentialStore {
    match service_override(service) {
        Some(s) => CredentialStore::new(s),
        None => CredentialStore::for_binary("wfr"),
    }
}

/// The service [`SERVICE_ENV`]'s value names, if any: a blank value names none.
fn service_override(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

/// Whether [`SERVICE_ENV`] points the keychain somewhere else. It does not move
/// the kept browser profile, so `auth logout` and `auth login --browser` leave that
/// alone while it does.
pub fn service_overridden() -> bool {
    service_override(std::env::var(SERVICE_ENV).ok().as_deref()).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blank value is no override: the real service is in use, as
    /// `store_for` decides.
    #[test]
    fn a_blank_variable_is_no_override() {
        assert_eq!(service_override(None), None);
        assert_eq!(service_override(Some("")), None);
        assert_eq!(service_override(Some("  ")), None);
        assert_eq!(service_override(Some(" dummy ")), Some("dummy"));
    }

    #[test]
    fn the_service_is_wfr_s_unless_the_variable_names_another() {
        assert_eq!(store_for(None).service(), "piekstra.wfr");
        assert_eq!(store_for(Some("")).service(), "piekstra.wfr");
        assert_eq!(store_for(Some("  ")).service(), "piekstra.wfr");
        assert_eq!(
            store_for(Some("piekstra.wfr-empty")).service(),
            "piekstra.wfr-empty"
        );
    }
}
