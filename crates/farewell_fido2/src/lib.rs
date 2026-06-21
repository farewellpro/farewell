//! FIDO2/CTAP2 hardware-key client for Farewell.
//!
//! Farewell uses the CTAP2 `hmac-secret` extension to bind vault unlock
//! to the physical presence of an enrolled authenticator (YubiKey,
//! Nitrokey, SoloKey, OnlyKey, etc.). At enrollment, a non-discoverable
//! credential is created on the authenticator. At unlock, a fixed salt
//! is presented; the authenticator returns a 32-byte HMAC output that
//! the authenticator alone can compute. This output is mixed into the
//! key derivation, so that a passphrase alone cannot unlock the vault.
//!
//! This crate exposes a transport-agnostic [`Authenticator`] trait so
//! that:
//!
//! - production builds use a real USB HID transport ([`HidAuthenticator`])
//!   that drives a physically-connected FIDO2 authenticator (YubiKey,
//!   Nitrokey, SoloKey, OnlyKey) via the `ctap-hid-fido2` crate,
//! - tests and dev builds use [`MockAuthenticator`] — a deterministic,
//!   software-only implementation that satisfies the trait and lets the
//!   rest of the stack be exercised end-to-end without hardware.
//!
//! The `Authenticator` trait deliberately mirrors CTAP2's allow-list
//! semantics: a single physical authenticator (one trait instance) may
//! be queried with multiple candidate credential IDs and returns the
//! one it recognizes plus its HMAC output. This matches what the
//! `authenticatorGetAssertion` request does on the wire.

#![deny(missing_docs)]
// We need limited `unsafe` only to invoke the ctap-hid-fido2 device
// (its API is safe Rust; the unsafe stays out of this crate). For now
// the crate forbids unsafe in all code we write.

use std::collections::HashMap;

use ctap_hid_fido2::{
    fidokey::{
        AssertionExtension as GAExt, CredentialExtension as McExt, GetAssertionArgsBuilder,
        MakeCredentialArgsBuilder,
    },
    get_fidokey_devices, verifier, Cfg, FidoKeyHid, FidoKeyHidFactory, HidParam,
};
use rand::Rng;
use rand_core::OsRng;
use thiserror::Error;
use zeroize::Zeroize;

/// Length of an `hmac-secret` output in bytes (HMAC-SHA-256).
pub const HMAC_OUTPUT_LEN: usize = 32;

/// Length of the salt presented to the authenticator.
pub const HMAC_SALT_LEN: usize = 32;

/// Maximum credential ID length we accommodate in the vault format.
pub const MAX_CRED_ID_LEN: usize = 256;

/// Errors that can be returned by an authenticator.
#[derive(Debug, Error)]
pub enum Fido2Error {
    /// No matching credential — the authenticator does not own any of
    /// the candidate credential IDs supplied. The user likely plugged in
    /// the wrong device.
    #[error("no matching credential on this authenticator")]
    NoMatchingCredential,

    /// The user did not confirm presence (no touch / no PIN), or
    /// cancelled.
    #[error("user cancelled or did not confirm presence")]
    UserCancelled,

    /// Transport-level failure (USB HID disconnect, NFC out of range,
    /// CBOR decoding error, etc.).
    #[error("transport error: {0}")]
    Transport(String),

    /// Authenticator returned a CTAP error code.
    #[error("authenticator protocol error: code={0:#04x}")]
    Protocol(u8),

    /// Credential ID too large to fit in the vault format.
    #[error("credential ID too large: {got} bytes (max {MAX_CRED_ID_LEN})")]
    CredentialTooLarge {
        /// Actual size received.
        got: usize,
    },
}

/// Transport-agnostic FIDO2 authenticator, bound to a single `rp_id` at
/// construction.
///
/// One trait instance = one physical device speaking for one
/// Relying-Party identifier (`farewell.foundation` for our use case).
/// Users with several physical keys instantiate the trait once per
/// device; the production app discovers all currently-connected
/// devices and runs queries against each in turn.
pub trait Authenticator {
    /// The Relying-Party identifier this authenticator instance speaks
    /// for. Returned for diagnostics; the implementation also passes
    /// this value down to CTAP2 internally.
    fn rp_id(&self) -> &str;

    /// Enroll a new credential on this authenticator under the bound
    /// `rp_id`. Returns the credential ID, which is opaque, must be
    /// stored alongside the vault, and is presented at unlock time.
    fn enroll(&mut self, user_handle: &[u8]) -> Result<Vec<u8>, Fido2Error>;

    /// Present a list of candidate credential IDs and a 32-byte salt.
    /// The authenticator returns the credential ID it recognized plus
    /// its 32-byte HMAC output for that salt.
    ///
    /// CTAP2 allow-list semantics: if the authenticator owns none of
    /// the candidates, it returns [`Fido2Error::NoMatchingCredential`].
    /// If multiple candidates are owned, behaviour is authenticator-
    /// specific; in practice authenticators pick one deterministically.
    fn challenge_response(
        &mut self,
        candidates: &[Vec<u8>],
        salt: &[u8; HMAC_SALT_LEN],
    ) -> Result<(Vec<u8>, [u8; HMAC_OUTPUT_LEN]), Fido2Error>;
}

/// Deterministic software-only authenticator for testing.
///
/// Stores an in-memory map from credential ID → internal HMAC key.
/// `enroll` generates a random credential ID and a random internal key;
/// `challenge_response` computes a BLAKE3 keyed hash of the salt under
/// the internal key (mimicking the algebraic shape of real `hmac-secret`,
/// which is HMAC-SHA-256). Output is deterministic per
/// (credential, salt) tuple, mirrors real-hardware behaviour, and
/// requires the credential to exist in this Mock to succeed.
///
/// **Do not** use in production: software-only authentication does not
/// satisfy the threat model (a stolen disk image containing the Mock's
/// internal state is enough to unlock). It exists for tests and for the
/// CLI's `--no-hardware-key` development mode.
pub struct MockAuthenticator {
    /// Relying-Party identifier bound to this mock at construction.
    rp_id: String,
    /// Map from credential ID to the 32-byte internal HMAC key.
    creds: HashMap<Vec<u8>, [u8; HMAC_OUTPUT_LEN]>,
}

impl MockAuthenticator {
    /// Create an empty mock authenticator bound to `rp_id`.
    pub fn new<S: Into<String>>(rp_id: S) -> Self {
        Self {
            rp_id: rp_id.into(),
            creds: HashMap::new(),
        }
    }

    /// Number of credentials currently enrolled in this mock.
    pub fn enrolled_count(&self) -> usize {
        self.creds.len()
    }
}

impl Default for MockAuthenticator {
    fn default() -> Self {
        Self::new("farewell.foundation")
    }
}

impl Drop for MockAuthenticator {
    fn drop(&mut self) {
        // Zeroize internal keys explicitly. credentials are public, no
        // need to scrub them.
        for v in self.creds.values_mut() {
            v.zeroize();
        }
    }
}

impl Authenticator for MockAuthenticator {
    fn rp_id(&self) -> &str {
        &self.rp_id
    }

    fn enroll(&mut self, _user_handle: &[u8]) -> Result<Vec<u8>, Fido2Error> {
        let mut rng = OsRng;
        // 64-byte credential ID, mirroring typical authenticator sizes.
        let mut cred = vec![0u8; 64];
        rng.fill(&mut cred[..]);
        let mut key = [0u8; HMAC_OUTPUT_LEN];
        rng.fill(&mut key);
        self.creds.insert(cred.clone(), key);
        Ok(cred)
    }

    fn challenge_response(
        &mut self,
        candidates: &[Vec<u8>],
        salt: &[u8; HMAC_SALT_LEN],
    ) -> Result<(Vec<u8>, [u8; HMAC_OUTPUT_LEN]), Fido2Error> {
        for cand in candidates {
            if let Some(key) = self.creds.get(cand) {
                // Mirror real-hmac-secret: keyed hash of salt under
                // the per-credential internal key. We use BLAKE3 keyed
                // mode (32-byte key, output truncated to 32 bytes).
                let mut keyed = blake3::Hasher::new_keyed(key);
                keyed.update(salt);
                let out = keyed.finalize();
                let mut bytes = [0u8; HMAC_OUTPUT_LEN];
                bytes.copy_from_slice(out.as_bytes());
                return Ok((cand.clone(), bytes));
            }
        }
        Err(Fido2Error::NoMatchingCredential)
    }
}

/// Real USB HID authenticator, talks CTAP2 to a physically-connected
/// FIDO2 device (YubiKey, Nitrokey, SoloKey, OnlyKey, etc.) via the
/// `ctap-hid-fido2` crate.
pub struct HidAuthenticator {
    rp_id: String,
    pin: Option<String>,
    /// When `Some`, operations target this specific USB device (required when
    /// multiple keys are plugged at once — `create()` errors on ambiguity).
    /// `None` uses the single connected device (today's create/open flows).
    device: Option<HidParam>,
}

/// A connected FIDO2 device, for **targeting a specific key** when several are
/// plugged simultaneously (e.g. enrolling a backup key alongside the primary).
pub struct HidDevice {
    param: HidParam,
    /// Human-readable label (product string, else the library's info string).
    pub label: String,
}

impl HidAuthenticator {
    /// Discover the first connected FIDO2 device, binding it to the given
    /// Relying-Party identifier. No PIN configured. Performs a presence
    /// check (open + drop a handle) so a missing key fails fast here.
    pub fn open_first<S: Into<String>>(rp_id: S) -> Result<Self, Fido2Error> {
        let me = Self {
            rp_id: rp_id.into(),
            pin: None,
            device: None,
        };
        let _ = me.open_device()?; // presence check; dropped immediately
        Ok(me)
    }

    /// List the connected FIDO2 devices so a caller can operate a specific one.
    pub fn list_devices() -> Vec<HidDevice> {
        get_fidokey_devices()
            .into_iter()
            .map(|info| {
                let label = if info.product_string.is_empty() {
                    info.info.clone()
                } else {
                    info.product_string.clone()
                };
                HidDevice {
                    param: info.param,
                    label,
                }
            })
            .collect()
    }

    /// Bind an authenticator to one specific connected `device` (from
    /// [`list_devices`](Self::list_devices)). Use this when 2+ keys are plugged.
    pub fn open_on<S: Into<String>>(rp_id: S, device: &HidDevice) -> Self {
        Self {
            rp_id: rp_id.into(),
            pin: None,
            device: Some(device.param.clone()),
        }
    }

    /// Configure a CTAP2 PIN to be sent with subsequent operations.
    ///
    /// Required for authenticators that have `clientPin` set. The PIN is
    /// held in memory (zeroized on drop via [`Drop`]) and sent to the
    /// authenticator in each command that needs PIN/UV auth.
    pub fn set_pin<S: Into<String>>(&mut self, pin: S) {
        self.pin = Some(pin.into());
    }

    /// Open a FRESH HID handle for a single FIDO operation.
    ///
    /// **Each operation gets its own handle, deliberately.** Reusing one
    /// `FidoKeyHid` across calls makes the *second* operation's
    /// user-presence touch silently never register on macOS — the
    /// keep-alive loop spins forever ("- Touch the sensor…" repeating)
    /// even as the user taps. Re-opening per call fixes it. We also
    /// disable the library's stdout keep-alive message (the GUI/CLI shows
    /// its own "touch your key" prompt).
    fn open_device(&self) -> Result<FidoKeyHid, Fido2Error> {
        let mut cfg = Cfg::init();
        cfg.enable_keep_alive_msg = false;
        match &self.device {
            // Targeted: open exactly this device (unambiguous with 2+ keys).
            Some(param) => FidoKeyHidFactory::create_by_params(std::slice::from_ref(param), &cfg),
            // Untargeted: the single connected device (errors if 2+ are present).
            None => FidoKeyHidFactory::create(&cfg),
        }
        .map_err(|e| Fido2Error::Transport(format!("could not open authenticator: {e}")))
    }
}

impl Drop for HidAuthenticator {
    fn drop(&mut self) {
        if let Some(pin) = self.pin.as_mut() {
            // Best-effort: scrub the PIN string in place.
            let bytes = unsafe { pin.as_bytes_mut() };
            bytes.zeroize();
        }
    }
}

impl Authenticator for HidAuthenticator {
    fn rp_id(&self) -> &str {
        &self.rp_id
    }

    fn enroll(&mut self, _user_handle: &[u8]) -> Result<Vec<u8>, Fido2Error> {
        let challenge = verifier::create_challenge();
        let ext = McExt::HmacSecret(Some(true));
        let args = {
            let mut b = MakeCredentialArgsBuilder::new(&self.rp_id, &challenge);
            if let Some(pin) = &self.pin {
                b = b.pin(pin);
            }
            b = b.extensions(&[ext]);
            b.build()
        };
        let device = self.open_device()?;
        let attestation = device
            .make_credential_with_args(&args)
            .map_err(classify_ctap_error)?;
        Ok(attestation.credential_descriptor.id)
    }

    fn challenge_response(
        &mut self,
        candidates: &[Vec<u8>],
        salt: &[u8; HMAC_SALT_LEN],
    ) -> Result<(Vec<u8>, [u8; HMAC_OUTPUT_LEN]), Fido2Error> {
        if candidates.is_empty() {
            return Err(Fido2Error::NoMatchingCredential);
        }
        let challenge = verifier::create_challenge();
        let ext = GAExt::HmacSecret(Some(*salt));
        let args = {
            let mut b = GetAssertionArgsBuilder::new(&self.rp_id, &challenge);
            if let Some(pin) = &self.pin {
                b = b.pin(pin);
            }
            for cred in candidates {
                b = b.add_credential_id(cred);
            }
            b = b.extensions(&[ext]);
            b.build()
        };
        let device = self.open_device()?;
        let assertions = device
            .get_assertion_with_args(&args)
            .map_err(classify_ctap_error)?;
        if assertions.is_empty() {
            return Err(Fido2Error::NoMatchingCredential);
        }
        let assertion = &assertions[0];
        let used_cred = assertion.credential_id.clone();
        let hmac_output = assertion
            .extensions
            .iter()
            .find_map(|e| match e {
                GAExt::HmacSecret(Some(out)) => Some(*out),
                _ => None,
            })
            .ok_or(Fido2Error::Protocol(0xFF))?;
        Ok((used_cred, hmac_output))
    }
}

/// Classify an `anyhow::Error` from ctap-hid-fido2 into one of our
/// transport-level variants. Best-effort: the upstream library
/// returns opaque anyhow errors with strings; we pattern-match on
/// substrings to produce useful diagnostics, defaulting to
/// `Transport` for the unknown.
fn classify_ctap_error(e: anyhow::Error) -> Fido2Error {
    let msg = e.to_string();
    let lower = msg.to_lowercase();
    if lower.contains("ctap2_err_pin")
        || (lower.contains("pin") && (lower.contains("invalid") || lower.contains("required")))
    {
        Fido2Error::Transport(format!("PIN required or invalid: {msg}"))
    } else if lower.contains("ctap2_err_no_credentials")
        || lower.contains("no credentials")
        || lower.contains("nocredentials")
    {
        Fido2Error::NoMatchingCredential
    } else if lower.contains("user")
        && (lower.contains("cancel") || lower.contains("timeout") || lower.contains("absent"))
    {
        Fido2Error::UserCancelled
    } else {
        Fido2Error::Transport(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock() -> MockAuthenticator {
        MockAuthenticator::new("farewell.foundation")
    }

    #[test]
    fn mock_enroll_and_unlock() {
        let mut auth = mock();
        let cred = auth.enroll(b"user-1").unwrap();
        assert!(!cred.is_empty());
        assert_eq!(auth.enrolled_count(), 1);
        assert_eq!(auth.rp_id(), "farewell.foundation");

        let salt = [0x42u8; HMAC_SALT_LEN];
        let (used, out) = auth.challenge_response(&[cred.clone()], &salt).unwrap();
        assert_eq!(used, cred);
        assert_eq!(out.len(), HMAC_OUTPUT_LEN);
    }

    #[test]
    fn mock_output_is_deterministic() {
        let mut auth = mock();
        let cred = auth.enroll(b"u").unwrap();
        let salt = [0xAAu8; HMAC_SALT_LEN];
        let (_, o1) = auth.challenge_response(&[cred.clone()], &salt).unwrap();
        let (_, o2) = auth.challenge_response(&[cred.clone()], &salt).unwrap();
        assert_eq!(o1, o2);
    }

    #[test]
    fn mock_output_depends_on_salt() {
        let mut auth = mock();
        let cred = auth.enroll(b"u").unwrap();
        let (_, o1) = auth
            .challenge_response(&[cred.clone()], &[0x01u8; HMAC_SALT_LEN])
            .unwrap();
        let (_, o2) = auth
            .challenge_response(&[cred.clone()], &[0x02u8; HMAC_SALT_LEN])
            .unwrap();
        assert_ne!(o1, o2);
    }

    #[test]
    fn mock_output_depends_on_credential() {
        let mut a = mock();
        let mut b = mock();
        let cred_a = a.enroll(b"u").unwrap();
        let cred_b = b.enroll(b"u").unwrap();
        let salt = [0x42u8; HMAC_SALT_LEN];
        let (_, oa) = a.challenge_response(&[cred_a], &salt).unwrap();
        let (_, ob) = b.challenge_response(&[cred_b], &salt).unwrap();
        // Different authenticators → different internal keys → different outputs.
        assert_ne!(oa, ob);
    }

    #[test]
    fn mock_rejects_unknown_credentials() {
        let mut a = mock();
        let _ = a.enroll(b"u").unwrap();
        let bogus = vec![0u8; 64];
        let r = a.challenge_response(&[bogus], &[0u8; HMAC_SALT_LEN]);
        assert!(matches!(r, Err(Fido2Error::NoMatchingCredential)));
    }

    #[test]
    fn mock_allowlist_selects_owned_credential() {
        // Authenticator A owns cred_a. Authenticator B owns cred_b.
        // When the app sends both as candidates to A, A returns cred_a
        // (and ignores cred_b).
        let mut a = mock();
        let mut b = mock();
        let cred_a = a.enroll(b"u").unwrap();
        let cred_b = b.enroll(b"u").unwrap();
        let salt = [0x33u8; HMAC_SALT_LEN];
        let (used, _) = a
            .challenge_response(&[cred_b.clone(), cred_a.clone()], &salt)
            .unwrap();
        assert_eq!(used, cred_a);
    }

    #[test]
    fn enroll_multiple_credentials_per_authenticator() {
        // A single authenticator may host multiple credentials.
        let mut a = mock();
        let c1 = a.enroll(b"u1").unwrap();
        let c2 = a.enroll(b"u2").unwrap();
        assert_ne!(c1, c2);
        let salt = [0u8; HMAC_SALT_LEN];
        let (_, o1) = a.challenge_response(&[c1.clone()], &salt).unwrap();
        let (_, o2) = a.challenge_response(&[c2.clone()], &salt).unwrap();
        assert_ne!(o1, o2);
    }
}
