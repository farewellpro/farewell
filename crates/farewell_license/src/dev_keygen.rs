//! Developer / SRL-side helpers for generating keypairs and signing
//! license tokens. **Not compiled into the user-facing binary.**
//!
//! Gated behind the `dev-keygen` feature so it cannot leak into a
//! product build:
//!
//! ```toml
//! farewell_license = { workspace = true, features = ["dev-keygen"] }
//! ```
//!
//! In production, license tokens are signed by a script the SRL
//! operates with a hardware-protected key (YubiKey 5C with PIN,
//! or YubiHSM 2 once volume justifies). This module is the in-Rust
//! reference implementation used for tests and for bootstrapping
//! the signing tool — never for routine signing of customer licenses.

use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use rand::rngs::OsRng;
use zeroize::Zeroize as _;

use crate::{key::encode_key, payload::Payload, token::write_token, LicenseError};

/// SEC1 **uncompressed** public-key bytes (0x04 || X || Y) of a signing key —
/// the same 65-byte form Google Cloud KMS exports, so dev keys and the
/// production KMS key are embedded identically.
fn pubkey_bytes(sk: &SigningKey) -> [u8; 65] {
    let pt = sk.verifying_key().to_encoded_point(false); // false = uncompressed
    let mut out = [0u8; 65];
    out.copy_from_slice(pt.as_bytes());
    out
}

fn signing_key_from(secret: &[u8; 32]) -> SigningKey {
    let mut copy = *secret;
    let sk = SigningKey::from_slice(&copy).expect("valid P-256 secret scalar");
    copy.zeroize();
    sk
}

/// Generate a fresh ECDSA P-256 keypair from the OS RNG.
///
/// Returns `(secret_scalar_bytes, public_sec1_uncompressed)`. The secret is
/// 32 bytes; handle it securely (zeroize, store on hardware/KMS, never log).
pub fn generate_keypair() -> ([u8; 32], [u8; 65]) {
    let sk = SigningKey::random(&mut OsRng);
    let pk = pubkey_bytes(&sk);
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&sk.to_bytes());
    (sk_bytes, pk)
}

/// Sign a [`Payload`] with the supplied secret key, returning the
/// complete token string (`base64url(payload).base64url(sig)`).
///
/// The secret-key bytes are zeroized inside this function before
/// returning, but the caller still owns the original buffer they
/// passed in and must zeroize it themselves once they no longer
/// need the key.
pub fn sign_payload(secret_key: &[u8; 32], payload: &Payload) -> Result<String, LicenseError> {
    let bytes = payload.to_bytes()?;
    let sk = signing_key_from(secret_key);
    let sig: Signature = sk.sign(&bytes);
    Ok(write_token(&bytes, sig.to_der().as_bytes()))
}

/// Sign a [`Payload`] and return the canonical, human-facing **license key**
/// (grouped Crockford-base32, the form the buyer pastes from their email).
/// Carries the same bytes as [`sign_payload`], just encoded as a key.
pub fn sign_payload_key(secret_key: &[u8; 32], payload: &Payload) -> Result<String, LicenseError> {
    let bytes = payload.to_bytes()?;
    let sk = signing_key_from(secret_key);
    let sig: Signature = sk.sign(&bytes);
    Ok(encode_key(&bytes, sig.to_der().as_bytes()))
}

/// Recover the public key corresponding to a secret key. Useful when
/// the SRL stores only the secret and wants to print the matching
/// public bytes to embed in the next major version of Farewell.
pub fn public_from_secret(secret_key: &[u8; 32]) -> [u8; 65] {
    pubkey_bytes(&signing_key_from(secret_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        payload::{LicenseType, MAJOR_VERSION_CURRENT},
        verify::verify_token,
    };

    #[test]
    fn generated_keypair_signs_and_verifies() {
        let (sk, pk) = generate_keypair();
        let payload = Payload {
            license_type: LicenseType::Single,
            major_version: MAJOR_VERSION_CURRENT,
            purchased_unix: 1_780_000_000,
            license_id: [1; 16],
            email: "bob@example.com".into(),
            bound_serials: vec!["MAC-Z".into()],
        };
        let token = sign_payload(&sk, &payload).unwrap();
        let verified = verify_token(&token, &pk).unwrap();
        assert_eq!(verified.payload().email, "bob@example.com");
    }

    #[test]
    fn public_from_secret_matches_keypair() {
        let (sk, pk) = generate_keypair();
        let recovered = public_from_secret(&sk);
        assert_eq!(pk, recovered);
    }

    /// The grouped license **key** verifies the same as the dotted token, and
    /// survives the kind of mangling that happens when a buyer pastes it.
    #[test]
    fn license_key_signs_verifies_and_survives_paste() {
        let (sk, pk) = generate_keypair();
        let payload = Payload {
            license_type: LicenseType::Duo,
            major_version: MAJOR_VERSION_CURRENT,
            purchased_unix: 1_780_000_000,
            license_id: [7; 16],
            email: "carol@example.com".into(),
            bound_serials: vec!["MAC-A".into(), "MAC-B".into()],
        };
        let key = sign_payload_key(&sk, &payload).unwrap();
        assert!(key.contains('-') && !key.contains('.'));

        // verify_token accepts the key directly…
        let v = verify_token(&key, &pk).unwrap();
        assert_eq!(v.payload().email, "carol@example.com");
        assert_eq!(v.payload().bound_serials.len(), 2);

        // …and still does after a paste mangles case/dashes/whitespace.
        let messy = format!("  {}\n", key.to_lowercase().replace('-', " "));
        assert!(verify_token(&messy, &pk).is_ok());
    }
}
