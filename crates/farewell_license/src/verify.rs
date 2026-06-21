//! Token verification: signature check, major-version check, and
//! optional hardware-serial check.
//!
//! Verification is layered so the caller can decide which layers apply:
//!
//! - [`verify_token`] returns a [`VerifiedLicense`] if the signature
//!   matches the embedded public key and the payload parses. It does
//!   NOT check the bound serials — useful for displaying license info
//!   in support contexts ("show me what's in this license file")
//!   without needing to be on the licensee's Mac.
//!
//! - [`verify_for_this_mac`] additionally reads the local hardware
//!   serial and rejects the license if it isn't bound to this machine.
//!   This is the function the production app calls at launch.

use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};

use crate::{
    payload::Payload,
    serial::SerialReader,
    token::parse_token,
    LicenseError, MAJOR_VERSION_CURRENT,
};

/// A license whose signature has been verified against a public key.
/// Construction is only possible by going through [`verify_token`] or
/// [`verify_for_this_mac`], which guarantees the contents are
/// trustworthy modulo the trust placed in the public key.
#[derive(Debug, Clone)]
pub struct VerifiedLicense {
    payload: Payload,
}

impl VerifiedLicense {
    /// The verified payload.
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    /// Consume the wrapper and return the inner payload.
    pub fn into_payload(self) -> Payload {
        self.payload
    }
}

/// Verify a token's signature against a 32-byte Ed25519 public key,
/// parse the payload, and check it is for this major version of
/// Farewell.
///
/// Does NOT check hardware serial binding. Use [`verify_for_this_mac`]
/// when running inside the user's app at activation time.
pub fn verify_token(token: &str, public_key: &[u8]) -> Result<VerifiedLicense, LicenseError> {
    let (payload_bytes, signature_bytes) = parse_token(token)?;

    // P-256 public key in SEC1 form (65-byte uncompressed or 33-byte
    // compressed). The signature is DER-encoded ECDSA, matching what Google
    // Cloud KMS emits. Verification hashes the payload with SHA-256 internally,
    // so we (and KMS) only ever sign the digest — the email is never exposed to
    // the signer.
    let vk = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| LicenseError::PublicKeyLength(public_key.len()))?;
    let signature = Signature::from_der(&signature_bytes)
        .map_err(|_| LicenseError::SignatureLength(signature_bytes.len()))?;
    vk.verify(&payload_bytes, &signature)
        .map_err(|_| LicenseError::InvalidSignature)?;

    let payload = Payload::from_bytes(&payload_bytes)?;

    if payload.major_version != MAJOR_VERSION_CURRENT {
        return Err(LicenseError::MajorVersionMismatch {
            license: payload.major_version,
            build: MAJOR_VERSION_CURRENT,
        });
    }

    Ok(VerifiedLicense { payload })
}

/// Verify a token, then additionally check that this Mac's hardware
/// serial number is among the license's `bound_serials`.
///
/// Every license tier (`Single`, `Duo`, and the free `Grant`) is bound
/// to at least one Mac serial. A license with an empty `bound_serials`
/// list is rejected as [`LicenseError::UnboundLicense`] — there is no
/// honor-system / serial-less mode.
pub fn verify_for_this_mac<S: SerialReader>(
    token: &str,
    public_key: &[u8],
    reader: &S,
) -> Result<VerifiedLicense, LicenseError> {
    let verified = verify_token(token, public_key)?;
    let p = verified.payload();

    if p.bound_serials.is_empty() {
        // No serial-less licenses exist: an unbound token would unlock on
        // any Mac, so treat it as invalid rather than a free pass.
        return Err(LicenseError::UnboundLicense);
    }

    let this_sn = reader.read_serial()?;
    if !p.bound_serials.iter().any(|s| s == &this_sn) {
        return Err(LicenseError::SerialNotAuthorized {
            this_mac: this_sn,
            authorized: p.bound_serials.clone(),
        });
    }

    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        payload::{LicenseType, Payload, MAJOR_VERSION_CURRENT},
        serial::StaticSerialReader,
        token::write_token,
    };
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
    use rand::rngs::OsRng;

    /// A fresh P-256 keypair: (signing key, SEC1 public-key bytes).
    fn keypair() -> (SigningKey, Vec<u8>) {
        let sk = SigningKey::random(&mut OsRng);
        let pk = sk.verifying_key().to_sec1_bytes().to_vec();
        (sk, pk)
    }

    fn make_test_token(
        signing_key: &SigningKey,
        license_type: LicenseType,
        major_version: u32,
        bound: Vec<String>,
    ) -> String {
        let payload = Payload {
            license_type,
            major_version,
            purchased_unix: 1_780_000_000,
            license_id: [0x12; 16],
            email: "alice@example.com".into(),
            bound_serials: bound,
        };
        let bytes = payload.to_bytes().unwrap();
        let sig: Signature = signing_key.sign(&bytes);
        write_token(&bytes, sig.to_der().as_bytes())
    }

    #[test]
    fn valid_duo_license_with_matching_serial() {
        let (sk, pk) = keypair();
        let token = make_test_token(
            &sk,
            LicenseType::Duo,
            MAJOR_VERSION_CURRENT,
            vec!["MAC-A".into(), "MAC-B".into()],
        );

        let reader = StaticSerialReader::new("MAC-A");
        let v = verify_for_this_mac(&token, &pk, &reader).unwrap();
        assert_eq!(v.payload().license_type, LicenseType::Duo);
        assert_eq!(v.payload().email, "alice@example.com");
    }

    #[test]
    fn rejects_token_signed_by_wrong_key() {
        let (_sk_legit, pk_legit) = keypair();
        let sk_attacker = SigningKey::random(&mut OsRng);
        // Token signed by attacker, but verified against legitimate pubkey.
        let token = make_test_token(
            &sk_attacker,
            LicenseType::Single,
            MAJOR_VERSION_CURRENT,
            vec!["MAC-A".into()],
        );
        let err = verify_token(&token, &pk_legit).unwrap_err();
        assert!(matches!(err, LicenseError::InvalidSignature));
    }

    #[test]
    fn rejects_tampered_payload() {
        let (sk, pk) = keypair();
        let token = make_test_token(
            &sk,
            LicenseType::Single,
            MAJOR_VERSION_CURRENT,
            vec!["MAC-A".into()],
        );

        // Flip a byte in the payload portion of the token.
        let mut bytes = token.into_bytes();
        let dot = bytes.iter().position(|&b| b == b'.').unwrap();
        // Pick a byte well inside the payload base64, before the dot.
        bytes[dot / 2] ^= 0x01;
        let tampered = String::from_utf8(bytes).unwrap();

        let err = verify_token(&tampered, &pk).unwrap_err();
        // Could be either InvalidSignature or Base64 depending on which
        // byte we flipped, but it MUST NOT verify.
        assert!(matches!(
            err,
            LicenseError::InvalidSignature | LicenseError::Base64(_) | LicenseError::BadMagic(_)
        ));
    }

    #[test]
    fn rejects_wrong_major_version() {
        let (sk, pk) = keypair();
        // Sign a license for major version 2 — this build is version 1.
        let token = make_test_token(
            &sk,
            LicenseType::Single,
            MAJOR_VERSION_CURRENT + 1,
            vec!["MAC-A".into()],
        );
        let err = verify_token(&token, &pk).unwrap_err();
        assert!(
            matches!(err, LicenseError::MajorVersionMismatch { license: 2, build: 1 }),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn rejects_unauthorized_serial() {
        let (sk, pk) = keypair();
        let token = make_test_token(
            &sk,
            LicenseType::Duo,
            MAJOR_VERSION_CURRENT,
            vec!["MAC-A".into(), "MAC-B".into()],
        );
        let reader = StaticSerialReader::new("MAC-C");
        let err = verify_for_this_mac(&token, &pk, &reader).unwrap_err();
        match err {
            LicenseError::SerialNotAuthorized { this_mac, authorized } => {
                assert_eq!(this_mac, "MAC-C");
                assert_eq!(authorized, vec!["MAC-A", "MAC-B"]);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_unbound_license_on_every_mac() {
        let (sk, pk) = keypair();
        // A Grant with no bound serial is invalid — every tier must bind
        // at least one Mac. It must be refused on any machine.
        let token = make_test_token(&sk, LicenseType::Grant, MAJOR_VERSION_CURRENT, vec![]);
        for sn in ["MAC-A", "RANDOM", "JOURNALIST-1"] {
            let reader = StaticSerialReader::new(sn);
            let err = verify_for_this_mac(&token, &pk, &reader).unwrap_err();
            assert!(matches!(err, LicenseError::UnboundLicense), "unexpected: {err:?}");
        }
    }

    #[test]
    fn valid_grant_is_bound_to_one_mac() {
        let (sk, pk) = keypair();
        let token =
            make_test_token(&sk, LicenseType::Grant, MAJOR_VERSION_CURRENT, vec!["MAC-A".into()]);
        // Matching Mac unlocks.
        let ok = StaticSerialReader::new("MAC-A");
        assert_eq!(
            verify_for_this_mac(&token, &pk, &ok).unwrap().payload().license_type,
            LicenseType::Grant
        );
        // A different Mac is refused.
        let other = StaticSerialReader::new("MAC-B");
        assert!(matches!(
            verify_for_this_mac(&token, &pk, &other).unwrap_err(),
            LicenseError::SerialNotAuthorized { .. }
        ));
    }
}
