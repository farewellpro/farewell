//! Key encapsulation: X25519 (classical) and ML-KEM-1024 (post-quantum).
//!
//! v0.10 — ML-KEM-1024 is provided by `libcrux-ml-kem`, formally
//! verified via hax + F* (Cryspen).
//!
//! The production architecture (ARCHITECTURE.md §3.2) requires hybrid
//! `KDF(X25519_shared || ML-KEM_shared)` so that confidentiality holds
//! if either primitive resists.

use libcrux_ml_kem::{
    mlkem1024::{
        self, MlKem1024Ciphertext, MlKem1024PrivateKey, MlKem1024PublicKey,
    },
    KEY_GENERATION_SEED_SIZE, MlKemSharedSecret,
};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecret};
use zeroize::Zeroize;

use crate::{hash, rng, CryptoError, Result};

/// Length in bytes of an X25519 public key.
pub const X25519_PK_LEN: usize = 32;
/// Length in bytes of an X25519 secret key.
pub const X25519_SK_LEN: usize = 32;
/// Length in bytes of an X25519 shared secret.
pub const X25519_SS_LEN: usize = 32;

/// Length in bytes of an ML-KEM-1024 encapsulation key (FIPS 203 §6, Table 3).
pub const MLKEM_PK_LEN: usize = 1568;
/// Length in bytes of an ML-KEM-1024 ciphertext.
pub const MLKEM_CT_LEN: usize = 1568;
/// Length in bytes of an ML-KEM-1024 shared secret.
pub const MLKEM_SS_LEN: usize = 32;
/// Length in bytes of an ML-KEM-1024 decapsulation key (private), full form.
///
/// The FIPS 203 IND-CCA decapsulation key is the concatenation of the
/// CPA secret key, the encapsulation key, and a 32-byte z value. For
/// ML-KEM-1024 this totals 3168 bytes.
pub const MLKEM_SK_LEN: usize = 3168;

/// Length of the combined hybrid shared secret derived from both halves.
pub const HYBRID_SS_LEN: usize = 32;

/// Length of the encapsulate randomness fed to `mlkem_encapsulate`.
const MLKEM_ENCAP_SEED_LEN: usize = 32;

// --- X25519 ---------------------------------------------------------------

/// An X25519 keypair. Secret is zeroized on drop via `StaticSecret`.
pub struct X25519KeyPair {
    /// Secret scalar.
    pub secret: XSecret,
    /// Derived public key.
    pub public: XPublicKey,
}

impl X25519KeyPair {
    /// Generate a fresh keypair from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; X25519_SK_LEN];
        rng::fill(&mut seed)?;
        let secret = XSecret::from(seed);
        seed.zeroize();
        let public = XPublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    /// Compute the X25519 shared secret with a peer's public key.
    pub fn ecdh(&self, peer: &XPublicKey) -> [u8; X25519_SS_LEN] {
        let ss = self.secret.diffie_hellman(peer);
        let mut out = [0u8; X25519_SS_LEN];
        out.copy_from_slice(ss.as_bytes());
        out
    }
}

// --- ML-KEM-1024 (libcrux, formally verified) -----------------------------

/// ML-KEM-1024 encapsulation key (public).
#[derive(Clone)]
pub struct MlKemPublicKey(MlKem1024PublicKey);

impl MlKemPublicKey {
    /// Serialize to a fixed-size byte buffer.
    pub fn to_bytes(&self) -> Box<[u8; MLKEM_PK_LEN]> {
        let mut out = Box::new([0u8; MLKEM_PK_LEN]);
        out.copy_from_slice(self.0.as_slice());
        out
    }

    /// Parse from a fixed-size byte buffer.
    pub fn from_bytes(bytes: &[u8; MLKEM_PK_LEN]) -> Result<Self> {
        Ok(Self(MlKem1024PublicKey::from(*bytes)))
    }
}

/// ML-KEM-1024 decapsulation key (private). The underlying bytes are
/// zeroized on drop by libcrux's `MlKemPrivateKey` impl.
pub struct MlKemSecretKey(MlKem1024PrivateKey);

impl MlKemSecretKey {
    /// Serialize to a fixed-size byte buffer.
    pub fn to_bytes(&self) -> Box<[u8; MLKEM_SK_LEN]> {
        let mut out = Box::new([0u8; MLKEM_SK_LEN]);
        out.copy_from_slice(self.0.as_slice());
        out
    }

    /// Parse from a fixed-size byte buffer.
    pub fn from_bytes(bytes: &[u8; MLKEM_SK_LEN]) -> Result<Self> {
        Ok(Self(MlKem1024PrivateKey::from(*bytes)))
    }
}

/// ML-KEM-1024 ciphertext (encapsulated shared secret).
#[derive(Clone)]
pub struct MlKemCiphertext(MlKem1024Ciphertext);

impl MlKemCiphertext {
    /// Serialize to a fixed-size byte buffer.
    pub fn to_bytes(&self) -> Box<[u8; MLKEM_CT_LEN]> {
        let mut out = Box::new([0u8; MLKEM_CT_LEN]);
        out.copy_from_slice(self.0.as_slice());
        out
    }

    /// Parse from a fixed-size byte buffer.
    pub fn from_bytes(bytes: &[u8; MLKEM_CT_LEN]) -> Self {
        Self(MlKem1024Ciphertext::from(*bytes))
    }
}

/// Generate an ML-KEM-1024 keypair using the OS CSPRNG.
pub fn mlkem_keygen() -> Result<(MlKemPublicKey, MlKemSecretKey)> {
    let mut seed = [0u8; KEY_GENERATION_SEED_SIZE];
    rng::fill(&mut seed)?;
    let kp = mlkem1024::generate_key_pair(seed);
    seed.zeroize();
    let (sk, pk) = kp.into_parts();
    Ok((MlKemPublicKey(pk), MlKemSecretKey(sk)))
}

/// Encapsulate against an ML-KEM-1024 public key, producing a ciphertext
/// and a shared secret.
pub fn mlkem_encapsulate(
    pk: &MlKemPublicKey,
) -> Result<(MlKemCiphertext, [u8; MLKEM_SS_LEN])> {
    let mut seed = [0u8; MLKEM_ENCAP_SEED_LEN];
    rng::fill(&mut seed)?;
    let (ct, ss): (MlKem1024Ciphertext, MlKemSharedSecret) =
        mlkem1024::encapsulate(&pk.0, seed);
    seed.zeroize();
    Ok((MlKemCiphertext(ct), ss))
}

/// Decapsulate an ML-KEM-1024 ciphertext using the corresponding
/// secret key, recovering the shared secret.
pub fn mlkem_decapsulate(
    sk: &MlKemSecretKey,
    ct: &MlKemCiphertext,
) -> Result<[u8; MLKEM_SS_LEN]> {
    let ss = mlkem1024::decapsulate(&sk.0, &ct.0);
    Ok(ss)
}

// --- Hybrid combiner ------------------------------------------------------

/// Combine two shared secrets into one via BLAKE3 KDF.
///
/// Both halves are concatenated under a domain-separating context. The
/// output is unpredictable to any adversary missing either input.
pub fn hybrid_combine(
    x25519_ss: &[u8; X25519_SS_LEN],
    mlkem_ss: &[u8; MLKEM_SS_LEN],
) -> [u8; HYBRID_SS_LEN] {
    let mut input = Vec::with_capacity(X25519_SS_LEN + MLKEM_SS_LEN);
    input.extend_from_slice(x25519_ss);
    input.extend_from_slice(mlkem_ss);
    let combined = hash::derive_key("farewell hybrid KEM combiner v1", &input);
    input.iter_mut().for_each(|b| *b = 0);
    combined
}

// Suppress an unused-import warning while we keep CryptoError in scope
// for future "validate_public_key" paths.
#[allow(dead_code)]
fn _force_crypto_error_reach() -> CryptoError {
    CryptoError::Kem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_ecdh_agreement() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();
        let alice_view = alice.ecdh(&bob.public);
        let bob_view = bob.ecdh(&alice.public);
        assert_eq!(alice_view, bob_view);
    }

    #[test]
    fn hybrid_combiner_is_deterministic() {
        let x = [0x11u8; X25519_SS_LEN];
        let m = [0x22u8; MLKEM_SS_LEN];
        assert_eq!(hybrid_combine(&x, &m), hybrid_combine(&x, &m));
    }

    #[test]
    fn hybrid_combiner_changes_on_either_input() {
        let x1 = [0x11u8; X25519_SS_LEN];
        let x2 = [0x12u8; X25519_SS_LEN];
        let m1 = [0x22u8; MLKEM_SS_LEN];
        let m2 = [0x23u8; MLKEM_SS_LEN];
        assert_ne!(hybrid_combine(&x1, &m1), hybrid_combine(&x2, &m1));
        assert_ne!(hybrid_combine(&x1, &m1), hybrid_combine(&x1, &m2));
    }

    #[test]
    fn mlkem_roundtrip() {
        let (pk, sk) = mlkem_keygen().unwrap();
        let (ct, ss_a) = mlkem_encapsulate(&pk).unwrap();
        let ss_b = mlkem_decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_a, ss_b);
        assert_eq!(ss_a.len(), MLKEM_SS_LEN);
    }

    #[test]
    fn mlkem_two_encapsulations_are_distinct() {
        let (pk, _sk) = mlkem_keygen().unwrap();
        let (ct1, ss1) = mlkem_encapsulate(&pk).unwrap();
        let (ct2, ss2) = mlkem_encapsulate(&pk).unwrap();
        assert_ne!(*ct1.to_bytes(), *ct2.to_bytes());
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn mlkem_public_key_byte_roundtrip() {
        let (pk, _sk) = mlkem_keygen().unwrap();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), MLKEM_PK_LEN);
        let pk2 = MlKemPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(*pk2.to_bytes(), *bytes);
    }

    #[test]
    fn mlkem_secret_key_byte_roundtrip() {
        let (_pk, sk) = mlkem_keygen().unwrap();
        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), MLKEM_SK_LEN);
        let sk2 = MlKemSecretKey::from_bytes(&bytes).unwrap();
        // A roundtripped key should decapsulate the same as the original.
        let (pk, _) = mlkem_keygen().unwrap();
        let _ = (pk, sk2); // just exercising; full decapsulate-via-roundtrip
                          // tested via mlkem_keygen_is_reproducible if added.
    }

    #[test]
    fn mlkem_full_roundtrip_via_byte_serialization() {
        let (pk, sk) = mlkem_keygen().unwrap();
        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();
        let pk2 = MlKemPublicKey::from_bytes(&pk_bytes).unwrap();
        let sk2 = MlKemSecretKey::from_bytes(&sk_bytes).unwrap();
        let (ct, ss_a) = mlkem_encapsulate(&pk2).unwrap();
        let ss_b = mlkem_decapsulate(&sk2, &ct).unwrap();
        assert_eq!(ss_a, ss_b);
    }
}
