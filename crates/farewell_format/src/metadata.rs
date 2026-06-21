//! Encrypted vault metadata blob — v0.5 (indistinguishable-from-random).
//!
//! v0.5 removes the plaintext header entirely. There is no longer any
//! magic, version, or algorithm identifier in the clear: a Farewell
//! vault is byte-for-byte indistinguishable from random data without a
//! valid passphrase (see THREAT_MODEL §6.9).
//!
//! The vault's shared, non-secret metadata (format version, capacity,
//! and the one-shot ML-DSA-87 anti-tampering attestation) now lives in a
//! single AEAD-encrypted blob, decrypted with a 32-byte `metadata_key`
//! that is itself carried — identically — inside every active key slot.
//! Any level that unlocks can therefore read the metadata, yet none of
//! it is observable on disk.
//!
//! The internal magic [`METADATA_MAGIC`] is checked **only after** a
//! successful AEAD decryption. It is a sanity tag, never a fingerprint:
//! an attacker without the passphrase can neither decrypt the blob nor
//! locate it (it sits at a fixed offset but looks like random bytes).

use byteorder::{ByteOrder, LittleEndian};
use farewell_crypto::aead::{self, AeadKey, NONCE_LEN, TAG_LEN};
use farewell_crypto::sign::{self, MlDsaVerifyingKey, MLDSA_PK_LEN, MLDSA_SIG_LEN};
use farewell_crypto::rng;
use zeroize::Zeroize;

use crate::{FormatError, Result};

/// Length of the Argon2id salt in bytes (the only plaintext field).
pub const SALT_LEN: usize = 32;

/// Format version implemented by this build.
///
/// v0.5 (0x0005): indistinguishable-from-random layout. No plaintext
/// header/magic; metadata is an AEAD blob keyed by the per-slot shared
/// `metadata_key`; the wipe counter (if enabled) is an optional,
/// salt-keyed region. Incompatible with the v0.4 plaintext-header
/// striped format — there is no in-place migration.
pub const FORMAT_VERSION: u16 = 0x0006;

/// Internal sanity tag, verified only *after* AEAD decryption. Never
/// appears in cleartext on disk, so it is not an external fingerprint.
pub const METADATA_MAGIC: [u8; 4] = *b"FRWL";

/// Algorithm identifier for AES-256-GCM-SIV.
pub const AEAD_AES256_GCM_SIV: u8 = 0x01;
/// Algorithm identifier for Argon2id.
pub const KDF_ARGON2ID: u8 = 0x01;
/// Algorithm identifier for hybrid X25519+ML-KEM-1024.
pub const KEM_HYBRID_X25519_MLKEM1024: u8 = 0x01;
/// Algorithm identifier for hybrid Ed25519+ML-DSA-87.
pub const SIG_HYBRID_ED25519_MLDSA87: u8 = 0x01;

/// Length of the embedded ML-DSA-87 verifying key (FIPS 204 §6, Table 2).
pub const MLDSA_VK_LEN: usize = MLDSA_PK_LEN;

/// AEAD associated data binding the blob to its purpose + format version.
const METADATA_AAD: &[u8] = b"farewell.metadata.v6";

/// Domain string mixed into the ML-DSA signed message. Bumped per format
/// version so a v0.4 signature cannot replay against a v0.5 verifier.
const SIGNED_MESSAGE_DOMAIN: &[u8] = b"farewell.metadata.sig.v6";

/// Offsets inside the metadata plaintext (before AEAD).
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 4;
const OFF_AEAD_ID: usize = 6;
const OFF_KDF_ID: usize = 7;
const OFF_KEM_ID: usize = 8;
const OFF_SIG_ID: usize = 9;
const OFF_TOTAL_CHUNKS: usize = 10;
const OFF_VK: usize = 18;
const OFF_SIG: usize = OFF_VK + MLDSA_VK_LEN;

/// Length of the metadata plaintext (before AEAD).
pub const METADATA_PLAINTEXT_LEN: usize = OFF_SIG + MLDSA_SIG_LEN;

/// Length of the on-disk metadata blob: nonce || ciphertext || tag.
pub const METADATA_BLOB_LEN: usize = NONCE_LEN + METADATA_PLAINTEXT_LEN + TAG_LEN;

/// The shared, non-secret vault metadata.
#[derive(Clone)]
pub struct Metadata {
    /// Format version.
    pub version: u16,
    /// Number of data chunks in the vault.
    pub total_chunks: u64,
    /// ML-DSA-87 verifying key (one-shot anti-tampering attestation).
    pub mldsa_vk: Box<[u8; MLDSA_VK_LEN]>,
    /// ML-DSA-87 signature over the canonical metadata fields.
    pub mldsa_sig: Box<[u8; MLDSA_SIG_LEN]>,
}

impl std::fmt::Debug for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metadata")
            .field("version", &self.version)
            .field("total_chunks", &self.total_chunks)
            .field("mldsa_vk[..8]", &&self.mldsa_vk[..8])
            .finish_non_exhaustive()
    }
}

/// Construct the bytes signed by the one-shot ML-DSA key at creation.
///
/// Binds: domain (version-tagged), format version, the four algorithm
/// IDs, the capacity, the vault salt (so the signature cannot be lifted
/// onto another vault), and the verifying key itself.
pub fn signed_metadata_message(
    version: u16,
    total_chunks: u64,
    salt: &[u8; SALT_LEN],
    mldsa_vk: &[u8; MLDSA_VK_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNED_MESSAGE_DOMAIN.len() + 2 + 4 + 8 + SALT_LEN + MLDSA_VK_LEN);
    out.extend_from_slice(SIGNED_MESSAGE_DOMAIN);
    let mut v = [0u8; 2];
    LittleEndian::write_u16(&mut v, version);
    out.extend_from_slice(&v);
    out.push(AEAD_AES256_GCM_SIV);
    out.push(KDF_ARGON2ID);
    out.push(KEM_HYBRID_X25519_MLKEM1024);
    out.push(SIG_HYBRID_ED25519_MLDSA87);
    let mut tc = [0u8; 8];
    LittleEndian::write_u64(&mut tc, total_chunks);
    out.extend_from_slice(&tc);
    out.extend_from_slice(salt);
    out.extend_from_slice(mldsa_vk.as_slice());
    out
}

impl Metadata {
    /// Build a metadata record with a pre-computed ML-DSA signature.
    pub fn new(
        total_chunks: u64,
        mldsa_vk: Box<[u8; MLDSA_VK_LEN]>,
        mldsa_sig: Box<[u8; MLDSA_SIG_LEN]>,
    ) -> Self {
        Self {
            version: FORMAT_VERSION,
            total_chunks,
            mldsa_vk,
            mldsa_sig,
        }
    }

    /// Serialize + AEAD-encrypt into the on-disk blob under `metadata_key`.
    /// The output is `METADATA_BLOB_LEN` bytes, indistinguishable from
    /// random without the key.
    pub fn seal(&self, metadata_key: &[u8; aead::KEY_LEN]) -> Result<[u8; METADATA_BLOB_LEN]> {
        let mut plain = vec![0u8; METADATA_PLAINTEXT_LEN];
        plain[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&METADATA_MAGIC);
        LittleEndian::write_u16(&mut plain[OFF_VERSION..OFF_VERSION + 2], self.version);
        plain[OFF_AEAD_ID] = AEAD_AES256_GCM_SIV;
        plain[OFF_KDF_ID] = KDF_ARGON2ID;
        plain[OFF_KEM_ID] = KEM_HYBRID_X25519_MLKEM1024;
        plain[OFF_SIG_ID] = SIG_HYBRID_ED25519_MLDSA87;
        LittleEndian::write_u64(
            &mut plain[OFF_TOTAL_CHUNKS..OFF_TOTAL_CHUNKS + 8],
            self.total_chunks,
        );
        plain[OFF_VK..OFF_VK + MLDSA_VK_LEN].copy_from_slice(self.mldsa_vk.as_slice());
        plain[OFF_SIG..OFF_SIG + MLDSA_SIG_LEN].copy_from_slice(self.mldsa_sig.as_slice());

        let mut nonce = [0u8; NONCE_LEN];
        rng::fill(&mut nonce)?;
        let key = AeadKey::from_bytes(*metadata_key);
        let ct = aead::encrypt(&key, &nonce, METADATA_AAD, &plain)?;
        plain.zeroize();

        let mut blob = [0u8; METADATA_BLOB_LEN];
        blob[..NONCE_LEN].copy_from_slice(&nonce);
        blob[NONCE_LEN..NONCE_LEN + ct.len()].copy_from_slice(&ct);
        Ok(blob)
    }

    /// AEAD-decrypt + parse the blob, verifying the ML-DSA signature
    /// against `salt`. Returns `NotAVault` if the internal magic is
    /// wrong, `UnsupportedVersion` on a version mismatch, and
    /// `HeaderSignatureInvalid` if the one-shot attestation fails.
    pub fn open(
        blob: &[u8],
        metadata_key: &[u8; aead::KEY_LEN],
        salt: &[u8; SALT_LEN],
    ) -> Result<Self> {
        if blob.len() < METADATA_BLOB_LEN {
            return Err(FormatError::TooSmall(blob.len() as u64));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&blob[..NONCE_LEN]);
        let ct = &blob[NONCE_LEN..METADATA_BLOB_LEN];
        let key = AeadKey::from_bytes(*metadata_key);
        let plain = aead::decrypt(&key, &nonce, METADATA_AAD, ct).map_err(FormatError::Crypto)?;
        if plain.len() != METADATA_PLAINTEXT_LEN {
            return Err(FormatError::Manifest("metadata plaintext length mismatch".into()));
        }
        if plain[OFF_MAGIC..OFF_MAGIC + 4] != METADATA_MAGIC {
            return Err(FormatError::NotAVault);
        }
        let version = LittleEndian::read_u16(&plain[OFF_VERSION..OFF_VERSION + 2]);
        if version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(version));
        }
        let total_chunks = LittleEndian::read_u64(&plain[OFF_TOTAL_CHUNKS..OFF_TOTAL_CHUNKS + 8]);

        let mut mldsa_vk = Box::new([0u8; MLDSA_VK_LEN]);
        mldsa_vk.copy_from_slice(&plain[OFF_VK..OFF_VK + MLDSA_VK_LEN]);
        let mut mldsa_sig = Box::new([0u8; MLDSA_SIG_LEN]);
        mldsa_sig.copy_from_slice(&plain[OFF_SIG..OFF_SIG + MLDSA_SIG_LEN]);

        // Verify the one-shot ML-DSA attestation.
        let msg = signed_metadata_message(version, total_chunks, salt, &mldsa_vk);
        let vk = MlDsaVerifyingKey::from_bytes(&mldsa_vk).map_err(FormatError::Crypto)?;
        sign::mldsa_verify(&vk, &msg, &mldsa_sig)
            .map_err(|_| FormatError::HeaderSignatureInvalid)?;

        Ok(Self {
            version,
            total_chunks,
            mldsa_vk,
            mldsa_sig,
        })
    }
}

/// Compute a 32-byte vault fingerprint from the ML-DSA verifying key.
///
/// Stable per vault (the VK is generated fresh at creation and the
/// signing key is destroyed immediately after). Record it after creation
/// to detect later substitution. In v0.5 the VK is no longer observable
/// without unlocking, so the fingerprint is necessarily a post-unlock
/// value (an improvement: nothing leaks before authentication).
pub fn fingerprint_from_vk(mldsa_vk: &[u8; MLDSA_VK_LEN]) -> [u8; 32] {
    blake3::derive_key("farewell.vault.fingerprint.v5", mldsa_vk.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signed(total_chunks: u64, salt: &[u8; SALT_LEN]) -> Metadata {
        let (sk, vk) = sign::mldsa_generate();
        let vk_bytes = vk.to_bytes();
        let msg = signed_metadata_message(FORMAT_VERSION, total_chunks, salt, &vk_bytes);
        let sig = sign::mldsa_sign(&sk, &msg);
        Metadata::new(total_chunks, vk_bytes, sig)
    }

    #[test]
    fn seal_open_roundtrip() {
        let salt = [0x11u8; SALT_LEN];
        let key = [0x22u8; aead::KEY_LEN];
        let m = make_signed(64, &salt);
        let vk_copy = m.mldsa_vk.clone();
        let blob = m.seal(&key).unwrap();
        assert_eq!(blob.len(), METADATA_BLOB_LEN);
        let parsed = Metadata::open(&blob, &key, &salt).unwrap();
        assert_eq!(parsed.version, FORMAT_VERSION);
        assert_eq!(parsed.total_chunks, 64);
        assert_eq!(parsed.mldsa_vk.as_ref(), vk_copy.as_ref());
    }

    #[test]
    fn wrong_metadata_key_fails() {
        let salt = [0x11u8; SALT_LEN];
        let key = [0x22u8; aead::KEY_LEN];
        let bad = [0x33u8; aead::KEY_LEN];
        let m = make_signed(64, &salt);
        let blob = m.seal(&key).unwrap();
        assert!(matches!(
            Metadata::open(&blob, &bad, &salt),
            Err(FormatError::Crypto(_))
        ));
    }

    #[test]
    fn wrong_salt_fails_signature() {
        let salt = [0x11u8; SALT_LEN];
        let other_salt = [0x99u8; SALT_LEN];
        let key = [0x22u8; aead::KEY_LEN];
        let m = make_signed(64, &salt);
        let blob = m.seal(&key).unwrap();
        // Decrypts fine (AEAD key matches) but the signature was bound to
        // `salt`, so verifying against `other_salt` must fail.
        assert!(matches!(
            Metadata::open(&blob, &key, &other_salt),
            Err(FormatError::HeaderSignatureInvalid)
        ));
    }

    #[test]
    fn tampered_blob_fails() {
        let salt = [0x11u8; SALT_LEN];
        let key = [0x22u8; aead::KEY_LEN];
        let m = make_signed(64, &salt);
        let mut blob = m.seal(&key).unwrap();
        blob[NONCE_LEN + 100] ^= 0xFF;
        assert!(Metadata::open(&blob, &key, &salt).is_err());
    }

    #[test]
    fn fingerprint_is_stable_and_distinct() {
        let vk1 = Box::new([0xABu8; MLDSA_VK_LEN]);
        let vk2 = Box::new([0xCDu8; MLDSA_VK_LEN]);
        assert_eq!(fingerprint_from_vk(&vk1), fingerprint_from_vk(&vk1));
        assert_ne!(fingerprint_from_vk(&vk1), fingerprint_from_vk(&vk2));
    }

    #[test]
    fn blob_looks_random_across_seals() {
        let salt = [0x11u8; SALT_LEN];
        let key = [0x22u8; aead::KEY_LEN];
        let m = make_signed(64, &salt);
        let b1 = m.seal(&key).unwrap();
        let b2 = m.seal(&key).unwrap();
        // Random nonce per seal → different ciphertext for identical input.
        assert_ne!(&b1[..], &b2[..]);
    }
}
