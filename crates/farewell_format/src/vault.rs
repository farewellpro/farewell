//! High-level Vault operations — v0.4 (FIDO2 hardware-key support).
//!
//! Builds on the v0.3 overlapping-range design: each level conceptually
//! owns the entire chunks region, its manifest at a chunk derived from
//! its master key. v0.4 adds optional FIDO2 hardware-key wrapping per
//! level (0 to 3 keys, each independently sufficient).
//!
//! At setup, callers provide one [`LevelSpec`] per level — its
//! passphrase plus a fully-prepared [`LevelEnrollment`]. The enrollment
//! is produced by calling `Authenticator::enroll` and
//! `challenge_response` upfront. This keeps the vault crate
//! transport-agnostic.
//!
//! At unlock, callers provide the passphrase plus an optional
//! [`Authenticator`]. The vault tries each slot in sequence; the unique
//! matching slot drives the rest of the unlock.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use farewell_crypto::{aead, kdf, rng};
use farewell_fido2::Authenticator;
use farewell_keys::SecureBuffer;
use rand::rngs::OsRng;
use rand::seq::IteratorRandom;
use zeroize::Zeroize;

use crate::chunk::{
    self, derive_chunk_key, encrypt_chunk, random_chunk, ChunkIndex, CHUNK_PLAINTEXT_LEN,
    CHUNK_STORED_LEN,
};
use crate::manifest::{FileEntry, FileStat, Manifest};
use crate::metadata::{self, Metadata, METADATA_BLOB_LEN, SALT_LEN};
use crate::slot::{
    LevelEnrollment, UnwrappedSlot, WrappedSlot, MASTER_KEY_LEN, METADATA_KEY_LEN, NUM_SLOTS,
    SLOT_LEN,
};
use crate::{FormatError, Result};

// ===== v0.5 on-disk layout (indistinguishable from random) =====
//
//   [0 .. 32)              salt                (plaintext, uniform random)
//   [32 .. +3·SLOT_LEN)    slots               (per-level AEAD, or random)
//   [.. +METADATA_BLOB)    metadata blob       (AEAD under shared metadata_key)
//   [.. EOF)               chunks              (per-chunk AEAD)
//
// No magic, version, or algorithm id appears in cleartext anywhere; the
// only plaintext is the salt, which is uniform random by construction.
// There is deliberately NO auto-wipe region: a wipe-after-N-failures
// defense and byte-level indistinguishability are mutually exclusive
// (the counter must be updatable on the wrong-passphrase path, hence
// outside passphrase-gated encryption and therefore detectable), and the
// wipe never defended against a disk-imaging adversary anyway. Defense
// against offline brute force rests on Argon2id hardness + passphrase
// entropy (+ an optional FIDO2 hardware key). See THREAT_MODEL §5.4.
const SALT_OFFSET: u64 = 0;
const SLOTS_REGION_OFFSET: u64 = SALT_LEN as u64;
const SLOTS_REGION_LEN: usize = NUM_SLOTS * SLOT_LEN;
const METADATA_REGION_OFFSET: u64 = SLOTS_REGION_OFFSET + SLOTS_REGION_LEN as u64;
const CHUNKS_REGION_OFFSET: u64 = METADATA_REGION_OFFSET + METADATA_BLOB_LEN as u64;

// ===== KDF profile selection =====
//
// The Argon2id cost is the *substitute* for hardware: for a
// passphrase-only vault it is the entire offline-brute-force defense
// (there is no auto-wipe), so it must be expensive. For a vault enrolled
// with a FIDO2 key, a copy is uncrackable without the physical key's
// hmac-secret regardless of KDF cost — so we use a light KDF there, which
// keeps the touch flow fluid (no multi-second gaps scattering the YubiKey
// prompts). See THREAT_MODEL §5.4.
//
// Trade-off, documented and accepted: with a light KDF an attacker who
// brute-forces the slot's outer AEAD could recover the *passphrase* (and
// confirm the file is a Farewell vault), but STILL cannot open the vault
// without the physical key. A strong/generated passphrase keeps even that
// infeasible. The data is always protected by the key.
//
// The chosen params are NOT stored on disk (that would be a deniability
// tell), so `open` tries the candidates in order (light first, so
// hardware vaults resolve instantly). Changing any params is a format
// change — vaults are not openable across different params.

/// Passphrase-only vaults: full hardening. Tests/dev use the light params.
#[cfg(any(test, feature = "dev-kdf"))]
const KDF_PP: &kdf::KdfParams = &kdf::DEV_PARAMS;
#[cfg(not(any(test, feature = "dev-kdf")))]
const KDF_PP: &kdf::KdfParams = &kdf::PRODUCTION_PARAMS;

/// Hardware-key vaults: light params (the key carries the resistance).
const KDF_HW: &kdf::KdfParams = &kdf::DEV_PARAMS;

/// Candidate profiles tried on open, in order (light → hardened).
const KDF_CANDIDATES: &[&kdf::KdfParams] = &[KDF_HW, KDF_PP];

/// Emit a one-line timing diagnostic to stderr when `FAREWELL_TIMING` is set;
/// silent and free otherwise. Used to pinpoint where a slow open goes (KDF
/// derivation vs. the authenticator challenge/touch). The closure runs only
/// when enabled.
fn timing(msg: impl FnOnce() -> String) {
    if std::env::var_os("FAREWELL_TIMING").is_some() {
        eprintln!("[farewell-timing] {}", msg());
    }
}

/// The KDF a freshly-built vault uses: light if any level enrolls a
/// hardware key, hardened otherwise.
fn build_kdf_params(levels: &[LevelSpec]) -> &'static kdf::KdfParams {
    if levels.iter().any(|l| !l.enrollment.is_empty()) {
        KDF_HW
    } else {
        KDF_PP
    }
}

/// Number of chunks in stripe `slot` within a region of `total_chunks`.
/// Stripe `s` owns chunks `{s, s+NUM_SLOTS, s+2·NUM_SLOTS, …}`.
fn stripe_len(slot: u8, total_chunks: u64) -> u64 {
    let s = slot as u64;
    let n = NUM_SLOTS as u64;
    if s >= total_chunks {
        0
    } else {
        // count of c in [0, total) with c % n == s
        (total_chunks - s + (n - 1)) / n
    }
}

/// Map a within-stripe ordinal to an absolute chunk index for `slot`.
fn stripe_chunk(slot: u8, ordinal: u64) -> ChunkIndex {
    ChunkIndex((slot as u64 + ordinal * (NUM_SLOTS as u64)) as u32)
}

/// Compute the chunk index where a level's manifest lives.
///
/// v0.4 (striped, non-overlapping): the manifest sits inside the
/// level's own disjoint stripe — chunks `c` with `c % NUM_SLOTS ==
/// slot`. Its ordinal within the stripe is derived deterministically
/// from the master key. Because every level is confined to its own
/// stripe, no level's manifest (or files) can ever land in another
/// level's chunks — cross-level corruption is impossible by
/// construction (see ARCHITECTURE §6).
pub fn manifest_chunk_for_slot(
    master: &[u8; MASTER_KEY_LEN],
    slot: u8,
    total_chunks: u64,
) -> ChunkIndex {
    let len = stripe_len(slot, total_chunks).max(1);
    let derived = blake3::derive_key("farewell.manifest.chunk.v4", master);
    let n = u64::from_le_bytes(derived[0..8].try_into().expect("8 bytes"));
    stripe_chunk(slot, n % len)
}

/// Normalize a folder path: drop leading/trailing/duplicate slashes,
/// reject empty results and any component containing ASCII control
/// chars. Returns the canonical `a/b/c` form, or `None` if invalid.
fn normalize_folder(path: &str) -> Option<String> {
    let parts: Vec<&str> = path
        .split('/')
        .filter(|c| !c.is_empty())
        .collect();
    if parts.is_empty() {
        return None;
    }
    for c in &parts {
        if c.bytes().any(|b| b.is_ascii_control()) {
            return None;
        }
    }
    Some(parts.join("/"))
}

/// The folder containing a file name, or `None` if the file is at the
/// root. `"a/b/x.txt"` → `Some("a/b")`; `"x.txt"` → `None`.
fn parent_folder(name: &str) -> Option<String> {
    name.rfind('/').map(|i| name[..i].to_string())
}

/// All ancestor paths of a normalized folder, root-first.
/// `"a/b/c"` → `["a", "a/b", "a/b/c"]`.
fn ancestor_paths(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut acc = String::new();
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(comp);
        out.push(acc.clone());
    }
    out
}

/// One level's setup specification: passphrase + HW key enrollment.
pub struct LevelSpec {
    /// Passphrase for this level (zeroized when the spec is consumed).
    pub passphrase: Vec<u8>,
    /// Hardware-key enrollment for this level. May be `passphrase_only()`
    /// for K=0 (development / passphrase-only mode).
    pub enrollment: LevelEnrollment,
}

impl LevelSpec {
    /// Construct a passphrase-only level spec.
    pub fn passphrase_only(passphrase: Vec<u8>) -> Self {
        Self {
            passphrase,
            enrollment: LevelEnrollment::passphrase_only(),
        }
    }
}

/// Enroll one hardware key against the salt of a vault under
/// construction. Returns `(credential_id, hmac_output)` ready to be
/// stored in a [`LevelEnrollment`].
///
/// The authenticator's Relying-Party identifier was bound at its
/// construction; only `user_handle` is supplied here.
///
/// ```ignore
/// let salt: [u8; 32] = rng::bytes(32).try_into().unwrap();
/// let (cred, out) = enroll_hw_key(&mut auth, &salt, b"vault-id")?;
/// let mut enr = LevelEnrollment::passphrase_only();
/// enr.push(cred, out)?;
/// VaultBuilder::new(path, vec![LevelSpec { passphrase, enrollment: enr }])?
///     .with_salt(salt)
///     .build()?;
/// ```
pub fn enroll_hw_key<A: Authenticator>(
    authenticator: &mut A,
    vault_salt: &[u8; 32],
    user_handle: &[u8],
) -> Result<(Vec<u8>, [u8; farewell_fido2::HMAC_OUTPUT_LEN])> {
    let cred = authenticator
        .enroll(user_handle)
        .map_err(|e| FormatError::Manifest(format!("fido2 enroll: {e}")))?;
    let fido_salt = crate::slot::fido_salt_from_vault_salt(vault_salt);
    let (_, out) = authenticator
        .challenge_response(&[cred.clone()], &fido_salt)
        .map_err(|e| FormatError::Manifest(format!("fido2 challenge: {e}")))?;
    Ok((cred, out))
}

/// Flush a file all the way to durable media (see `Vault::durable_sync`).
/// On macOS, `fcntl(F_FULLFSYNC)`; elsewhere a plain `fsync`.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)] // one fcntl(F_FULLFSYNC); see lib.rs preamble
fn durable_sync_file(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    // SAFETY: `file` is open for the lifetime of this call; F_FULLFSYNC only flushes.
    let r = unsafe { libc::fcntl(fd, libc::F_FULLFSYNC) };
    if r == 0 {
        Ok(())
    } else {
        file.sync_all()
    }
}

#[cfg(not(target_os = "macos"))]
fn durable_sync_file(file: &File) -> std::io::Result<()> {
    file.sync_all()
}

/// Phase of a [`migrate_vault`] run, for progress reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigratePhase {
    /// Pre-allocating the destination vault's chunks (the slow part).
    Allocate,
    /// Copying file content from source to destination.
    Copy,
    /// Re-reading the destination and verifying it matches the source.
    Verify,
}

/// Destination capacity for a [`migrate_vault`].
#[derive(Debug, Clone, Copy)]
pub enum MigrateCapacity {
    /// Same capacity as the source (preserve free headroom).
    Same,
    /// Just enough for the current contents, plus a modest margin
    /// (`max(used/4, 256 chunks ≈ 16 MiB)`). The lever for tight disks.
    ShrinkToFit,
    /// An exact capacity in chunks; rejected if it can't hold the contents.
    Exact(u64),
}

/// Outcome of a successful [`migrate_vault`].
#[derive(Debug, Clone, Copy)]
pub struct MigrateReport {
    /// Number of files migrated.
    pub files: u64,
    /// Total plaintext bytes copied.
    pub bytes: u64,
    /// Source manifest counter before migration.
    pub old_counter: u64,
    /// Destination manifest counter (carried forward: ≥ old + 1).
    pub new_counter: u64,
    /// Capacity (chunks) of the destination vault.
    pub new_total_chunks: u64,
}

/// Re-encrypt an entire vault into a **new** vault file at `dst_path` (fresh
/// salt + keys, and — the seam a future format bump uses — written in the
/// current [`FORMAT_VERSION`]). This is the crypto-agility / rotation engine.
///
/// It is deliberately **side-by-side**: the source is opened read-only and left
/// untouched; everything is streamed (64 KiB windows, never a whole file in
/// RAM) into the destination, which is then re-read and verified byte-for-byte
/// (via BLAKE3) before this returns `Ok`. The caller owns the atomic swap and
/// the disposition of the old file. On **any** error the destination at
/// `dst_path` is left for the caller to delete; the source is never modified.
///
/// `new_total_chunks`:
/// - `None` → same capacity as the source (preserve free headroom).
/// - `Some(n)` → caller-chosen capacity (e.g. "shrink to fit"); rejected if it
///   cannot hold the current contents.
///
/// `hw_user_handle`: `Some(handle)` enrolls a hardware key (via `authenticator`)
/// on the destination; `None` builds a passphrase-only destination. The same
/// `authenticator` is used to open the (possibly hardware-protected) source.
///
/// The destination's manifest counter is carried forward to `old + 1` so a
/// migrated vault can't be rolled back to a pre-migration copy via
/// `--expect-counter`.
#[allow(clippy::too_many_arguments)]
pub fn migrate_vault<A: Authenticator>(
    src_path: impl AsRef<Path>,
    dst_path: impl AsRef<Path>,
    passphrase: Vec<u8>,
    mut authenticator: Option<&mut A>,
    hw_user_handle: Option<&[u8]>,
    capacity: MigrateCapacity,
    mut progress: impl FnMut(MigratePhase, u64, u64),
) -> Result<MigrateReport> {
    let chunk_plain = CHUNK_PLAINTEXT_LEN as u64;

    // 1. Open the source (read-only intent; opened r/w for the advisory lock).
    let mut src = Vault::open(src_path.as_ref(), passphrase.clone(), authenticator.as_deref_mut())?;

    // 2. Snapshot the plan: files (name, size) and folders.
    let files: Vec<(String, u64)> = src.list().iter().map(|e| (e.name.clone(), e.size)).collect();
    let folders: Vec<String> = src.folders();
    let old_counter = src.counter().unwrap_or(0);
    let src_total = src.total_chunks();

    // 3. Target capacity. The destination needs one chunk for the manifest
    //    plus enough for every file's data chunks.
    let used_file_chunks: u64 = files
        .iter()
        .map(|(_, sz)| sz.div_ceil(chunk_plain))
        .sum();
    let min_chunks = used_file_chunks + 1;
    let target_chunks = match capacity {
        MigrateCapacity::Same => src_total,
        MigrateCapacity::ShrinkToFit => {
            // ~25% headroom, with a small floor (16 chunks ≈ 1 MiB), but never
            // larger than the source — "shrink" must not grow a small vault.
            let margin = (used_file_chunks / 4).max(16);
            (min_chunks + margin).min(src_total)
        }
        MigrateCapacity::Exact(n) if n < min_chunks => {
            return Err(FormatError::Manifest(format!(
                "requested capacity {n} chunks too small; need at least {min_chunks}"
            )));
        }
        MigrateCapacity::Exact(n) => n,
    };

    // 4. Fresh salt for the destination.
    let mut salt = [0u8; SALT_LEN];
    rng::fill(&mut salt)?;

    // 5. Build the destination's level spec, enrolling a hardware key if asked.
    let mut enrollment = LevelEnrollment::passphrase_only();
    if let (Some(auth), Some(handle)) = (authenticator.as_deref_mut(), hw_user_handle) {
        let (cred, out) = enroll_hw_key(auth, &salt, handle)?;
        enrollment.push(cred, out)?;
    }
    let level = LevelSpec { passphrase, enrollment };

    // 6. Build the destination (full pre-allocation; slow → reports progress).
    let mut dst = VaultBuilder::new(dst_path.as_ref(), vec![level])?
        .with_salt(salt)
        .total_chunks(target_chunks)
        .build_with_progress(|done, total| progress(MigratePhase::Allocate, done, total))?;

    // 7. Recreate folders (empty folders persist; non-empty are implied).
    for f in &folders {
        dst.create_folder(f)?;
    }

    // 8. Copy each file, streamed, hashing the source bytes as we go.
    let total_files = files.len() as u64;
    let mut total_bytes = 0u64;
    let mut hashes: Vec<(String, u64, [u8; 32])> = Vec::with_capacity(files.len());
    for (i, (name, size)) in files.iter().enumerate() {
        dst.create_file(name)?;
        let mut hasher = blake3::Hasher::new();
        let mut off = 0u64;
        while off < *size {
            let buf = src.read_file_range(name, off, chunk_plain)?;
            if buf.is_empty() {
                break;
            }
            hasher.update(&buf);
            dst.write_file_range(name, off, &buf)?;
            off += buf.len() as u64;
        }
        total_bytes += *size;
        hashes.push((name.clone(), *size, *hasher.finalize().as_bytes()));
        progress(MigratePhase::Copy, (i + 1) as u64, total_files);
    }

    // 9. Carry the anti-rollback counter forward (old + 1, at least), and the
    //    opt-in creator identity (a migrated vault keeps its original owner).
    let want_counter = old_counter.saturating_add(1);
    let src_owner = src.owner().map(str::to_string);
    {
        let m = dst
            .mounted
            .as_mut()
            .ok_or_else(|| FormatError::Manifest("destination not mounted".into()))?;
        if m.manifest.counter < want_counter {
            m.manifest.counter = want_counter;
        }
        m.manifest.owner = src_owner;
    }
    dst.commit_manifest()?;

    // 10. Verify: re-read the destination and compare to the source hashes.
    if dst.list().len() != files.len() {
        return Err(FormatError::Manifest("destination file count mismatch".into()));
    }
    for (i, (name, size, expected)) in hashes.iter().enumerate() {
        let mut hasher = blake3::Hasher::new();
        let mut off = 0u64;
        while off < *size {
            let buf = dst.read_file_range(name, off, chunk_plain)?;
            if buf.is_empty() {
                break;
            }
            hasher.update(&buf);
            off += buf.len() as u64;
        }
        if hasher.finalize().as_bytes() != expected {
            return Err(FormatError::Manifest(format!(
                "verification mismatch for \"{name}\""
            )));
        }
        progress(MigratePhase::Verify, (i + 1) as u64, total_files);
    }

    // 11. Force the destination to durable media before declaring success.
    dst.durable_sync()?;
    let new_counter = dst.counter().unwrap_or(0);

    Ok(MigrateReport {
        files: total_files,
        bytes: total_bytes,
        old_counter,
        new_counter,
        new_total_chunks: target_chunks,
    })
}

/// Builder used to create a new vault.
pub struct VaultBuilder {
    path: PathBuf,
    levels: Vec<LevelSpec>,
    total_chunks: u64,
    explicit_salt: Option<[u8; 32]>,
    /// Opt-in creator identity recorded in the manifest (None = anonymous).
    owner: Option<String>,
}

impl VaultBuilder {
    /// Start building a vault at `path` with 1 to 3 [`LevelSpec`]s.
    pub fn new(path: impl Into<PathBuf>, levels: Vec<LevelSpec>) -> Result<Self> {
        if levels.is_empty() || levels.len() > NUM_SLOTS {
            return Err(FormatError::Manifest(format!(
                "expected 1..={NUM_SLOTS} levels, got {}",
                levels.len()
            )));
        }
        Ok(Self {
            path: path.into(),
            levels,
            total_chunks: 16,
            explicit_salt: None,
            owner: None,
        })
    }

    /// Convenience for the single-level passphrase-only case.
    pub fn single_passphrase(path: impl Into<PathBuf>, passphrase: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            levels: vec![LevelSpec::passphrase_only(passphrase)],
            total_chunks: 16,
            explicit_salt: None,
            owner: None,
        }
    }

    /// Record an opt-in creator identity (e.g. the license email) in the
    /// vault's manifest. Stored encrypted (visible only after unlock); empty
    /// or unset means anonymous. OFF by default.
    pub fn owner(mut self, owner: Option<String>) -> Self {
        self.owner = owner.filter(|s| !s.is_empty());
        self
    }

    /// Override the vault's random salt with a caller-provided one.
    ///
    /// Useful when hardware-key enrollment must be performed *before*
    /// the vault is written to disk: the caller derives the FIDO salt
    /// from this value, enrolls credentials, and feeds the resulting
    /// [`LevelEnrollment`] into the builder.
    pub fn with_salt(mut self, salt: [u8; 32]) -> Self {
        self.explicit_salt = Some(salt);
        self
    }

    /// Set the total chunk capacity. Must be ≥ 2 × number_of_levels so
    /// each level has at least its manifest plus one data chunk.
    pub fn total_chunks(mut self, n: u64) -> Self {
        let min_required = 2 * self.levels.len() as u64;
        self.total_chunks = n.max(min_required);
        self
    }

    /// Create the vault on disk.
    pub fn build(self) -> Result<Vault> {
        self.build_with_progress(|_, _| {})
    }

    /// Like [`build`](Self::build), but reports chunk-write progress via
    /// `progress(written, total)` (throttled to ~100 calls) so a caller
    /// can drive a real progress bar — the chunk fill (random CSPRNG, for
    /// deniability) dominates creation time for large vaults.
    pub fn build_with_progress<F: FnMut(u64, u64)>(mut self, mut progress: F) -> Result<Vault> {
        // The only plaintext field: a uniform-random salt.
        let salt: [u8; SALT_LEN] = match self.explicit_salt.take() {
            Some(s) => s,
            None => {
                let mut s = [0u8; SALT_LEN];
                rng::fill(&mut s)?;
                s
            }
        };

        // Shared metadata key, carried (identically) inside every active
        // slot, decrypting the single metadata blob. Generated fresh.
        let mut metadata_key = [0u8; METADATA_KEY_LEN];
        rng::fill(&mut metadata_key)?;

        // ===== One-shot ML-DSA signing key =====
        //
        // The verifying key goes into the (encrypted) metadata blob. The
        // signing key signs the canonical metadata once, then is dropped
        // (Drop zeroizes the seed). Afterward nobody can produce a valid
        // attestation for this vault.
        let (sig_sk, sig_vk) = farewell_crypto::sign::mldsa_generate();
        let vk_bytes = sig_vk.to_bytes();
        let signed_message =
            metadata::signed_metadata_message(metadata::FORMAT_VERSION, self.total_chunks, &salt, &vk_bytes);
        let signature = farewell_crypto::sign::mldsa_sign(&sig_sk, &signed_message);
        drop(sig_sk);

        let metadata = Metadata::new(self.total_chunks, vk_bytes, signature);
        let metadata_blob = metadata.seal(&metadata_key)?;

        // Light KDF if this vault enrolls a hardware key, hardened
        // otherwise. Applied uniformly to every level of the vault.
        let build_kdf = build_kdf_params(&self.levels);

        let mut active: Vec<(usize, [u8; MASTER_KEY_LEN])> = Vec::new();
        let mut slots = [[0u8; SLOT_LEN]; NUM_SLOTS];

        for (i, spec) in self.levels.iter_mut().enumerate() {
            let derived = kdf::derive(&spec.passphrase, &salt, build_kdf)?;
            spec.passphrase.zeroize();
            let passphrase_key = *derived.as_bytes();

            // Striped layout: level `i` lives entirely in stripe `i`.
            let mut master_bytes = [0u8; MASTER_KEY_LEN];
            rng::fill(&mut master_bytes)?;

            slots[i] =
                WrappedSlot::wrap(&passphrase_key, &master_bytes, &metadata_key, &spec.enrollment)?;
            active.push((i, master_bytes));
        }

        // Indistinguishable random for unused slots.
        for i in self.levels.len()..NUM_SLOTS {
            slots[i] = WrappedSlot::fill_indistinguishable()?;
        }

        // Create the file.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&self.path)?;

        // Acquire the cross-process advisory lock before writing anything.
        crate::lock::acquire_exclusive(&file)?;

        // Layout: salt || slots || metadata blob || chunks
        file.write_all(&salt)?;
        for s in &slots {
            file.write_all(s)?;
        }
        file.write_all(&metadata_blob)?;
        let total = self.total_chunks;
        let step = (total / 100).max(1); // ~100 progress callbacks max
        for i in 0..total {
            file.write_all(&random_chunk()?)?;
            if (i + 1) % step == 0 || i + 1 == total {
                progress(i + 1, total);
            }
        }
        file.sync_all()?;

        // Commit the empty manifest for the single content tree.
        let mut vault = Vault {
            file,
            path: self.path.clone(),
            metadata,
            mounted: None,
            hw_key_count: None,
        };
        // The opt-in owner is recorded only on the PRIMARY level's manifest.
        for (i, (slot, master)) in active.iter().enumerate() {
            let owner = if i == 0 { self.owner.as_deref() } else { None };
            vault.write_empty_manifest_for(*slot as u8, master, owner)?;
        }
        vault.file.sync_all()?;

        // Leave the PRIMARY level (first declared, slot 0) mounted, reusing
        // the master key we just generated. This means a freshly created
        // vault comes back already open — no re-derivation and, crucially,
        // no extra hardware-key touch to mount it.
        if let Some((pslot, pmaster)) = active.first().copied() {
            let mut pmaster = pmaster;
            let manifest_chunk =
                manifest_chunk_for_slot(&pmaster, pslot as u8, vault.metadata.total_chunks);
            let mut mounted_manifest = Manifest::empty();
            mounted_manifest.owner = self.owner.clone();
            vault.mounted = Some(MountedLevel {
                master: SecureBuffer::from_vec(pmaster.to_vec()),
                slot: pslot as u8,
                manifest_chunk,
                manifest: mounted_manifest,
                off_limits: BTreeSet::new(),
            });
            pmaster.zeroize();
        }

        for (_, mut master) in active.drain(..) {
            master.zeroize();
        }

        Ok(vault)
    }

    /// Alias for [`build`].
    pub fn create(self) -> Result<Vault> {
        self.build()
    }
}

/// An open vault. May be mounted (after `open*`) or unmounted (right
/// after `build`).
pub struct Vault {
    file: File,
    path: PathBuf,
    /// Decrypted shared metadata (version, capacity, ML-DSA attestation).
    metadata: Metadata,
    mounted: Option<MountedLevel>,
    /// Hardware-key credentials enrolled in the mounted slot (0 =
    /// passphrase-only). `None` until mounted. Lets callers show how many
    /// keys open the vault and cap further enrollment.
    hw_key_count: Option<usize>,
}

struct MountedLevel {
    master: SecureBuffer,
    /// The single slot index (always 0). Retained for chunk-key and
    /// manifest derivation.
    slot: u8,
    manifest_chunk: ChunkIndex,
    manifest: Manifest,
    off_limits: BTreeSet<u32>,
}

impl Vault {
    /// Open `path` with `passphrase`. If the vault's enrolled level
    /// requires a hardware key, pass an [`Authenticator`] in
    /// `authenticator`; otherwise pass `None` (acceptable in K=0 mode
    /// only).
    pub fn open<A: Authenticator>(
        path: impl AsRef<Path>,
        passphrase: Vec<u8>,
        authenticator: Option<&mut A>,
    ) -> Result<Self> {
        Self::open_inner(path, passphrase, authenticator)
    }

    fn open_inner<A: Authenticator>(
        path: impl AsRef<Path>,
        mut passphrase: Vec<u8>,
        mut authenticator: Option<&mut A>,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;

        // Acquire the cross-process advisory lock before any further
        // I/O. Two concurrent mounts would race on the manifest commit;
        // we refuse here with AlreadyLocked rather than risk corruption.
        crate::lock::acquire_exclusive(&file)?;

        // ----- Read the plaintext salt (the only cleartext field) -----
        let mut salt = [0u8; SALT_LEN];
        file.seek(SeekFrom::Start(SALT_OFFSET))?;
        file.read_exact(&mut salt)?;

        // There is no auto-wipe and no on-disk attempt counter: defense
        // against offline brute force is the cost of Argon2id per guess
        // plus passphrase entropy (+ an optional FIDO2 key). See the
        // module-level layout note and THREAT_MODEL §5.4.

        // Read slots.
        let mut slots = [[0u8; SLOT_LEN]; NUM_SLOTS];
        file.seek(SeekFrom::Start(SLOTS_REGION_OFFSET))?;
        for s in &mut slots {
            file.read_exact(s)?;
        }

        // Read the encrypted metadata blob.
        let mut metadata_blob = [0u8; METADATA_BLOB_LEN];
        file.seek(SeekFrom::Start(METADATA_REGION_OFFSET))?;
        file.read_exact(&mut metadata_blob)?;

        // Wrap the rest of the open in a closure-like block so the file
        // handle moves into the (partial) Vault cleanly on success.
        let attempt: Result<(Vault, [u8; MASTER_KEY_LEN])> = (|| {
            // Try each KDF profile in turn (light first → hardware vaults
            // resolve instantly; the params aren't stored on disk). A
            // passphrase-only vault's outer AEAD fails under the light key
            // *before* the authenticator is queried, so it never triggers
            // a spurious touch; only the matching hardware vault does.
            let mut found: Option<(&'static kdf::KdfParams, UnwrappedSlot)> = None;
            for (ci, cand) in KDF_CANDIDATES.iter().enumerate() {
                let t_kdf = std::time::Instant::now();
                let pp_derived = kdf::derive(&passphrase, &salt, cand)?;
                timing(|| format!("kdf candidate {ci}: derive {:?}", t_kdf.elapsed()));
                let mut pp_key = [0u8; 32];
                pp_key.copy_from_slice(pp_derived.as_bytes());
                let t_unwrap = std::time::Instant::now();
                let r = WrappedSlot::try_unwrap_all(
                    &slots,
                    &pp_key,
                    &salt,
                    authenticator.as_deref_mut(),
                );
                timing(|| {
                    format!(
                        "kdf candidate {ci}: try_unwrap_all {:?} -> {}",
                        t_unwrap.elapsed(),
                        if r.is_ok() { "match" } else { "no" }
                    )
                });
                pp_key.zeroize();
                match r {
                    Ok(u) => {
                        found = Some((cand, u));
                        break;
                    }
                    // The outer decrypted (this is the slot's KDF) but the
                    // slot needs a hardware key and none was supplied. The
                    // remaining candidate(s) can't decrypt this slot, so
                    // stop now instead of doing a slow wasted derive, and
                    // report that a key is required.
                    Err(FormatError::HardwareKeyRequired) => {
                        passphrase.zeroize();
                        return Err(FormatError::HardwareKeyRequired);
                    }
                    Err(_) => {}
                }
            }
            passphrase.zeroize();
            let (chosen_kdf, primary) = match found {
                Some(v) => v,
                None => return Err(FormatError::Crypto(farewell_crypto::CryptoError::Decrypt)),
            };
            let primary_slot = primary.slot;

            // Decrypt + verify the shared metadata with the recovered
            // metadata key. This also performs the one-shot ML-DSA
            // attestation check (formerly the plaintext-header signature).
            let metadata = Metadata::open(&metadata_blob, &primary.metadata_key, &salt)?;
            let total_chunks = metadata.total_chunks;

            let primary_manifest_chunk =
                manifest_chunk_for_slot(&primary.master_key, primary_slot, total_chunks);

            let off_limits: BTreeSet<u32> = BTreeSet::new();
            let _ = chosen_kdf;
            let mut vault_for_reading = Vault {
                file,
                path: path.clone(),
                metadata,
                mounted: None,
                hw_key_count: Some(primary.num_hw_keys),
            };

            // Mount the (single) content tree.
            let stored = vault_for_reading.read_chunk_raw(primary_manifest_chunk)?;
            let chunk_key = derive_chunk_key(&primary.master_key, primary_manifest_chunk);
            let bytes = chunk::decrypt_chunk(&chunk_key, primary_manifest_chunk, &stored)?;
            let manifest = Manifest::parse(&bytes)?;

            vault_for_reading.mounted = Some(MountedLevel {
                master: SecureBuffer::from_vec(primary.master_key.to_vec()),
                slot: primary_slot,
                manifest_chunk: primary_manifest_chunk,
                manifest,
                off_limits,
            });
            Ok((vault_for_reading, primary.master_key))
        })();

        match attempt {
            Ok((vault, mut master_keep_alive)) => {
                // The local copy of the master key was only retained to
                // satisfy the closure's borrow-checker dance; zeroize it.
                master_keep_alive.zeroize();
                Ok(vault)
            }
            Err(e) => Err(e),
        }
    }

    fn write_empty_manifest_for(
        &mut self,
        slot: u8,
        master: &[u8; MASTER_KEY_LEN],
        owner: Option<&str>,
    ) -> Result<()> {
        let mc = manifest_chunk_for_slot(master, slot, self.metadata.total_chunks);
        let mut manifest = Manifest::empty();
        manifest.owner = owner.map(str::to_string);
        let bytes = manifest.serialize()?;
        let chunk_key = derive_chunk_key(master, mc);
        let stored = encrypt_chunk(&chunk_key, mc, &bytes)?;
        self.write_chunk_raw(mc, &stored)?;
        Ok(())
    }

    /// Path on disk.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The opt-in creator identity recorded in this vault's manifest, or `None`
    /// if anonymous. Only meaningful while a level is mounted — it lives inside
    /// the AEAD-encrypted manifest, so it never appears in cleartext on disk.
    pub fn owner(&self) -> Option<&str> {
        self.mounted.as_ref()?.manifest.owner.as_deref()
    }

    /// Number of hardware-key credentials enrolled in the mounted slot
    /// (0 = passphrase-only). `None` if the vault is not mounted (e.g.
    /// straight after `build` before any `open`).
    pub fn hw_key_count(&self) -> Option<usize> {
        self.hw_key_count
    }

    /// Files in the mounted level.
    pub fn list(&self) -> Vec<&FileEntry> {
        match &self.mounted {
            Some(m) => m.manifest.entries.iter().collect(),
            None => Vec::new(),
        }
    }

    /// Total chunks in the file.
    pub fn total_chunks(&self) -> u64 {
        self.metadata.total_chunks
    }

    /// Public, stable identifier of this vault: BLAKE3 of the
    /// embedded ML-DSA-87 verifying key.
    ///
    /// Same value as `farewell info` prints. Record it after vault
    /// creation; compare it later to detect substitution
    /// (a different `.vault` file would have a different
    /// fingerprint even if it opens with the same passphrase).
    pub fn fingerprint(&self) -> [u8; 32] {
        metadata::fingerprint_from_vk(&self.metadata.mldsa_vk)
    }

    /// Monotonic counter of the currently mounted level's manifest.
    ///
    /// Incremented on every state-changing operation (`add_file`,
    /// `delete_file`). Persisted inside the AEAD-encrypted manifest
    /// chunk, so it is cryptographically tamper-proof against
    /// in-place modification.
    ///
    /// **Anti-rollback note.** This counter cannot defend on its own
    /// against an attacker who replaces the entire `.vault` file with
    /// an older snapshot — that snapshot has a valid AEAD and a lower
    /// counter, but the file is internally consistent. Detection in
    /// that case requires the user to have recorded the latest
    /// counter externally and to compare it on next mount. The
    /// [`Vault::require_counter_at_least`] helper enforces such a
    /// check.
    pub fn counter(&self) -> Option<u64> {
        self.mounted.as_ref().map(|m| m.manifest.counter)
    }

    /// Usable capacity of the vault, in plaintext bytes, as
    /// `(total_bytes, free_bytes)`. Chunk-granular: `total` excludes
    /// the manifest chunk; `free` is what remains for new file data.
    /// Returns `None` if the vault is not mounted.
    ///
    /// The single content tree owns the whole capacity. A file of `S`
    /// bytes fits iff `S <= free_bytes` (chunk-granular:
    /// ceil(S/chunk) ≤ free_chunks ⟺ S ≤ free_bytes).
    pub fn space(&self) -> Option<(u64, u64)> {
        let m = self.mounted.as_ref()?;
        let total = self.metadata.total_chunks;
        if total == 0 {
            return Some((0, 0));
        }
        // One chunk holds the manifest; the rest are available for data.
        let usable_chunks = total - 1;
        let used_file_chunks: u64 = m
            .manifest
            .entries
            .iter()
            .map(|e| e.chunks.len() as u64)
            .sum();
        let free_chunks = usable_chunks.saturating_sub(used_file_chunks);
        let c = CHUNK_PLAINTEXT_LEN as u64;
        Some((usable_chunks * c, free_chunks * c))
    }

    /// Refuse if the mounted level's counter is below `expected`.
    /// Returns `Ok(())` if no level is mounted (no counter to compare).
    pub fn require_counter_at_least(&self, expected: u64) -> Result<()> {
        match self.counter() {
            Some(actual) if actual < expected => {
                Err(FormatError::CounterRollback { expected, actual })
            }
            _ => Ok(()),
        }
    }

    /// Add (or replace) a file in the mounted level.
    pub fn add_file(&mut self, name: &str, mut plaintext: Vec<u8>) -> Result<()> {
        if name.is_empty() {
            return Err(FormatError::InvalidName);
        }

        let existing_chunks: Vec<ChunkIndex> = self
            .mounted
            .as_ref()
            .and_then(|m| m.manifest.find(name).map(|e| e.chunks.clone()))
            .unwrap_or_default();

        let needed = plaintext.len().div_ceil(CHUNK_PLAINTEXT_LEN).max(1);
        let mut allocated = self.allocate_chunks(needed, &existing_chunks)?;

        let master_key = self.master_key_view()?;
        for (i, chunk_idx) in allocated.iter().copied().enumerate() {
            let start = i * CHUNK_PLAINTEXT_LEN;
            let end = ((i + 1) * CHUNK_PLAINTEXT_LEN).min(plaintext.len());
            let slice = &plaintext[start..end];
            let chunk_key = derive_chunk_key(&master_key, chunk_idx);
            let stored = encrypt_chunk(&chunk_key, chunk_idx, slice)?;
            self.write_chunk_raw(chunk_idx, &stored)?;
        }

        for old in &existing_chunks {
            if !allocated.contains(old) {
                self.write_chunk_raw(*old, &random_chunk()?)?;
            }
        }

        let entry = FileEntry {
            name: name.to_string(),
            size: plaintext.len() as u64,
            chunks: std::mem::take(&mut allocated),
        };
        plaintext.zeroize();

        let m = self.mounted.as_mut().expect("mounted ensured");
        m.manifest.upsert(entry);
        self.commit_manifest()?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Read a file's plaintext from the mounted level.
    pub fn read_file(&mut self, name: &str) -> Result<Vec<u8>> {
        let (size, chunks) = {
            let m = self
                .mounted
                .as_ref()
                .ok_or_else(|| FormatError::Manifest("no level mounted".into()))?;
            let entry = m
                .manifest
                .find(name)
                .ok_or_else(|| FormatError::FileNotFound(name.into()))?;
            (entry.size, entry.chunks.clone())
        };

        let master_key = self.master_key_view()?;
        let mut out = Vec::with_capacity(size as usize);
        for chunk_idx in chunks {
            let stored = self.read_chunk_raw(chunk_idx)?;
            let chunk_key = derive_chunk_key(&master_key, chunk_idx);
            let pt = chunk::decrypt_chunk(&chunk_key, chunk_idx, &stored)?;
            out.extend_from_slice(&pt);
        }
        out.truncate(size as usize);
        Ok(out)
    }

    /// `stat` equivalent: return lightweight metadata (name, size) for
    /// a file in the mounted level. Does NOT touch the encrypted
    /// chunks region — purely a manifest lookup, very cheap.
    ///
    /// Designed as the first call a filesystem layer (FSKit, FUSE)
    /// makes when resolving a path. Returns
    /// [`FormatError::FileNotFound`] if the name is not in the
    /// current manifest.
    pub fn stat_file(&self, name: &str) -> Result<FileStat> {
        let m = self
            .mounted
            .as_ref()
            .ok_or_else(|| FormatError::Manifest("no level mounted".into()))?;
        let entry = m
            .manifest
            .find(name)
            .ok_or_else(|| FormatError::FileNotFound(name.into()))?;
        Ok(FileStat::from(entry))
    }

    /// `readdir` equivalent: enumerate all files in the mounted level
    /// as a list of [`FileStat`]. Order matches manifest insertion.
    /// Returns an empty `Vec` if no level is mounted.
    pub fn readdir(&self) -> Vec<FileStat> {
        match &self.mounted {
            Some(m) => m.manifest.entries.iter().map(FileStat::from).collect(),
            None => Vec::new(),
        }
    }

    /// Read up to `len` bytes of a file's plaintext starting at
    /// `offset`. Returns fewer bytes (or an empty `Vec`) only when
    /// `offset` is at or past the end of the file.
    ///
    /// This is the range-aware primitive a filesystem layer needs:
    /// macOS's `pread`/FSKit calls land here directly, and only the
    /// chunks overlapping `[offset, offset + len)` get decrypted —
    /// never the whole file.
    ///
    /// Semantics:
    ///
    /// - If `offset >= file.size`, returns `Ok(vec![])` (EOF).
    /// - If `offset + len > file.size`, the read is clamped to the
    ///   real size; result length is `file.size - offset`.
    /// - `len == 0` is valid and returns `Ok(vec![])` without touching
    ///   the encrypted region.
    ///
    /// Errors propagate from chunk reads / AEAD verification just
    /// like [`Self::read_file`].
    pub fn read_file_range(
        &mut self,
        name: &str,
        offset: u64,
        len: u64,
    ) -> Result<Vec<u8>> {
        let (size, chunks) = {
            let m = self
                .mounted
                .as_ref()
                .ok_or_else(|| FormatError::Manifest("no level mounted".into()))?;
            let entry = m
                .manifest
                .find(name)
                .ok_or_else(|| FormatError::FileNotFound(name.into()))?;
            (entry.size, entry.chunks.clone())
        };

        // Past-EOF or zero-length: nothing to decrypt, fast path.
        if offset >= size || len == 0 {
            return Ok(Vec::new());
        }

        // Clamp the request window to the real file size.
        let effective_len = core::cmp::min(len, size - offset) as usize;
        let end_byte = offset + effective_len as u64; // exclusive

        // Chunk window we actually need to touch.
        let chunk_plain = CHUNK_PLAINTEXT_LEN as u64;
        let first_chunk = (offset / chunk_plain) as usize;
        let last_chunk_exclusive = ((end_byte + chunk_plain - 1) / chunk_plain) as usize;
        // Defense in depth: the manifest's chunk list is the source
        // of truth for the file's allocated space. If it is shorter
        // than the math suggests (corrupted manifest, partial write),
        // bail rather than read random chunks.
        let last_chunk_exclusive = last_chunk_exclusive.min(chunks.len());
        if first_chunk >= last_chunk_exclusive {
            return Err(FormatError::Manifest(
                "manifest chunk list inconsistent with file size".into(),
            ));
        }

        let master_key = self.master_key_view()?;
        let mut out = Vec::with_capacity(effective_len);

        for (logical_i, chunk_idx) in chunks[first_chunk..last_chunk_exclusive]
            .iter()
            .copied()
            .enumerate()
        {
            let global_chunk_i = (first_chunk + logical_i) as u64;
            let chunk_start_byte = global_chunk_i * chunk_plain;

            let stored = self.read_chunk_raw(chunk_idx)?;
            let chunk_key = derive_chunk_key(&master_key, chunk_idx);
            let pt = chunk::decrypt_chunk(&chunk_key, chunk_idx, &stored)?;

            // Compute the slice within this chunk that overlaps the
            // requested window.
            let local_start = if offset > chunk_start_byte {
                (offset - chunk_start_byte) as usize
            } else {
                0
            };
            let local_end = core::cmp::min(
                (end_byte - chunk_start_byte) as usize,
                pt.len(),
            );
            out.extend_from_slice(&pt[local_start..local_end]);
        }

        debug_assert_eq!(out.len(), effective_len);
        Ok(out)
    }

    /// Create an empty file in the mounted level.
    ///
    /// Idempotent: if a file with `name` already exists, leaves it alone
    /// and returns `Ok(())` — matching POSIX `O_CREAT` (without
    /// `O_EXCL`). Empty file = zero size, zero chunks; the manifest is
    /// committed but no chunk I/O happens.
    pub fn create_file(&mut self, name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(FormatError::InvalidName);
        }
        let m = self
            .mounted
            .as_mut()
            .ok_or_else(|| FormatError::Manifest("no level mounted".into()))?;
        if m.manifest.find(name).is_some() {
            return Ok(());
        }
        m.manifest.upsert(FileEntry {
            name: name.to_string(),
            size: 0,
            chunks: Vec::new(),
        });
        self.commit_manifest()?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Write `data` into `name` at byte `offset`, growing the file if
    /// the write extends past the current end.
    ///
    /// Holes (writes whose `offset` exceeds the current file size) are
    /// **zero-filled** rather than left sparse: the chunks region has no
    /// "hole" representation, every chunk must be a real AEAD-encrypted
    /// block. Writing one byte at offset 1 MiB into an empty file
    /// therefore allocates ~16 chunks of mostly-zero plaintext.
    ///
    /// Strategy: every chunk that overlaps the modified range is
    /// **migrated** — re-encrypted under a freshly-allocated chunk
    /// index, the old chunk index then random-filled. An adversary
    /// watching the disk across time therefore cannot correlate
    /// "chunk N was rewritten" with "file X was modified at byte
    /// range Y", because the chunk position itself shifts with the
    /// write. (Untouched chunks of the same file remain in place;
    /// re-encrypting them would be needless work with no deniability
    /// benefit, since their ciphertext doesn't change.)
    ///
    /// The crash window is the same as for [`Self::add_file`]:
    ///  1. fresh chunks are written;
    ///  2. old chunks are random-filled;
    ///  3. the manifest is committed and fsynced.
    /// A crash between (1) and (2) leaves the on-disk state intact and
    /// the new chunks dangling (indistinguishable from unused random).
    /// A crash between (2) and (3) corrupts the file: the manifest
    /// still points at old chunk indices that are now random. This
    /// matches the existing behavior of `add_file`; a journaling layer
    /// can be added later if real deployments hit this window.
    pub fn write_file_range(&mut self, name: &str, offset: u64, data: &[u8]) -> Result<()> {
        if name.is_empty() {
            return Err(FormatError::InvalidName);
        }
        if data.is_empty() {
            return Ok(());
        }

        let (current_size, current_chunks) = {
            let m = self
                .mounted
                .as_ref()
                .ok_or_else(|| FormatError::Manifest("no level mounted".into()))?;
            let entry = m
                .manifest
                .find(name)
                .ok_or_else(|| FormatError::FileNotFound(name.into()))?;
            (entry.size, entry.chunks.clone())
        };

        let data_len = data.len();
        let end_byte = offset + data_len as u64;
        let new_size = end_byte.max(current_size);

        let cp_len = CHUNK_PLAINTEXT_LEN as u64;
        let new_chunk_count = ((new_size + cp_len - 1) / cp_len) as usize;

        // The first chunk we must re-encrypt:
        //   - normal in-range write: the chunk containing `offset`
        //   - write past EOF (hole): the chunk of the last existing
        //     byte, because its real_len must be extended to make room
        //     for the hole-fill that follows.
        let first_dirty: usize = if current_size == 0 {
            0
        } else if offset <= current_size {
            (offset / cp_len) as usize
        } else {
            ((current_size - 1) / cp_len) as usize
        };

        // Allocate all fresh chunk slots in one shot (better deniability
        // — the allocator picks randomly from the free set as a batch,
        // rather than as a stream that could correlate with read times).
        let n_fresh = new_chunk_count - first_dirty;
        let fresh: Vec<ChunkIndex> = self.allocate_chunks(n_fresh, &[])?;

        let master_key = self.master_key_view()?;

        // The new chunks list, length = new_chunk_count.
        let mut new_chunks_list: Vec<ChunkIndex> = Vec::with_capacity(new_chunk_count);
        new_chunks_list.extend_from_slice(&current_chunks[..first_dirty]);
        new_chunks_list.extend_from_slice(&fresh);
        debug_assert_eq!(new_chunks_list.len(), new_chunk_count);

        // Chunks displaced by the write that must be random-filled
        // after we have written the fresh replacements.
        let mut to_free: Vec<ChunkIndex> = Vec::new();
        for (i, _) in fresh.iter().enumerate() {
            let global_i = first_dirty + i;
            if global_i < current_chunks.len() {
                to_free.push(current_chunks[global_i]);
            }
        }

        for (i, fresh_idx) in fresh.iter().copied().enumerate() {
            let global_i = first_dirty + i;
            let chunk_byte_start = (global_i as u64) * cp_len;
            let chunk_byte_end_cap = chunk_byte_start + cp_len;
            let chunk_real_end = new_size.min(chunk_byte_end_cap);
            let chunk_real_len = (chunk_real_end - chunk_byte_start) as usize;

            // Start with zeros (so hole-fill is automatic).
            let mut plaintext = vec![0u8; chunk_real_len];

            // Preserve old content for this chunk position, if it
            // existed before.
            if global_i < current_chunks.len() {
                let old_real_end = chunk_byte_end_cap.min(current_size);
                if old_real_end > chunk_byte_start {
                    let stored = self.read_chunk_raw(current_chunks[global_i])?;
                    let old_key = derive_chunk_key(&master_key, current_chunks[global_i]);
                    let old_pt =
                        chunk::decrypt_chunk(&old_key, current_chunks[global_i], &stored)?;
                    let preserved = old_pt.len().min(plaintext.len());
                    plaintext[..preserved].copy_from_slice(&old_pt[..preserved]);
                }
            }

            // Overlay the write data wherever it overlaps this chunk.
            let overlap_start = offset.max(chunk_byte_start);
            let overlap_end = end_byte.min(chunk_real_end);
            if overlap_start < overlap_end {
                let local_start = (overlap_start - chunk_byte_start) as usize;
                let local_end = (overlap_end - chunk_byte_start) as usize;
                let data_start = (overlap_start - offset) as usize;
                let data_end = (overlap_end - offset) as usize;
                plaintext[local_start..local_end].copy_from_slice(&data[data_start..data_end]);
            }

            // Encrypt under the fresh chunk index and write to disk.
            let fresh_key = derive_chunk_key(&master_key, fresh_idx);
            let stored = encrypt_chunk(&fresh_key, fresh_idx, &plaintext)?;
            self.write_chunk_raw(fresh_idx, &stored)?;
        }

        // Random-fill displaced chunks.
        for old in to_free {
            self.write_chunk_raw(old, &random_chunk()?)?;
        }

        // Update manifest atomically.
        let m = self.mounted.as_mut().expect("mounted ensured");
        m.manifest.upsert(FileEntry {
            name: name.to_string(),
            size: new_size,
            chunks: new_chunks_list,
        });
        self.commit_manifest()?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Truncate or extend `name` to exactly `new_size` bytes.
    ///
    /// Semantics:
    ///  - `new_size == current_size`: no-op (no I/O, no manifest bump).
    ///  - `new_size < current_size`: trailing chunks beyond `new_size`
    ///    are random-filled (cryptographic shred); the chunk straddling
    ///    `new_size` is re-encrypted with the surviving prefix under a
    ///    fresh index (its old index is random-filled, same chunk
    ///    migration as in [`Self::write_file_range`]).
    ///  - `new_size > current_size`: equivalent to
    ///    `write_file_range(name, current_size, &zeros)` of the right
    ///    length — every new chunk is zero-filled and the previous
    ///    final chunk has its real_len extended.
    pub fn truncate_file(&mut self, name: &str, new_size: u64) -> Result<()> {
        if name.is_empty() {
            return Err(FormatError::InvalidName);
        }

        let (current_size, current_chunks) = {
            let m = self
                .mounted
                .as_ref()
                .ok_or_else(|| FormatError::Manifest("no level mounted".into()))?;
            let entry = m
                .manifest
                .find(name)
                .ok_or_else(|| FormatError::FileNotFound(name.into()))?;
            (entry.size, entry.chunks.clone())
        };

        if new_size == current_size {
            return Ok(());
        }

        if new_size > current_size {
            // Grow path: delegate to write_file_range with zero bytes.
            // We rely on its hole-fill logic for the gap.
            let extra = (new_size - current_size) as usize;
            let zeros = vec![0u8; extra];
            return self.write_file_range(name, current_size, &zeros);
        }

        // Shrink path.
        let cp_len = CHUNK_PLAINTEXT_LEN as u64;
        let new_chunk_count = if new_size == 0 {
            0
        } else {
            ((new_size + cp_len - 1) / cp_len) as usize
        };

        // Chunks we will keep (possibly with the last one re-encrypted).
        let mut new_chunks_list: Vec<ChunkIndex> =
            current_chunks[..new_chunk_count].to_vec();
        // Chunks past new_chunk_count are dropped entirely.
        let mut to_free: Vec<ChunkIndex> =
            current_chunks[new_chunk_count..].to_vec();

        // Does the new last chunk straddle the truncation point? If the
        // straddled chunk's real_len changes, we must re-encrypt with a
        // fresh index and free the old.
        if new_chunk_count > 0 {
            let last = new_chunk_count - 1;
            let last_byte_start = (last as u64) * cp_len;
            let old_last_real_end = ((last as u64 + 1) * cp_len).min(current_size);
            let old_last_real_len = (old_last_real_end - last_byte_start) as usize;
            let new_last_real_len = (new_size - last_byte_start) as usize;

            if new_last_real_len != old_last_real_len {
                let master_key = self.master_key_view()?;
                let old_idx = new_chunks_list[last];
                let stored = self.read_chunk_raw(old_idx)?;
                let old_key = derive_chunk_key(&master_key, old_idx);
                let old_pt = chunk::decrypt_chunk(&old_key, old_idx, &stored)?;
                let truncated = &old_pt[..new_last_real_len];

                let fresh = self.allocate_chunks(1, &[])?[0];
                let fresh_key = derive_chunk_key(&master_key, fresh);
                let new_stored = encrypt_chunk(&fresh_key, fresh, truncated)?;
                self.write_chunk_raw(fresh, &new_stored)?;

                new_chunks_list[last] = fresh;
                to_free.push(old_idx);
            }
        }

        for old in to_free {
            self.write_chunk_raw(old, &random_chunk()?)?;
        }

        let m = self.mounted.as_mut().expect("mounted ensured");
        m.manifest.upsert(FileEntry {
            name: name.to_string(),
            size: new_size,
            chunks: new_chunks_list,
        });
        self.commit_manifest()?;
        // Shrinking frees + shreds chunks; force that overwrite to durable media.
        self.durable_sync()?;
        Ok(())
    }

    /// Rename `old_name` to `new_name` in the mounted level.
    ///
    /// Semantics match POSIX `rename(2)`: if `new_name` already
    /// exists, it is **atomically replaced** — its chunks are
    /// cryptographically shredded (random-filled) and only then is
    /// the new manifest committed. The destination file's content is
    /// gone after this call.
    ///
    /// Special cases:
    /// - `old_name == new_name`: no-op, no manifest bump.
    /// - `old_name` missing: returns [`FormatError::FileNotFound`].
    /// - Either name empty: returns [`FormatError::InvalidName`].
    ///
    /// Note: this method does NOT migrate the renamed file's chunks
    /// (renaming is not a write — the encrypted content is
    /// unchanged). A file's chunk indices only change when its
    /// content is modified (cf. [`Self::write_file_range`]).
    pub fn rename_file(&mut self, old_name: &str, new_name: &str) -> Result<()> {
        if old_name.is_empty() || new_name.is_empty() {
            return Err(FormatError::InvalidName);
        }
        if old_name == new_name {
            return Ok(());
        }

        let (renamed, displaced_chunks) = {
            let m = self
                .mounted
                .as_ref()
                .ok_or_else(|| FormatError::Manifest("no level mounted".into()))?;
            let old_entry = m
                .manifest
                .find(old_name)
                .ok_or_else(|| FormatError::FileNotFound(old_name.into()))?;
            let renamed = FileEntry {
                name: new_name.to_string(),
                size: old_entry.size,
                chunks: old_entry.chunks.clone(),
            };
            let displaced: Vec<ChunkIndex> = m
                .manifest
                .find(new_name)
                .map(|e| e.chunks.clone())
                .unwrap_or_default();
            (renamed, displaced)
        };

        // Mutate the manifest: drop old_name, drop any existing
        // new_name, insert the renamed entry.
        let m = self.mounted.as_mut().expect("mounted ensured");
        m.manifest.remove(old_name);
        m.manifest.remove(new_name);
        m.manifest.upsert(renamed);

        // Shred the displaced destination's chunks (if any).
        for old_idx in displaced_chunks {
            self.write_chunk_raw(old_idx, &random_chunk()?)?;
        }

        self.commit_manifest()?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Flush all the way to **durable media**, for secure-delete paths.
    ///
    /// On macOS, `File::sync_all` (an `fsync`) does NOT flush the drive's
    /// internal write cache, so a "secure overwrite" can sit in volatile cache
    /// and never reach the platters / flash. `fcntl(F_FULLFSYNC)` forces the
    /// drive to commit. On other targets we fall back to `sync_all`. If a
    /// filesystem doesn't support `F_FULLFSYNC` (returns an error, e.g. some
    /// network mounts), we degrade to a normal `sync_all` rather than failing
    /// the deletion.
    fn durable_sync(&self) -> std::io::Result<()> {
        durable_sync_file(&self.file)
    }

    /// Inspect the vault's slot **without unlocking the content**: returns the
    /// per-vault FIDO salt, the enrolled credential IDs, their labels, and the
    /// hardware-key count `K`. Used by the keys-management flow to challenge a
    /// present key and list named keys. Tries each KDF profile to find the one
    /// matching the passphrase (like `open`).
    pub fn slot_enrollment_info(
        path: impl AsRef<Path>,
        mut passphrase: Vec<u8>,
    ) -> Result<([u8; farewell_fido2::HMAC_SALT_LEN], Vec<Vec<u8>>, Vec<String>, usize)> {
        let mut file = OpenOptions::new().read(true).open(path.as_ref())?;
        let mut salt = [0u8; SALT_LEN];
        file.seek(SeekFrom::Start(SALT_OFFSET))?;
        file.read_exact(&mut salt)?;
        let mut slot = [0u8; SLOT_LEN];
        file.seek(SeekFrom::Start(SLOTS_REGION_OFFSET))?;
        file.read_exact(&mut slot)?;

        for cand in KDF_CANDIDATES {
            let derived = kdf::derive(&passphrase, &salt, cand)?;
            let mut pp_key = [0u8; 32];
            pp_key.copy_from_slice(derived.as_bytes());
            let r = WrappedSlot::read_enrollment(&slot, &pp_key);
            pp_key.zeroize();
            if let Ok((k, creds, labels)) = r {
                passphrase.zeroize();
                return Ok((crate::slot::fido_salt_from_vault_salt(&salt), creds, labels, k));
            }
        }
        passphrase.zeroize();
        Err(FormatError::Crypto(farewell_crypto::CryptoError::Decrypt))
    }

    /// Add a hardware-key credential to the vault's slot **in place** (no
    /// re-encryption of vault data). `recover_hmac` is the hmac-secret output of
    /// a present, already-enrolled key (or `None` for a passphrase-only vault,
    /// `K==0`). `new_cred`/`new_hmac` are the just-enrolled backup key's
    /// credential id and hmac-secret output. The file is exclusively locked for
    /// the write, so the vault must not be open elsewhere.
    pub fn add_hw_credential(
        path: impl AsRef<Path>,
        mut passphrase: Vec<u8>,
        recover_hmac: Option<&[u8; farewell_fido2::HMAC_OUTPUT_LEN]>,
        new_cred: &[u8],
        new_hmac: &[u8; farewell_fido2::HMAC_OUTPUT_LEN],
        new_label: &str,
    ) -> Result<()> {
        let mut file = OpenOptions::new().read(true).write(true).open(path.as_ref())?;
        crate::lock::acquire_exclusive(&file)?;

        let mut salt = [0u8; SALT_LEN];
        file.seek(SeekFrom::Start(SALT_OFFSET))?;
        file.read_exact(&mut salt)?;
        let mut slot = [0u8; SLOT_LEN];
        file.seek(SeekFrom::Start(SLOTS_REGION_OFFSET))?;
        file.read_exact(&mut slot)?;

        for cand in KDF_CANDIDATES {
            let derived = kdf::derive(&passphrase, &salt, cand)?;
            let mut pp_key = [0u8; 32];
            pp_key.copy_from_slice(derived.as_bytes());
            if WrappedSlot::read_enrollment(&slot, &pp_key).is_ok() {
                let new_slot = WrappedSlot::add_credential(
                    &slot, &pp_key, recover_hmac, new_cred, new_hmac, new_label,
                );
                pp_key.zeroize();
                passphrase.zeroize();
                let new_slot = new_slot?;
                file.seek(SeekFrom::Start(SLOTS_REGION_OFFSET))?;
                file.write_all(&new_slot)?;
                durable_sync_file(&file)?;
                return Ok(());
            }
            pp_key.zeroize();
        }
        passphrase.zeroize();
        Err(FormatError::Crypto(farewell_crypto::CryptoError::Decrypt))
    }

    /// Remove the hardware-key credential at `index` from the vault's slot **in
    /// place**, with the passphrase alone (no key need be present). Used to
    /// revoke a lost or stolen key. The file is exclusively locked for the
    /// write, so the vault must not be open elsewhere.
    ///
    /// Requires the vault to have `K >= 2` keys: removing the last one would
    /// orphan the master, so turning a vault back into passphrase-only is a
    /// separate operation. Returns [`FormatError::Manifest`] if `index` is out
    /// of range or this is the last key.
    pub fn remove_hw_credential(
        path: impl AsRef<Path>,
        mut passphrase: Vec<u8>,
        index: usize,
    ) -> Result<()> {
        let mut file = OpenOptions::new().read(true).write(true).open(path.as_ref())?;
        crate::lock::acquire_exclusive(&file)?;

        let mut salt = [0u8; SALT_LEN];
        file.seek(SeekFrom::Start(SALT_OFFSET))?;
        file.read_exact(&mut salt)?;
        let mut slot = [0u8; SLOT_LEN];
        file.seek(SeekFrom::Start(SLOTS_REGION_OFFSET))?;
        file.read_exact(&mut slot)?;

        for cand in KDF_CANDIDATES {
            let derived = kdf::derive(&passphrase, &salt, cand)?;
            let mut pp_key = [0u8; 32];
            pp_key.copy_from_slice(derived.as_bytes());
            if WrappedSlot::read_enrollment(&slot, &pp_key).is_ok() {
                let new_slot = WrappedSlot::remove_credential(&slot, &pp_key, index);
                pp_key.zeroize();
                passphrase.zeroize();
                let new_slot = new_slot?;
                file.seek(SeekFrom::Start(SLOTS_REGION_OFFSET))?;
                file.write_all(&new_slot)?;
                durable_sync_file(&file)?;
                return Ok(());
            }
            pp_key.zeroize();
        }
        passphrase.zeroize();
        Err(FormatError::Crypto(farewell_crypto::CryptoError::Decrypt))
    }

    /// Rebuild the vault's slot for a new hardware-key enrollment **under the
    /// matching KDF**, preserving the content. This is the K=0↔1 conversion
    /// that [`add_hw_credential`] / [`remove_hw_credential`] deliberately can't
    /// do in place: those keep the existing KDF, but flipping between
    /// passphrase-only and hardware-protected must also flip the KDF profile
    /// (heavy when the passphrase is the only secret; light when a key carries
    /// the resistance), which means re-deriving the passphrase key and writing
    /// a fresh slot.
    ///
    /// - Empty `new_enrollment` → convert to passphrase-only (re-hardens the
    ///   KDF and re-wraps the master under the passphrase-only KWK). The
    ///   current key must be present in `present_auth` to recover the master.
    /// - Non-empty `new_enrollment` → convert a passphrase-only vault to
    ///   hardware (lightens the KDF). The master is recovered with the
    ///   passphrase alone (`present_auth` may be `None`); the new key's
    ///   `(cred, hmac, label)` are supplied by the caller.
    ///
    /// The master key and shared metadata key are preserved, so all vault
    /// content stays readable. Exclusive-locked + durably synced.
    pub fn reenroll_slot<A: farewell_fido2::Authenticator>(
        path: impl AsRef<Path>,
        mut passphrase: Vec<u8>,
        mut present_auth: Option<&mut A>,
        new_enrollment: &LevelEnrollment,
    ) -> Result<()> {
        let mut file = OpenOptions::new().read(true).write(true).open(path.as_ref())?;
        crate::lock::acquire_exclusive(&file)?;

        let mut salt = [0u8; SALT_LEN];
        file.seek(SeekFrom::Start(SALT_OFFSET))?;
        file.read_exact(&mut salt)?;
        let mut slot = [0u8; SLOT_LEN];
        file.seek(SeekFrom::Start(SLOTS_REGION_OFFSET))?;
        file.read_exact(&mut slot)?;

        // Find the CURRENT passphrase key (whichever KDF profile the slot was
        // last written under), then recover the master + metadata keys.
        let mut unwrapped: Option<UnwrappedSlot> = None;
        for cand in KDF_CANDIDATES {
            let derived = kdf::derive(&passphrase, &salt, cand)?;
            let mut pp_key = [0u8; 32];
            pp_key.copy_from_slice(derived.as_bytes());
            if WrappedSlot::read_enrollment(&slot, &pp_key).is_ok() {
                let r = WrappedSlot::try_unwrap(
                    &slot,
                    &pp_key,
                    &salt,
                    present_auth.as_deref_mut(),
                );
                pp_key.zeroize();
                unwrapped = Some(r?);
                break;
            }
            pp_key.zeroize();
        }
        let mut unwrapped = match unwrapped {
            Some(u) => u,
            None => {
                passphrase.zeroize();
                return Err(FormatError::Crypto(farewell_crypto::CryptoError::Decrypt));
            }
        };

        // Re-derive the passphrase key under the profile that matches the new
        // enrollment, and write a fresh slot wrapping the SAME master/metadata.
        let new_params: &kdf::KdfParams = if new_enrollment.is_empty() {
            KDF_PP
        } else {
            KDF_HW
        };
        let derived = kdf::derive(&passphrase, &salt, new_params)?;
        passphrase.zeroize();
        let mut new_pp = [0u8; 32];
        new_pp.copy_from_slice(derived.as_bytes());
        let new_slot = WrappedSlot::wrap(
            &new_pp,
            &unwrapped.master_key,
            &unwrapped.metadata_key,
            new_enrollment,
        );
        new_pp.zeroize();
        unwrapped.master_key.zeroize();
        unwrapped.metadata_key.zeroize();
        let new_slot = new_slot?;

        file.seek(SeekFrom::Start(SLOTS_REGION_OFFSET))?;
        file.write_all(&new_slot)?;
        durable_sync_file(&file)?;
        Ok(())
    }

    /// Securely delete a file from the mounted level.
    pub fn delete_file(&mut self, name: &str) -> Result<()> {
        let entry = {
            let m = self
                .mounted
                .as_mut()
                .ok_or_else(|| FormatError::Manifest("no level mounted".into()))?;
            m.manifest
                .remove(name)
                .ok_or_else(|| FormatError::FileNotFound(name.into()))?
        };

        for chunk_idx in entry.chunks {
            self.write_chunk_raw(chunk_idx, &random_chunk()?)?;
        }

        self.commit_manifest()?;
        // Force the random overwrite to durable media (not just the OS cache).
        self.durable_sync()?;
        Ok(())
    }

    // ---- folders (organizational; names are slash-separated paths) ----

    /// List all folders in the mounted level: the union of explicitly
    /// created folders and those implied by file-name prefixes. Each is
    /// a normalized path with no leading/trailing slash. Sorted.
    pub fn folders(&self) -> Vec<String> {
        let m = match self.mounted.as_ref() {
            Some(m) => m,
            None => return Vec::new(),
        };
        let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        // Explicit (possibly empty) folders + all their ancestors.
        for f in &m.manifest.folders {
            for anc in ancestor_paths(f) {
                set.insert(anc);
            }
        }
        // Folders implied by file names.
        for e in &m.manifest.entries {
            if let Some(parent) = parent_folder(&e.name) {
                for anc in ancestor_paths(&parent) {
                    set.insert(anc);
                }
            }
        }
        set.into_iter().collect()
    }

    /// Create an (initially empty) folder at `path`. Idempotent.
    /// Normalizes the path; rejects empty or control-char paths.
    pub fn create_folder(&mut self, path: &str) -> Result<()> {
        let norm = normalize_folder(path).ok_or(FormatError::InvalidName)?;
        let m = self
            .mounted
            .as_mut()
            .ok_or_else(|| FormatError::Manifest("no level mounted".into()))?;
        if !m.manifest.folders.contains(&norm) {
            m.manifest.folders.push(norm);
            m.manifest.counter += 1;
            self.commit_manifest()?;
            self.file.sync_all()?;
        }
        Ok(())
    }

    /// Delete a folder and everything under it: every file whose name
    /// is under `path/` is securely shredded, and the folder (plus any
    /// descendant explicit folders) is removed from the folder list.
    pub fn delete_folder(&mut self, path: &str) -> Result<()> {
        let norm = normalize_folder(path).ok_or(FormatError::InvalidName)?;
        let prefix = format!("{norm}/");

        // Collect the files to remove (names under the folder).
        let victims: Vec<String> = {
            let m = self
                .mounted
                .as_ref()
                .ok_or_else(|| FormatError::Manifest("no level mounted".into()))?;
            m.manifest
                .entries
                .iter()
                .filter(|e| e.name.starts_with(&prefix))
                .map(|e| e.name.clone())
                .collect()
        };

        // Shred + remove each file's chunks.
        for name in &victims {
            let entry = {
                let m = self.mounted.as_mut().expect("mounted");
                m.manifest.remove(name)
            };
            if let Some(entry) = entry {
                for chunk_idx in entry.chunks {
                    self.write_chunk_raw(chunk_idx, &random_chunk()?)?;
                }
            }
        }

        // Drop the folder and its descendant explicit folders.
        {
            let m = self.mounted.as_mut().expect("mounted");
            m.manifest
                .folders
                .retain(|f| f != &norm && !f.starts_with(&prefix));
            m.manifest.counter += 1;
        }

        self.commit_manifest()?;
        // Every victim file's chunks were shredded above; make it durable.
        self.durable_sync()?;
        Ok(())
    }

    /// Rename a folder: every file under `old/` is re-prefixed to
    /// `new/` (metadata only — no chunk movement), and explicit folder
    /// entries are updated. Refuses if the new path would collide with
    /// an existing file name.
    pub fn rename_folder(&mut self, old: &str, new: &str) -> Result<()> {
        let old_n = normalize_folder(old).ok_or(FormatError::InvalidName)?;
        let new_n = normalize_folder(new).ok_or(FormatError::InvalidName)?;
        if old_n == new_n {
            return Ok(());
        }
        let old_prefix = format!("{old_n}/");
        let new_prefix = format!("{new_n}/");

        let m = self
            .mounted
            .as_mut()
            .ok_or_else(|| FormatError::Manifest("no level mounted".into()))?;

        // Collision check: no existing file already at a target name.
        let existing: std::collections::BTreeSet<&str> =
            m.manifest.entries.iter().map(|e| e.name.as_str()).collect();
        for e in &m.manifest.entries {
            if let Some(rest) = e.name.strip_prefix(&old_prefix) {
                let target = format!("{new_prefix}{rest}");
                if existing.contains(target.as_str()) {
                    return Err(FormatError::Manifest(format!(
                        "rename would overwrite {target}"
                    )));
                }
            }
        }

        // Re-prefix file names (metadata only).
        for e in m.manifest.entries.iter_mut() {
            if let Some(rest) = e.name.strip_prefix(&old_prefix) {
                e.name = format!("{new_prefix}{rest}");
            }
        }
        // Update explicit folder entries.
        for f in m.manifest.folders.iter_mut() {
            if *f == old_n {
                *f = new_n.clone();
            } else if let Some(rest) = f.strip_prefix(&old_prefix) {
                *f = format!("{new_prefix}{rest}");
            }
        }
        m.manifest.counter += 1;

        self.commit_manifest()?;
        self.file.sync_all()?;
        Ok(())
    }

    // ---- internals ----

    fn master_key_view(&self) -> Result<[u8; aead::KEY_LEN]> {
        let m = self
            .mounted
            .as_ref()
            .ok_or_else(|| FormatError::Manifest("no level mounted".into()))?;
        let mut k = [0u8; aead::KEY_LEN];
        k.copy_from_slice(m.master.as_slice());
        Ok(k)
    }

    fn commit_manifest(&mut self) -> Result<()> {
        let master_key = self.master_key_view()?;
        let m = self.mounted.as_ref().expect("mounted ensured");
        let mc = m.manifest_chunk;
        let bytes = m.manifest.serialize()?;
        let chunk_key = derive_chunk_key(&master_key, mc);
        let stored = encrypt_chunk(&chunk_key, mc, &bytes)?;
        self.write_chunk_raw(mc, &stored)?;
        Ok(())
    }

    fn write_chunk_raw(&mut self, idx: ChunkIndex, data: &[u8; CHUNK_STORED_LEN]) -> Result<()> {
        if (idx.0 as u64) >= self.metadata.total_chunks {
            return Err(FormatError::InvalidChunk(idx.0));
        }
        let offset = CHUNKS_REGION_OFFSET + idx.offset_in_region();
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(data)?;
        Ok(())
    }

    fn read_chunk_raw(&mut self, idx: ChunkIndex) -> Result<[u8; CHUNK_STORED_LEN]> {
        if (idx.0 as u64) >= self.metadata.total_chunks {
            return Err(FormatError::InvalidChunk(idx.0));
        }
        let offset = CHUNKS_REGION_OFFSET + idx.offset_in_region();
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = [0u8; CHUNK_STORED_LEN];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn allocate_chunks(&self, n: usize, reusable: &[ChunkIndex]) -> Result<Vec<ChunkIndex>> {
        let m = self
            .mounted
            .as_ref()
            .ok_or_else(|| FormatError::Manifest("no level mounted".into()))?;

        let mut used: BTreeSet<u32> = BTreeSet::new();
        used.insert(m.manifest_chunk.0);
        for e in &m.manifest.entries {
            for c in &e.chunks {
                used.insert(c.0);
            }
        }
        for r in reusable {
            used.remove(&r.0);
        }

        let total = self.metadata.total_chunks as u32;
        let mut out: Vec<ChunkIndex> = Vec::with_capacity(n);

        for r in reusable.iter().take(n) {
            out.push(*r);
        }
        if out.len() == n {
            return Ok(out);
        }

        // Striped allocation: only chunks in THIS level's stripe are
        // candidates (`c % NUM_SLOTS == slot`). This is what makes
        // cross-level corruption impossible — a level physically cannot
        // allocate a chunk that belongs to another level's stripe.
        // `off_limits` is retained as a harmless extra filter (it only
        // ever contains chunks from other stripes now, so it excludes
        // nothing within ours).
        let stripe = m.slot as u32;
        let n_slots = NUM_SLOTS as u32;
        let mut osrng = OsRng;
        let candidates_iter = (0..total).filter(|c| {
            c % n_slots == stripe
                && !used.contains(c)
                && !m.off_limits.contains(c)
                && !reusable.iter().any(|r| r.0 == *c)
        });
        let needed = n - out.len();
        let picked = candidates_iter.choose_multiple(&mut osrng, needed);
        if picked.len() < needed {
            return Err(FormatError::Full);
        }
        for c in picked {
            out.push(ChunkIndex(c));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use farewell_fido2::MockAuthenticator;
    use tempfile::tempdir;

    fn pp(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    /// No-authenticator helper for tests using K=0 mode.
    fn no_auth() -> Option<&'static mut MockAuthenticator> {
        None
    }

    #[test]
    fn single_level_k0_create_open_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("single.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        let v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        assert!(v.list().is_empty());
        assert_eq!(v.total_chunks(), 8);
    }

    #[test]
    fn more_than_one_level_is_rejected() {
        // The format is single-domain: a builder with >1 level is refused.
        let dir = tempdir().unwrap();
        let path = dir.path().join("multi.vault");
        let levels = vec![
            LevelSpec::passphrase_only(pp("alpha")),
            LevelSpec::passphrase_only(pp("beta")),
        ];
        assert!(VaultBuilder::new(&path, levels).is_err());
    }

    #[test]
    fn wrong_passphrase_fails_k0() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wrong.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(16)
            .build()
            .unwrap();
        assert!(Vault::open(&path, pp("nope"), no_auth()).is_err());
    }

    #[test]
    fn k1_vault_roundtrip_with_authenticator() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k1.vault");

        // Caller picks a fixed salt up front so they can enroll the HW
        // key before the vault is written to disk.
        let salt: [u8; 32] = {
            let mut s = [0u8; 32];
            rng::fill(&mut s).unwrap();
            s
        };

        let mut auth = MockAuthenticator::new("farewell.foundation");
        let (cred, hw_output) =
            enroll_hw_key(&mut auth, &salt, b"v1").unwrap();

        let mut enr = LevelEnrollment::passphrase_only();
        enr.push(cred, hw_output).unwrap();
        let spec = LevelSpec {
            passphrase: pp("alpha"),
            enrollment: enr,
        };

        let _ = VaultBuilder::new(&path, vec![spec])
            .unwrap()
            .total_chunks(8)
            .with_salt(salt)
            .build()
            .unwrap();

        // Open and round-trip a file.
        {
            let mut v = Vault::open(&path, pp("alpha"), Some(&mut auth)).unwrap();
            assert!(v.list().is_empty());
            v.add_file("test.txt", b"hello hardware".to_vec()).unwrap();
        }
        {
            let mut v = Vault::open(&path, pp("alpha"), Some(&mut auth)).unwrap();
            assert_eq!(v.read_file("test.txt").unwrap(), b"hello hardware");
        }
    }

    #[test]
    fn k1_vault_rejects_passphrase_only_unlock() {
        // A vault built with K=1 requires the authenticator at unlock.
        let dir = tempdir().unwrap();
        let path = dir.path().join("k1req.vault");
        let salt: [u8; 32] = {
            let mut s = [0u8; 32];
            rng::fill(&mut s).unwrap();
            s
        };
        let mut auth = MockAuthenticator::new("farewell.foundation");
        let (cred, hw_output) =
            enroll_hw_key(&mut auth, &salt, b"v").unwrap();
        let mut enr = LevelEnrollment::passphrase_only();
        enr.push(cred, hw_output).unwrap();
        let _ = VaultBuilder::new(
            &path,
            vec![LevelSpec {
                passphrase: pp("p"),
                enrollment: enr,
            }],
        )
        .unwrap()
        .total_chunks(8)
        .with_salt(salt)
        .build()
        .unwrap();

        // Without authenticator: unlock fails with the *distinct*
        // HardwareKeyRequired (not a generic decrypt error) — the
        // passphrase decrypted the slot's outer, so a key is the only thing
        // missing. farewell_open_hw relies on this to know it must
        // enumerate keys (vs. a wrong passphrase, which never gets here).
        assert!(matches!(
            Vault::open::<MockAuthenticator>(&path, pp("p"), None),
            Err(FormatError::HardwareKeyRequired)
        ));
        // A wrong passphrase, by contrast, never decrypts the outer, so it
        // is a generic decrypt failure — never HardwareKeyRequired.
        assert!(matches!(
            Vault::open::<MockAuthenticator>(&path, pp("wrong"), None),
            Err(FormatError::Crypto(_))
        ));

        // With a fresh authenticator that owns no credentials: unlock fails.
        let mut wrong = MockAuthenticator::new("farewell.foundation");
        assert!(Vault::open(&path, pp("p"), Some(&mut wrong)).is_err());
    }

    #[test]
    fn k2_vault_either_authenticator_unlocks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k2.vault");
        let salt: [u8; 32] = {
            let mut s = [0u8; 32];
            rng::fill(&mut s).unwrap();
            s
        };

        let mut auth_a = MockAuthenticator::new("farewell.foundation");
        let mut auth_b = MockAuthenticator::new("farewell.foundation");
        let (cred_a, out_a) =
            enroll_hw_key(&mut auth_a, &salt, b"v").unwrap();
        let (cred_b, out_b) =
            enroll_hw_key(&mut auth_b, &salt, b"v").unwrap();

        let mut enr = LevelEnrollment::passphrase_only();
        enr.push(cred_a, out_a).unwrap();
        enr.push(cred_b, out_b).unwrap();
        let _ = VaultBuilder::new(
            &path,
            vec![LevelSpec {
                passphrase: pp("p"),
                enrollment: enr,
            }],
        )
        .unwrap()
        .total_chunks(8)
        .with_salt(salt)
        .build()
        .unwrap();

        // Either authenticator alone unlocks (they own different credentials).
        // Open sequentially: since v0.16.1 the vault holds an exclusive
        // flock, so two simultaneous opens of the same file would fail
        // with `AlreadyLocked` — which is the correct behavior, not a
        // test bug.
        {
            let v_a = Vault::open(&path, pp("p"), Some(&mut auth_a)).unwrap();
            assert_eq!(v_a.total_chunks(), 8);
        }
        {
            let v_b = Vault::open(&path, pp("p"), Some(&mut auth_b)).unwrap();
            assert_eq!(v_b.total_chunks(), 8);
        }
    }

    #[test]
    fn add_backup_key_to_existing_one_key_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("backup.vault");
        let salt: [u8; 32] = {
            let mut s = [0u8; 32];
            rng::fill(&mut s).unwrap();
            s
        };

        // Build a vault enrolled with a single key A.
        let mut auth_a = MockAuthenticator::new("farewell.foundation");
        let (cred_a, out_a) = enroll_hw_key(&mut auth_a, &salt, b"v").unwrap();
        let mut enr = LevelEnrollment::passphrase_only();
        enr.push(cred_a, out_a).unwrap();
        VaultBuilder::new(
            &path,
            vec![LevelSpec { passphrase: pp("p"), enrollment: enr }],
        )
        .unwrap()
        .total_chunks(8)
        .with_salt(salt)
        .build()
        .unwrap();

        // Inspect the slot without unlocking → fido_salt + the one credential.
        let (fido_salt, creds, _labels, k) = Vault::slot_enrollment_info(&path, pp("p")).unwrap();
        assert_eq!(k, 1);
        assert_eq!(creds.len(), 1);

        // Recover the KWK via the present primary, enroll backup B, add it.
        let (_, recover_hmac) = auth_a.challenge_response(&creds, &fido_salt).unwrap();
        let mut auth_b = MockAuthenticator::new("farewell.foundation");
        let (cred_b, out_b) = enroll_hw_key(&mut auth_b, &salt, b"v").unwrap();
        Vault::add_hw_credential(&path, pp("p"), Some(&recover_hmac), &cred_b, &out_b, "Backup")
            .unwrap();

        // EITHER key now opens the vault.
        {
            let v = Vault::open(&path, pp("p"), Some(&mut auth_a)).unwrap();
            assert_eq!(v.total_chunks(), 8);
        }
        {
            let v = Vault::open(&path, pp("p"), Some(&mut auth_b)).unwrap();
            assert_eq!(v.total_chunks(), 8);
        }
        let (_, creds2, labels2, k2) = Vault::slot_enrollment_info(&path, pp("p")).unwrap();
        assert_eq!(k2, 2);
        assert_eq!(creds2.len(), 2);
        assert_eq!(labels2[1], "Backup");

        // Revoke the backup key (index 1) with the passphrase alone.
        Vault::remove_hw_credential(&path, pp("p"), 1).unwrap();
        let (_, creds3, _l3, k3) = Vault::slot_enrollment_info(&path, pp("p")).unwrap();
        assert_eq!(k3, 1);
        assert_eq!(creds3.len(), 1);
        // A still opens; the revoked B no longer does.
        assert!(Vault::open(&path, pp("p"), Some(&mut auth_a)).is_ok());
        assert!(Vault::open(&path, pp("p"), Some(&mut auth_b)).is_err());
        // Removing the last remaining key is refused (needs the downgrade path).
        assert!(Vault::remove_hw_credential(&path, pp("p"), 0).is_err());
    }

    #[test]
    fn reenroll_converts_between_passphrase_and_hardware() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("convert.vault");
        let salt: [u8; 32] = {
            let mut s = [0u8; 32];
            rng::fill(&mut s).unwrap();
            s
        };

        // Start passphrase-only; it opens with the passphrase alone.
        VaultBuilder::new(&path, vec![LevelSpec::passphrase_only(pp("p"))])
            .unwrap()
            .total_chunks(8)
            .with_salt(salt)
            .build()
            .unwrap();
        assert!(Vault::open(&path, pp("p"), no_auth()).is_ok());

        // --- add-first (K=0 -> 1): convert to hardware-protected. ---
        let mut auth = MockAuthenticator::new("farewell.foundation");
        let (cred, out) = enroll_hw_key(&mut auth, &salt, b"v").unwrap();
        let mut enr = LevelEnrollment::passphrase_only();
        enr.push_labeled(cred, out, "Primary".into()).unwrap();
        Vault::reenroll_slot(&path, pp("p"), no_auth(), &enr).unwrap();

        // The key is now REQUIRED; the passphrase alone no longer opens it,
        // and the content (8 chunks) survives.
        assert!(Vault::open(&path, pp("p"), no_auth()).is_err());
        {
            let v = Vault::open(&path, pp("p"), Some(&mut auth)).unwrap();
            assert_eq!(v.total_chunks(), 8);
        }
        let (_, _, labels, k) = Vault::slot_enrollment_info(&path, pp("p")).unwrap();
        assert_eq!(k, 1);
        assert_eq!(labels[0], "Primary");

        // --- remove-last (K=1 -> 0): convert back to passphrase-only. ---
        // The present key is required to recover the master before re-wrapping.
        Vault::reenroll_slot(
            &path,
            pp("p"),
            Some(&mut auth),
            &LevelEnrollment::passphrase_only(),
        )
        .unwrap();
        {
            let v = Vault::open(&path, pp("p"), no_auth()).unwrap();
            assert_eq!(v.total_chunks(), 8);
        }
        let (_, _, _, k2) = Vault::slot_enrollment_info(&path, pp("p")).unwrap();
        assert_eq!(k2, 0);
    }

    #[test]
    fn owner_recorded_at_create_and_read_on_open() {
        let dir = tempdir().unwrap();
        // With an opt-in owner → recorded and persisted across re-open.
        let path = dir.path().join("owned.vault");
        VaultBuilder::single_passphrase(&path, pp("p"))
            .total_chunks(8)
            .owner(Some("alice@example.org".into()))
            .build()
            .unwrap();
        let v = Vault::open(&path, pp("p"), no_auth()).unwrap();
        assert_eq!(v.owner(), Some("alice@example.org"));

        // Without one → anonymous (and an empty string is treated as none).
        let path2 = dir.path().join("anon.vault");
        VaultBuilder::single_passphrase(&path2, pp("p"))
            .total_chunks(8)
            .owner(Some(String::new()))
            .build()
            .unwrap();
        let v2 = Vault::open(&path2, pp("p"), no_auth()).unwrap();
        assert_eq!(v2.owner(), None);
    }

    #[test]
    fn folders_create_move_rename_delete() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("folders.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("p"))
            .total_chunks(48)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("p"), no_auth()).unwrap();

        // Create an empty folder; it persists in the folder list.
        v.create_folder("projet/2026").unwrap();
        assert!(v.folders().contains(&"projet".to_string()));
        assert!(v.folders().contains(&"projet/2026".to_string()));

        // Add a file at the root, then "move" it into the folder by
        // renaming with a prefix (metadata only).
        v.add_file("notes.md", b"hello".to_vec()).unwrap();
        v.rename_file("notes.md", "projet/2026/notes.md").unwrap();
        assert!(v.stat_file("projet/2026/notes.md").is_ok());
        assert!(v.stat_file("notes.md").is_err());

        // Rename the folder: the file follows.
        v.rename_folder("projet", "archive").unwrap();
        assert!(v.stat_file("archive/2026/notes.md").is_ok());
        assert_eq!(v.read_file("archive/2026/notes.md").unwrap(), b"hello");
        assert!(v.folders().contains(&"archive/2026".to_string()));
        assert!(!v.folders().contains(&"projet".to_string()));

        // Delete the folder: file is gone (shredded), folder removed.
        v.delete_folder("archive").unwrap();
        assert!(v.stat_file("archive/2026/notes.md").is_err());
        assert!(!v.folders().iter().any(|f| f.starts_with("archive")));
    }

    #[test]
    fn space_reports_total_and_free_and_shrinks_on_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("space.vault");
        // total 24 → single tree owns all 24; 1 manifest → 23 usable.
        let _ = VaultBuilder::single_passphrase(&path, pp("p"))
            .total_chunks(24)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("p"), no_auth()).unwrap();
        let c = CHUNK_PLAINTEXT_LEN as u64;

        let (total, free) = v.space().unwrap();
        assert_eq!(total, 23 * c, "23 usable chunks (whole capacity)");
        assert_eq!(free, 23 * c, "all free initially");

        // Add a 1-chunk file → free drops by one chunk.
        v.add_file("a", vec![0xAA; 100]).unwrap();
        let (_t, free2) = v.space().unwrap();
        assert_eq!(free2, 22 * c);

        // Add a 2-chunk file.
        v.add_file("b", vec![0xBB; (c as usize) + 10]).unwrap();
        let (_t, free3) = v.space().unwrap();
        assert_eq!(free3, 20 * c);
    }

    #[test]
    fn writing_more_than_free_fails_cleanly_without_partial_state() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("full.vault");
        // total 4 → single tree owns all 4; 1 manifest → 3 usable.
        let _ = VaultBuilder::single_passphrase(&path, pp("p"))
            .total_chunks(4)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("p"), no_auth()).unwrap();
        let c = CHUNK_PLAINTEXT_LEN as u64;
        let (_t, free) = v.space().unwrap();
        assert_eq!(free, 3 * c);

        // A 4-chunk file doesn't fit (only 3 usable). add_file allocates
        // all chunks up front, so it fails Full and writes NOTHING.
        let too_big = vec![0xCC; 4 * c as usize];
        assert!(matches!(v.add_file("big", too_big), Err(FormatError::Full)));
        // No partial file left behind.
        assert!(v.list().is_empty());
        let (_t, free_after) = v.space().unwrap();
        assert_eq!(free_after, 3 * c, "free unchanged after failed write");
    }

    #[test]
    fn rejects_zero_or_too_many_levels() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("z.vault");
        assert!(VaultBuilder::new(&path, vec![]).is_err());
        assert!(VaultBuilder::new(
            &path,
            vec![
                LevelSpec::passphrase_only(pp("a")),
                LevelSpec::passphrase_only(pp("b")),
                LevelSpec::passphrase_only(pp("c")),
                LevelSpec::passphrase_only(pp("d")),
            ],
        )
        .is_err());
    }

    // (Auto-wipe removed: see module-level note. Defense against offline
    // brute force is Argon2id + passphrase entropy, not a counter.)

    // ===== Header signature (v0.11) =====

    /// Flip one byte at `offset` in the vault file (XOR with 0x01).
    fn flip_byte(path: &std::path::Path, offset: u64) {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let mut byte = [0u8; 1];
        f.seek(SeekFrom::Start(offset)).unwrap();
        f.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x01;
        f.seek(SeekFrom::Start(offset)).unwrap();
        f.write_all(&byte).unwrap();
        f.sync_all().unwrap();
    }

    #[test]
    fn metadata_attestation_valid_at_creation() {
        // Sanity: a freshly built vault opens (the metadata blob decrypts
        // and the ML-DSA attestation verifies).
        let dir = tempdir().unwrap();
        let path = dir.path().join("sigok.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        let _ = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
    }

    #[test]
    fn tampering_salt_prevents_open() {
        // The salt is the only plaintext field (offset 0..32). Flipping a
        // salt byte changes every derived key, so unlocking fails.
        let dir = tempdir().unwrap();
        let path = dir.path().join("tamsalt.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        flip_byte(&path, 20); // somewhere inside the salt
        assert!(Vault::open(&path, pp("alpha"), no_auth()).is_err());
    }

    #[test]
    fn tampering_metadata_blob_prevents_open() {
        // The metadata blob (version, total_chunks, VK, signature) is
        // AEAD-encrypted under the shared metadata key. Flipping any byte
        // in it breaks the AEAD tag, so the vault refuses to open even
        // with the correct passphrase. This subsumes the old
        // tampered-total_chunks / tampered-VK / tampered-signature cases:
        // none of those fields is observable or malleable on disk anymore.
        let dir = tempdir().unwrap();
        let path = dir.path().join("tammeta.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        // Flip a byte well inside the ciphertext of the metadata region.
        flip_byte(&path, METADATA_REGION_OFFSET + 100);
        assert!(Vault::open(&path, pp("alpha"), no_auth()).is_err());
    }

    // ===== Manifest counter / anti-rollback (v0.12) =====

    #[test]
    fn counter_starts_at_zero_and_increments_on_add() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ctr.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("p"))
            .total_chunks(8)
            .build()
            .unwrap();

        let v = Vault::open(&path, pp("p"), no_auth()).unwrap();
        assert_eq!(v.counter(), Some(0));
        drop(v);

        let mut v = Vault::open(&path, pp("p"), no_auth()).unwrap();
        v.add_file("a", b"hello".to_vec()).unwrap();
        assert_eq!(v.counter(), Some(1));
        v.add_file("b", b"world".to_vec()).unwrap();
        assert_eq!(v.counter(), Some(2));
    }

    #[test]
    fn counter_increments_on_delete_not_on_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ctr2.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("p"))
            .total_chunks(8)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("p"), no_auth()).unwrap();
        v.add_file("x", b"data".to_vec()).unwrap();
        let after_add = v.counter().unwrap();

        // Read doesn't bump the counter.
        let _ = v.read_file("x").unwrap();
        let _ = v.list();
        assert_eq!(v.counter(), Some(after_add));

        // Delete does.
        v.delete_file("x").unwrap();
        assert_eq!(v.counter(), Some(after_add + 1));
    }

    #[test]
    fn counter_survives_close_and_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ctr3.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("p"))
            .total_chunks(24) // striped: slot-0 stripe = total/3 chunks
            .build()
            .unwrap();
        {
            let mut v = Vault::open(&path, pp("p"), no_auth()).unwrap();
            v.add_file("a", b"x".to_vec()).unwrap();
            v.add_file("b", b"y".to_vec()).unwrap();
            v.add_file("c", b"z".to_vec()).unwrap();
        }
        let v = Vault::open(&path, pp("p"), no_auth()).unwrap();
        assert_eq!(v.counter(), Some(3));
    }

    #[test]
    fn require_counter_at_least_passes_when_equal_or_higher() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ctr4.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("p"))
            .total_chunks(8)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("p"), no_auth()).unwrap();
        v.add_file("a", b"x".to_vec()).unwrap();
        v.add_file("b", b"y".to_vec()).unwrap();
        // counter = 2
        assert!(v.require_counter_at_least(0).is_ok());
        assert!(v.require_counter_at_least(2).is_ok());
        assert!(matches!(
            v.require_counter_at_least(3),
            Err(FormatError::CounterRollback {
                expected: 3,
                actual: 2,
            })
        ));
    }

    #[test]
    fn rollback_attack_detected_by_external_counter_record() {
        // Concrete scenario: user takes a snapshot at counter=N, makes
        // more writes (counter rises), attacker substitutes the
        // snapshot back in, and the user catches it via
        // require_counter_at_least.
        let dir = tempdir().unwrap();
        let path = dir.path().join("rollback.vault");
        let snapshot = dir.path().join("rollback.snap");
        let _ = VaultBuilder::single_passphrase(&path, pp("p"))
            .total_chunks(24) // striped: slot-0 stripe = total/3 chunks
            .build()
            .unwrap();

        // Phase 1: user does 3 ops, snapshots the file.
        {
            let mut v = Vault::open(&path, pp("p"), no_auth()).unwrap();
            v.add_file("a", b"1".to_vec()).unwrap();
            v.add_file("b", b"2".to_vec()).unwrap();
            v.add_file("c", b"3".to_vec()).unwrap();
            assert_eq!(v.counter(), Some(3));
        }
        std::fs::copy(&path, &snapshot).unwrap();

        // Phase 2: user does 2 more ops; counter rises to 5. User
        // records this externally.
        let recorded_counter;
        {
            let mut v = Vault::open(&path, pp("p"), no_auth()).unwrap();
            v.add_file("d", b"4".to_vec()).unwrap();
            v.add_file("e", b"5".to_vec()).unwrap();
            recorded_counter = v.counter().unwrap();
            assert_eq!(recorded_counter, 5);
        }

        // Phase 3: attacker substitutes the older snapshot in place
        // of the current file.
        std::fs::copy(&snapshot, &path).unwrap();

        // Phase 4: user mounts and checks against the recorded
        // counter. Rollback detected.
        let v = Vault::open(&path, pp("p"), no_auth()).unwrap();
        let check = v.require_counter_at_least(recorded_counter);
        assert!(matches!(
            check,
            Err(FormatError::CounterRollback {
                expected: 5,
                actual: 3,
            })
        ));
    }

    #[test]
    fn repeated_wrong_passphrase_does_not_lock_or_wipe() {
        // With auto-wipe removed, repeated failures never destroy or lock
        // the vault — defense is purely the per-guess KDF cost. The
        // correct passphrase still opens after many wrong attempts.
        let dir = tempdir().unwrap();
        let path = dir.path().join("nolock.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();

        for i in 0..8 {
            assert!(Vault::open(&path, pp(&format!("w{i}")), no_auth()).is_err());
        }

        let v = Vault::open(&path, pp("alpha"), no_auth());
        assert!(
            v.is_ok(),
            "vault must still open after many wrong attempts; got {:?}",
            v.err()
        );
    }

    // ---------- v0.15: range-aware reads ----------

    /// Create a vault with one file of `size` bytes, returning the
    /// (opened vault, plaintext, file name) for further inspection.
    fn vault_with_one_file(size: usize, total_chunks: u64) -> (tempfile::TempDir, PathBuf, Vec<u8>)
    {
        let dir = tempdir().unwrap();
        let path = dir.path().join("range.vault");
        // Striped layout: a single-level vault uses only slot-0's
        // stripe = total/NUM_SLOTS chunks. Triple the requested count
        // so the usable capacity matches what these tests intended
        // before the striped redesign.
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(total_chunks * NUM_SLOTS as u64)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        v.add_file("doc", plaintext.clone()).unwrap();
        drop(v);
        (dir, path, plaintext)
    }

    #[test]
    fn stat_file_returns_size_without_decrypting() {
        let (_dir, path, plaintext) = vault_with_one_file(3 * CHUNK_PLAINTEXT_LEN + 7, 16);
        let v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        let st = v.stat_file("doc").unwrap();
        assert_eq!(st.name, "doc");
        assert_eq!(st.size, plaintext.len() as u64);
    }

    #[test]
    fn stat_file_not_found() {
        let (_dir, path, _) = vault_with_one_file(100, 8);
        let v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        assert!(matches!(
            v.stat_file("nope"),
            Err(FormatError::FileNotFound(_))
        ));
    }

    #[test]
    fn readdir_lists_all_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rd.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.add_file("a.txt", b"hello".to_vec()).unwrap();
        v.add_file("b.bin", b"\x00\x01\x02".to_vec()).unwrap();
        let stats = v.readdir();
        assert_eq!(stats.len(), 2);
        let names: Vec<&str> = stats.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"b.bin"));
    }

    /// Deterministic pseudo-random bytes for migration fidelity checks.
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 131 + 7) % 251) as u8).collect()
    }

    /// Populate a source vault, migrate it, and assert the destination is a
    /// byte-perfect copy with folders preserved and the counter advanced.
    #[test]
    fn migrate_preserves_content_folders_and_counter() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.vault");
        let dst = dir.path().join("dst.vault");

        let small = b"a short note".to_vec();
        let big = pattern(200_000); // spans multiple 64 KiB chunks
        let nested = pattern(1234);

        let old_counter;
        {
            VaultBuilder::single_passphrase(&src, pp("alpha"))
                .total_chunks(24)
                .build()
                .unwrap();
            let mut v = Vault::open(&src, pp("alpha"), no_auth()).unwrap();
            v.add_file("a.txt", small.clone()).unwrap();
            v.add_file("big.bin", big.clone()).unwrap();
            v.create_folder("empty").unwrap();
            v.add_file("docs/note.txt", nested.clone()).unwrap();
            old_counter = v.counter().unwrap();
            // `v` dropped here → releases the advisory lock for the migration.
        }

        let report = migrate_vault(
            &src,
            &dst,
            pp("alpha"),
            no_auth(),
            None,
            MigrateCapacity::Same,
            |_, _, _| {},
        )
        .unwrap();
        assert_eq!(report.files, 3);
        assert_eq!(report.new_total_chunks, 24);
        assert!(report.new_counter > old_counter);

        // Destination must be a byte-perfect copy.
        let mut d = Vault::open(&dst, pp("alpha"), no_auth()).unwrap();
        assert_eq!(d.read_file("a.txt").unwrap(), small);
        assert_eq!(d.read_file("big.bin").unwrap(), big);
        assert_eq!(d.read_file("docs/note.txt").unwrap(), nested);
        let folders = d.folders();
        assert!(folders.contains(&"empty".to_string()), "explicit empty folder lost");
        assert!(folders.contains(&"docs".to_string()), "implied folder lost");
        assert!(d.counter().unwrap() > old_counter);
        // The source is untouched and still openable.
        assert!(Vault::open(&src, pp("alpha"), no_auth()).is_ok());
    }

    #[test]
    fn migrate_carries_owner_forward() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.vault");
        let dst = dir.path().join("dst.vault");

        // A vault created WITH an opt-in owner…
        VaultBuilder::single_passphrase(&src, pp("p"))
            .total_chunks(16)
            .owner(Some("denis@example.com".into()))
            .build()
            .unwrap();

        migrate_vault(&src, &dst, pp("p"), no_auth(), None, MigrateCapacity::Same, |_, _, _| {})
            .unwrap();

        // …keeps that owner after migration.
        let d = Vault::open(&dst, pp("p"), no_auth()).unwrap();
        assert_eq!(d.owner(), Some("denis@example.com"));
    }

    /// "Shrink to fit": migrate into a smaller capacity that still holds the
    /// content. Verifies the destination capacity and content.
    #[test]
    fn migrate_shrink_to_fit() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.vault");
        let dst = dir.path().join("dst.vault");
        let data = pattern(100_000); // ~2 chunks

        {
            VaultBuilder::single_passphrase(&src, pp("alpha"))
                .total_chunks(64) // big, mostly empty
                .build()
                .unwrap();
            let mut v = Vault::open(&src, pp("alpha"), no_auth()).unwrap();
            v.add_file("f", data.clone()).unwrap();
        }

        // Exact small capacity.
        let report =
            migrate_vault(&src, &dst, pp("alpha"), no_auth(), None, MigrateCapacity::Exact(8), |_, _, _| {}).unwrap();
        assert_eq!(report.new_total_chunks, 8);
        let mut d = Vault::open(&dst, pp("alpha"), no_auth()).unwrap();
        assert_eq!(d.read_file("f").unwrap(), data);

        // ShrinkToFit must produce a capacity smaller than the (mostly empty)
        // 64-chunk source, never larger.
        let dst2 = dir.path().join("dst2.vault");
        let r2 = migrate_vault(
            &src, &dst2, pp("alpha"), no_auth(), None, MigrateCapacity::ShrinkToFit, |_, _, _| {},
        )
        .unwrap();
        assert!(r2.new_total_chunks < 64, "shrink should reduce capacity");
        assert!(r2.new_total_chunks >= 3, "must still hold the 2-chunk file + manifest");
        let mut d2 = Vault::open(&dst2, pp("alpha"), no_auth()).unwrap();
        assert_eq!(d2.read_file("f").unwrap(), data);
    }

    /// A target capacity too small to hold the content is rejected, and the
    /// source is left intact.
    #[test]
    fn migrate_rejects_too_small_capacity() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.vault");
        let dst = dir.path().join("dst.vault");

        {
            VaultBuilder::single_passphrase(&src, pp("alpha"))
                .total_chunks(32)
                .build()
                .unwrap();
            let mut v = Vault::open(&src, pp("alpha"), no_auth()).unwrap();
            v.add_file("f", pattern(300_000)).unwrap(); // ~5 chunks → need ≥6
        }

        let err = migrate_vault(&src, &dst, pp("alpha"), no_auth(), None, MigrateCapacity::Exact(3), |_, _, _| {});
        assert!(err.is_err());
        assert!(!dst.exists(), "rejected migration must not leave a destination");
        assert!(Vault::open(&src, pp("alpha"), no_auth()).is_ok());
    }

    #[test]
    fn read_file_range_full_file_matches_read_file() {
        let (_dir, path, plaintext) = vault_with_one_file(3 * CHUNK_PLAINTEXT_LEN + 1234, 16);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        let whole = v.read_file_range("doc", 0, plaintext.len() as u64).unwrap();
        assert_eq!(whole, plaintext);
    }

    #[test]
    fn read_file_range_partial_within_first_chunk() {
        let (_dir, path, plaintext) = vault_with_one_file(2 * CHUNK_PLAINTEXT_LEN, 8);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        let slice = v.read_file_range("doc", 100, 256).unwrap();
        assert_eq!(slice, plaintext[100..100 + 256]);
    }

    #[test]
    fn read_file_range_crosses_chunk_boundary() {
        let (_dir, path, plaintext) = vault_with_one_file(3 * CHUNK_PLAINTEXT_LEN, 8);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        let start = (CHUNK_PLAINTEXT_LEN - 50) as u64;
        let len = 200;
        let slice = v.read_file_range("doc", start, len).unwrap();
        assert_eq!(slice, plaintext[start as usize..(start as usize + len as usize)]);
    }

    #[test]
    fn read_file_range_clamps_past_eof() {
        let (_dir, path, plaintext) = vault_with_one_file(100, 4);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        // Ask for 500 bytes starting at 70 — file only has 30 left.
        let slice = v.read_file_range("doc", 70, 500).unwrap();
        assert_eq!(slice, plaintext[70..]);
        assert_eq!(slice.len(), 30);
    }

    #[test]
    fn read_file_range_at_eof_returns_empty() {
        let (_dir, path, plaintext) = vault_with_one_file(100, 4);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        let slice = v
            .read_file_range("doc", plaintext.len() as u64, 100)
            .unwrap();
        assert!(slice.is_empty());
    }

    #[test]
    fn read_file_range_past_eof_returns_empty() {
        let (_dir, path, _plaintext) = vault_with_one_file(100, 4);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        let slice = v.read_file_range("doc", 1_000_000, 100).unwrap();
        assert!(slice.is_empty());
    }

    #[test]
    fn read_file_range_zero_length_returns_empty_without_io() {
        let (_dir, path, _plaintext) = vault_with_one_file(100, 4);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        let slice = v.read_file_range("doc", 50, 0).unwrap();
        assert!(slice.is_empty());
    }

    #[test]
    fn read_file_range_spans_all_chunks_of_large_file() {
        let n_chunks = 5;
        let size = n_chunks * CHUNK_PLAINTEXT_LEN + 17;
        let (_dir, path, plaintext) = vault_with_one_file(size, 16);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        // Read a window starting in chunk 0, ending in the last chunk.
        let start = 4096u64;
        let len = (size as u64) - start - 1;
        let slice = v.read_file_range("doc", start, len).unwrap();
        assert_eq!(
            slice,
            plaintext[start as usize..(start as usize + len as usize)]
        );
    }

    #[test]
    fn read_file_range_not_found() {
        let (_dir, path, _plaintext) = vault_with_one_file(100, 4);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        assert!(matches!(
            v.read_file_range("missing", 0, 10),
            Err(FormatError::FileNotFound(_))
        ));
    }

    // ---------- v0.16: range-aware writes, truncate, create ----------

    #[test]
    fn create_file_creates_empty_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.create_file("empty.txt").unwrap();
        let st = v.stat_file("empty.txt").unwrap();
        assert_eq!(st.size, 0);
        assert!(v.read_file("empty.txt").unwrap().is_empty());
    }

    #[test]
    fn create_file_idempotent_when_already_exists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c2.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.add_file("doc", b"hello".to_vec()).unwrap();
        // create_file on an existing name must NOT clobber.
        v.create_file("doc").unwrap();
        assert_eq!(v.read_file("doc").unwrap(), b"hello");
    }

    #[test]
    fn create_file_rejects_empty_name() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c3.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(4)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        assert!(matches!(v.create_file(""), Err(FormatError::InvalidName)));
    }

    #[test]
    fn write_file_range_overwrites_within_first_chunk() {
        let (_dir, path, mut plaintext) = vault_with_one_file(1000, 8);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        let new_bytes = vec![0xCCu8; 50];
        v.write_file_range("doc", 100, &new_bytes).unwrap();
        plaintext[100..150].copy_from_slice(&new_bytes);
        let read = v.read_file("doc").unwrap();
        assert_eq!(read, plaintext);
    }

    #[test]
    fn write_file_range_crosses_chunk_boundary() {
        // Big enough to span 2 chunks.
        let size = CHUNK_PLAINTEXT_LEN + 1000;
        let (_dir, path, mut plaintext) = vault_with_one_file(size, 16);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        // Write 200 bytes spanning the chunk boundary.
        let start = CHUNK_PLAINTEXT_LEN as u64 - 50;
        let new_bytes = vec![0xDDu8; 200];
        v.write_file_range("doc", start, &new_bytes).unwrap();
        plaintext[start as usize..start as usize + 200].copy_from_slice(&new_bytes);
        let read = v.read_file("doc").unwrap();
        assert_eq!(read, plaintext);
    }

    #[test]
    fn write_file_range_extends_existing_chunk() {
        // File originally fits in chunk 0, write extends it within chunk 0.
        let (_dir, path, mut plaintext) = vault_with_one_file(100, 4);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        let new_bytes = vec![0xEEu8; 50];
        v.write_file_range("doc", 100, &new_bytes).unwrap();
        plaintext.extend_from_slice(&new_bytes);
        let read = v.read_file("doc").unwrap();
        assert_eq!(read, plaintext);
        assert_eq!(v.stat_file("doc").unwrap().size, 150);
    }

    #[test]
    fn write_file_range_extends_past_eof_into_new_chunks() {
        // Append data that lands well past the current chunk count.
        let (_dir, path, mut plaintext) = vault_with_one_file(100, 16);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        // Write 100 bytes starting in chunk 2 (after a small hole).
        let start = 2 * CHUNK_PLAINTEXT_LEN as u64 + 7;
        let new_bytes = vec![0xAAu8; 100];
        v.write_file_range("doc", start, &new_bytes).unwrap();

        let new_size = start as usize + 100;
        plaintext.resize(new_size, 0); // hole-fill is zeros
        plaintext[start as usize..start as usize + 100].copy_from_slice(&new_bytes);

        assert_eq!(v.stat_file("doc").unwrap().size as usize, new_size);
        let read = v.read_file("doc").unwrap();
        assert_eq!(read.len(), new_size);
        assert_eq!(read, plaintext);
    }

    #[test]
    fn write_file_range_fills_hole_with_zeros() {
        // Empty file, then write at large offset — bytes in between
        // must read back as zero.
        let dir = tempdir().unwrap();
        let path = dir.path().join("hole.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.create_file("hole.bin").unwrap();
        v.write_file_range("hole.bin", 1000, &[0x42, 0x42, 0x42]).unwrap();
        let read = v.read_file("hole.bin").unwrap();
        assert_eq!(read.len(), 1003);
        assert!(read[..1000].iter().all(|&b| b == 0));
        assert_eq!(&read[1000..1003], &[0x42, 0x42, 0x42]);
    }

    #[test]
    fn write_file_range_zero_data_is_noop() {
        let (_dir, path, plaintext) = vault_with_one_file(100, 4);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.write_file_range("doc", 50, &[]).unwrap();
        let read = v.read_file("doc").unwrap();
        assert_eq!(read, plaintext);
        assert_eq!(v.stat_file("doc").unwrap().size, 100);
    }

    #[test]
    fn write_file_range_empty_name_rejected() {
        let (_dir, path, _plaintext) = vault_with_one_file(100, 4);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        assert!(matches!(
            v.write_file_range("", 0, &[0xAA]),
            Err(FormatError::InvalidName)
        ));
    }

    #[test]
    fn write_file_range_not_found() {
        let (_dir, path, _plaintext) = vault_with_one_file(100, 4);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        assert!(matches!(
            v.write_file_range("nope", 0, &[0xAA]),
            Err(FormatError::FileNotFound(_))
        ));
    }

    #[test]
    fn write_file_range_migrates_chunk_indices() {
        // Deniability property: a chunk that is modified must change
        // its on-disk position (chunk_idx). Snapshot the chunks list
        // before and after a write and verify it moved.
        let (_dir, path, _plaintext) = vault_with_one_file(1000, 16);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        let before: Vec<u32> = v.list().iter().flat_map(|e| e.chunks.iter()).map(|c| c.0).collect();
        v.write_file_range("doc", 100, &[0xFE; 10]).unwrap();
        let after: Vec<u32> = v.list().iter().flat_map(|e| e.chunks.iter()).map(|c| c.0).collect();
        assert_eq!(before.len(), after.len());
        assert_ne!(
            before, after,
            "chunk migration: modifying a chunk should change its on-disk index"
        );
    }

    #[test]
    fn truncate_file_noop_when_size_matches() {
        let (_dir, path, plaintext) = vault_with_one_file(100, 4);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.truncate_file("doc", 100).unwrap();
        assert_eq!(v.read_file("doc").unwrap(), plaintext);
    }

    #[test]
    fn truncate_file_shrink_within_first_chunk() {
        let (_dir, path, plaintext) = vault_with_one_file(1000, 4);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.truncate_file("doc", 250).unwrap();
        assert_eq!(v.stat_file("doc").unwrap().size, 250);
        let read = v.read_file("doc").unwrap();
        assert_eq!(read, plaintext[..250]);
    }

    #[test]
    fn truncate_file_shrink_to_zero() {
        let (_dir, path, _plaintext) = vault_with_one_file(1000, 4);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.truncate_file("doc", 0).unwrap();
        assert_eq!(v.stat_file("doc").unwrap().size, 0);
        assert!(v.read_file("doc").unwrap().is_empty());
    }

    #[test]
    fn truncate_file_shrink_crosses_chunk_boundary() {
        // File spans 3 chunks; truncate so only 1 chunk remains.
        let size = 3 * CHUNK_PLAINTEXT_LEN;
        let (_dir, path, plaintext) = vault_with_one_file(size, 16);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.truncate_file("doc", 1000).unwrap();
        assert_eq!(v.stat_file("doc").unwrap().size, 1000);
        let read = v.read_file("doc").unwrap();
        assert_eq!(read, plaintext[..1000]);
    }

    #[test]
    fn truncate_file_grow_delegates_to_write_with_zeros() {
        let (_dir, path, mut plaintext) = vault_with_one_file(100, 8);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.truncate_file("doc", 5000).unwrap();
        plaintext.resize(5000, 0);
        let read = v.read_file("doc").unwrap();
        assert_eq!(read.len(), 5000);
        assert_eq!(read, plaintext);
    }

    #[test]
    fn truncate_file_not_found() {
        let (_dir, path, _plaintext) = vault_with_one_file(100, 4);
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        assert!(matches!(
            v.truncate_file("missing", 50),
            Err(FormatError::FileNotFound(_))
        ));
    }

    // ---------- v0.16.1: rename_file ----------

    #[test]
    fn rename_file_basic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rn.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.add_file("old.txt", b"hello".to_vec()).unwrap();
        v.rename_file("old.txt", "new.txt").unwrap();
        assert!(matches!(
            v.stat_file("old.txt"),
            Err(FormatError::FileNotFound(_))
        ));
        assert_eq!(v.read_file("new.txt").unwrap(), b"hello");
    }

    #[test]
    fn rename_file_replaces_existing_destination() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rn2.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.add_file("a", b"AAAA".to_vec()).unwrap();
        v.add_file("b", b"BBBB".to_vec()).unwrap();
        v.rename_file("a", "b").unwrap();
        // After rename, "a" is gone and "b" has the old content of "a".
        assert!(matches!(
            v.stat_file("a"),
            Err(FormatError::FileNotFound(_))
        ));
        assert_eq!(v.read_file("b").unwrap(), b"AAAA");
        assert_eq!(v.list().len(), 1);
    }

    #[test]
    fn rename_file_same_name_is_noop() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rn3.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.add_file("a", b"AAAA".to_vec()).unwrap();
        let before = v.counter().unwrap();
        v.rename_file("a", "a").unwrap();
        assert_eq!(v.counter().unwrap(), before, "no-op must not bump counter");
    }

    #[test]
    fn rename_file_missing_source_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rn4.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        assert!(matches!(
            v.rename_file("missing", "whatever"),
            Err(FormatError::FileNotFound(_))
        ));
    }

    #[test]
    fn rename_file_empty_names_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rn5.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.add_file("a", b"hi".to_vec()).unwrap();
        assert!(matches!(
            v.rename_file("", "x"),
            Err(FormatError::InvalidName)
        ));
        assert!(matches!(
            v.rename_file("a", ""),
            Err(FormatError::InvalidName)
        ));
    }

    #[test]
    fn rename_file_preserves_chunk_indices() {
        // rename is metadata-only — encrypted content doesn't move.
        let dir = tempdir().unwrap();
        let path = dir.path().join("rn6.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(16)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.add_file("doc", vec![0x77; 3 * CHUNK_PLAINTEXT_LEN]).unwrap();
        let before: Vec<u32> = v
            .list()
            .iter()
            .find(|e| e.name == "doc")
            .unwrap()
            .chunks
            .iter()
            .map(|c| c.0)
            .collect();
        v.rename_file("doc", "renamed").unwrap();
        let after: Vec<u32> = v
            .list()
            .iter()
            .find(|e| e.name == "renamed")
            .unwrap()
            .chunks
            .iter()
            .map(|c| c.0)
            .collect();
        assert_eq!(before, after, "rename should not move chunks");
    }

    // ---------- v0.16.1: cross-process flock ----------

    #[test]
    fn second_open_while_first_is_alive_fails_with_already_locked() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("locked.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        let _v1 = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        // Use a pattern match instead of `unwrap_err()` because `Vault`
        // doesn't impl `Debug` (intentional — its contents are
        // sensitive).
        match Vault::open(&path, pp("alpha"), no_auth()) {
            Err(FormatError::AlreadyLocked) => {}
            Err(other) => panic!("expected AlreadyLocked, got {other:?}"),
            Ok(_) => panic!("expected AlreadyLocked, got Ok"),
        }
    }

    #[test]
    fn lock_released_when_first_vault_dropped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("relock.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(8)
            .build()
            .unwrap();
        {
            let _v1 = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
            // _v1 drops at end of block.
        }
        // Re-opening must work now.
        Vault::open(&path, pp("alpha"), no_auth()).expect("lock should be free after drop");
    }

    #[test]
    fn create_then_open_same_process_fails_until_create_dropped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("co.vault");
        // VaultBuilder::build returns a Vault that still holds the
        // lock; a subsequent Vault::open in the same process should
        // therefore fail until the builder's Vault is dropped.
        let built = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(4)
            .build()
            .unwrap();
        match Vault::open(&path, pp("alpha"), no_auth()) {
            Err(FormatError::AlreadyLocked) => {}
            Err(other) => panic!("expected AlreadyLocked, got {other:?}"),
            Ok(_) => panic!("expected AlreadyLocked, got Ok"),
        }
        drop(built);
        Vault::open(&path, pp("alpha"), no_auth()).expect("after drop, should reopen");
    }

    #[test]
    fn write_then_truncate_then_read_range_consistent() {
        // End-to-end smoke: build a file via writes only, truncate it,
        // verify read_file_range still works on the result.
        let dir = tempdir().unwrap();
        let path = dir.path().join("etoe.vault");
        let _ = VaultBuilder::single_passphrase(&path, pp("alpha"))
            .total_chunks(16)
            .build()
            .unwrap();
        let mut v = Vault::open(&path, pp("alpha"), no_auth()).unwrap();
        v.create_file("scratch").unwrap();
        v.write_file_range("scratch", 0, &vec![0x11; 100]).unwrap();
        v.write_file_range("scratch", 100, &vec![0x22; 100]).unwrap();
        v.write_file_range("scratch", 300, &vec![0x33; 100]).unwrap(); // hole at 200..300
        assert_eq!(v.stat_file("scratch").unwrap().size, 400);

        v.truncate_file("scratch", 250).unwrap();
        let whole = v.read_file("scratch").unwrap();
        assert_eq!(whole.len(), 250);
        assert!(whole[..100].iter().all(|&b| b == 0x11));
        assert!(whole[100..200].iter().all(|&b| b == 0x22));
        assert!(whole[200..250].iter().all(|&b| b == 0)); // hole was zero-filled

        // Range read across the patches.
        let range = v.read_file_range("scratch", 95, 15).unwrap();
        assert_eq!(&range[..5], &[0x11; 5]);
        assert_eq!(&range[5..], &[0x22; 10]);
    }
}
