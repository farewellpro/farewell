//! C ABI shim exposing parts of `farewell_format` to native callers.
//!
//! # Status
//!
//! v0.17 was the minimal bridge (two trivial functions to validate
//! the Rust ↔ Swift toolchain).
//!
//! **v0.18 (Phase A — this version)**: the real lifecycle surface,
//! enough for a read-only FSKit mount.
//!
//! - opaque handle [`FarewellVault`]
//! - error catalogue [`FarewellStatus`]
//! - `farewell_open` (passphrase-only, K=0; hardware-key opens come
//!   later — they need an authenticator object passed through)
//! - `farewell_close`
//! - `farewell_stat`
//! - `farewell_read_range`
//!
//! Phase B (next): write_range, truncate, create, delete, rename.
//! Phase C (later): readdir with callback, hardware-key opens,
//! protected mounts, vault info / fingerprint.
//!
//! # Conventions
//!
//! - **Status return value**: every fallible function returns an
//!   `int32_t`. `0` means success; non-zero is one of the
//!   [`FarewellStatus`] discriminants. Output values come back via
//!   out-pointers.
//! - **Pointer parameters** are non-null unless documented otherwise.
//!   Passing `NULL` for a non-null parameter returns
//!   [`FarewellStatus::InvalidArgument`] rather than crashing.
//! - **C strings** are NUL-terminated UTF-8. Non-UTF-8 returns
//!   [`FarewellStatus::InvalidArgument`].
//! - **Raw byte buffers** (passphrase, read/write data) are
//!   `pointer + length`; we never assume NUL termination on them.
//! - **No exceptions, no panics** ever cross the FFI: every entry
//!   point wraps its body in [`catch_panic`].
//! - **Thread safety**: all operations on the same handle must be
//!   serialized by the caller. The binding does not provide internal
//!   synchronization. Different handles may be used concurrently.
//! - **Lifetime of returned C strings** (like the one from
//!   [`farewell_version`]): valid for the entire process lifetime,
//!   never free them.
//!
//! # Why a separate crate rather than `extern "C"` blocks in
//!   `farewell_format`?
//!
//! - Keeps the FFI surface explicit and reviewable as one unit.
//! - Lets `farewell_format` stay a pure Rust API with no extern
//!   "C" pollution.
//! - Allows cbindgen (or a hand-written header) to target a single
//!   crate.
//! - Crate-type `staticlib` only makes sense here.

// This crate IS the FFI shim — `unsafe` (specifically the
// `#[unsafe(no_mangle)]` attribute and `extern "C"` blocks, plus
// dereferencing caller-provided pointers) is its whole purpose.
// All inner Rust crates keep `#![forbid/deny(unsafe_code)]`; the
// unsafe surface is intentionally concentrated here so reviewers
// can audit one file rather than chasing it across the workspace.
#![deny(missing_docs)]

use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::time::{Duration, Instant};

use farewell_fido2::{
    Authenticator, Fido2Error, HidAuthenticator, HidDevice, HMAC_OUTPUT_LEN, HMAC_SALT_LEN,
    MockAuthenticator,
};
use farewell_format::{FormatError, Vault};

/// FIDO2 Relying-Party identifier. Must match the value used by every
/// other entry point (the CLI uses the same), so a vault enrolled in one
/// place opens in another.
const FIDO_RP_ID: &str = "farewell.foundation";

// =============================================================================
// Version + constants (carried over from v0.17)
// =============================================================================

/// Null-terminated build-time version string for the FFI surface.
const VERSION_CSTR: &[u8] = b"0.18\0";

/// Return a pointer to a static NUL-terminated C string identifying
/// this build of the FFI shim (e.g. `"0.18"`). Lifetime: process.
#[unsafe(no_mangle)]
pub extern "C" fn farewell_version() -> *const c_char {
    VERSION_CSTR.as_ptr() as *const c_char
}

/// Return the plaintext capacity of one encrypted chunk, in bytes.
#[unsafe(no_mangle)]
pub extern "C" fn farewell_chunk_plaintext_len() -> u64 {
    farewell_format::CHUNK_PLAINTEXT_LEN as u64
}

// =============================================================================
// Passphrase strength + generation (v0.5)
// =============================================================================

/// Estimate the strength of a passphrase, returning the zxcvbn score
/// (0 = weakest, 4 = strongest) via `*out_score`. The creation policy
/// requires 4. Lets the UI show a live meter using the *same* estimator
/// the core enforces.
///
/// Returns [`FarewellStatus::InvalidArgument`] if `out_score` is NULL or
/// the bytes are not valid UTF-8; otherwise [`FarewellStatus::Ok`].
///
/// # Safety
/// `passphrase` must point to `passphrase_len` readable bytes (may be
/// NULL iff `passphrase_len == 0`). `out_score` must be a valid `*u8`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_passphrase_score(
    passphrase: *const u8,
    passphrase_len: u64,
    out_score: *mut u8,
) -> i32 {
    catch_panic(|| {
        if out_score.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let pw = match collect_passphrase(passphrase, passphrase_len) {
            Some(v) => v,
            None => return FarewellStatus::InvalidArgument,
        };
        let s = match std::str::from_utf8(&pw) {
            Ok(s) => s,
            Err(_) => return FarewellStatus::InvalidArgument,
        };
        let score = farewell_passphrase::estimate(s).score;
        // SAFETY: out_score non-null per contract.
        unsafe { *out_score = score };
        FarewellStatus::Ok
    })
}

/// Callback receiving a freshly generated passphrase as a NUL-terminated
/// UTF-8 string. The pointer is valid ONLY for the duration of the call;
/// copy it out. The buffer is zeroized after the callback returns.
pub type FarewellPassphraseCb = extern "C" fn(utf8: *const c_char, user_data: *mut std::ffi::c_void);

/// Progress reported by long operations so the UI can show real status.
///
/// `phase` is one of the `FAREWELL_PROGRESS_*` constants. `done`/`total`
/// carry detail: for [`FAREWELL_PROGRESS_AWAIT_TOUCH`], `done` is the
/// touch number and `total` the number of touches expected (e.g. step 1
/// of 2); for [`FAREWELL_PROGRESS_WRITING`], `done`/`total` are chunks
/// written / to write (drive a real progress bar from `done/total`).
pub type FarewellProgressCb =
    extern "C" fn(phase: u32, done: u64, total: u64, user_data: *mut std::ffi::c_void);

/// Progress phase: waiting for a hardware-key touch (`done` of `total`).
pub const FAREWELL_PROGRESS_AWAIT_TOUCH: u32 = 0;
/// Progress phase: writing the vault file (`done`/`total` chunks). Also used
/// for a migration's destination pre-allocation.
pub const FAREWELL_PROGRESS_WRITING: u32 = 1;
/// Progress phase: copying files during a migration (`done`/`total` files).
pub const FAREWELL_PROGRESS_MIGRATE_COPY: u32 = 2;
/// Progress phase: verifying the migrated copy (`done`/`total` files).
pub const FAREWELL_PROGRESS_MIGRATE_VERIFY: u32 = 3;
/// Progress phase: waiting for the user to **insert** a hardware key (one-port
/// swap enrollment). `done` is the key number being enrolled, `total` the
/// total number of keys.
pub const FAREWELL_PROGRESS_AWAIT_INSERT: u32 = 4;
/// Progress phase: waiting for the user to **remove** the current hardware key
/// before inserting the next one. `done`/`total` as for `AWAIT_INSERT`.
pub const FAREWELL_PROGRESS_AWAIT_REMOVE: u32 = 5;

/// Generate a strong EFF-diceware passphrase of `word_count` words
/// (use 0 for the recommended default) and hand it to `cb`. The
/// generated passphrase always satisfies the creation policy.
///
/// # Safety
/// `cb` must be a valid function pointer. `user_data` is passed through
/// opaquely.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_generate_passphrase(
    word_count: u64,
    cb: Option<FarewellPassphraseCb>,
    user_data: *mut std::ffi::c_void,
) -> i32 {
    catch_panic(|| {
        let cb = match cb {
            Some(f) => f,
            None => return FarewellStatus::InvalidArgument,
        };
        let n = if word_count == 0 {
            farewell_passphrase::DEFAULT_WORDS
        } else {
            word_count as usize
        };
        let pw = match farewell_passphrase::generate(n) {
            Ok(s) => s,
            Err(_) => return FarewellStatus::Internal,
        };
        let cstr = match std::ffi::CString::new(pw) {
            Ok(c) => c,
            Err(_) => return FarewellStatus::Internal,
        };
        cb(cstr.as_ptr(), user_data);
        // Best-effort scrub: overwrite the CString's bytes before it is
        // dropped/freed. (The caller has already copied what it needs.)
        let mut bytes = cstr.into_bytes();
        for b in bytes.iter_mut() {
            *b = 0;
        }
        FarewellStatus::Ok
    })
}

// =============================================================================
// Status codes
// =============================================================================

/// Status codes returned by every fallible FFI function.
///
/// Numbers are part of the ABI: do NOT renumber existing variants
/// when adding new ones, only append.
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(missing_docs)] // each variant documents itself via its name + the table
pub enum FarewellStatus {
    Ok = 0,
    /// A required pointer was NULL, a string was not valid UTF-8, a
    /// length was negative-when-interpreted, or similar misuse.
    InvalidArgument = 1,
    /// The vault file or a manifest entry could not be found.
    NotFound = 2,
    /// Underlying filesystem I/O error (read/write/open/sync).
    Io = 3,
    /// Another process holds the advisory flock on the vault file.
    AlreadyLocked = 4,
    /// Vault has been wiped (failed-attempts threshold reached).
    Wiped = 5,
    /// File name violates manifest constraints (empty, etc.).
    InvalidName = 6,
    /// Cryptographic failure: wrong passphrase, AEAD verification
    /// failure, signature check failure, ...
    Crypto = 7,
    /// Vault is full (no free chunks for the requested allocation).
    Full = 8,
    /// Manifest decode failure (corruption, post-decrypt).
    Manifest = 9,
    /// Vault file is too small for its declared layout.
    TooSmall = 10,
    /// Not a Farewell vault (magic bytes mismatch).
    NotAVault = 11,
    /// Header signature does not verify (tampering detected).
    HeaderSignatureInvalid = 12,
    /// Format version is not supported by this build.
    UnsupportedVersion = 13,
    /// Counter rollback detected (require_counter_at_least failed).
    CounterRollback = 14,
    /// A passphrase failed the strength policy (zxcvbn score below the
    /// required floor). Use a stronger passphrase or a generated one.
    WeakPassphrase = 15,
    /// A hardware key was required but none could be opened (not plugged
    /// in, or the OS denied USB/HID access).
    HwNotPresent = 16,
    /// Hardware-key authentication failed: wrong PIN, the key was not
    /// touched in time, or a transport/protocol error.
    HwAuthFailed = 17,
    /// More than one hardware key is plugged in while a PIN was supplied.
    /// Refused up front: trying the PIN against the wrong key would burn
    /// that key's limited CTAP2 PIN-retry counter (and could lock it). The
    /// caller should ask the user to leave only the key they're using.
    HwMultipleKeys = 18,
    /// A Rust panic was caught at the FFI boundary. This indicates a
    /// bug in the Rust code; report it.
    Internal = 100,
}

impl FarewellStatus {
    fn from_format_error(e: &FormatError) -> Self {
        match e {
            FormatError::TooSmall(_) => Self::TooSmall,
            FormatError::NotAVault => Self::NotAVault,
            FormatError::UnsupportedVersion(_) => Self::UnsupportedVersion,
            FormatError::Crypto(_) => Self::Crypto,
            FormatError::Io(_) => Self::Io,
            FormatError::Manifest(_) => Self::Manifest,
            FormatError::InvalidChunk(_) => Self::Manifest,
            FormatError::Full => Self::Full,
            FormatError::FileNotFound(_) => Self::NotFound,
            FormatError::InvalidName => Self::InvalidName,
            FormatError::ManifestOverflow => Self::Manifest,
            FormatError::Wiped => Self::Wiped,
            FormatError::HeaderSignatureInvalid => Self::HeaderSignatureInvalid,
            FormatError::CounterRollback { .. } => Self::CounterRollback,
            FormatError::HardwareKeyRequired => Self::HwNotPresent,
            FormatError::AlreadyLocked => Self::AlreadyLocked,
        }
    }
}

// =============================================================================
// Opaque handle
// =============================================================================

/// Opaque vault handle returned by [`farewell_open`] and consumed by
/// [`farewell_close`]. Callers MUST NOT inspect, copy, or
/// arithmetic-on the pointer; treat it as a token.
pub struct FarewellVault {
    inner: Vault,
}

// =============================================================================
// Panic guard
// =============================================================================

/// Run `f`, returning its status code or [`FarewellStatus::Internal`]
/// if `f` panics. Every FFI entry point wraps its body in this so
/// that a Rust panic never crosses the FFI boundary (which would be
/// undefined behavior in any C consumer, and crash the macOS app
/// hosting our FSKit module).
fn catch_panic<F: FnOnce() -> FarewellStatus>(f: F) -> i32 {
    let r = std::panic::catch_unwind(AssertUnwindSafe(f))
        .unwrap_or(FarewellStatus::Internal);
    r as i32
}

/// Pointer-returning variant: NULL on panic.
fn catch_panic_ptr<T, F: FnOnce() -> *mut T>(f: F) -> *mut T {
    std::panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or(std::ptr::null_mut())
}

/// i64-returning variant: -1 on panic.
fn catch_panic_i64<F: FnOnce() -> i64>(f: F) -> i64 {
    std::panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or(-1)
}

// =============================================================================
// Byte-slice passing (for lists of passphrases)
// =============================================================================

/// A borrowed byte slice passed across the FFI: pointer + length.
/// Used to pass a list of passphrases (each of arbitrary bytes,
/// possibly containing NULs) without C-string assumptions.
///
/// The pointer must remain valid for the duration of the call that
/// receives it; the callee copies what it needs.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FarewellBytes {
    /// Pointer to `len` readable bytes. May be NULL only if `len == 0`.
    pub ptr: *const u8,
    /// Number of valid bytes at `ptr`.
    pub len: u64,
}

impl FarewellBytes {
    /// Copy into an owned `Vec<u8>`, or `None` if the slice is
    /// malformed (null ptr with non-zero len, or len overflows usize).
    ///
    /// # Safety
    /// `self.ptr` must point to `self.len` initialized bytes when
    /// `self.len > 0`.
    unsafe fn to_vec(self) -> Option<Vec<u8>> {
        if self.len == 0 {
            return Some(Vec::new());
        }
        if self.ptr.is_null() {
            return None;
        }
        let len = usize::try_from(self.len).ok()?;
        // SAFETY: caller contracts ptr/len validity per the struct docs.
        let slice = unsafe { std::slice::from_raw_parts(self.ptr, len) };
        Some(slice.to_vec())
    }
}

// =============================================================================
// Vault creation (multi-level — hidden volumes)
// =============================================================================

/// Create a new single-domain vault file, protected by one passphrase.
///
/// A Farewell vault holds exactly one content tree, openable by exactly
/// one passphrase, using the whole capacity. (There are no hidden /
/// decoy volumes — that feature was removed.)
///
/// Parameters:
/// - `path_utf8`: NUL-terminated UTF-8 path; the file must NOT exist.
/// - `total_chunks`: chunk capacity. Must be ≥ 2.
/// - `passphrases`: array of [`FarewellBytes`]; exactly one entry.
/// - `passphrase_count`: must be 1.
///
/// Does NOT return a handle: the file is created on disk and the
/// advisory lock released. Mount it afterwards with [`farewell_open`].
///
/// This entry is passphrase-only. To enroll a FIDO2 hardware key at
/// creation, use [`farewell_create_vault_hw`].
///
/// # Safety
///
/// `path_utf8` must be a valid C string. `passphrases` must point to
/// `passphrase_count` valid [`FarewellBytes`], each describing a valid
/// byte slice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_create_vault(
    path_utf8: *const c_char,
    total_chunks: u64,
    passphrases: *const FarewellBytes,
    passphrase_count: u64,
) -> i32 {
    catch_panic(|| {
        if path_utf8.is_null() || passphrases.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let count = match usize::try_from(passphrase_count) {
            Ok(n) if n >= 1 => n,
            _ => return FarewellStatus::InvalidArgument,
        };

        let path = match cstr_to_path(path_utf8) {
            Some(p) => p,
            None => return FarewellStatus::InvalidArgument,
        };

        // SAFETY: caller contracts `passphrases` points to `count`
        // valid FarewellBytes.
        let entries = unsafe { std::slice::from_raw_parts(passphrases, count) };

        let mut specs: Vec<farewell_format::LevelSpec> = Vec::with_capacity(count);
        for e in entries {
            // SAFETY: each entry's ptr/len validity is the caller's
            // contract.
            let pw = match unsafe { e.to_vec() } {
                Some(v) if !v.is_empty() => v,
                _ => return FarewellStatus::InvalidArgument,
            };
            // Strength policy backstop: every level's passphrase must pass
            // the floor. The UI also checks this live, but the FFI refuses
            // weak passphrases unconditionally — there is no auto-wipe and
            // no recovery, so the passphrase is the whole defense.
            if let Ok(s) = std::str::from_utf8(&pw) {
                if !farewell_passphrase::meets_policy(s) {
                    return FarewellStatus::WeakPassphrase;
                }
            }
            specs.push(farewell_format::LevelSpec::passphrase_only(pw));
        }

        let builder = match farewell_format::VaultBuilder::new(&path, specs) {
            Ok(b) => b,
            Err(e) => return FarewellStatus::from_format_error(&e),
        };
        let builder = builder.total_chunks(total_chunks);

        match builder.build() {
            // Drop the returned (unmounted) Vault immediately: it holds
            // the flock, and we want the file on disk + unlocked so a
            // subsequent open can mount it.
            Ok(_vault) => FarewellStatus::Ok,
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

/// Create a vault, enrolling `hw_keys_per_level` FIDO2 hardware keys per
/// level (the same physical key is enrolled once per level).
///
/// With `hw_keys_per_level == 0` this is exactly [`farewell_create_vault`]
/// (no hardware involved). Otherwise a connected authenticator is opened,
/// the optional CTAP2 `pin` is applied, and the user is asked to TOUCH the
/// key once per enrollment — so this call BLOCKS and must be made off the
/// UI thread.
///
/// Strength policy applies to every passphrase (same as the non-HW path).
///
/// On success the vault is returned **already open** (the primary level is
/// mounted, reusing the master key from creation) via `out_handle`, so the
/// caller does NOT re-open — avoiding a second slow KDF and, for hardware
/// vaults, an extra mount touch. Close it with [`farewell_close`].
///
/// Returns [`FarewellStatus::HwNotPresent`] if no key can be opened, and
/// surfaces enrollment failures (wrong PIN, no touch) via the format-error
/// mapping.
///
/// # Safety
/// Same contract as [`farewell_create_vault`]; additionally `pin` must
/// point to `pin_len` bytes (may be NULL iff `pin_len == 0`), and
/// `out_handle` must be a valid writable pointer.
///
/// `progress`, if non-NULL, is invoked with a phase code as the operation
/// proceeds so the UI can update its message (no more "touch" prompt while
/// the file is being written): [`FAREWELL_PROGRESS_AWAIT_TOUCH`] before a
/// hardware-key touch, [`FAREWELL_PROGRESS_WORKING`] before the (touch-
/// free) vault write. It is called on the calling thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_create_vault_hw(
    path_utf8: *const c_char,
    total_chunks: u64,
    passphrases: *const FarewellBytes,
    passphrase_count: u64,
    hw_keys_per_level: u32,
    pin: *const u8,
    pin_len: u64,
    owner_utf8: *const c_char,
    out_handle: *mut *mut FarewellVault,
    progress: Option<FarewellProgressCb>,
    progress_user_data: *mut std::ffi::c_void,
) -> i32 {
    catch_panic(|| {
        let notify = |phase: u32, done: u64, total: u64| {
            if let Some(cb) = progress {
                cb(phase, done, total, progress_user_data);
            }
        };
        if path_utf8.is_null() || passphrases.is_null() || out_handle.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: out_handle non-null per contract.
        unsafe {
            *out_handle = std::ptr::null_mut();
        }
        let count = match usize::try_from(passphrase_count) {
            Ok(n) if n >= 1 => n,
            _ => return FarewellStatus::InvalidArgument,
        };
        // Opt-in creator identity (NULL/empty → anonymous).
        let owner: Option<String> = cstr_to_str(owner_utf8)
            .map(str::to_string)
            .filter(|s| !s.trim().is_empty());
        let hw = hw_keys_per_level as usize;
        if hw > farewell_format::MAX_HW_KEYS_PER_LEVEL {
            return FarewellStatus::InvalidArgument;
        }
        let path = match cstr_to_path(path_utf8) {
            Some(p) => p,
            None => return FarewellStatus::InvalidArgument,
        };
        // SAFETY: caller contract.
        let entries = unsafe { std::slice::from_raw_parts(passphrases, count) };

        // Collect + policy-check every passphrase first.
        let mut pws: Vec<Vec<u8>> = Vec::with_capacity(count);
        for e in entries {
            let pw = match unsafe { e.to_vec() } {
                Some(v) if !v.is_empty() => v,
                _ => return FarewellStatus::InvalidArgument,
            };
            if let Ok(s) = std::str::from_utf8(&pw) {
                if !farewell_passphrase::meets_policy(s) {
                    return FarewellStatus::WeakPassphrase;
                }
            }
            pws.push(pw);
        }

        // Boxes a freshly-built (already-mounted) vault into out_handle.
        let finish = |built: Result<farewell_format::Vault, farewell_format::FormatError>| -> FarewellStatus {
            match built {
                Ok(v) => {
                    let boxed = Box::new(FarewellVault { inner: v });
                    // SAFETY: out_handle non-null per contract.
                    unsafe {
                        *out_handle = Box::into_raw(boxed);
                    }
                    FarewellStatus::Ok
                }
                Err(e) => FarewellStatus::from_format_error(&e),
            }
        };

        // No hardware → passphrase-only path; just report the write.
        if hw == 0 {
            let specs: Vec<_> = pws
                .into_iter()
                .map(farewell_format::LevelSpec::passphrase_only)
                .collect();
            let builder = match farewell_format::VaultBuilder::new(&path, specs) {
                Ok(b) => b,
                Err(e) => return FarewellStatus::from_format_error(&e),
            };
            let built = builder
                .total_chunks(total_chunks)
                .owner(owner.clone())
                .build_with_progress(|done, total| notify(FAREWELL_PROGRESS_WRITING, done, total));
            return finish(built);
        }

        // Hardware path: fix the salt up front (enrollment derives the FIDO
        // salt from it), then enroll `hw` distinct physical keys ONE AT A TIME
        // on a single USB port (insert → touch → remove → insert next). One key
        // is ever connected at a time, so the touch is necessarily the right
        // key — no reliance on a visible blink (some keys, e.g. the 5C Nano,
        // don't visibly blink). Re-inserting an already-enrolled key is
        // rejected by a non-touch credential probe so each enrolled entry is a
        // genuinely distinct key.
        let mut salt = [0u8; 32];
        if farewell_crypto::rng::fill(&mut salt).is_err() {
            return FarewellStatus::Internal;
        }
        let fido_salt = farewell_format::fido_salt_from_vault_salt(&salt);

        // Enroll each distinct key once; reuse its (cred, hmac) for every level
        // (the hmac depends only on the credential + the vault-wide salt). For
        // the single-domain vault this app builds, `count == 1`.
        let mut key_creds: Vec<(Vec<u8>, [u8; HMAC_OUTPUT_LEN])> = Vec::with_capacity(hw);
        for k in 0..hw {
            let dev = if k == 0 {
                notify(FAREWELL_PROGRESS_AWAIT_INSERT, 1, hw as u64);
                match wait_for_single_device() {
                    Some(d) => d,
                    None => return FarewellStatus::HwNotPresent,
                }
            } else {
                // Swap: remove the previous key, insert the next (distinct) one.
                notify(FAREWELL_PROGRESS_AWAIT_REMOVE, (k + 1) as u64, hw as u64);
                if !wait_for_no_device() {
                    return FarewellStatus::HwNotPresent;
                }
                notify(FAREWELL_PROGRESS_AWAIT_INSERT, (k + 1) as u64, hw as u64);
                match wait_for_fresh_device(&key_creds, &fido_salt, pin, pin_len) {
                    Ok(Some(d)) => d,
                    Ok(None) => return FarewellStatus::HwNotPresent,
                    Err(e) => return status_from_fido(&e),
                }
            };

            let mut auth = HidAuthenticator::open_on(FIDO_RP_ID, &dev);
            apply_pin(&mut auth, pin, pin_len);
            let user_handle = format!("farewell-K{k}").into_bytes();
            notify(FAREWELL_PROGRESS_AWAIT_TOUCH, 1, 2);
            let cred = match auth.enroll(&user_handle) {
                Ok(c) => c,
                Err(e) => return status_from_fido(&e),
            };
            notify(FAREWELL_PROGRESS_AWAIT_TOUCH, 2, 2);
            let out = match auth.challenge_response(&[cred.clone()], &fido_salt) {
                Ok((_, out)) => out,
                Err(e) => return status_from_fido(&e),
            };
            key_creds.push((cred, out));
        }

        let mut specs: Vec<farewell_format::LevelSpec> = Vec::with_capacity(count);
        for pw in pws {
            let mut enr = farewell_format::LevelEnrollment::passphrase_only();
            for (cred, out) in &key_creds {
                if enr.push(cred.clone(), *out).is_err() {
                    return FarewellStatus::Internal;
                }
            }
            specs.push(farewell_format::LevelSpec {
                passphrase: pw,
                enrollment: enr,
            });
        }

        let builder = match farewell_format::VaultBuilder::new(&path, specs) {
            Ok(b) => b,
            Err(e) => return FarewellStatus::from_format_error(&e),
        };
        let built = builder
            .total_chunks(total_chunks)
            .with_salt(salt)
            .owner(owner.clone())
            .build_with_progress(|done, total| notify(FAREWELL_PROGRESS_WRITING, done, total));
        finish(built)
    })
}

/// Re-encrypt a vault into a **new** file at `dst_path_utf8` (crypto-agility /
/// rotation). The source is opened read-only and left untouched; the
/// destination is built, content streamed in, and verified byte-for-byte
/// before this returns `Ok`. The caller owns the atomic swap and disposal of
/// the old file, and must delete `dst_path` on any non-Ok return.
///
/// `new_total_chunks`: 0 = keep the source's capacity; otherwise the
/// destination capacity (e.g. "shrink to fit"). `hw_keys`: 0 = passphrase-only;
/// > 0 = open the source with, and enroll one, hardware key on the destination
/// (the YubiKey blinks a few times — one touch to open the source, two to
/// enroll on the new vault). `pin` is the CTAP2 PIN bytes (may be empty).
///
/// `progress` phases: [`FAREWELL_PROGRESS_WRITING`] (destination allocation),
/// [`FAREWELL_PROGRESS_MIGRATE_COPY`], [`FAREWELL_PROGRESS_MIGRATE_VERIFY`].
///
/// # Safety
/// All pointers must be valid for their stated lengths; strings NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_migrate(
    src_path_utf8: *const c_char,
    dst_path_utf8: *const c_char,
    passphrase: *const u8,
    passphrase_len: u64,
    hw_keys: u32,
    pin: *const u8,
    pin_len: u64,
    new_total_chunks: u64,
    progress: Option<FarewellProgressCb>,
    progress_user_data: *mut std::ffi::c_void,
) -> i32 {
    catch_panic(|| {
        if src_path_utf8.is_null() || dst_path_utf8.is_null() || passphrase.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let src = match cstr_to_path(src_path_utf8) {
            Some(p) => p,
            None => return FarewellStatus::InvalidArgument,
        };
        let dst = match cstr_to_path(dst_path_utf8) {
            Some(p) => p,
            None => return FarewellStatus::InvalidArgument,
        };
        let plen = match usize::try_from(passphrase_len) {
            Ok(n) if n >= 1 => n,
            _ => return FarewellStatus::InvalidArgument,
        };
        // SAFETY: caller contract — `passphrase` valid for `plen` bytes.
        let pw = unsafe { std::slice::from_raw_parts(passphrase, plen) }.to_vec();
        // 0 = same capacity; u64::MAX = shrink to fit; else an exact capacity.
        let capacity = match new_total_chunks {
            0 => farewell_format::MigrateCapacity::Same,
            u64::MAX => farewell_format::MigrateCapacity::ShrinkToFit,
            n => farewell_format::MigrateCapacity::Exact(n),
        };

        let on_progress = move |phase: farewell_format::MigratePhase, done: u64, total: u64| {
            if let Some(cb) = progress {
                let code = match phase {
                    farewell_format::MigratePhase::Allocate => FAREWELL_PROGRESS_WRITING,
                    farewell_format::MigratePhase::Copy => FAREWELL_PROGRESS_MIGRATE_COPY,
                    farewell_format::MigratePhase::Verify => FAREWELL_PROGRESS_MIGRATE_VERIFY,
                };
                cb(code, done, total, progress_user_data);
            }
        };

        let result = if hw_keys == 0 {
            farewell_format::migrate_vault(
                &src,
                &dst,
                pw,
                None::<&mut MockAuthenticator>,
                None,
                capacity,
                on_progress,
            )
        } else {
            let mut auth = match HidAuthenticator::open_first(FIDO_RP_ID) {
                Ok(a) => a,
                Err(_) => return FarewellStatus::HwNotPresent,
            };
            apply_pin(&mut auth, pin, pin_len);
            farewell_format::migrate_vault(
                &src,
                &dst,
                pw,
                Some(&mut auth),
                Some(b"farewell-L0-K0"),
                capacity,
                on_progress,
            )
        };

        match result {
            Ok(_) => FarewellStatus::Ok,
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

/// Enroll a **backup** hardware key on an existing vault, in place — afterwards
/// either the original key or this new one unlocks it. The vault data is not
/// re-encrypted (only the slot's key-wrapping region is updated).
///
/// Keys are handled **one at a time on a single USB port** (insert → touch →
/// swap), so the touch is always unambiguously the right key — no reliance on a
/// visible blink. For a key-protected vault (K≥1): insert the CURRENT key (one
/// touch recovers the wrapping secret), then remove it and insert the NEW key
/// (which must not already open the vault) to enroll it. For a passphrase-only
/// vault (K==0): insert the single new key, which becomes required.
///
/// `progress` emits `FAREWELL_PROGRESS_AWAIT_INSERT` / `_AWAIT_REMOVE` while
/// waiting for the user to plug/unplug, and `_AWAIT_TOUCH` around each touch.
///
/// On success `out_handle` receives an **already-open** vault — the function
/// re-mounts it internally by replaying the key response it just captured, so
/// the user is NOT asked to touch the key again merely to re-open. The caller
/// adopts the handle exactly as from `farewell_open_hw` (and must
/// `farewell_close` it). If the slot write succeeds but this convenience
/// re-open fails, a non-OK status is returned with `out_handle` left NULL; the
/// enrollment is still persisted and the vault can be opened normally.
///
/// # Safety
/// `path_utf8` NUL-terminated; `passphrase`/`pin` valid for their lengths.
/// `out_handle` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_add_backup_key(
    path_utf8: *const c_char,
    passphrase: *const u8,
    passphrase_len: u64,
    pin: *const u8,
    pin_len: u64,
    new_pin: *const u8,
    new_pin_len: u64,
    label_utf8: *const c_char,
    progress: Option<FarewellProgressCb>,
    progress_user_data: *mut std::ffi::c_void,
    out_handle: *mut *mut FarewellVault,
) -> i32 {
    catch_panic(|| {
        let notify = |phase: u32, done: u64, total: u64| {
            if let Some(cb) = progress {
                cb(phase, done, total, progress_user_data);
            }
        };
        if path_utf8.is_null() || passphrase.is_null() || out_handle.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: out_handle non-null per the check + caller contract.
        unsafe {
            *out_handle = std::ptr::null_mut();
        }
        let path = match cstr_to_path(path_utf8) {
            Some(p) => p,
            None => return FarewellStatus::InvalidArgument,
        };
        let pw = match collect_passphrase(passphrase, passphrase_len) {
            Some(v) => v,
            None => return FarewellStatus::InvalidArgument,
        };

        // 1. Read the slot's enrollment (verifies the passphrase; no unlock).
        let (fido_salt, existing_creds, _labels, k) =
            match Vault::slot_enrollment_info(&path, pw.clone()) {
                Ok(x) => x,
                Err(e) => return FarewellStatus::from_format_error(&e),
            };

        // 2. One key at a time on one USB port (no swap-free two-port juggling;
        //    the touch is unambiguous because only one key is ever connected).
        //    For a key-protected vault (K≥1): first insert the CURRENT key to
        //    recover the unwrap secret, then swap to the NEW backup key. For a
        //    passphrase-only vault (K==0): just insert the single new key.
        let recover_hmac: Option<[u8; HMAC_OUTPUT_LEN]>;
        // The (cred, hmac) of a key that opens the vault, kept so we can
        // re-mount WITHOUT a fresh touch after writing the slot (the user
        // already proved presence above). For K≥1 this is the current key;
        // for K==0 it's the just-enrolled key (filled in at step 3).
        let mut remount_cred: Option<Vec<u8>> = None;
        let backup: HidDevice;
        if k == 0 {
            recover_hmac = None;
            notify(FAREWELL_PROGRESS_AWAIT_INSERT, 1, 1);
            backup = match wait_for_single_device() {
                Some(d) => d,
                None => return FarewellStatus::HwNotPresent,
            };
        } else {
            // 2a. Insert the current key; one touch recovers its hmac.
            notify(FAREWELL_PROGRESS_AWAIT_INSERT, 1, 2);
            let current = match wait_for_single_device() {
                Some(d) => d,
                None => return FarewellStatus::HwNotPresent,
            };
            let mut auth = HidAuthenticator::open_on(FIDO_RP_ID, &current);
            apply_pin(&mut auth, pin, pin_len);
            notify(FAREWELL_PROGRESS_AWAIT_TOUCH, 1, 1);
            recover_hmac = match auth.challenge_response(&existing_creds, &fido_salt) {
                Ok((used_cred, hmac)) => {
                    remount_cred = Some(used_cred);
                    Some(hmac)
                }
                // This key does not open this vault — wrong key for the recover.
                Err(Fido2Error::NoMatchingCredential) => return FarewellStatus::HwAuthFailed,
                Err(e) => return status_from_fido(&e),
            };

            // 2b. Swap to the new backup key (must NOT already open the vault).
            notify(FAREWELL_PROGRESS_AWAIT_REMOVE, 2, 2);
            if !wait_for_no_device() {
                return FarewellStatus::HwNotPresent;
            }
            notify(FAREWELL_PROGRESS_AWAIT_INSERT, 2, 2);
            let creds_pairs: Vec<(Vec<u8>, [u8; HMAC_OUTPUT_LEN])> = existing_creds
                .iter()
                .map(|c| (c.clone(), [0u8; HMAC_OUTPUT_LEN]))
                .collect();
            // Probe the freshly-inserted key with ITS own PIN — this is the new
            // backup key, so `new_pin`, not the current key's `pin`.
            backup = match wait_for_fresh_device(&creds_pairs, &fido_salt, new_pin, new_pin_len) {
                Ok(Some(d)) => d,
                Ok(None) => return FarewellStatus::HwNotPresent,
                Err(e) => return status_from_fido(&e),
            };
        }

        // 3. Enroll the backup key, then read its hmac for this vault. The
        //    backup key has its OWN PIN (`new_pin`), independent of the current
        //    key's `pin` used in step 2a — never assume they match (a wrong PIN
        //    would burn this key's CTAP2 retry counter). For the K==0 path there
        //    is no current key, so only `new_pin` is ever used.
        let mut backup_auth = HidAuthenticator::open_on(FIDO_RP_ID, &backup);
        apply_pin(&mut backup_auth, new_pin, new_pin_len);
        let user_handle = format!("farewell-backup-K{k}").into_bytes();
        notify(FAREWELL_PROGRESS_AWAIT_TOUCH, 1, 2);
        let new_cred = match backup_auth.enroll(&user_handle) {
            Ok(c) => c,
            Err(e) => return status_from_fido(&e),
        };
        notify(FAREWELL_PROGRESS_AWAIT_TOUCH, 2, 2);
        let (_, new_hmac) = match backup_auth.challenge_response(&[new_cred.clone()], &fido_salt) {
            Ok(x) => x,
            Err(e) => return status_from_fido(&e),
        };

        // Both touches are done. What follows — persisting the credential and
        // re-mounting — needs no key interaction, but for the FIRST key it runs
        // the heavy passphrase KDF (recover master → rebuild slot under the
        // lighter hardware KDF), a couple of seconds. Flip the UI off the touch
        // prompt to a "writing" phase so it doesn't look hung (mirrors the
        // convert/remove-last path). `total == 0` → the app shows an estimated
        // bar (there is no countable work to report).
        notify(FAREWELL_PROGRESS_WRITING, 0, 0);

        // 4. Persist the new credential. Use the caller's name if given, else a
        //    sensible default ("Key N").
        let new_label = match cstr_to_str(label_utf8) {
            Some(s) if !s.trim().is_empty() => s.to_string(),
            _ => format!("Key {}", k + 1),
        };
        let write_result = if k == 0 {
            // First key: convert passphrase-only -> hardware. This also lightens
            // the KDF (the key now carries the brute-force resistance), so the
            // slot is rebuilt rather than edited in place — the heavy KDF would
            // otherwise leave the vault slow to open forever.
            let mut enr = farewell_format::LevelEnrollment::passphrase_only();
            match enr.push_labeled(new_cred.clone(), new_hmac, new_label) {
                Ok(()) => {
                    Vault::reenroll_slot::<HidAuthenticator>(&path, pw.clone(), None, &enr)
                }
                Err(e) => Err(e),
            }
        } else {
            // Backup key: add in place, keeping the existing (light) KDF.
            Vault::add_hw_credential(
                &path,
                pw.clone(),
                recover_hmac.as_ref(),
                &new_cred,
                &new_hmac,
                &new_label,
            )
        };
        if let Err(e) = write_result {
            return FarewellStatus::from_format_error(&e);
        }

        // 5. Re-mount the (unchanged) vault WITHOUT another touch: replay the
        //    (cred, hmac) we already captured. For K≥1 that's the current key;
        //    for K==0 it's the just-enrolled key. This is what skips the
        //    otherwise-confusing "touch again to re-open" step.
        let (replay_cred, replay_hmac) = match (remount_cred, recover_hmac) {
            (Some(c), Some(h)) => (c, h),                 // K≥1
            _ => (new_cred.clone(), new_hmac),            // K==0
        };
        let mut replay = ReplayAuthenticator::new(FIDO_RP_ID, replay_cred, replay_hmac);
        match Vault::open(&path, pw, Some(&mut replay)) {
            Ok(v) => {
                let boxed = Box::new(FarewellVault { inner: v });
                // SAFETY: out_handle non-null and writable per contract.
                unsafe {
                    *out_handle = Box::into_raw(boxed);
                }
                FarewellStatus::Ok
            }
            // The slot write succeeded; only the convenience re-open failed.
            // Report the failure but the enrollment IS persisted — the caller
            // can re-open normally (one touch).
            Err(e) => {
                FarewellStatus::from_format_error(&e)
            }
        }
    })
}

/// Callback invoked once per enrolled hardware key by [`farewell_key_list`].
/// `label_utf8` is valid only during the callback — copy it out to keep it.
pub type FarewellKeyCb =
    extern "C" fn(index: u32, label_utf8: *const c_char, user_data: *mut std::ffi::c_void);

/// List the hardware keys enrolled in a vault — index and human-readable name
/// — verifying the passphrase WITHOUT unlocking the content and WITHOUT a
/// hardware touch. Invokes `cb` once per key in slot order (index `0..K`).
/// Backs the keys-management panel. A passphrase-only vault (K==0) yields no
/// callbacks and still returns OK.
///
/// # Safety
/// `path_utf8` NUL-terminated; `passphrase` valid for `passphrase_len`; `cb` a
/// valid function pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_key_list(
    path_utf8: *const c_char,
    passphrase: *const u8,
    passphrase_len: u64,
    cb: FarewellKeyCb,
    user_data: *mut std::ffi::c_void,
) -> i32 {
    catch_panic(|| {
        if path_utf8.is_null() || passphrase.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let path = match cstr_to_path(path_utf8) {
            Some(p) => p,
            None => return FarewellStatus::InvalidArgument,
        };
        let pw = match collect_passphrase(passphrase, passphrase_len) {
            Some(v) => v,
            None => return FarewellStatus::InvalidArgument,
        };
        let (_fido_salt, _creds, labels, _k) = match Vault::slot_enrollment_info(&path, pw) {
            Ok(x) => x,
            Err(e) => return FarewellStatus::from_format_error(&e),
        };
        for (i, label) in labels.iter().enumerate() {
            // decode_label trims at the first NUL, so labels never contain an
            // interior NUL; the fallback to empty is belt-and-suspenders.
            let clabel = std::ffi::CString::new(label.as_bytes()).unwrap_or_default();
            cb(i as u32, clabel.as_ptr(), user_data);
        }
        FarewellStatus::Ok
    })
}

/// Revoke the hardware key at `index` from a vault, with the passphrase ALONE
/// — no key need be present (this is the path for a lost or stolen key). The
/// remaining keys still open the vault. The vault is locked exclusively for the
/// write, so it must not be open elsewhere.
///
/// Requires the vault to keep at least one key afterwards (i.e. `K >= 2` before
/// removal). Removing the LAST key — which would turn the vault back into a
/// passphrase-only one — is refused here (non-OK status); that conversion needs
/// the key present (to re-wrap the master and re-harden the KDF).
///
/// # Safety
/// `path_utf8` NUL-terminated; `passphrase` valid for `passphrase_len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_remove_hw_key(
    path_utf8: *const c_char,
    passphrase: *const u8,
    passphrase_len: u64,
    index: u32,
) -> i32 {
    catch_panic(|| {
        if path_utf8.is_null() || passphrase.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let path = match cstr_to_path(path_utf8) {
            Some(p) => p,
            None => return FarewellStatus::InvalidArgument,
        };
        let pw = match collect_passphrase(passphrase, passphrase_len) {
            Some(v) => v,
            None => return FarewellStatus::InvalidArgument,
        };
        match Vault::remove_hw_credential(&path, pw, index as usize) {
            Ok(()) => FarewellStatus::Ok,
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

/// Convert a hardware-protected vault back to PASSPHRASE-ONLY: remove its last
/// remaining key and re-harden the KDF so the passphrase alone is sufficient
/// again. The key being removed must be PRESENT (one touch) so its wrapped
/// master can be recovered and re-wrapped under the passphrase-only key. After
/// this the passphrase by itself opens the vault (and opening is slower again,
/// since the heavy KDF is restored).
///
/// `progress` emits `AWAIT_INSERT` then `AWAIT_TOUCH` while waiting for the key.
/// On success `out_handle` receives an ALREADY-OPEN vault (re-opened with the
/// passphrase alone — no second touch). On a non-OK status `out_handle` is
/// NULL; if only the convenience re-open failed, the conversion is still
/// persisted and the vault opens normally with the passphrase.
///
/// # Safety
/// `path_utf8` NUL-terminated; `passphrase`/`pin` valid for their lengths;
/// `out_handle` a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_convert_to_passphrase_only(
    path_utf8: *const c_char,
    passphrase: *const u8,
    passphrase_len: u64,
    pin: *const u8,
    pin_len: u64,
    progress: Option<FarewellProgressCb>,
    progress_user_data: *mut std::ffi::c_void,
    out_handle: *mut *mut FarewellVault,
) -> i32 {
    catch_panic(|| {
        let notify = |phase: u32, done: u64, total: u64| {
            if let Some(cb) = progress {
                cb(phase, done, total, progress_user_data);
            }
        };
        if path_utf8.is_null() || passphrase.is_null() || out_handle.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: out_handle non-null per the check + caller contract.
        unsafe {
            *out_handle = std::ptr::null_mut();
        }
        let path = match cstr_to_path(path_utf8) {
            Some(p) => p,
            None => return FarewellStatus::InvalidArgument,
        };
        let pw = match collect_passphrase(passphrase, passphrase_len) {
            Some(v) => v,
            None => return FarewellStatus::InvalidArgument,
        };

        // 1. Confirm the passphrase and that there is in fact a key to remove.
        let (fido_salt, existing_creds, _labels, k) = match Vault::slot_enrollment_info(&path, pw.clone()) {
            Ok(x) => x,
            Err(e) => return FarewellStatus::from_format_error(&e),
        };
        if k == 0 {
            // Already passphrase-only — nothing to convert.
            return FarewellStatus::InvalidArgument;
        }

        // 2. Insert the (last) key; reenroll_slot challenges it (one touch) to
        //    recover the master, then re-wraps it under the passphrase alone.
        notify(FAREWELL_PROGRESS_AWAIT_INSERT, 1, 1);
        let device = match wait_for_single_device() {
            Some(d) => d,
            None => return FarewellStatus::HwNotPresent,
        };
        let mut auth = HidAuthenticator::open_on(FIDO_RP_ID, &device);
        apply_pin(&mut auth, pin, pin_len);
        notify(FAREWELL_PROGRESS_AWAIT_TOUCH, 1, 1);
        // Challenge the present key OURSELVES (this is the touch). The instant
        // it's done we flip the UI to the "writing" phase, because what follows
        // — re-deriving the (heavy) passphrase-only KDF and re-opening — takes a
        // couple of seconds with no further key interaction; leaving the touch
        // prompt up there made it look hung. We then replay the captured
        // response into reenroll_slot so the user isn't asked to touch twice.
        let (used_cred, hmac) = match auth.challenge_response(&existing_creds, &fido_salt) {
            Ok(x) => x,
            Err(Fido2Error::NoMatchingCredential) => return FarewellStatus::HwAuthFailed,
            Err(e) => return status_from_fido(&e),
        };
        notify(FAREWELL_PROGRESS_WRITING, 0, 0);
        let empty = farewell_format::LevelEnrollment::passphrase_only();
        let mut replay = ReplayAuthenticator::new(FIDO_RP_ID, used_cred, hmac);
        if let Err(e) = Vault::reenroll_slot(&path, pw.clone(), Some(&mut replay), &empty) {
            return FarewellStatus::from_format_error(&e);
        }

        // 3. Re-open with the passphrase alone (now sufficient; no touch).
        match Vault::open::<HidAuthenticator>(&path, pw, None) {
            Ok(v) => {
                let boxed = Box::new(FarewellVault { inner: v });
                // SAFETY: out_handle non-null and writable per contract.
                unsafe {
                    *out_handle = Box::into_raw(boxed);
                }
                FarewellStatus::Ok
            }
            // The conversion succeeded; only the convenience re-open failed.
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

/// An [`Authenticator`] that replays a single, already-obtained
/// `(credential, hmac)` pair without touching any hardware.
///
/// Used to RE-mount a vault immediately after enrolling a backup key,
/// reusing the key response captured moments earlier — so the user is not
/// asked to touch the key a second time just to re-open (a 5C Nano gives no
/// visible cue, so that surprise touch looked like a minute-long hang).
/// Never enrolls.
struct ReplayAuthenticator {
    rp_id: String,
    cred: Vec<u8>,
    hmac: [u8; HMAC_OUTPUT_LEN],
}

impl ReplayAuthenticator {
    fn new(rp_id: impl Into<String>, cred: Vec<u8>, hmac: [u8; HMAC_OUTPUT_LEN]) -> Self {
        Self {
            rp_id: rp_id.into(),
            cred,
            hmac,
        }
    }
}

impl Authenticator for ReplayAuthenticator {
    fn rp_id(&self) -> &str {
        &self.rp_id
    }

    fn enroll(&mut self, _user_handle: &[u8]) -> Result<Vec<u8>, Fido2Error> {
        Err(Fido2Error::Transport(
            "replay authenticator cannot enroll".into(),
        ))
    }

    fn challenge_response(
        &mut self,
        candidates: &[Vec<u8>],
        _salt: &[u8; HMAC_SALT_LEN],
    ) -> Result<(Vec<u8>, [u8; HMAC_OUTPUT_LEN]), Fido2Error> {
        // The captured hmac was computed for this vault's fido_salt already,
        // so the salt argument is irrelevant; we only confirm our credential
        // is among the ones the slot is asking about.
        if candidates.iter().any(|c| c == &self.cred) {
            Ok((self.cred.clone(), self.hmac))
        } else {
            Err(Fido2Error::NoMatchingCredential)
        }
    }
}

/// Map a FIDO error to a status: a transport failure means the key
/// vanished; anything else is an auth failure (wrong PIN, no touch, …).
fn status_from_fido(e: &Fido2Error) -> FarewellStatus {
    match e {
        Fido2Error::Transport(_) => FarewellStatus::HwNotPresent,
        _ => FarewellStatus::HwAuthFailed,
    }
}

/// Emit a one-line timing diagnostic to stderr, but only when the
/// `FAREWELL_TIMING` environment variable is set. Lets us pinpoint where a
/// slow open spends its time (USB enumeration vs. the KDF/touch) without any
/// cost or noise in a normal run. The closure is only evaluated when enabled.
fn timing(msg: impl FnOnce() -> String) {
    if std::env::var_os("FAREWELL_TIMING").is_some() {
        eprintln!("[farewell-timing] {}", msg());
    }
}

/// Apply an optional CTAP2 PIN (UTF-8 bytes) to an authenticator.
fn apply_pin(auth: &mut HidAuthenticator, pin: *const u8, pin_len: u64) {
    if pin_len == 0 {
        return;
    }
    if let Some(bytes) = collect_passphrase(pin, pin_len) {
        if let Ok(s) = String::from_utf8(bytes) {
            auth.set_pin(s);
        }
    }
}

// ---- One-port-swap device waits --------------------------------------------
//
// These run on the dedicated HID worker thread (never the UI thread), so the
// blocking poll-sleep is fine. They power the single-key-at-a-time enrollment:
// only one key is connected at a time, so a touch is unambiguously the right
// key — no reliance on a visible blink.

/// How long to wait for the user to insert/remove a key before giving up.
const DEVICE_WAIT_TIMEOUT: Duration = Duration::from_secs(120);
/// How often to re-enumerate USB while waiting.
const DEVICE_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Block until **exactly one** FIDO device is connected, and return it. Returns
/// `None` on timeout. Requiring exactly one keeps the touch unambiguous; if the
/// user has several plugged, we keep waiting (the UI tells them to connect one).
fn wait_for_single_device() -> Option<HidDevice> {
    let deadline = Instant::now() + DEVICE_WAIT_TIMEOUT;
    loop {
        let mut devs = HidAuthenticator::list_devices();
        if devs.len() == 1 {
            return devs.pop();
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(DEVICE_POLL_INTERVAL);
    }
}

/// Block until **no** FIDO device is connected (the user unplugged the previous
/// key). Returns `false` on timeout.
fn wait_for_no_device() -> bool {
    let deadline = Instant::now() + DEVICE_WAIT_TIMEOUT;
    loop {
        if HidAuthenticator::list_devices().is_empty() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(DEVICE_POLL_INTERVAL);
    }
}

/// Block until a single connected key is present that does **not** already own
/// any of `known_creds` — i.e. a genuinely fresh key, not one we just enrolled.
///
/// A fresh key answers the credential probe with `NoMatchingCredential` and,
/// crucially, **without a touch** (CTAP2 allow-list miss). If the user
/// re-inserts an already-enrolled key it owns a candidate, requires a touch,
/// and we loop (waiting for them to swap). Returns `Ok(None)` on timeout, or a
/// non-`NoMatchingCredential` transport/PIN error verbatim.
fn wait_for_fresh_device(
    known_creds: &[(Vec<u8>, [u8; HMAC_OUTPUT_LEN])],
    fido_salt: &[u8; farewell_fido2::HMAC_SALT_LEN],
    pin: *const u8,
    pin_len: u64,
) -> Result<Option<HidDevice>, Fido2Error> {
    let candidates: Vec<Vec<u8>> = known_creds.iter().map(|(c, _)| c.clone()).collect();
    let deadline = Instant::now() + DEVICE_WAIT_TIMEOUT;
    loop {
        if let Some(dev) = wait_for_single_device() {
            if candidates.is_empty() {
                return Ok(Some(dev)); // nothing to exclude yet
            }
            let mut probe = HidAuthenticator::open_on(FIDO_RP_ID, &dev);
            apply_pin(&mut probe, pin, pin_len);
            match probe.challenge_response(&candidates, fido_salt) {
                Err(Fido2Error::NoMatchingCredential) => return Ok(Some(dev)),
                Ok(_) => {
                    // Same key as before — wait for it to be removed, then retry.
                    if !wait_for_no_device() {
                        return Ok(None);
                    }
                }
                Err(e) => return Err(e),
            }
        } else {
            return Ok(None); // timed out waiting for a single device
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
    }
}

// =============================================================================
// Lifecycle
// =============================================================================

/// Open a vault file with a passphrase.
///
/// Parameters:
/// - `path_utf8`: NUL-terminated UTF-8 path to the `.vault` file.
/// - `passphrase`: pointer to `passphrase_len` raw bytes (NOT
///   NUL-terminated; passphrases may contain any byte).
/// - `passphrase_len`: number of valid bytes at `passphrase`.
/// - `out_handle`: on success, set to a non-null
///   [`FarewellVault`] pointer; on failure, set to NULL.
///
/// Returns [`FarewellStatus`] as `int32_t`.
///
/// Hardware-key vaults are NOT supported by this entry yet (K=0 only).
/// HW-key support requires passing an authenticator object through
/// the FFI, which is a separate design decision deferred to a later
/// version.
///
/// # Safety
///
/// `path_utf8` must point to a valid NUL-terminated C string.
/// `passphrase` must point to `passphrase_len` initialized bytes.
/// `out_handle` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_open(
    path_utf8: *const c_char,
    passphrase: *const u8,
    passphrase_len: u64,
    out_handle: *mut *mut FarewellVault,
) -> i32 {
    catch_panic(|| {
        if path_utf8.is_null() || out_handle.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: out_handle non-null and writable per contract.
        unsafe {
            *out_handle = std::ptr::null_mut();
        }

        let path = match cstr_to_path(path_utf8) {
            Some(p) => p,
            None => return FarewellStatus::InvalidArgument,
        };

        let passphrase_vec = match collect_passphrase(passphrase, passphrase_len) {
            Some(v) => v,
            None => return FarewellStatus::InvalidArgument,
        };

        match Vault::open(&path, passphrase_vec, None::<&mut MockAuthenticator>) {
            Ok(v) => {
                let boxed = Box::new(FarewellVault { inner: v });
                // SAFETY: out_handle non-null and writable per contract.
                unsafe {
                    *out_handle = Box::into_raw(boxed);
                }
                FarewellStatus::Ok
            }
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

/// Open a vault, threading a connected FIDO2 hardware key when present.
///
/// This is a superset of [`farewell_open`]: it is always safe to call.
/// - If no key is plugged in, behaves exactly like [`farewell_open`]
///   (fine for passphrase-only vaults).
/// - If a key is present, it is opened (with the optional `pin`) and
///   passed to the core. A passphrase-only (K=0) level never touches it —
///   no blink, no PIN needed. A hardware level (K≥1) triggers a TOUCH, so
///   this call may BLOCK and must be made off the UI thread.
///
/// Because nothing in the call signals whether the vault needs a key, the
/// UI can keep a single passphrase field and stay deniable.
///
/// A wrong PIN / un-touched key surfaces as [`FarewellStatus::Crypto`]
/// (indistinguishable, by design, from a wrong passphrase).
///
/// # Safety
/// Same as [`farewell_open`]; additionally `pin` must point to `pin_len`
/// bytes (may be NULL iff `pin_len == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_open_hw(
    path_utf8: *const c_char,
    passphrase: *const u8,
    passphrase_len: u64,
    pin: *const u8,
    pin_len: u64,
    progress: Option<FarewellProgressCb>,
    progress_user_data: *mut std::ffi::c_void,
    out_handle: *mut *mut FarewellVault,
) -> i32 {
    catch_panic(|| {
        let notify = |phase: u32, done: u64, total: u64| {
            if let Some(cb) = progress {
                cb(phase, done, total, progress_user_data);
            }
        };
        if path_utf8.is_null() || out_handle.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: out_handle non-null and writable per contract.
        unsafe {
            *out_handle = std::ptr::null_mut();
        }

        let path = match cstr_to_path(path_utf8) {
            Some(p) => p,
            None => return FarewellStatus::InvalidArgument,
        };
        let passphrase_vec = match collect_passphrase(passphrase, passphrase_len) {
            Some(v) => v,
            None => return FarewellStatus::InvalidArgument,
        };

        // Open in two stages: first try passphrase-only (no USB at all),
        // and only enumerate + challenge hardware keys if the vault turns
        // out to require one. See the fast-path comment below.
        let finish = |v: Vault| {
            let boxed = Box::new(FarewellVault { inner: v });
            // SAFETY: out_handle non-null and writable per contract.
            unsafe {
                *out_handle = Box::into_raw(boxed);
            }
            FarewellStatus::Ok
        };

        // Fast path: try to open WITHOUT enumerating USB at all. A
        // passphrase-only (K=0) vault opens here directly; a hardware-
        // protected vault fails fast with `HardwareKeyRequired` (the
        // matching KDF decrypts the slot's outer, sees K>=1, and — with no
        // authenticator — stops before the slow hardened-KDF candidate).
        // Any other error (wrong passphrase, tamper, …) is final.
        //
        // Skipping `list_devices` on the no-touch path both speeds up the
        // common open and avoids hidapi's non-thread-safe global init,
        // whose concurrent enumeration traps under parallel tests.
        let t0 = Instant::now();
        let r0 = Vault::open(&path, passphrase_vec.clone(), None::<&mut HidAuthenticator>);
        let needs_hw = matches!(r0, Err(FormatError::HardwareKeyRequired));
        timing(|| {
            format!(
                "Vault::open (no enum): {:?} -> {}",
                t0.elapsed(),
                match &r0 {
                    Ok(_) => "OPENED",
                    Err(_) if needs_hw => "needs-hw",
                    Err(_) => "no",
                }
            )
        });
        match r0 {
            Ok(v) => return finish(v),
            // Passphrase right but a hardware key is required: enumerate and
            // try each connected key below.
            Err(_) if needs_hw => {}
            Err(e) => return FarewellStatus::from_format_error(&e),
        }

        // Enumerate connected keys. We can't use `open_first` because
        // `create()` ERRORS when 2+ keys are plugged ("Multiple FIDO
        // devices found") — and a backup-key user may well have BOTH their
        // primary and backup plugged at unlock time. So try each device in
        // turn: a non-enrolled key returns NoMatchingCredential (no touch on
        // YubiKeys) and we move on; the enrolled key opens with one touch.
        let t_enum = Instant::now();
        let devices = HidAuthenticator::list_devices();
        timing(|| {
            format!(
                "list_devices: {:?} ({} found: {})",
                t_enum.elapsed(),
                devices.len(),
                devices
                    .iter()
                    .map(|d| d.label.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        });
        if devices.is_empty() {
            // Hardware key required but none plugged in.
            return FarewellStatus::HwNotPresent;
        }
        // Safety: a PIN belongs to exactly ONE key. If several keys are plugged
        // in, trying this PIN against the non-matching ones would decrement —
        // and could exhaust — their CTAP2 retry counters (8 wrong PINs locks a
        // key, forcing a reset that erases its credentials). So when a PIN is
        // supplied we refuse to spray it across keys and ask the user to leave
        // only the key they're unlocking with. With no PIN there is no counter
        // to burn, so trying each key (touch on the matching one) stays safe.
        if pin_len > 0 && devices.len() > 1 {
            return FarewellStatus::HwMultipleKeys;
        }

        // A real touch is now imminent (we've passed every fast refusal — wrong
        // passphrase, no key, multiple keys). Tell the UI only here, so the
        // "touch your key" prompt never flashes for a refusal that needed no
        // touch. A non-matching key returns NoMatchingCredential with no touch,
        // so at worst the prompt is shown a beat early; the enrolled key touches.
        notify(FAREWELL_PROGRESS_AWAIT_TOUCH, 1, 1);

        let mut last_err = None;
        for dev in &devices {
            let mut auth = HidAuthenticator::open_on(FIDO_RP_ID, dev);
            apply_pin(&mut auth, pin, pin_len);
            let t = Instant::now();
            let r = Vault::open(&path, passphrase_vec.clone(), Some(&mut auth));
            timing(|| {
                format!(
                    "Vault::open on '{}': {:?} -> {}",
                    dev.label,
                    t.elapsed(),
                    if r.is_ok() { "OPENED" } else { "no" }
                )
            });
            match r {
                Ok(v) => return finish(v),
                Err(e) => last_err = Some(e),
            }
        }
        match last_err {
            Some(e) => FarewellStatus::from_format_error(&e),
            None => FarewellStatus::HwAuthFailed,
        }
    })
}

/// Close a vault handle previously returned by [`farewell_open`].
///
/// Drops the inner [`Vault`], which closes the underlying file and
/// releases the advisory flock. Passing a NULL pointer is a no-op
/// (mirrors `free(NULL)` semantics).
///
/// After this call, `handle` must not be used again.
///
/// # Safety
///
/// `handle` must either be NULL or a pointer previously returned by
/// [`farewell_open`] that has not yet been closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_close(handle: *mut FarewellVault) {
    if handle.is_null() {
        return;
    }
    // Panic in Drop would still be bad, but `Vault::drop` does no
    // user code beyond closing a File, which doesn't panic.
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: handle is non-null and came from a Box::into_raw
        // in farewell_open, per the contract.
        let boxed = unsafe { Box::from_raw(handle) };
        drop(boxed);
    }));
}

// =============================================================================
// Read-only operations
// =============================================================================

/// File metadata returned by [`farewell_stat`].
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FarewellStat {
    /// Plaintext size in bytes.
    pub size: u64,
}

/// Look up a file's metadata.
///
/// Parameters:
/// - `handle`: open vault.
/// - `name_utf8`: NUL-terminated UTF-8 file name.
/// - `out_stat`: written on success.
///
/// # Safety
///
/// `handle` must be a valid open vault pointer. `name_utf8` must be a
/// valid NUL-terminated C string. `out_stat` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_stat(
    handle: *const FarewellVault,
    name_utf8: *const c_char,
    out_stat: *mut FarewellStat,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || name_utf8.is_null() || out_stat.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: handle non-null per contract.
        let vault = unsafe { &(*handle).inner };
        let name = match cstr_to_str(name_utf8) {
            Some(s) => s,
            None => return FarewellStatus::InvalidArgument,
        };

        match vault.stat_file(name) {
            Ok(st) => {
                // SAFETY: out_stat non-null and writable per contract.
                unsafe {
                    (*out_stat).size = st.size;
                }
                FarewellStatus::Ok
            }
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

/// Read a range of bytes from a file into a caller-provided buffer.
///
/// Parameters:
/// - `handle`: open vault.
/// - `name_utf8`: NUL-terminated UTF-8 file name.
/// - `offset`: byte offset within the file.
/// - `want_len`: maximum number of bytes to read.
/// - `out_buf`: writable buffer of at least `want_len` bytes.
/// - `out_actual_len`: written with the number of bytes actually
///   read (≤ `want_len`; smaller only when clamped by EOF).
///
/// POSIX `pread`-like semantics:
/// - `offset >= size` → returns Ok with `*out_actual_len = 0`.
/// - `want_len == 0` → returns Ok with `*out_actual_len = 0` and
///   touches no buffer.
///
/// # Safety
///
/// `handle` must be a valid open vault. `out_buf` must point to at
/// least `want_len` writable bytes; `out_actual_len` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_read_range(
    handle: *mut FarewellVault,
    name_utf8: *const c_char,
    offset: u64,
    want_len: u64,
    out_buf: *mut u8,
    out_actual_len: *mut u64,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || name_utf8.is_null() || out_actual_len.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        if want_len > 0 && out_buf.is_null() {
            return FarewellStatus::InvalidArgument;
        }

        let name = match cstr_to_str(name_utf8) {
            Some(s) => s,
            None => return FarewellStatus::InvalidArgument,
        };

        // SAFETY: handle non-null per contract.
        let vault = unsafe { &mut (*handle).inner };

        match vault.read_file_range(name, offset, want_len) {
            Ok(bytes) => {
                let actual = bytes.len();
                // Defensive: should never happen, but if read_file_range
                // returned more than want_len we'd overflow the buffer.
                if actual as u64 > want_len {
                    return FarewellStatus::Internal;
                }
                if actual > 0 {
                    // SAFETY: out_buf has at least want_len ≥ actual
                    // writable bytes per caller contract; bytes.as_ptr()
                    // is valid for actual.
                    unsafe {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, actual);
                    }
                }
                // SAFETY: out_actual_len non-null and writable per contract.
                unsafe {
                    *out_actual_len = actual as u64;
                }
                FarewellStatus::Ok
            }
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

// =============================================================================
// Mutation operations (v0.18 Phase B)
// =============================================================================

/// POSIX `O_CREAT` (without `O_EXCL`): create the file if it doesn't
/// exist, leave existing content alone if it does. Empty initial
/// content (size = 0, no chunks allocated).
///
/// # Safety
///
/// `handle` must be a valid open vault; `name_utf8` a valid NUL-
/// terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_create(
    handle: *mut FarewellVault,
    name_utf8: *const c_char,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || name_utf8.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let name = match cstr_to_str(name_utf8) {
            Some(s) => s,
            None => return FarewellStatus::InvalidArgument,
        };
        // SAFETY: handle non-null per contract.
        let vault = unsafe { &mut (*handle).inner };
        match vault.create_file(name) {
            Ok(()) => FarewellStatus::Ok,
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

/// POSIX `pwrite` + automatic extension. Writes `data_len` bytes
/// starting at `offset`. Grows the file when needed; the gap between
/// the previous EOF and `offset` is zero-filled in plaintext.
///
/// Returns [`FarewellStatus::NotFound`] if the file does not exist
/// (call [`farewell_create`] first).
///
/// `data_len == 0` is a no-op (success, no I/O).
///
/// # Safety
///
/// `handle` must be a valid open vault. `data` must point to at least
/// `data_len` readable bytes. `name_utf8` must be a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_write_range(
    handle: *mut FarewellVault,
    name_utf8: *const c_char,
    offset: u64,
    data: *const u8,
    data_len: u64,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || name_utf8.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        if data_len > 0 && data.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let len = match usize::try_from(data_len) {
            Ok(n) => n,
            Err(_) => return FarewellStatus::InvalidArgument,
        };
        let name = match cstr_to_str(name_utf8) {
            Some(s) => s,
            None => return FarewellStatus::InvalidArgument,
        };
        // SAFETY: handle non-null per contract; data + data_len valid
        // per contract when data_len > 0.
        let slice = if len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(data, len) }
        };
        let vault = unsafe { &mut (*handle).inner };
        match vault.write_file_range(name, offset, slice) {
            Ok(()) => FarewellStatus::Ok,
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

/// POSIX `ftruncate`. Shrink frees trailing chunks (cryptographic
/// shred); grow zero-fills via the same path as
/// [`farewell_write_range`].
///
/// # Safety
///
/// `handle` must be a valid open vault; `name_utf8` a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_truncate(
    handle: *mut FarewellVault,
    name_utf8: *const c_char,
    new_size: u64,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || name_utf8.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let name = match cstr_to_str(name_utf8) {
            Some(s) => s,
            None => return FarewellStatus::InvalidArgument,
        };
        let vault = unsafe { &mut (*handle).inner };
        match vault.truncate_file(name, new_size) {
            Ok(()) => FarewellStatus::Ok,
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

/// POSIX `rename`. Atomically replace destination if it exists
/// (destination's chunks are cryptographically shredded). Same-name
/// rename is a no-op.
///
/// # Safety
///
/// `handle` must be a valid open vault. Both name arguments must be
/// valid NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_rename(
    handle: *mut FarewellVault,
    old_name_utf8: *const c_char,
    new_name_utf8: *const c_char,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || old_name_utf8.is_null() || new_name_utf8.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let old = match cstr_to_str(old_name_utf8) {
            Some(s) => s,
            None => return FarewellStatus::InvalidArgument,
        };
        let new = match cstr_to_str(new_name_utf8) {
            Some(s) => s,
            None => return FarewellStatus::InvalidArgument,
        };
        let vault = unsafe { &mut (*handle).inner };
        match vault.rename_file(old, new) {
            Ok(()) => FarewellStatus::Ok,
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

/// POSIX `unlink`. Secure-deletes the file's chunks (random-fill on
/// disk) and removes its manifest entry. Returns [`FarewellStatus::NotFound`]
/// if the file does not exist.
///
/// # Safety
///
/// `handle` must be a valid open vault; `name_utf8` a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_delete(
    handle: *mut FarewellVault,
    name_utf8: *const c_char,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || name_utf8.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let name = match cstr_to_str(name_utf8) {
            Some(s) => s,
            None => return FarewellStatus::InvalidArgument,
        };
        let vault = unsafe { &mut (*handle).inner };
        match vault.delete_file(name) {
            Ok(()) => FarewellStatus::Ok,
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

// =============================================================================
// Folders (organizational; names are slash-separated paths)
// =============================================================================

/// Create an (initially empty) folder. Idempotent. Path is normalized
/// (no leading/trailing/duplicate slashes).
///
/// # Safety
/// `handle` valid open vault; `path_utf8` a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_create_folder(
    handle: *mut FarewellVault,
    path_utf8: *const c_char,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || path_utf8.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let path = match cstr_to_str(path_utf8) {
            Some(s) => s,
            None => return FarewellStatus::InvalidArgument,
        };
        let vault = unsafe { &mut (*handle).inner };
        match vault.create_folder(path) {
            Ok(()) => FarewellStatus::Ok,
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

/// Delete a folder and everything under it (files securely shredded).
///
/// # Safety
/// `handle` valid open vault; `path_utf8` a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_delete_folder(
    handle: *mut FarewellVault,
    path_utf8: *const c_char,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || path_utf8.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let path = match cstr_to_str(path_utf8) {
            Some(s) => s,
            None => return FarewellStatus::InvalidArgument,
        };
        let vault = unsafe { &mut (*handle).inner };
        match vault.delete_folder(path) {
            Ok(()) => FarewellStatus::Ok,
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

/// Rename a folder (re-prefix all files under it; metadata only).
///
/// # Safety
/// `handle` valid open vault; both paths valid NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_rename_folder(
    handle: *mut FarewellVault,
    old_path_utf8: *const c_char,
    new_path_utf8: *const c_char,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || old_path_utf8.is_null() || new_path_utf8.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let old = match cstr_to_str(old_path_utf8) {
            Some(s) => s,
            None => return FarewellStatus::InvalidArgument,
        };
        let new = match cstr_to_str(new_path_utf8) {
            Some(s) => s,
            None => return FarewellStatus::InvalidArgument,
        };
        let vault = unsafe { &mut (*handle).inner };
        match vault.rename_folder(old, new) {
            Ok(()) => FarewellStatus::Ok,
            Err(e) => FarewellStatus::from_format_error(&e),
        }
    })
}

/// Callback invoked once per folder by [`farewell_folders`].
pub type FarewellFolderCb =
    extern "C" fn(path_utf8: *const c_char, user_data: *mut std::ffi::c_void);

/// Enumerate all folders in the mounted level (explicit + implied by
/// file prefixes), sorted. The path pointer is valid only during the
/// callback.
///
/// # Safety
/// `handle` valid open vault; `cb` a valid function pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_folders(
    handle: *const FarewellVault,
    cb: FarewellFolderCb,
    user_data: *mut std::ffi::c_void,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let vault = unsafe { &(*handle).inner };
        for path in vault.folders() {
            let cpath = match std::ffi::CString::new(path.as_bytes()) {
                Ok(c) => c,
                Err(_) => return FarewellStatus::InvalidName,
            };
            cb(cpath.as_ptr(), user_data);
        }
        FarewellStatus::Ok
    })
}

// =============================================================================
// Enumeration + introspection (v0.18 Phase C)
// =============================================================================

/// One directory entry yielded by [`farewell_readdir`]. The string
/// pointer is valid only for the duration of the callback invocation
/// — copy out anything you need to keep.
#[repr(C)]
#[derive(Debug)]
pub struct FarewellDirent {
    /// NUL-terminated UTF-8 file name. Lifetime: callback invocation.
    pub name_utf8: *const c_char,
    /// Length of `name_utf8` in bytes, excluding the trailing NUL.
    pub name_len: u64,
    /// Plaintext size of the file in bytes.
    pub size: u64,
}

/// Callback invoked once per file by [`farewell_readdir`].
pub type FarewellReaddirCb = extern "C" fn(entry: *const FarewellDirent, user_data: *mut std::ffi::c_void);

/// Enumerate every file in the mounted level.
///
/// For each file, allocates a temporary NUL-terminated copy of the
/// name and invokes `cb(&entry, user_data)`. The dirent pointer and
/// the name pointer inside it are valid ONLY for the duration of the
/// callback call; copy them out if you need them later.
///
/// If a file name contains an interior NUL byte (pathological — should
/// never happen with manifests written by this crate, but theoretically
/// possible if a hostile crafted vault is opened), the readdir aborts
/// with [`FarewellStatus::InvalidName`].
///
/// # Safety
///
/// `handle` must be a valid open vault. `cb` must be a valid function
/// pointer; `user_data` is opaque to Rust (passed through verbatim).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_readdir(
    handle: *const FarewellVault,
    cb: FarewellReaddirCb,
    user_data: *mut std::ffi::c_void,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: handle non-null per contract.
        let vault = unsafe { &(*handle).inner };

        for stat in vault.readdir() {
            // CString::new fails iff the name contains an interior
            // NUL byte. The name came from a valid in-memory
            // manifest entry, so this is defensive.
            let cname = match std::ffi::CString::new(stat.name.as_bytes()) {
                Ok(c) => c,
                Err(_) => return FarewellStatus::InvalidName,
            };
            let entry = FarewellDirent {
                name_utf8: cname.as_ptr(),
                name_len: stat.name.len() as u64,
                size: stat.size,
            };
            // Callback may panic in the consumer's code; the outer
            // catch_panic catches it and returns INTERNAL.
            cb(&entry, user_data);
            // `cname` drops here. Per the contract documented above,
            // the pointer passed to `cb` is now invalid — which is
            // why the contract restricts its use to inside the
            // callback.
        }
        FarewellStatus::Ok
    })
}

/// Total chunks declared in the vault's public header.
///
/// Returns 0 if `handle` is NULL (we cannot fail more gracefully:
/// the function signature is u64, not i32 — caller must validate
/// the handle themselves before calling).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_total_chunks(handle: *const FarewellVault) -> u64 {
    if handle.is_null() {
        return 0;
    }
    // catch_unwind around the field access just in case.
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: handle non-null per the early return + caller contract.
        unsafe { (*handle).inner.total_chunks() }
    }))
    .unwrap_or(0)
}

/// Read the mounted level's monotonic manifest counter.
///
/// Use this together with [`farewell_open`] (and the consumer's own
/// out-of-band recording of expected counter) to detect rollback:
/// store the counter externally after every write; on next mount,
/// compare and refuse if it dropped. See THREAT_MODEL §5.6.
///
/// # Safety
///
/// `handle` must be a valid open vault; `out_counter` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_counter(
    handle: *const FarewellVault,
    out_counter: *mut u64,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || out_counter.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: handle non-null per contract.
        let vault = unsafe { &(*handle).inner };
        match vault.counter() {
            Some(c) => {
                // SAFETY: out_counter non-null and writable per contract.
                unsafe {
                    *out_counter = c;
                }
                FarewellStatus::Ok
            }
            // Shouldn't happen via a normally-opened vault, but guard
            // against future open paths that don't mount.
            None => FarewellStatus::Manifest,
        }
    })
}

/// Number of hardware keys that can be enrolled per vault (the slot cap).
/// Callers use this to stop offering "add backup key" once a vault is full.
pub const FAREWELL_MAX_HW_KEYS: u32 = farewell_format::MAX_HW_KEYS_PER_LEVEL as u32;

/// Read how many hardware keys are enrolled on the open vault (0 =
/// passphrase-only). Up to [`FAREWELL_MAX_HW_KEYS`] keys may be enrolled.
///
/// # Safety
/// `handle` must be a valid open vault; `out_count` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_hw_key_count(
    handle: *const FarewellVault,
    out_count: *mut u32,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || out_count.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: handle non-null per contract.
        let vault = unsafe { &(*handle).inner };
        match vault.hw_key_count() {
            Some(n) => {
                // SAFETY: out_count non-null and writable per contract.
                unsafe {
                    *out_count = n as u32;
                }
                FarewellStatus::Ok
            }
            None => FarewellStatus::Manifest, // not mounted
        }
    })
}

/// Read the opt-in creator identity recorded in the open vault (empty if none
/// was recorded). Writes up to `buf_len - 1` UTF-8 bytes into `buf`, always
/// NUL-terminated, and reports the FULL byte length (excluding NUL) in
/// `out_len` so a caller can detect truncation and re-query with a bigger
/// buffer. Pass `buf == NULL` to query the length only. Returns Ok even when
/// there is no owner (out_len = 0).
///
/// # Safety
/// `handle` a valid open vault; `buf` writable for `buf_len` bytes (or NULL);
/// `out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_owner(
    handle: *const FarewellVault,
    buf: *mut c_char,
    buf_len: u64,
    out_len: *mut u64,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || out_len.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: handle non-null per contract.
        let vault = unsafe { &(*handle).inner };
        let owner = vault.owner().unwrap_or("");
        let bytes = owner.as_bytes();
        // SAFETY: out_len non-null and writable per contract.
        unsafe {
            *out_len = bytes.len() as u64;
        }
        if !buf.is_null() && buf_len > 0 {
            let cap = (buf_len as usize).saturating_sub(1); // room for the NUL
            let n = bytes.len().min(cap);
            // SAFETY: buf writable for buf_len bytes; n < buf_len.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
                *buf.add(n) = 0;
            }
        }
        FarewellStatus::Ok
    })
}

/// Report the mounted level's usable capacity, in plaintext bytes.
/// `out_total` = total usable for file data (excludes the manifest
/// chunk); `out_free` = what remains. A file of `S` bytes fits iff
/// `S <= *out_free`.
///
/// Per-level (each level owns its own stripe = total/NUM_SLOTS).
///
/// # Safety
///
/// `handle` must be a valid open vault; `out_total` and `out_free`
/// must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_space(
    handle: *const FarewellVault,
    out_total: *mut u64,
    out_free: *mut u64,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || out_total.is_null() || out_free.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: handle non-null per contract.
        let vault = unsafe { &(*handle).inner };
        match vault.space() {
            Some((total, free)) => {
                // SAFETY: out pointers non-null and writable per contract.
                unsafe {
                    *out_total = total;
                    *out_free = free;
                }
                FarewellStatus::Ok
            }
            None => FarewellStatus::Manifest,
        }
    })
}

/// Copy the vault's 32-byte fingerprint (BLAKE3 of the ML-DSA-87
/// verifying key) into `out_buf`. Same value as printed by
/// `farewell info` on the CLI.
///
/// Caller MUST provide a buffer of at least 32 bytes.
///
/// # Safety
///
/// `handle` must be a valid open vault; `out_buf` must point to at
/// least 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_fingerprint(
    handle: *const FarewellVault,
    out_buf: *mut u8,
) -> i32 {
    catch_panic(|| {
        if handle.is_null() || out_buf.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: handle non-null per contract.
        let vault = unsafe { &(*handle).inner };
        let fp: [u8; 32] = vault.fingerprint();
        // SAFETY: out_buf has at least 32 writable bytes per contract;
        // fp.as_ptr() valid for 32 bytes by construction.
        unsafe {
            std::ptr::copy_nonoverlapping(fp.as_ptr(), out_buf, 32);
        }
        FarewellStatus::Ok
    })
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Convert a NUL-terminated C string pointer to a Rust `&str`. Returns
/// `None` if the pointer is null or the content is not valid UTF-8.
fn cstr_to_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    // SAFETY: p is non-null and the caller contracts that it points
    // to a NUL-terminated C string.
    let cstr = unsafe { CStr::from_ptr(p) };
    cstr.to_str().ok()
}

fn cstr_to_path(p: *const c_char) -> Option<std::path::PathBuf> {
    cstr_to_str(p).map(|s| Path::new(s).to_path_buf())
}

fn collect_passphrase(p: *const u8, len: u64) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    if p.is_null() {
        return None;
    }
    let len_usize = match usize::try_from(len) {
        Ok(n) => n,
        Err(_) => return None,
    };
    // SAFETY: caller contracts that p points to `len` valid bytes.
    let slice = unsafe { std::slice::from_raw_parts(p, len_usize) };
    Some(slice.to_vec())
}

// =============================================================================
// Audio decoding (in-app viewer)
// =============================================================================
//
// The caller (the app) reads a file's decrypted bytes into memory via
// `farewell_read_range`, then hands them here. We decode to PCM **in
// process, in RAM** (farewell_audio / Symphonia) and stream interleaved
// f32 frames to AVAudioEngine. No bytes ever hit disk.

/// Opaque streaming PCM decoder. Create with [`farewell_audio_open`],
/// free with [`farewell_audio_close`].
pub struct FarewellAudioDecoder {
    inner: farewell_audio::AudioDecoder,
}

/// Stream properties filled by [`farewell_audio_open`].
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FarewellAudioInfo {
    /// Output sample rate (Hz).
    pub sample_rate: u32,
    /// Channel count (interleaved in the `read` output).
    pub channels: u16,
    /// Reserved for alignment / future use.
    pub _reserved: u16,
    /// Total frames if known, else 0.
    pub total_frames: u64,
}

/// Open an in-memory audio file for streaming PCM decode.
///
/// Copies `len` bytes (the decoder owns them for its lifetime), probes the
/// format, and writes stream properties to `out_info`. Returns a decoder
/// handle, or NULL if the bytes aren't a supported/parseable audio file.
///
/// # Safety
/// `bytes` must point to `len` initialized bytes; `out_info` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_audio_open(
    bytes: *const u8,
    len: u64,
    out_info: *mut FarewellAudioInfo,
) -> *mut FarewellAudioDecoder {
    catch_panic_ptr(|| {
        if bytes.is_null() || out_info.is_null() {
            return std::ptr::null_mut();
        }
        let n = match usize::try_from(len) {
            Ok(n) => n,
            Err(_) => return std::ptr::null_mut(),
        };
        // SAFETY: caller contract.
        let owned = unsafe { std::slice::from_raw_parts(bytes, n) }.to_vec();
        match farewell_audio::AudioDecoder::open(owned) {
            Ok(d) => {
                let info = FarewellAudioInfo {
                    sample_rate: d.sample_rate,
                    channels: d.channels,
                    _reserved: 0,
                    total_frames: d.total_frames,
                };
                // SAFETY: out_info writable per contract.
                unsafe { *out_info = info };
                Box::into_raw(Box::new(FarewellAudioDecoder { inner: d }))
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Pull up to `out_cap` interleaved f32 samples into `out`. Returns the
/// number written (`0` = end of stream, `< 0` = invalid argument).
///
/// # Safety
/// `dec` a live decoder; `out` writable for `out_cap` f32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_audio_read(
    dec: *mut FarewellAudioDecoder,
    out: *mut f32,
    out_cap: u64,
) -> i64 {
    catch_panic_i64(|| {
        if dec.is_null() || out.is_null() {
            return -1;
        }
        let cap = match usize::try_from(out_cap) {
            Ok(c) => c,
            Err(_) => return -1,
        };
        // SAFETY: dec live, out writable per contract.
        let d = unsafe { &mut *dec };
        let buf = unsafe { std::slice::from_raw_parts_mut(out, cap) };
        d.inner.read(buf) as i64
    })
}

/// Seek so the next read starts at `frame`. Returns 0 on success, -1 on
/// failure / unsupported.
///
/// # Safety
/// `dec` must be a live decoder.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_audio_seek(dec: *mut FarewellAudioDecoder, frame: u64) -> i32 {
    catch_panic(|| {
        if dec.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: dec live per contract.
        let d = unsafe { &mut *dec };
        if d.inner.seek(frame) {
            FarewellStatus::Ok
        } else {
            FarewellStatus::Io
        }
    })
}

/// Free a decoder. NULL is a no-op.
///
/// # Safety
/// `dec` must be a handle from [`farewell_audio_open`], not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_audio_close(dec: *mut FarewellAudioDecoder) {
    if dec.is_null() {
        return;
    }
    // SAFETY: dec from farewell_audio_open per contract.
    drop(unsafe { Box::from_raw(dec) });
}

/// Decode `bytes` fully and write `buckets` peak-amplitude values in 0.0..=1.0
/// into `out` (caller-allocated, `buckets` floats) for drawing a waveform.
/// Decoding happens entirely in our pure-Rust code, in RAM. Returns
/// [`FarewellStatus::Ok`] on success, or an error status (e.g. undecodable
/// input) in which case `out` is left untouched.
///
/// # Safety
/// `bytes` must be valid for `len` bytes; `out` must be valid for `buckets`
/// `f32` values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_audio_waveform(
    bytes: *const u8,
    len: u64,
    buckets: u64,
    out: *mut f32,
) -> i32 {
    catch_panic(|| {
        if bytes.is_null() || out.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        let n = match usize::try_from(len) {
            Ok(n) if n >= 1 => n,
            _ => return FarewellStatus::InvalidArgument,
        };
        let b = match usize::try_from(buckets) {
            Ok(b) if (1..=100_000).contains(&b) => b,
            _ => return FarewellStatus::InvalidArgument,
        };
        // SAFETY: caller contract — `bytes` valid for `len` bytes.
        let data = unsafe { std::slice::from_raw_parts(bytes, n) }.to_vec();
        let peaks = match farewell_audio::compute_waveform(data, b) {
            Some(p) => p,
            None => return FarewellStatus::Internal, // undecodable audio
        };
        // SAFETY: `out` valid for `b` f32 values per contract; `peaks.len() == b`.
        unsafe {
            std::ptr::copy_nonoverlapping(peaks.as_ptr(), out, b);
        }
        FarewellStatus::Ok
    })
}

// =============================================================================
// License FFI (offline activation + status)
// =============================================================================

/// License verdicts, carried in [`FarewellLicenseInfo::verdict`].
pub const FAREWELL_LICENSE_VALID: i32 = 0;
/// No license is installed on this Mac.
pub const FAREWELL_LICENSE_NONE: i32 = 1;
/// Signature does not verify (wrong key, tampered, or wrong major version).
pub const FAREWELL_LICENSE_BAD_SIGNATURE: i32 = 2;
/// License is for a different major version of Farewell.
pub const FAREWELL_LICENSE_WRONG_VERSION: i32 = 3;
/// This Mac's hardware serial isn't authorized by the license.
pub const FAREWELL_LICENSE_SERIAL_MISMATCH: i32 = 4;
/// The key / token is malformed.
pub const FAREWELL_LICENSE_MALFORMED: i32 = 5;
/// An environment error (couldn't read the serial, file I/O, …).
pub const FAREWELL_LICENSE_ERROR: i32 = 6;

/// License details for the UI. `license_type` and `email` are meaningful only
/// when `verdict == FAREWELL_LICENSE_VALID`.
#[repr(C)]
pub struct FarewellLicenseInfo {
    /// One of the `FAREWELL_LICENSE_*` verdicts.
    pub verdict: i32,
    /// `LicenseType` discriminant (0=Single, 1=Duo, 2=Quintet, 3=Grant).
    pub license_type: u32,
    /// NUL-terminated UTF-8 buyer email (up to 255 bytes).
    pub email: [u8; 256],
}

impl FarewellLicenseInfo {
    fn empty() -> Self {
        Self { verdict: FAREWELL_LICENSE_NONE, license_type: 0, email: [0u8; 256] }
    }
}

/// The ECDSA P-256 verifying key (SEC1 uncompressed, 65 bytes) the license is
/// checked against. Normally the key embedded in this build; a dev-only
/// `FAREWELL_DEV_LICENSE_PUBKEY` (130 hex chars) override lets a test license
/// signed by a local key be accepted. The override is never set in a shipped
/// build.
fn license_pubkey() -> [u8; 65] {
    if let Ok(hex) = std::env::var("FAREWELL_DEV_LICENSE_PUBKEY") {
        if let Some(k) = parse_hex65(hex.trim()) {
            return k;
        }
    }
    farewell_license::MAJOR_VERSION_1_PUBKEY
}

fn parse_hex65(s: &str) -> Option<[u8; 65]> {
    if s.len() != 130 {
        return None;
    }
    let mut out = [0u8; 65];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn license_verdict(e: &farewell_license::LicenseError) -> i32 {
    use farewell_license::LicenseError as E;
    match e {
        E::InvalidSignature | E::SignatureLength(_) | E::PublicKeyLength(_) => {
            FAREWELL_LICENSE_BAD_SIGNATURE
        }
        E::MajorVersionMismatch { .. } | E::PayloadVersion { .. } => FAREWELL_LICENSE_WRONG_VERSION,
        E::SerialNotAuthorized { .. } => FAREWELL_LICENSE_SERIAL_MISMATCH,
        E::MalformedToken(_)
        | E::Base64(_)
        | E::BadMagic(_)
        | E::Truncated { .. }
        | E::UnknownLicenseType(_)
        | E::EmailNotUtf8
        | E::UnboundLicense
        | E::SerialNotAscii => FAREWELL_LICENSE_MALFORMED,
        E::SerialReadFailed(_) | E::Io(_) => FAREWELL_LICENSE_ERROR,
    }
}

fn fill_license_info(info: &mut FarewellLicenseInfo, v: &farewell_license::VerifiedLicense) {
    let p = v.payload();
    info.verdict = FAREWELL_LICENSE_VALID;
    info.license_type = p.license_type as u32;
    let bytes = p.email.as_bytes();
    let n = bytes.len().min(255);
    info.email[..n].copy_from_slice(&bytes[..n]);
    info.email[n] = 0;
}

/// Read the installed license (if any) and verify it against this Mac. Fills
/// `out` with the verdict and, when valid, the email + tier. The C ABI call
/// returns [`FarewellStatus::Ok`] whenever it ran (the *license* verdict is in
/// `out.verdict`), or `InvalidArgument` on a NULL pointer.
///
/// # Safety
/// `out` must be a valid, writable pointer to a `FarewellLicenseInfo`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_license_status(out: *mut FarewellLicenseInfo) -> i32 {
    catch_panic(|| {
        if out.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: out non-null per contract.
        let info = unsafe { &mut *out };
        *info = FarewellLicenseInfo::empty();

        let store = match farewell_license::FileLicenseStore::default_for_user() {
            Ok(s) => s,
            Err(_) => {
                info.verdict = FAREWELL_LICENSE_ERROR;
                return FarewellStatus::Ok;
            }
        };
        let token = match farewell_license::LicenseStore::load(&store) {
            Ok(Some(t)) => t,
            Ok(None) => {
                info.verdict = FAREWELL_LICENSE_NONE;
                return FarewellStatus::Ok;
            }
            Err(_) => {
                info.verdict = FAREWELL_LICENSE_ERROR;
                return FarewellStatus::Ok;
            }
        };
        let reader = farewell_license::MacosSerialReader;
        match farewell_license::verify_for_this_mac(&token, &license_pubkey(), &reader) {
            Ok(v) => fill_license_info(info, &v),
            Err(e) => info.verdict = license_verdict(&e),
        }
        FarewellStatus::Ok
    })
}

/// Verify a pasted license key (or token), and on success install it for this
/// Mac. Fills `out` with the verdict and, when valid, the email + tier.
///
/// # Safety
/// `key_utf8` must be a valid NUL-terminated string; `out` a writable
/// `FarewellLicenseInfo` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_license_activate(
    key_utf8: *const c_char,
    out: *mut FarewellLicenseInfo,
) -> i32 {
    catch_panic(|| {
        if key_utf8.is_null() || out.is_null() {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: out non-null per contract.
        let info = unsafe { &mut *out };
        *info = FarewellLicenseInfo::empty();

        // SAFETY: key_utf8 non-null, NUL-terminated per contract.
        let key = match unsafe { CStr::from_ptr(key_utf8) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                info.verdict = FAREWELL_LICENSE_MALFORMED;
                return FarewellStatus::Ok;
            }
        };

        let reader = farewell_license::MacosSerialReader;
        match farewell_license::verify_for_this_mac(key, &license_pubkey(), &reader) {
            Ok(v) => {
                fill_license_info(info, &v);
                // Install only after it verifies for this Mac.
                if let Ok(store) = farewell_license::FileLicenseStore::default_for_user() {
                    let _ = farewell_license::LicenseStore::save(&store, key);
                }
            }
            Err(e) => info.verdict = license_verdict(&e),
        }
        FarewellStatus::Ok
    })
}

/// Read this Mac's hardware serial number into `out_buf` as a NUL-terminated
/// UTF-8 string (`cap` = buffer capacity in bytes, including the terminator).
/// Returns [`FarewellStatus::Ok`] on success, [`FarewellStatus::Io`] if the
/// serial could not be read, or `InvalidArgument` on a bad pointer. On any
/// failure an empty string is written. Local only — shells out to `ioreg`,
/// never the network. Same value the license check uses.
///
/// # Safety
/// `out_buf` must point to at least `cap` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn farewell_read_serial(out_buf: *mut u8, cap: usize) -> i32 {
    catch_panic(|| {
        if out_buf.is_null() || cap == 0 {
            return FarewellStatus::InvalidArgument;
        }
        // SAFETY: caller guarantees `cap` writable bytes at `out_buf`.
        let buf = unsafe { std::slice::from_raw_parts_mut(out_buf, cap) };
        buf[0] = 0;
        use farewell_license::SerialReader as _;
        match farewell_license::MacosSerialReader.read_serial() {
            Ok(sn) => {
                let bytes = sn.as_bytes();
                let n = bytes.len().min(cap - 1);
                buf[..n].copy_from_slice(&bytes[..n]);
                buf[n] = 0;
                FarewellStatus::Ok
            }
            Err(_) => FarewellStatus::Io,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr;

    // -------- v0.17 carryover tests --------

    #[test]
    fn version_round_trip() {
        let ptr = farewell_version();
        assert!(!ptr.is_null());
        // SAFETY: see farewell_version() docs.
        let cstr = unsafe { CStr::from_ptr(ptr) };
        assert_eq!(cstr.to_str().unwrap(), "0.18");
    }

    #[test]
    fn chunk_len_matches_format_crate() {
        assert_eq!(
            farewell_chunk_plaintext_len(),
            farewell_format::CHUNK_PLAINTEXT_LEN as u64
        );
    }

    // -------- v0.18 tests --------

    /// Build a minimal vault on disk, return its path. Caller owns
    /// the TempDir.
    fn make_vault(passphrase: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        use farewell_format::VaultBuilder;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ffi.vault");
        // Build creates the on-disk file but the returned Vault is
        // not mounted. Drop it (releases flock), then open to mount.
        {
            let _ = VaultBuilder::single_passphrase(&path, passphrase.to_vec())
                // Striped layout: single level uses slot-0 stripe =
                // total/NUM_SLOTS chunks. 24 → 8 usable, room for the
                // mutation round-trip (which migrates chunks on write).
                .total_chunks(24)
                .build()
                .unwrap();
        }
        let mut v = Vault::open(&path, passphrase.to_vec(), None::<&mut MockAuthenticator>)
            .unwrap();
        v.add_file("greeting", b"hello from farewell".to_vec()).unwrap();
        drop(v); // release flock so the FFI tests can re-open
        (dir, path)
    }

    /// The replay path used right after enrolling a backup key: a vault with
    /// a hardware key re-mounts from a captured `(cred, hmac)` pair, with no
    /// hardware touched. Proves `farewell_add_backup_key`'s no-extra-touch
    /// re-open is sound.
    #[test]
    fn replay_authenticator_remounts_hw_vault() {
        use farewell_format::{
            fido_salt_from_vault_salt, LevelEnrollment, LevelSpec, VaultBuilder,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hw.vault");
        let pass = b"correct horse battery staple".to_vec();

        // Build a 1-key HW vault with a Mock, capturing its (cred, hmac).
        let mut salt = [0u8; 32];
        farewell_crypto::rng::fill(&mut salt).unwrap();
        let fido_salt = fido_salt_from_vault_salt(&salt);
        let mut mock = MockAuthenticator::new(FIDO_RP_ID);
        let cred = mock.enroll(b"u").unwrap();
        let (_, hmac) = mock.challenge_response(&[cred.clone()], &fido_salt).unwrap();
        let mut enr = LevelEnrollment::passphrase_only();
        enr.push(cred.clone(), hmac).unwrap();
        {
            let _ = VaultBuilder::new(
                &path,
                vec![LevelSpec {
                    passphrase: pass.clone(),
                    enrollment: enr,
                }],
            )
            .unwrap()
            .total_chunks(24)
            .with_salt(salt)
            .build()
            .unwrap();
        }

        // Re-open with ONLY the replayed pair — no authenticator hardware.
        let mut replay = ReplayAuthenticator::new(FIDO_RP_ID, cred.clone(), hmac);
        let v = Vault::open(&path, pass.clone(), Some(&mut replay)).unwrap();
        assert_eq!(v.hw_key_count(), Some(1));

        // A replay with the WRONG credential must NOT open it.
        let mut wrong = ReplayAuthenticator::new(FIDO_RP_ID, vec![0u8; cred.len()], hmac);
        assert!(Vault::open(&path, pass, Some(&mut wrong)).is_err());
    }

    #[test]
    fn open_and_close_roundtrip() {
        let (_dir, path) = make_vault(b"alpha");
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let pp = b"alpha";
        let mut handle: *mut FarewellVault = ptr::null_mut();
        // SAFETY: ptrs are valid for the call.
        let st = unsafe {
            farewell_open(
                cpath.as_ptr(),
                pp.as_ptr(),
                pp.len() as u64,
                &mut handle,
            )
        };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert!(!handle.is_null());
        // SAFETY: handle was just returned by farewell_open.
        unsafe { farewell_close(handle) };
    }

    #[test]
    fn open_rejects_wrong_passphrase_as_crypto() {
        let (_dir, path) = make_vault(b"correct");
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let pp = b"wrong";
        let mut handle: *mut FarewellVault = ptr::null_mut();
        let st = unsafe {
            farewell_open(
                cpath.as_ptr(),
                pp.as_ptr(),
                pp.len() as u64,
                &mut handle,
            )
        };
        assert_eq!(st, FarewellStatus::Crypto as i32);
        assert!(handle.is_null());
    }

    #[test]
    fn open_rejects_missing_file_as_io() {
        let cpath = CString::new("/nonexistent/path/to.vault").unwrap();
        let pp = b"x";
        let mut handle: *mut FarewellVault = ptr::null_mut();
        let st = unsafe {
            farewell_open(
                cpath.as_ptr(),
                pp.as_ptr(),
                pp.len() as u64,
                &mut handle,
            )
        };
        assert_eq!(st, FarewellStatus::Io as i32);
    }

    #[test]
    fn open_rejects_null_path_as_invalid_argument() {
        let pp = b"x";
        let mut handle: *mut FarewellVault = ptr::null_mut();
        let st = unsafe {
            farewell_open(
                ptr::null(),
                pp.as_ptr(),
                pp.len() as u64,
                &mut handle,
            )
        };
        assert_eq!(st, FarewellStatus::InvalidArgument as i32);
    }

    #[test]
    fn open_then_stat_returns_correct_size() {
        let (_dir, path) = make_vault(b"alpha");
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let pp = b"alpha";
        let mut handle: *mut FarewellVault = ptr::null_mut();
        unsafe {
            farewell_open(cpath.as_ptr(), pp.as_ptr(), pp.len() as u64, &mut handle);
        }
        assert!(!handle.is_null());

        let cname = CString::new("greeting").unwrap();
        let mut stat = FarewellStat { size: 0 };
        let st = unsafe { farewell_stat(handle, cname.as_ptr(), &mut stat) };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert_eq!(stat.size, b"hello from farewell".len() as u64);

        unsafe { farewell_close(handle) };
    }

    #[test]
    fn stat_unknown_file_returns_not_found() {
        let (_dir, path) = make_vault(b"alpha");
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let pp = b"alpha";
        let mut handle: *mut FarewellVault = ptr::null_mut();
        unsafe {
            farewell_open(cpath.as_ptr(), pp.as_ptr(), pp.len() as u64, &mut handle);
        }
        let cname = CString::new("nope").unwrap();
        let mut stat = FarewellStat { size: 0 };
        let st = unsafe { farewell_stat(handle, cname.as_ptr(), &mut stat) };
        assert_eq!(st, FarewellStatus::NotFound as i32);
        unsafe { farewell_close(handle) };
    }

    #[test]
    fn read_range_returns_expected_bytes() {
        let (_dir, path) = make_vault(b"alpha");
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let pp = b"alpha";
        let mut handle: *mut FarewellVault = ptr::null_mut();
        unsafe {
            farewell_open(cpath.as_ptr(), pp.as_ptr(), pp.len() as u64, &mut handle);
        }
        let cname = CString::new("greeting").unwrap();
        // Read bytes 6..=10 i.e. "from "
        let mut buf = vec![0u8; 5];
        let mut actual: u64 = 0;
        let st = unsafe {
            farewell_read_range(
                handle,
                cname.as_ptr(),
                6,
                5,
                buf.as_mut_ptr(),
                &mut actual,
            )
        };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert_eq!(actual, 5);
        assert_eq!(&buf, b"from ");
        unsafe { farewell_close(handle) };
    }

    #[test]
    fn read_range_clamps_past_eof() {
        let (_dir, path) = make_vault(b"alpha");
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let pp = b"alpha";
        let mut handle: *mut FarewellVault = ptr::null_mut();
        unsafe {
            farewell_open(cpath.as_ptr(), pp.as_ptr(), pp.len() as u64, &mut handle);
        }
        let cname = CString::new("greeting").unwrap();
        // File is 19 bytes; ask for 1000 starting at 15 → expect 4 bytes "well".
        let mut buf = vec![0u8; 1000];
        let mut actual: u64 = 0;
        let st = unsafe {
            farewell_read_range(
                handle,
                cname.as_ptr(),
                15,
                1000,
                buf.as_mut_ptr(),
                &mut actual,
            )
        };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert_eq!(actual, 4);
        assert_eq!(&buf[..actual as usize], b"well");
        unsafe { farewell_close(handle) };
    }

    #[test]
    fn read_range_zero_length_returns_ok() {
        let (_dir, path) = make_vault(b"alpha");
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let pp = b"alpha";
        let mut handle: *mut FarewellVault = ptr::null_mut();
        unsafe {
            farewell_open(cpath.as_ptr(), pp.as_ptr(), pp.len() as u64, &mut handle);
        }
        let cname = CString::new("greeting").unwrap();
        // want_len = 0; out_buf is allowed to be null.
        let mut actual: u64 = 999;
        let st = unsafe {
            farewell_read_range(handle, cname.as_ptr(), 0, 0, ptr::null_mut(), &mut actual)
        };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert_eq!(actual, 0);
        unsafe { farewell_close(handle) };
    }

    #[test]
    fn close_null_is_noop() {
        unsafe { farewell_close(ptr::null_mut()) };
    }

    // -------- v0.18 Phase B: mutation operations --------

    /// Open the fixture vault made by `make_vault` and return its
    /// handle. Caller is responsible for closing.
    fn open_for_mutation(path: &std::path::Path, pp: &[u8]) -> *mut FarewellVault {
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let mut handle: *mut FarewellVault = ptr::null_mut();
        let st = unsafe {
            farewell_open(cpath.as_ptr(), pp.as_ptr(), pp.len() as u64, &mut handle)
        };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert!(!handle.is_null());
        handle
    }

    fn read_via_ffi(handle: *mut FarewellVault, name: &str) -> Vec<u8> {
        let cname = CString::new(name).unwrap();
        let mut stat = FarewellStat { size: 0 };
        let st = unsafe { farewell_stat(handle, cname.as_ptr(), &mut stat) };
        assert_eq!(st, FarewellStatus::Ok as i32, "stat({name}) failed");
        let mut buf = vec![0u8; stat.size as usize];
        let mut actual: u64 = 0;
        let st = unsafe {
            farewell_read_range(
                handle,
                cname.as_ptr(),
                0,
                buf.len() as u64,
                if buf.is_empty() {
                    ptr::null_mut()
                } else {
                    buf.as_mut_ptr()
                },
                &mut actual,
            )
        };
        assert_eq!(st, FarewellStatus::Ok as i32, "read({name}) failed");
        buf.truncate(actual as usize);
        buf
    }

    #[test]
    fn create_then_stat_returns_zero_size() {
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");
        let cname = CString::new("brand_new").unwrap();
        let st = unsafe { farewell_create(h, cname.as_ptr()) };
        assert_eq!(st, FarewellStatus::Ok as i32);
        let mut stat = FarewellStat { size: 999 };
        unsafe { farewell_stat(h, cname.as_ptr(), &mut stat) };
        assert_eq!(stat.size, 0);
        unsafe { farewell_close(h) };
    }

    #[test]
    fn create_is_idempotent_on_existing() {
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");
        let cname = CString::new("greeting").unwrap(); // already exists
        let st = unsafe { farewell_create(h, cname.as_ptr()) };
        assert_eq!(st, FarewellStatus::Ok as i32);
        // Original content must be preserved.
        let bytes = read_via_ffi(h, "greeting");
        assert_eq!(&bytes, b"hello from farewell");
        unsafe { farewell_close(h) };
    }

    #[test]
    fn write_range_extends_file_and_round_trips() {
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");
        let cname = CString::new("greeting").unwrap();
        // Append 8 bytes past the original 19-byte content.
        let append = b" + extra";
        let st = unsafe {
            farewell_write_range(
                h,
                cname.as_ptr(),
                19,
                append.as_ptr(),
                append.len() as u64,
            )
        };
        assert_eq!(st, FarewellStatus::Ok as i32);
        let bytes = read_via_ffi(h, "greeting");
        assert_eq!(&bytes, b"hello from farewell + extra");
        unsafe { farewell_close(h) };
    }

    #[test]
    fn write_range_zero_length_is_noop() {
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");
        let cname = CString::new("greeting").unwrap();
        let st = unsafe {
            farewell_write_range(h, cname.as_ptr(), 0, ptr::null(), 0)
        };
        assert_eq!(st, FarewellStatus::Ok as i32);
        let bytes = read_via_ffi(h, "greeting");
        assert_eq!(&bytes, b"hello from farewell");
        unsafe { farewell_close(h) };
    }

    #[test]
    fn write_range_on_missing_file_returns_not_found() {
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");
        let cname = CString::new("nope").unwrap();
        let data = b"abc";
        let st = unsafe {
            farewell_write_range(h, cname.as_ptr(), 0, data.as_ptr(), data.len() as u64)
        };
        assert_eq!(st, FarewellStatus::NotFound as i32);
        unsafe { farewell_close(h) };
    }

    #[test]
    fn truncate_shrink_and_grow() {
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");
        let cname = CString::new("greeting").unwrap();

        // Shrink to 5: "hello"
        let st = unsafe { farewell_truncate(h, cname.as_ptr(), 5) };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert_eq!(&read_via_ffi(h, "greeting"), b"hello");

        // Grow to 10: "hello\0\0\0\0\0"
        let st = unsafe { farewell_truncate(h, cname.as_ptr(), 10) };
        assert_eq!(st, FarewellStatus::Ok as i32);
        let bytes = read_via_ffi(h, "greeting");
        assert_eq!(bytes.len(), 10);
        assert_eq!(&bytes[..5], b"hello");
        assert!(bytes[5..].iter().all(|&b| b == 0));

        unsafe { farewell_close(h) };
    }

    #[test]
    fn rename_moves_file_and_replaces_existing_destination() {
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");

        // Add a second file first, then rename greeting → other.
        let c_other = CString::new("other").unwrap();
        unsafe { farewell_create(h, c_other.as_ptr()) };
        let data = b"to-be-replaced";
        unsafe {
            farewell_write_range(h, c_other.as_ptr(), 0, data.as_ptr(), data.len() as u64);
        }

        let c_greeting = CString::new("greeting").unwrap();
        let st = unsafe { farewell_rename(h, c_greeting.as_ptr(), c_other.as_ptr()) };
        assert_eq!(st, FarewellStatus::Ok as i32);

        // "greeting" gone.
        let mut stat = FarewellStat { size: 0 };
        let st = unsafe { farewell_stat(h, c_greeting.as_ptr(), &mut stat) };
        assert_eq!(st, FarewellStatus::NotFound as i32);

        // "other" now contains the original greeting content.
        assert_eq!(&read_via_ffi(h, "other"), b"hello from farewell");

        unsafe { farewell_close(h) };
    }

    #[test]
    fn delete_removes_file() {
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");
        let cname = CString::new("greeting").unwrap();
        let st = unsafe { farewell_delete(h, cname.as_ptr()) };
        assert_eq!(st, FarewellStatus::Ok as i32);

        let mut stat = FarewellStat { size: 0 };
        let st = unsafe { farewell_stat(h, cname.as_ptr(), &mut stat) };
        assert_eq!(st, FarewellStatus::NotFound as i32);

        unsafe { farewell_close(h) };
    }

    #[test]
    fn delete_missing_returns_not_found() {
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");
        let cname = CString::new("never_existed").unwrap();
        let st = unsafe { farewell_delete(h, cname.as_ptr()) };
        assert_eq!(st, FarewellStatus::NotFound as i32);
        unsafe { farewell_close(h) };
    }

    // -------- v0.18 Phase C: readdir + info accessors --------

    #[test]
    fn total_chunks_matches_format_crate() {
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");
        // make_vault uses total_chunks(24) (striped layout needs the
        // headroom). The public `total_chunks` is the chunks-region
        // length, reported verbatim.
        let n = unsafe { farewell_total_chunks(h) };
        assert_eq!(n, 24);
        unsafe { farewell_close(h) };
    }

    #[test]
    fn total_chunks_zero_on_null() {
        assert_eq!(unsafe { farewell_total_chunks(ptr::null()) }, 0);
    }

    #[test]
    fn counter_reads_back_post_add() {
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");
        // make_vault adds one file before drop, so counter is 1.
        let mut c: u64 = 999;
        let st = unsafe { farewell_counter(h, &mut c) };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert_eq!(c, 1);
        unsafe { farewell_close(h) };
    }

    #[test]
    fn counter_advances_after_mutation() {
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");
        let mut before: u64 = 0;
        unsafe { farewell_counter(h, &mut before) };
        let c = CString::new("x").unwrap();
        unsafe { farewell_create(h, c.as_ptr()) };
        let mut after: u64 = 0;
        unsafe { farewell_counter(h, &mut after) };
        assert!(after > before, "counter must advance after create");
        unsafe { farewell_close(h) };
    }

    #[test]
    fn fingerprint_is_stable_across_reopens() {
        let (_dir, path) = make_vault(b"alpha");
        let mut fp1 = [0u8; 32];
        let mut fp2 = [0u8; 32];
        {
            let h = open_for_mutation(&path, b"alpha");
            let st = unsafe { farewell_fingerprint(h, fp1.as_mut_ptr()) };
            assert_eq!(st, FarewellStatus::Ok as i32);
            unsafe { farewell_close(h) };
        }
        {
            let h = open_for_mutation(&path, b"alpha");
            let st = unsafe { farewell_fingerprint(h, fp2.as_mut_ptr()) };
            assert_eq!(st, FarewellStatus::Ok as i32);
            unsafe { farewell_close(h) };
        }
        assert_eq!(fp1, fp2, "fingerprint must be deterministic");
        // Non-zero (the all-zero placeholder would be suspicious).
        assert!(fp1.iter().any(|&b| b != 0));
    }

    #[test]
    fn fingerprint_differs_across_vaults() {
        let (_d1, p1) = make_vault(b"alpha");
        let (_d2, p2) = make_vault(b"alpha");
        let mut fp1 = [0u8; 32];
        let mut fp2 = [0u8; 32];
        {
            let h = open_for_mutation(&p1, b"alpha");
            unsafe { farewell_fingerprint(h, fp1.as_mut_ptr()) };
            unsafe { farewell_close(h) };
        }
        {
            let h = open_for_mutation(&p2, b"alpha");
            unsafe { farewell_fingerprint(h, fp2.as_mut_ptr()) };
            unsafe { farewell_close(h) };
        }
        assert_ne!(
            fp1, fp2,
            "two independently created vaults must have distinct fingerprints"
        );
    }

    // Counter for the readdir tests: cb appends each name to a Vec.
    extern "C" fn collect_names_cb(
        entry: *const FarewellDirent,
        user_data: *mut std::ffi::c_void,
    ) {
        // SAFETY: user_data was passed in as &mut Vec<(String, u64)>.
        let collected = unsafe { &mut *(user_data as *mut Vec<(String, u64)>) };
        // SAFETY: entry valid for the callback's lifetime (FFI contract).
        let entry_ref = unsafe { &*entry };
        // SAFETY: name_utf8 is a valid NUL-terminated C string for
        // the callback's lifetime.
        let cstr = unsafe { CStr::from_ptr(entry_ref.name_utf8) };
        let s = cstr.to_str().expect("UTF-8 name").to_string();
        collected.push((s, entry_ref.size));
    }

    #[test]
    fn readdir_yields_all_entries() {
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");
        // make_vault added "greeting"; add two more.
        let c1 = CString::new("a").unwrap();
        let c2 = CString::new("b").unwrap();
        unsafe { farewell_create(h, c1.as_ptr()) };
        unsafe { farewell_create(h, c2.as_ptr()) };

        let mut collected: Vec<(String, u64)> = Vec::new();
        let user_data = &mut collected as *mut _ as *mut std::ffi::c_void;
        let st = unsafe { farewell_readdir(h, collect_names_cb, user_data) };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert_eq!(collected.len(), 3);

        let names: Vec<String> = collected.iter().map(|(n, _)| n.clone()).collect();
        assert!(names.contains(&"greeting".to_string()));
        assert!(names.contains(&"a".to_string()));
        assert!(names.contains(&"b".to_string()));

        // Sizes are honest.
        let greeting_entry = collected.iter().find(|(n, _)| n == "greeting").unwrap();
        assert_eq!(greeting_entry.1, b"hello from farewell".len() as u64);

        unsafe { farewell_close(h) };
    }

    #[test]
    fn readdir_on_empty_vault_invokes_callback_zero_times() {
        use farewell_format::VaultBuilder;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.vault");
        {
            let _ = VaultBuilder::single_passphrase(&path, b"x".to_vec())
                .total_chunks(4)
                .build()
                .unwrap();
        }
        let h = open_for_mutation(&path, b"x");
        let mut collected: Vec<(String, u64)> = Vec::new();
        let user_data = &mut collected as *mut _ as *mut std::ffi::c_void;
        let st = unsafe { farewell_readdir(h, collect_names_cb, user_data) };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert!(collected.is_empty());
        unsafe { farewell_close(h) };
    }

    #[test]
    fn readdir_null_handle_rejected() {
        let mut collected: Vec<(String, u64)> = Vec::new();
        let user_data = &mut collected as *mut _ as *mut std::ffi::c_void;
        let st = unsafe { farewell_readdir(ptr::null(), collect_names_cb, user_data) };
        assert_eq!(st, FarewellStatus::InvalidArgument as i32);
    }

    #[test]
    fn mutation_round_trip_full_lifecycle() {
        // Exercise the whole Phase B surface in one shot:
        // create → write → read → truncate → rename → delete.
        let (_dir, path) = make_vault(b"alpha");
        let h = open_for_mutation(&path, b"alpha");

        let c1 = CString::new("scratch").unwrap();
        unsafe { farewell_create(h, c1.as_ptr()) };

        let data = vec![0xABu8; 1000];
        unsafe {
            farewell_write_range(h, c1.as_ptr(), 0, data.as_ptr(), data.len() as u64);
        }
        assert_eq!(read_via_ffi(h, "scratch"), data);

        unsafe { farewell_truncate(h, c1.as_ptr(), 100) };
        assert_eq!(read_via_ffi(h, "scratch"), &data[..100]);

        let c2 = CString::new("renamed").unwrap();
        unsafe { farewell_rename(h, c1.as_ptr(), c2.as_ptr()) };
        assert_eq!(read_via_ffi(h, "renamed"), &data[..100]);

        unsafe { farewell_delete(h, c2.as_ptr()) };
        let mut stat = FarewellStat { size: 0 };
        let st = unsafe { farewell_stat(h, c2.as_ptr(), &mut stat) };
        assert_eq!(st, FarewellStatus::NotFound as i32);

        unsafe { farewell_close(h) };
    }

    // -------- v0.20.A: hidden volumes via FFI --------

    /// Helper: create a multi-level vault via the FFI from a list of
    /// passphrases.
    fn create_vault_ffi(
        path: &std::path::Path,
        total_chunks: u64,
        passphrases: &[&[u8]],
    ) -> i32 {
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let byteslices: Vec<FarewellBytes> = passphrases
            .iter()
            .map(|p| FarewellBytes { ptr: p.as_ptr(), len: p.len() as u64 })
            .collect();
        unsafe {
            farewell_create_vault(
                cpath.as_ptr(),
                total_chunks,
                byteslices.as_ptr(),
                byteslices.len() as u64,
            )
        }
    }

    /// Helper: open via FFI single passphrase; returns (status, handle).
    fn open_ffi(path: &std::path::Path, pp: &[u8]) -> (i32, *mut FarewellVault) {
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let mut h: *mut FarewellVault = ptr::null_mut();
        let st = unsafe {
            farewell_open(cpath.as_ptr(), pp.as_ptr(), pp.len() as u64, &mut h)
        };
        (st, h)
    }

    #[test]
    fn create_single_vault_and_open_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.vault");

        let p1 = farewell_passphrase::generate_default().unwrap();
        let st = create_vault_ffi(&path, 32, &[p1.as_bytes()]);
        assert_eq!(st, FarewellStatus::Ok as i32, "create_vault failed");

        let (st, h) = open_ffi(&path, p1.as_bytes());
        assert_eq!(st, FarewellStatus::Ok as i32, "open failed");
        assert!(!h.is_null());
        let cname = CString::new("notes.txt").unwrap();
        assert_eq!(unsafe { farewell_create(h, cname.as_ptr()) }, FarewellStatus::Ok as i32);
        let wst = b"the leak".as_slice().withFfiWrite(h, "notes.txt", 0);
        assert_eq!(wst, FarewellStatus::Ok as i32);
        unsafe { farewell_close(h) };

        // Re-open: the file is there.
        let (st, h) = open_ffi(&path, p1.as_bytes());
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert!(readdir_names(h).contains(&"notes.txt".to_string()));
        unsafe { farewell_close(h) };
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ml.vault");
        let p1 = farewell_passphrase::generate_default().unwrap();
        assert_eq!(create_vault_ffi(&path, 16, &[p1.as_bytes()]), FarewellStatus::Ok as i32);
        let (st, h) = open_ffi(&path, b"not-the-passphrase");
        assert_eq!(st, FarewellStatus::Crypto as i32);
        assert!(h.is_null());
    }

    #[test]
    fn create_vault_rejects_zero_levels() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero.vault");
        let st = unsafe {
            farewell_create_vault(
                CString::new(path.to_str().unwrap()).unwrap().as_ptr(),
                16,
                ptr::null(),
                0,
            )
        };
        assert_eq!(st, FarewellStatus::InvalidArgument as i32);
    }

    #[test]
    fn create_vault_rejects_weak_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("weak.vault");
        let st = create_vault_ffi(&path, 16, &[b"password"]);
        assert_eq!(st, FarewellStatus::WeakPassphrase as i32);
        // And the file must NOT have been created.
        assert!(!path.exists(), "no vault should be written for a weak passphrase");
    }

    #[test]
    fn create_hw_zero_keys_then_open_hw_needs_no_touch() {
        // hw_keys_per_level = 0 → passphrase-only. open_hw opens any
        // connected key but a K=0 vault never calls it (no blink, no PIN).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hw0.vault");
        let pw = farewell_passphrase::generate_default().unwrap();
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let slices = [FarewellBytes { ptr: pw.as_ptr(), len: pw.len() as u64 }];
        // create now returns an already-open handle; close it, then prove
        // open_hw re-opens a K=0 vault with no touch.
        let mut ch: *mut FarewellVault = ptr::null_mut();
        let st = unsafe {
            farewell_create_vault_hw(
                cpath.as_ptr(), 16, slices.as_ptr(), 1, 0, ptr::null(), 0,
                ptr::null(), &mut ch, None, ptr::null_mut(),
            )
        };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert!(!ch.is_null());
        unsafe { farewell_close(ch) };

        let mut h: *mut FarewellVault = ptr::null_mut();
        let st = unsafe {
            farewell_open_hw(cpath.as_ptr(), pw.as_ptr(), pw.len() as u64, ptr::null(), 0, None, ptr::null_mut(), &mut h)
        };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert!(!h.is_null());
        unsafe { farewell_close(h) };
    }

    #[test]
    fn open_hw_opens_a_plain_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.vault");
        let pw = farewell_passphrase::generate_default().unwrap();
        assert_eq!(
            create_vault_ffi(&path, 16, &[pw.as_bytes()]),
            FarewellStatus::Ok as i32
        );
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let mut h: *mut FarewellVault = ptr::null_mut();
        let st = unsafe {
            farewell_open_hw(cpath.as_ptr(), pw.as_ptr(), pw.len() as u64, ptr::null(), 0, None, ptr::null_mut(), &mut h)
        };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert!(!h.is_null());
        unsafe { farewell_close(h) };
    }

    #[test]
    fn create_hw_rejects_weak_passphrase_before_touching_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hwweak.vault");
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let weak = b"password";
        let slices = [FarewellBytes { ptr: weak.as_ptr(), len: weak.len() as u64 }];
        // hw=1 but the policy check happens FIRST, so no key is touched.
        let mut ch: *mut FarewellVault = ptr::null_mut();
        let st = unsafe {
            farewell_create_vault_hw(
                cpath.as_ptr(), 16, slices.as_ptr(), 1, 1, ptr::null(), 0,
                ptr::null(), &mut ch, None, ptr::null_mut(),
            )
        };
        assert_eq!(st, FarewellStatus::WeakPassphrase as i32);
        assert!(ch.is_null());
        assert!(!path.exists());
    }

    #[test]
    fn passphrase_score_ffi_ranks_weak_below_strong() {
        let weak = b"password";
        let mut ws = 9u8;
        let st = unsafe { farewell_passphrase_score(weak.as_ptr(), weak.len() as u64, &mut ws) };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert!(ws < 4, "‘password’ should score < 4, got {ws}");

        let strong = farewell_passphrase::generate_default().unwrap();
        let mut ss = 0u8;
        let st = unsafe {
            farewell_passphrase_score(strong.as_ptr(), strong.len() as u64, &mut ss)
        };
        assert_eq!(st, FarewellStatus::Ok as i32);
        assert_eq!(ss, 4, "generated passphrase should score 4, got {ss}");
    }

    #[test]
    fn generate_passphrase_ffi_yields_policy_compliant_string() {
        extern "C" fn cb(s: *const c_char, ud: *mut std::ffi::c_void) {
            let out = unsafe { &mut *(ud as *mut Option<String>) };
            *out = Some(unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_string());
        }
        let mut captured: Option<String> = None;
        let st = unsafe {
            farewell_generate_passphrase(
                0,
                Some(cb),
                &mut captured as *mut Option<String> as *mut std::ffi::c_void,
            )
        };
        assert_eq!(st, FarewellStatus::Ok as i32);
        let pw = captured.expect("callback should have fired");
        assert!(farewell_passphrase::meets_policy(&pw), "generated must pass policy: {pw:?}");
    }

    // -- small test helpers --

    fn readdir_names(h: *mut FarewellVault) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        extern "C" fn cb(entry: *const FarewellDirent, ud: *mut std::ffi::c_void) {
            let v = unsafe { &mut *(ud as *mut Vec<String>) };
            let e = unsafe { &*entry };
            v.push(unsafe { CStr::from_ptr(e.name_utf8) }.to_str().unwrap().to_string());
        }
        let ud = &mut names as *mut _ as *mut std::ffi::c_void;
        unsafe { farewell_readdir(h, cb, ud) };
        names
    }

    // Tiny extension so the loop above reads cleanly.
    trait FfiWrite {
        fn withFfiWrite(&self, h: *mut FarewellVault, name: &str, offset: u64) -> i32;
    }
    impl FfiWrite for &[u8] {
        fn withFfiWrite(&self, h: *mut FarewellVault, name: &str, offset: u64) -> i32 {
            let cname = CString::new(name).unwrap();
            unsafe {
                farewell_write_range(h, cname.as_ptr(), offset, self.as_ptr(), self.len() as u64)
            }
        }
    }
}
