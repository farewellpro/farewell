/*
 * farewell_mount — C ABI for native callers (Swift FSKit, etc.)
 *
 * v0.18 Phase A: lifecycle + read-only ops.
 *
 * The canonical source of truth for the ABI is the `extern "C"`
 * declarations in `crates/farewell_mount/src/lib.rs`. This header is
 * currently maintained by hand; cbindgen integration will land when
 * the surface stabilizes.
 *
 * Conventions:
 *   - Status: every fallible function returns an int32_t.
 *       0  = OK
 *       !0 = one of the FarewellStatus codes below.
 *   - Output values come back via out-pointers, never through the
 *     return value (which is reserved for the status).
 *   - C strings (`name_utf8`, `path_utf8`): NUL-terminated UTF-8.
 *   - Raw byte buffers (passphrase, read/write data): pointer +
 *     explicit length, never NUL-terminated.
 *   - Returned C strings from accessor functions (e.g.
 *     farewell_version) are statically allocated; never free() them.
 *   - All operations on the same handle must be serialized by the
 *     caller. Different handles may be used concurrently.
 *   - No exceptions, no panics ever cross this boundary.
 */

#ifndef FAREWELL_MOUNT_H
#define FAREWELL_MOUNT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----- Version / constants (v0.17+) ----- */

const char *farewell_version(void);
uint64_t farewell_chunk_plaintext_len(void);

/* ----- Passphrase strength + generation (v0.5) -----
 *
 * Farewell has no auto-wipe and no recovery: the passphrase is the whole
 * defense once an attacker holds a copy. Creation enforces a strength
 * floor (zxcvbn score must be 4). These let the UI show a live meter and
 * offer a strong generated passphrase, using the SAME estimator the core
 * enforces.
 */

/*
 * Estimate a passphrase's strength. Writes the zxcvbn score (0..4) to
 * *out_score (4 = required floor). Returns FAREWELL_INVALID_ARGUMENT if
 * out_score is NULL or the bytes are not valid UTF-8.
 * `passphrase` may be NULL iff passphrase_len == 0.
 */
int32_t farewell_passphrase_score(
    const uint8_t *passphrase,
    uint64_t passphrase_len,
    uint8_t *out_score);

/*
 * Callback receiving a generated passphrase as a NUL-terminated UTF-8
 * string. Valid ONLY during the call — copy it out. The buffer is
 * scrubbed after the callback returns.
 */
typedef void (*FarewellPassphraseCb)(const char *utf8, void *user_data);

/*
 * Generate a strong EFF-diceware passphrase of `word_count` words (pass
 * 0 for the recommended default) and hand it to `cb`. The result always
 * satisfies the creation policy.
 */
int32_t farewell_generate_passphrase(
    uint64_t word_count,
    FarewellPassphraseCb cb,
    void *user_data);

/* ----- Status codes (v0.18) -----
 *
 * Numbers are part of the ABI: do NOT renumber existing variants,
 * only append.
 */
typedef enum FarewellStatus {
    FAREWELL_OK                       = 0,
    FAREWELL_INVALID_ARGUMENT         = 1,
    FAREWELL_NOT_FOUND                = 2,
    FAREWELL_IO                       = 3,
    FAREWELL_ALREADY_LOCKED           = 4,
    FAREWELL_WIPED                    = 5,
    FAREWELL_INVALID_NAME             = 6,
    FAREWELL_CRYPTO                   = 7,
    FAREWELL_FULL                     = 8,
    FAREWELL_MANIFEST                 = 9,
    FAREWELL_TOO_SMALL                = 10,
    FAREWELL_NOT_A_VAULT              = 11,
    FAREWELL_HEADER_SIGNATURE_INVALID = 12,
    FAREWELL_UNSUPPORTED_VERSION      = 13,
    FAREWELL_COUNTER_ROLLBACK         = 14,
    FAREWELL_WEAK_PASSPHRASE          = 15,
    FAREWELL_HW_NOT_PRESENT           = 16,
    FAREWELL_HW_AUTH_FAILED           = 17,
    FAREWELL_HW_MULTIPLE_KEYS         = 18,
    FAREWELL_INTERNAL                 = 100,
} FarewellStatus;

/* ----- Opaque handle (v0.18) ----- */

typedef struct FarewellVault FarewellVault;

/* ----- Byte slice for passphrase lists (v0.20) ----- */

/*
 * A borrowed byte slice: pointer + length. Used to pass a list of
 * passphrases (each arbitrary bytes, possibly containing NULs). The
 * pointer must stay valid for the duration of the call.
 */
typedef struct FarewellBytes {
    const uint8_t *ptr;
    uint64_t       len;
} FarewellBytes;

/* ----- Vault creation (single-domain) ----- */

/*
 * Create a new single-domain vault, protected by one passphrase. A
 * Farewell vault holds exactly one content tree, openable by exactly
 * one passphrase, using the whole capacity. (No hidden/decoy volumes.)
 *
 * - path_utf8        : NUL-terminated UTF-8 path; file must NOT exist
 * - total_chunks     : capacity in chunks (>= 2)
 * - passphrases      : array of FarewellBytes; exactly one entry
 * - passphrase_count : must be 1
 *
 * There is no auto-wipe: the file is unconditionally indistinguishable
 * from random data. Defense against offline brute force is Argon2id +
 * passphrase entropy (+ an optional FIDO2 hardware key).
 *
 * Does NOT return a handle: the file is created and the lock released.
 * Mount afterwards with farewell_open.
 */
int32_t farewell_create_vault(
    const char *path_utf8,
    uint64_t total_chunks,
    const FarewellBytes *passphrases,
    uint64_t passphrase_count);

/*
 * Like farewell_create_vault, but enrolls `hw_keys_per_level` FIDO2
 * hardware keys on the vault. With hw_keys_per_level == 0 this is
 * identical to farewell_create_vault (no hardware). Otherwise a connected
 * key is opened (CTAP2 `pin` applied if pin_len > 0) and the user must
 * TOUCH it once per enrollment — so this BLOCKS; call it off the UI thread.
 *
 * `pin` may be NULL iff pin_len == 0. Returns FAREWELL_HW_NOT_PRESENT if
 * no key can be opened.
 *
 * On success the vault is returned ALREADY OPEN via out_handle (primary
 * level mounted, reusing the creation master key) — do NOT re-open, which
 * would cost a second KDF and, for hardware vaults, an extra mount touch.
 * Close it with farewell_close. On error, out_handle is set to NULL.
 */
/*
 * Progress reported via FarewellProgressCb so the UI can show real status.
 * For AWAIT_TOUCH, (done,total) = touch number / touches expected;
 * for WRITING, (done,total) = chunks written / to write (drive a bar);
 * for AWAIT_INSERT / AWAIT_REMOVE, (done,total) = key number / total keys
 * (one-port-swap enrollment: insert/remove one key at a time).
 */
#define FAREWELL_PROGRESS_AWAIT_TOUCH   0u /* waiting for a hardware-key touch  */
#define FAREWELL_PROGRESS_WRITING       1u /* writing the vault file            */
#define FAREWELL_PROGRESS_MIGRATE_COPY  2u /* migration: copying files          */
#define FAREWELL_PROGRESS_MIGRATE_VERIFY 3u /* migration: verifying the copy     */
#define FAREWELL_PROGRESS_AWAIT_INSERT  4u /* swap: waiting for a key to be inserted */
#define FAREWELL_PROGRESS_AWAIT_REMOVE  5u /* swap: waiting for the key to be removed */
typedef void (*FarewellProgressCb)(uint32_t phase, uint64_t done, uint64_t total,
                                   void *user_data);

int32_t farewell_create_vault_hw(
    const char *path_utf8,
    uint64_t total_chunks,
    const FarewellBytes *passphrases,
    uint64_t passphrase_count,
    uint32_t hw_keys_per_level,
    const uint8_t *pin,
    uint64_t pin_len,
    const char *owner_utf8,        /* opt-in creator identity; NULL/"" = none */
    FarewellVault **out_handle,
    FarewellProgressCb progress,   /* may be NULL */
    void *progress_user_data);

/*
 * Re-encrypt a vault into a NEW file at dst_path (crypto-agility / rotation).
 * The source is opened read-only and left untouched; the destination is built,
 * content streamed in, and verified byte-for-byte before Ok is returned. The
 * CALLER owns the atomic swap and the disposal of the old file, and MUST delete
 * dst_path on any non-Ok return.
 *
 * new_total_chunks: 0 = keep the source's capacity; UINT64_MAX = shrink to fit
 * (just enough for current contents + a margin); else an exact destination
 * capacity in chunks. hw_keys: 0 = passphrase-only; >0 = open the
 * source with, and enroll one, hardware key on the destination. pin = CTAP2 PIN
 * bytes (may be empty). progress phases: WRITING (allocation), MIGRATE_COPY,
 * MIGRATE_VERIFY. Runs on the calling thread.
 */
int32_t farewell_migrate(
    const char *src_path_utf8,
    const char *dst_path_utf8,
    const uint8_t *passphrase,
    uint64_t passphrase_len,
    uint32_t hw_keys,
    const uint8_t *pin,
    uint64_t pin_len,
    uint64_t new_total_chunks,
    FarewellProgressCb progress,   /* may be NULL */
    void *progress_user_data);

/*
 * Enroll a BACKUP hardware key on an existing vault, in place: afterwards
 * either the original key or this new one unlocks it. Keys are handled ONE AT A
 * TIME on a single USB port (insert current -> touch -> swap -> insert new); the
 * touch is unambiguous because only one key is ever connected. Vault data is not
 * re-encrypted. progress emits AWAIT_INSERT / AWAIT_REMOVE while waiting for the
 * user to plug/unplug and AWAIT_TOUCH around each touch.
 *
 * On success *out_handle receives an ALREADY-OPEN vault (re-mounted internally
 * by replaying the captured key response, so no extra touch). Adopt it like a
 * farewell_open_hw handle and farewell_close it. On a non-OK status out_handle
 * is NULL; if only the convenience re-open failed, the enrollment is still
 * persisted and the vault opens normally.
 *
 * Each key carries its OWN CTAP2 PIN: `pin` is the CURRENT key's PIN (used in
 * step 2a to recover the unwrap secret), `new_pin` is the NEW backup key's PIN
 * (used to enrol it). Never assume they match — applying the wrong PIN would
 * burn a key's limited retry counter. Either may be NULL iff its length is 0
 * (key has no PIN). For the K==0 path (first key on a passphrase-only vault)
 * there is no current key, so `pin` is ignored and only `new_pin` is used.
 *
 * label_utf8 is the new key's human-readable name (NUL-terminated UTF-8); pass
 * NULL or "" for a default ("Key N"). Names over 48 UTF-8 bytes are truncated.
 */
int32_t farewell_add_backup_key(
    const char *path_utf8,
    const uint8_t *passphrase,
    uint64_t passphrase_len,
    const uint8_t *pin,            /* current key's PIN; NULL iff pin_len==0 */
    uint64_t pin_len,
    const uint8_t *new_pin,        /* new key's PIN;     NULL iff new_pin_len==0 */
    uint64_t new_pin_len,
    const char *label_utf8,        /* may be NULL */
    FarewellProgressCb progress,   /* may be NULL */
    void *progress_user_data,
    FarewellVault **out_handle);

/* ----- Keys management (v0.6) ----- */

/* Callback invoked once per enrolled hardware key by farewell_key_list.
 * label_utf8 is valid only during the callback — copy it to keep it. */
typedef void (*FarewellKeyCb)(uint32_t index, const char *label_utf8, void *user_data);

/*
 * List the hardware keys enrolled in a vault — index and name — verifying the
 * passphrase WITHOUT unlocking the content and WITHOUT a hardware touch. cb is
 * invoked once per key in slot order (index 0..K). A passphrase-only vault
 * (K==0) yields no callbacks and still returns FAREWELL_OK. Backs the
 * keys-management panel.
 */
int32_t farewell_key_list(
    const char *path_utf8,
    const uint8_t *passphrase,
    uint64_t passphrase_len,
    FarewellKeyCb cb,
    void *user_data);

/*
 * Revoke the hardware key at `index`, with the passphrase ALONE — no key need
 * be present (the path for a lost or stolen key). The remaining keys still open
 * the vault. Requires the vault to keep at least one key afterwards (K >= 2
 * before removal); removing the LAST key is refused (non-OK), as that
 * conversion to passphrase-only needs the key present. The vault must not be
 * open elsewhere (it is locked exclusively for the write).
 */
int32_t farewell_remove_hw_key(
    const char *path_utf8,
    const uint8_t *passphrase,
    uint64_t passphrase_len,
    uint32_t index);

/*
 * Convert a hardware-protected vault back to PASSPHRASE-ONLY: remove its last
 * remaining key and re-harden the KDF so the passphrase alone opens it again.
 * The key being removed must be PRESENT (one touch) to recover and re-wrap the
 * master. progress emits AWAIT_INSERT then AWAIT_TOUCH while waiting for it.
 *
 * On success *out_handle receives an ALREADY-OPEN vault (re-opened with the
 * passphrase alone — no second touch); adopt it like a farewell_open handle and
 * farewell_close it. On a non-OK status out_handle is NULL; if only the
 * convenience re-open failed, the conversion is still persisted and the vault
 * opens normally with the passphrase. Returns InvalidArgument if the vault is
 * already passphrase-only (K==0).
 *
 * NOTE: opening is slower afterwards (the heavy passphrase-only KDF is
 * restored) — this is the intended security trade, not a regression.
 */
int32_t farewell_convert_to_passphrase_only(
    const char *path_utf8,
    const uint8_t *passphrase,
    uint64_t passphrase_len,
    const uint8_t *pin,
    uint64_t pin_len,
    FarewellProgressCb progress,   /* may be NULL */
    void *progress_user_data,
    FarewellVault **out_handle);

/* ----- Lifecycle (v0.18 / v0.20) ----- */

/*
 * Open a vault file with its passphrase, mounting the content tree.
 *
 * - path_utf8      : NUL-terminated UTF-8 vault path
 * - passphrase     : pointer to passphrase_len raw bytes
 * - passphrase_len : number of valid bytes at `passphrase`
 * - out_handle     : on FAREWELL_OK, set to a non-null handle;
 *                    on error, set to NULL.
 */
int32_t farewell_open(
    const char *path_utf8,
    const uint8_t *passphrase,
    uint64_t passphrase_len,
    FarewellVault **out_handle);

/*
 * Open a vault, threading a connected FIDO2 hardware key when present.
 * Superset of farewell_open — always safe to call:
 *   - no key plugged in  -> behaves exactly like farewell_open
 *   - key present, K=0 vault -> key opened but never used (no touch/PIN)
 *   - key present, K>=1 vault -> triggers a TOUCH; may BLOCK (off-thread!)
 * `pin` (CTAP2) is applied if pin_len > 0; may be NULL iff pin_len == 0.
 * A wrong PIN / un-touched key returns FAREWELL_CRYPTO (indistinguishable
 * from a wrong passphrase, by design). Nothing in the call reveals whether
 * the vault needs a key, so the UI can keep one passphrase field.
 *
 * If more than one key is plugged in while a PIN is supplied, returns
 * FAREWELL_HW_MULTIPLE_KEYS up front (trying the PIN on the wrong key could
 * lock it). progress, if non-NULL, emits AWAIT_TOUCH exactly once just before
 * a real touch is awaited — never for a fast refusal — so the UI can show the
 * "touch your key" prompt only when a touch is genuinely coming.
 */
int32_t farewell_open_hw(
    const char *path_utf8,
    const uint8_t *passphrase,
    uint64_t passphrase_len,
    const uint8_t *pin,
    uint64_t pin_len,
    FarewellProgressCb progress,   /* may be NULL */
    void *progress_user_data,
    FarewellVault **out_handle);

/*
 * Close a handle previously returned by farewell_open. Releases the
 * underlying file (and its advisory flock). Passing NULL is a no-op.
 */
void farewell_close(FarewellVault *handle);

/* ----- Read-only operations (v0.18) ----- */

typedef struct FarewellStat {
    uint64_t size;
} FarewellStat;

/*
 * stat(2) equivalent. Sets *out_stat on success.
 */
int32_t farewell_stat(
    const FarewellVault *handle,
    const char *name_utf8,
    FarewellStat *out_stat);

/*
 * pread(2) equivalent. Writes up to want_len bytes into out_buf and
 * sets *out_actual_len to the number actually written. POSIX-shaped:
 *   - offset >= file size              → returns OK, *out_actual_len = 0
 *   - offset + want_len > file size    → clamps to actual remainder
 *   - want_len == 0                    → returns OK, *out_actual_len = 0
 *                                        (out_buf may be NULL in this case)
 */
int32_t farewell_read_range(
    FarewellVault *handle,
    const char *name_utf8,
    uint64_t offset,
    uint64_t want_len,
    uint8_t *out_buf,
    uint64_t *out_actual_len);

/* ----- Mutation operations (v0.18 Phase B) ----- */

/*
 * POSIX O_CREAT (without O_EXCL): create the file if missing, leave
 * existing content alone if present. Idempotent.
 */
int32_t farewell_create(FarewellVault *handle, const char *name_utf8);

/*
 * POSIX pwrite + automatic extension. Writes data_len bytes at
 * offset. Grows the file when needed; the gap between previous EOF
 * and offset is zero-filled in plaintext (no sparse holes).
 *
 * - data_len == 0 is a no-op (success, no I/O); `data` may be NULL.
 * - File must already exist (call farewell_create first if needed).
 */
int32_t farewell_write_range(
    FarewellVault *handle,
    const char *name_utf8,
    uint64_t offset,
    const uint8_t *data,
    uint64_t data_len);

/*
 * POSIX ftruncate. Shrink frees trailing chunks (cryptographic shred);
 * grow zero-fills via the same path as farewell_write_range.
 */
int32_t farewell_truncate(
    FarewellVault *handle,
    const char *name_utf8,
    uint64_t new_size);

/*
 * POSIX rename. Atomically replace the destination if it exists
 * (destination's chunks are cryptographically shredded). Same-name
 * rename is a no-op.
 */
int32_t farewell_rename(
    FarewellVault *handle,
    const char *old_name_utf8,
    const char *new_name_utf8);

/*
 * POSIX unlink. Secure-deletes the file's chunks (random-fill on
 * disk) and removes its manifest entry.
 */
int32_t farewell_delete(FarewellVault *handle, const char *name_utf8);

/* ----- Folders (organizational; names are slash-separated paths) ----- */

/* Create an (initially empty) folder. Idempotent; path normalized. */
int32_t farewell_create_folder(FarewellVault *handle, const char *path_utf8);

/* Delete a folder and everything under it (files securely shredded). */
int32_t farewell_delete_folder(FarewellVault *handle, const char *path_utf8);

/* Rename a folder (re-prefixes all files under it; metadata only). */
int32_t farewell_rename_folder(
    FarewellVault *handle,
    const char *old_path_utf8,
    const char *new_path_utf8);

/* Enumerate all folders (explicit + implied by file prefixes), sorted.
 * The path pointer is valid only during the callback. */
typedef void (*FarewellFolderCb)(const char *path_utf8, void *user_data);
int32_t farewell_folders(
    const FarewellVault *handle,
    FarewellFolderCb cb,
    void *user_data);

/* ----- Enumeration + introspection (v0.18 Phase C) ----- */

/*
 * One directory entry yielded by farewell_readdir. The string pointer
 * is valid ONLY for the duration of the callback invocation — copy
 * it out if you need to keep it.
 */
typedef struct FarewellDirent {
    const char *name_utf8;  /* NUL-terminated UTF-8 */
    uint64_t    name_len;   /* bytes excluding NUL  */
    uint64_t    size;       /* plaintext size       */
} FarewellDirent;

/*
 * Callback invoked once per file. Must not retain the entry pointer
 * past return. May call other farewell_* functions on the same
 * handle ONLY if those don't mutate the manifest during the
 * enumeration (read-only ops are fine; create/write/etc. are not).
 */
typedef void (*FarewellReaddirCb)(
    const FarewellDirent *entry,
    void *user_data);

/*
 * Enumerate every file in the mounted level, invoking `cb` once
 * per entry with the user-provided context pointer.
 */
int32_t farewell_readdir(
    const FarewellVault *handle,
    FarewellReaddirCb cb,
    void *user_data);

/*
 * Total chunks declared in the vault's public header.
 * Returns 0 if `handle` is NULL.
 */
uint64_t farewell_total_chunks(const FarewellVault *handle);

/*
 * Read the mounted level's monotonic manifest counter (anti-rollback
 * support; see THREAT_MODEL §5.6).
 */
int32_t farewell_counter(
    const FarewellVault *handle,
    uint64_t *out_counter);

/* Maximum hardware keys enrollable per vault (the slot cap). */
#define FAREWELL_MAX_HW_KEYS 3u

/*
 * Read how many hardware keys are enrolled on the open vault
 * (0 = passphrase-only; up to FAREWELL_MAX_HW_KEYS). Lets the UI stop
 * offering "add backup key" once the vault is full.
 */
int32_t farewell_hw_key_count(
    const FarewellVault *handle,
    uint32_t *out_count);

/*
 * Read the opt-in creator identity recorded in the open vault (empty if none).
 * Writes up to buf_len-1 UTF-8 bytes into buf (always NUL-terminated) and sets
 * *out_len to the FULL byte length (excluding NUL) so truncation is detectable.
 * Pass buf = NULL to query the length only. Returns FAREWELL_OK even with no
 * owner (out_len = 0).
 */
int32_t farewell_owner(
    const FarewellVault *handle,
    char *buf,
    uint64_t buf_len,
    uint64_t *out_len);

/*
 * Report the mounted level's usable capacity in plaintext bytes.
 *   *out_total : total usable for file data (excludes manifest chunk)
 *   *out_free  : bytes remaining
 * A file of S bytes fits iff S <= *out_free. Per-level (each level
 * owns total/NUM_SLOTS).
 */
int32_t farewell_space(
    const FarewellVault *handle,
    uint64_t *out_total,
    uint64_t *out_free);

/*
 * Copy the 32-byte vault fingerprint (BLAKE3 of the embedded
 * ML-DSA-87 verifying key) into out_buf. Same value as `farewell info`
 * prints. Caller MUST provide a buffer of at least 32 bytes.
 */
int32_t farewell_fingerprint(
    const FarewellVault *handle,
    uint8_t *out_buf);

/* ----- Audio decoding (in-app viewer) ----- */

/*
 * Opaque streaming PCM decoder. The app reads a file's decrypted bytes
 * into memory (farewell_read_range), hands them here, and pulls
 * interleaved f32 frames to feed AVAudioEngine. Decoding is in-process,
 * in RAM (Symphonia) — no bytes ever hit disk.
 */
typedef struct FarewellAudioDecoder FarewellAudioDecoder;

typedef struct FarewellAudioInfo {
    uint32_t sample_rate;   /* Hz                                   */
    uint16_t channels;      /* interleaved in the read() output     */
    uint16_t _reserved;
    uint64_t total_frames;  /* 0 if unknown                         */
} FarewellAudioInfo;

/*
 * Open in-memory audio bytes for streaming decode. Copies `len` bytes
 * (the decoder owns them), probes the format, fills *out_info. Returns a
 * handle, or NULL if not a supported/parseable audio file.
 * Supported: MP3, AAC/M4A, ALAC, FLAC, Vorbis/Ogg, WAV, AIFF, CAF, PCM.
 */
FarewellAudioDecoder *farewell_audio_open(
    const uint8_t *bytes,
    uint64_t len,
    FarewellAudioInfo *out_info);

/*
 * Pull up to `out_cap` interleaved f32 samples into `out`. Returns the
 * number written (0 = end of stream, < 0 = invalid argument).
 */
int64_t farewell_audio_read(
    FarewellAudioDecoder *dec,
    float *out,
    uint64_t out_cap);

/*
 * Seek so the next read starts at frame `frame`. 0 = success, -1 = fail.
 */
int32_t farewell_audio_seek(FarewellAudioDecoder *dec, uint64_t frame);

/* Free a decoder handle. NULL is a no-op. */
void farewell_audio_close(FarewellAudioDecoder *dec);

/*
 * Decode `bytes` fully and write `buckets` peak-amplitude values in 0.0..=1.0
 * into `out` (caller-allocated, `buckets` floats) for drawing a waveform.
 * Decoded entirely in pure-Rust code, in RAM. Returns FAREWELL_OK on success;
 * on error (e.g. undecodable input) `out` is left untouched.
 */
int32_t farewell_audio_waveform(
    const uint8_t *bytes,
    uint64_t len,
    uint64_t buckets,
    float *out);

/* ----- License (offline activation + status) ----- */

#define FAREWELL_LICENSE_VALID           0  /* a valid license is installed   */
#define FAREWELL_LICENSE_NONE            1  /* none installed                 */
#define FAREWELL_LICENSE_BAD_SIGNATURE   2  /* wrong key / tampered           */
#define FAREWELL_LICENSE_WRONG_VERSION   3  /* for a different major version  */
#define FAREWELL_LICENSE_SERIAL_MISMATCH 4  /* this Mac not authorized        */
#define FAREWELL_LICENSE_MALFORMED       5  /* key/token malformed            */
#define FAREWELL_LICENSE_ERROR           6  /* serial read / I/O error        */

/* license_type / email are meaningful only when verdict == VALID. */
typedef struct {
    int32_t  verdict;        /* one of FAREWELL_LICENSE_*               */
    uint32_t license_type;   /* 0=Single 1=Duo 2=Quintet 3=Grant        */
    uint8_t  email[256];     /* NUL-terminated UTF-8                     */
} FarewellLicenseInfo;

/* Read + verify the installed license against this Mac. Returns FAREWELL_OK
 * whenever it ran; the license verdict is in out->verdict. */
int32_t farewell_license_status(FarewellLicenseInfo *out);

/* Verify a pasted license key (or token) for this Mac and, on success, install
 * it. Fills out->verdict (+ email/type when valid). */
int32_t farewell_license_activate(const char *key_utf8, FarewellLicenseInfo *out);

/* Read this Mac's hardware serial number into out_buf as a NUL-terminated
 * UTF-8 string (cap = capacity incl. terminator). FAREWELL_OK on success;
 * FAREWELL_IO if it couldn't be read. Local only — no network. */
int32_t farewell_read_serial(uint8_t *out_buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* FAREWELL_MOUNT_H */
