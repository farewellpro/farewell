//! Cross-process exclusion via `flock(2)`.
//!
//! Two processes mounting the same `.vault` simultaneously would race
//! on the manifest commit: their in-memory views diverge from disk and
//! the file ends up with one writer's manifest pointing at the other
//! writer's chunks. We avoid that by acquiring a non-blocking
//! advisory exclusive lock on the file descriptor at open time.
//!
//! ## Why `flock(2)` rather than POSIX `fcntl` locks?
//!
//! `flock` locks are bound to the open file description, so two opens
//! of the same path get separate, conflicting locks — which is what we
//! want for cross-process protection. Locks are automatically released
//! when the file is closed (including on process death, including on
//! `SIGKILL`), so a crashed `farewell` doesn't leave the vault
//! permanently locked.
//!
//! `flock` is supported on macOS and Linux with identical semantics for
//! our use; it's not POSIX, but we don't target POSIX-strict systems
//! that lack it. On non-Unix targets (we don't ship any, but the crate
//! should still compile) [`acquire_exclusive`] is a no-op.
//!
//! ## Limitations honestly stated
//!
//! - **Advisory only.** A non-cooperating process that doesn't call
//!   `flock` can still open and modify the file. This protects against
//!   two well-behaved `farewell` invocations, not against malicious
//!   processes that already have write access (which would be a worse
//!   problem anyway).
//! - **Intra-process.** Two `Vault::open` calls in the same process
//!   each get their own file descriptor and each gets its own flock —
//!   they DO conflict (good). What flock does NOT distinguish is
//!   process identity: it sees two open file descriptions as
//!   independent, regardless of whether they live in the same PID.
//! - **NFS and some network filesystems** have flaky `flock` support.
//!   Don't store a `.vault` on NFS.

use std::fs::File;

use crate::{FormatError, Result};

#[cfg(unix)]
#[allow(unsafe_code)] // one syscall, audited; see lib.rs preamble
pub(crate) fn acquire_exclusive(file: &File) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();
    // LOCK_EX = exclusive; LOCK_NB = fail-fast rather than block.
    // Safety: `fd` is owned by `file` and remains valid for the
    // duration of this call. `flock` is `extern "C"` with no
    // pointer parameters, so memory safety is trivially preserved.
    let r = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if r == 0 {
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        // On macOS and Linux EWOULDBLOCK == EAGAIN, but be explicit
        // about both to survive any future divergence.
        Some(e) if e == libc::EWOULDBLOCK || e == libc::EAGAIN => Err(FormatError::AlreadyLocked),
        _ => Err(FormatError::Io(err)),
    }
}

#[cfg(not(unix))]
pub(crate) fn acquire_exclusive(_file: &File) -> Result<()> {
    // No-op on non-Unix targets. We do not ship for Windows; if and
    // when we do, this gets a real implementation using LockFileEx.
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::tempdir;

    fn make_file() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let p = dir.path().join("lock.bin");
        let mut f = File::create(&p).unwrap();
        f.write_all(b"x").unwrap();
        (dir, p)
    }

    #[test]
    fn first_open_acquires_lock() {
        let (_dir, p) = make_file();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        acquire_exclusive(&f).expect("first open should succeed");
    }

    #[test]
    fn second_open_via_separate_fd_collides() {
        let (_dir, p) = make_file();
        let f1 = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        acquire_exclusive(&f1).unwrap();

        // A second OPEN gets a separate "open file description"; flock
        // treats it as independent and refuses the lock. This mimics
        // the cross-process scenario.
        let f2 = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        let err = acquire_exclusive(&f2).unwrap_err();
        assert!(
            matches!(err, FormatError::AlreadyLocked),
            "expected AlreadyLocked, got {err:?}"
        );
    }

    #[test]
    fn lock_releases_when_file_dropped() {
        let (_dir, p) = make_file();
        {
            let f1 = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&p)
                .unwrap();
            acquire_exclusive(&f1).unwrap();
            // Drop at end of block releases.
        }
        let f2 = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        acquire_exclusive(&f2).expect("after drop, lock should be free");
    }
}
