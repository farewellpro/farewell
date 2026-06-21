//! Local storage of an activated license.
//!
//! Farewell stores the user's license token on disk in PEM-framed
//! form, in `~/Library/Application Support/Farewell/license.flw` on
//! macOS or `$XDG_CONFIG_HOME/farewell/license.flw` on Linux. The
//! file contains nothing secret: the signed token is already public
//! information (the user paid for it and can email it to themselves).

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::token::wrap_pem;
use crate::LicenseError;

/// Trait for getting/setting the active license token. Abstracted so
/// that tests can use [`tempfile`-like temporary directories] without
/// touching the user's real Application Support folder.
pub trait LicenseStore {
    /// Read the currently-activated license token, or `None` if no
    /// license is installed yet.
    fn load(&self) -> Result<Option<String>, LicenseError>;

    /// Write the license token, overwriting any previous one.
    fn save(&self, token: &str) -> Result<(), LicenseError>;

    /// Delete the license file. No-op if no license is installed.
    fn clear(&self) -> Result<(), LicenseError>;
}

/// Filesystem-backed license store. The license file is created with
/// permissions `0o600` on Unix to discourage casual leakage on shared
/// machines.
#[derive(Debug, Clone)]
pub struct FileLicenseStore {
    path: PathBuf,
}

impl FileLicenseStore {
    /// Construct a store at an explicit path. Use [`Self::default_for_user`]
    /// to pick the canonical OS-specific location.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Default path:
    /// - macOS: `~/Library/Application Support/Farewell/license.flw`
    /// - Linux: `$XDG_CONFIG_HOME/farewell/license.flw` or
    ///          `~/.config/farewell/license.flw`
    pub fn default_for_user() -> Result<Self, LicenseError> {
        let base = default_dir()?;
        Ok(Self::new(base.join("license.flw")))
    }

    /// Returns the on-disk path. Useful for `farewell license-status`
    /// to tell the user where the file lives.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl LicenseStore for FileLicenseStore {
    fn load(&self) -> Result<Option<String>, LicenseError> {
        match fs::read_to_string(&self.path) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(LicenseError::Io(e)),
        }
    }

    fn save(&self, token: &str) -> Result<(), LicenseError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let pem = wrap_pem(token.trim());

        // Write atomically: tmp file in the same dir, then rename.
        let tmp = self.path.with_extension("flw.tmp");
        {
            let mut f = open_owner_rw(&tmp)?;
            f.write_all(pem.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    fn clear(&self) -> Result<(), LicenseError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(LicenseError::Io(e)),
        }
    }
}

#[cfg(unix)]
fn open_owner_rw(path: &Path) -> Result<fs::File, LicenseError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    Ok(fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(not(unix))]
fn open_owner_rw(path: &Path) -> Result<fs::File, LicenseError> {
    Ok(fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?)
}

fn default_dir() -> Result<PathBuf, LicenseError> {
    if cfg!(target_os = "macos") {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| io_other("$HOME is not set"))?;
        let mut p = PathBuf::from(home);
        p.push("Library");
        p.push("Application Support");
        p.push("Farewell");
        Ok(p)
    } else {
        let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            PathBuf::from(xdg)
        } else {
            let home = std::env::var_os("HOME")
                .ok_or_else(|| io_other("$HOME is not set"))?;
            let mut p = PathBuf::from(home);
            p.push(".config");
            p
        };
        Ok(base.join("farewell"))
    }
}

fn io_other(msg: &str) -> LicenseError {
    LicenseError::Io(std::io::Error::new(std::io::ErrorKind::Other, msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal "tempdir" without an extra dependency: a directory
    /// under `std::env::temp_dir()` with a randomish name.
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            // A process-global monotonic counter guarantees uniqueness
            // even when tests run concurrently in the same process
            // (same pid, and the nanosecond clock can repeat). The
            // previous pid+nanos scheme collided intermittently.
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let mut p = std::env::temp_dir();
            p.push(format!(
                "farewell_license_test_{}_{nanos}_{seq}",
                std::process::id()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn load_returns_none_when_missing() {
        let dir = TmpDir::new();
        let s = FileLicenseStore::new(dir.path().join("license.flw"));
        assert!(s.load().unwrap().is_none());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = TmpDir::new();
        let s = FileLicenseStore::new(dir.path().join("license.flw"));
        let token = "abc.def";
        s.save(token).unwrap();
        let read_back = s.load().unwrap().unwrap();
        assert!(read_back.contains("-----BEGIN FAREWELL LICENSE-----"));
        assert!(read_back.contains("abc.def"));
    }

    #[test]
    fn save_overwrites_previous() {
        let dir = TmpDir::new();
        let s = FileLicenseStore::new(dir.path().join("license.flw"));
        s.save("first.signature").unwrap();
        s.save("second.signature").unwrap();
        let read_back = s.load().unwrap().unwrap();
        assert!(read_back.contains("second.signature"));
        assert!(!read_back.contains("first.signature"));
    }

    #[test]
    fn clear_removes_the_file() {
        let dir = TmpDir::new();
        let s = FileLicenseStore::new(dir.path().join("license.flw"));
        s.save("abc.def").unwrap();
        s.clear().unwrap();
        assert!(s.load().unwrap().is_none());
        // Idempotent: clearing again is fine.
        s.clear().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_owner_only_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TmpDir::new();
        let path = dir.path().join("license.flw");
        let s = FileLicenseStore::new(&path);
        s.save("abc.def").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
    }
}
