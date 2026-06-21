//! Hardware serial-number reading.
//!
//! On macOS, this shells out to `ioreg -d2 -c IOPlatformExpertDevice`
//! and extracts the value of the `IOPlatformSerialNumber` property. The
//! resulting string is identical to what Apple menu → About this Mac
//! displays as the Serial Number. No private API, no kext, no
//! entitlement.
//!
//! Why `ioreg` instead of `system_profiler`? Starting on macOS Tahoe
//! (26), `system_profiler -detailLevel mini SPHardwareDataType` hides
//! the serial as a privacy hardening. `ioreg` reads the same IOKit
//! property directly and stays stable across versions — it is the
//! underlying source `system_profiler` itself uses.
//!
//! On non-macOS targets, the production reader returns
//! [`LicenseError::SerialReadFailed`]: Farewell licenses are macOS-bound
//! for v1.0. The trait nonetheless exposes [`StaticSerialReader`] so
//! that tests on Linux/CI can exercise the verification path with an
//! injected serial.

use std::process::Command;

use crate::LicenseError;

/// Abstract source of "this machine's hardware serial number". The
/// real macOS implementation talks to `system_profiler`; tests use
/// [`StaticSerialReader`] to inject a deterministic value.
pub trait SerialReader {
    /// Return the hardware serial number, or an error if it cannot
    /// be read (Hackintosh, VM stripped of identifiers, permission
    /// problem on some hardened sandbox, …).
    fn read_serial(&self) -> Result<String, LicenseError>;
}

/// Production reader for macOS. Reads `IOPlatformSerialNumber` from
/// IOKit by shelling out to `ioreg`.
///
/// We do not link directly against IOKit (which would require `unsafe`
/// bindings and pull a non-trivial dependency); `ioreg` is on every
/// Mac, returns exactly the IOKit property value, has stable output
/// format across macOS versions, and runs read-only with no
/// entitlement requirements.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosSerialReader;

impl SerialReader for MacosSerialReader {
    fn read_serial(&self) -> Result<String, LicenseError> {
        if !cfg!(target_os = "macos") {
            return Err(LicenseError::SerialReadFailed(
                "MacosSerialReader called on non-macOS target".into(),
            ));
        }

        // `-d 2` limits depth (enough to reach IOPlatformExpertDevice's
        // properties). `-c IOPlatformExpertDevice` filters to that
        // class only.
        let output = Command::new("ioreg")
            .args(["-d", "2", "-c", "IOPlatformExpertDevice"])
            .output()
            .map_err(|e| LicenseError::SerialReadFailed(format!("spawn ioreg: {e}")))?;

        if !output.status.success() {
            return Err(LicenseError::SerialReadFailed(format!(
                "ioreg exited with {:?}",
                output.status.code()
            )));
        }

        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            // Lines look like:
            //     "IOPlatformSerialNumber" = "LV6M5Q6WYC"
            if let Some(value) = extract_ioreg_value(line, "IOPlatformSerialNumber") {
                if !value.is_empty() && value != "Not Available" {
                    return Ok(value.to_string());
                }
            }
        }

        Err(LicenseError::SerialReadFailed(
            "no IOPlatformSerialNumber property found in ioreg output".into(),
        ))
    }
}

/// Extract the quoted value of `key` from an `ioreg` line of the form
/// `    "key" = "value"`. Returns `None` if the line does not refer to
/// the requested key or is malformed.
fn extract_ioreg_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let line = line.trim();
    let key_quoted = format!("\"{key}\"");
    let after_key = line.strip_prefix(&key_quoted)?;
    let after_eq = after_key.trim_start().strip_prefix('=')?.trim_start();
    let after_eq = after_eq.strip_prefix('"')?;
    after_eq.strip_suffix('"')
}

/// Test-only reader that always returns a fixed string.
#[derive(Debug, Clone)]
pub struct StaticSerialReader(pub String);

impl StaticSerialReader {
    /// Convenience constructor that takes any string-like value.
    pub fn new(serial: impl Into<String>) -> Self {
        Self(serial.into())
    }
}

impl SerialReader for StaticSerialReader {
    fn read_serial(&self) -> Result<String, LicenseError> {
        Ok(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_reader_returns_injected_value() {
        let r = StaticSerialReader::new("FAKE-SN-123");
        assert_eq!(r.read_serial().unwrap(), "FAKE-SN-123");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reader_finds_a_serial_on_real_mac() {
        // On a real Mac this should succeed. On CI without macOS,
        // this test is compiled away by the cfg gate.
        let r = MacosSerialReader;
        let sn = r.read_serial().expect("ioreg should work on macOS");
        assert!(!sn.is_empty());
        assert!(sn.is_ascii());
        // Apple serial numbers are typically 10-12 alphanumeric chars,
        // but we don't hardcode that range — just sanity check.
        assert!(sn.len() >= 8 && sn.len() <= 32, "unexpected SN length: {sn:?}");
    }

    #[test]
    fn extract_ioreg_value_parses_canonical_line() {
        let line = r#"    "IOPlatformSerialNumber" = "LV6M5Q6WYC""#;
        assert_eq!(extract_ioreg_value(line, "IOPlatformSerialNumber"), Some("LV6M5Q6WYC"));
    }

    #[test]
    fn extract_ioreg_value_returns_none_for_wrong_key() {
        let line = r#"    "IOPlatformSerialNumber" = "LV6M5Q6WYC""#;
        assert_eq!(extract_ioreg_value(line, "IOPlatformUUID"), None);
    }

    #[test]
    fn extract_ioreg_value_handles_extra_whitespace() {
        let line = r#"      "IOPlatformSerialNumber"   =   "ABC123""#;
        assert_eq!(extract_ioreg_value(line, "IOPlatformSerialNumber"), Some("ABC123"));
    }
}
