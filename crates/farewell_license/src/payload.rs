//! Binary payload of a license.
//!
//! Layout (little-endian where applicable):
//!
//! ```text
//! offset  size  field            description
//! ──────  ────  ───────────────  ──────────────────────────────────────────
//!   0      4   magic            = b"FLW1"  (Farewell License v1)
//!   4      1   payload_version  = 1
//!   5      1   license_type     LicenseType discriminant
//!   6      4   major_version    Farewell major version this license is for
//!  10      8   purchased_unix   Unix timestamp (i64) of purchase
//!  18     16   license_id       Opaque 128-bit id (e.g. UUID v4 bytes)
//!  34      2   email_len        u16 length of UTF-8 email bytes
//!  36     ..   email_bytes      UTF-8 encoded buyer email
//!   +      1   num_serials      Count of bound hardware serials (>= 1)
//!   +      ..  serials          Repeated num_serials times:
//!                                  - u8 sn_len
//!                                  - sn_len ASCII bytes
//! ```
//!
//! The signing key signs over the entire payload as a contiguous byte
//! slice. No JSON, no whitespace, no canonicalization ambiguity — the
//! bytes either match or they don't.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};

use crate::LicenseError;

/// Magic 4-byte prefix of every license payload. Lets `farewell info` or
/// human inspection identify a stray license blob.
pub const PAYLOAD_MAGIC: [u8; 4] = *b"FLW1";

/// Major version of Farewell this build of `farewell_license` is
/// compatible with. Bump in lockstep with `farewell_format::FORMAT_VERSION`
/// when we ship Farewell 2.0.
pub const MAJOR_VERSION_CURRENT: u32 = 1;

const PAYLOAD_VERSION: u8 = 1;

/// Edition / tier of a license. Mirrors the public pricing plans.
///
/// Every tier is hardware-bound to at least one Mac serial number — there
/// is no honor-system / serial-less tier. `Grant` (the free license for
/// at-risk users) is bound exactly like a paid `Single`; it simply costs
/// nothing and is not advertised in the public pricing panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LicenseType {
    /// 49 € — individual user, 1 Mac.
    Single = 0,
    /// 69 € — individual user, up to 2 Macs.
    Duo = 1,
    /// 129 € — up to 5 Macs (small team / household).
    Quintet = 2,
    /// Free license for at-risk users (journalists, dissidents,
    /// whistleblowers). 1 Mac, bound to a serial like any other tier;
    /// not shown in the public pricing panel.
    Grant = 3,
}

impl LicenseType {
    /// Decode a tier discriminant byte.
    pub fn from_u8(v: u8) -> Result<Self, LicenseError> {
        match v {
            0 => Ok(LicenseType::Single),
            1 => Ok(LicenseType::Duo),
            2 => Ok(LicenseType::Quintet),
            3 => Ok(LicenseType::Grant),
            other => Err(LicenseError::UnknownLicenseType(other)),
        }
    }

    /// Maximum hardware-bound serials the tier permits at issue time.
    /// Every tier requires at least one (see [`min_devices`]); the signed
    /// payload is the source of truth.
    ///
    /// [`min_devices`]: LicenseType::min_devices
    pub fn max_devices_hint(&self) -> u8 {
        match self {
            LicenseType::Single => 1,
            LicenseType::Duo => 2,
            LicenseType::Quintet => 5,
            LicenseType::Grant => 1,
        }
    }

    /// Minimum hardware-bound serials a valid license of this tier must
    /// carry. Currently 1 for every tier — no serial-less licenses exist.
    pub fn min_devices(&self) -> u8 {
        match self {
            LicenseType::Single => 1,
            LicenseType::Duo => 1,
            LicenseType::Quintet => 1,
            LicenseType::Grant => 1,
        }
    }
}

/// Decoded license payload. The buyer email is kept verbatim — it is the
/// canonical identifier of the license holder and is displayed prominently
/// in the app (mild social deterrent to casual sharing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// Tier of the license.
    pub license_type: LicenseType,
    /// Major version of Farewell this license is valid for.
    pub major_version: u32,
    /// Unix timestamp (seconds since epoch) of purchase.
    pub purchased_unix: i64,
    /// Opaque 128-bit identifier of this specific license issuance.
    pub license_id: [u8; 16],
    /// Buyer's email, as captured at Stripe checkout.
    pub email: String,
    /// Hardware serial numbers (ASCII) the license is bound to. Every
    /// tier binds at least one Mac; an empty list is not a valid license.
    pub bound_serials: Vec<String>,
}

impl Payload {
    /// Serialize to the canonical byte layout described at the top of the
    /// module. The output is what gets signed by the issuing key and what
    /// the verifying key checks the signature against.
    pub fn to_bytes(&self) -> Result<Vec<u8>, LicenseError> {
        let mut out = Vec::with_capacity(64 + self.email.len() + 16 * self.bound_serials.len());
        out.write_all(&PAYLOAD_MAGIC)?;
        out.write_u8(PAYLOAD_VERSION)?;
        out.write_u8(self.license_type as u8)?;
        out.write_u32::<LittleEndian>(self.major_version)?;
        out.write_i64::<LittleEndian>(self.purchased_unix)?;
        out.write_all(&self.license_id)?;

        let email_bytes = self.email.as_bytes();
        // u16 is enough: 65,535 bytes of email would be absurd.
        let email_len = u16::try_from(email_bytes.len())
            .map_err(|_| LicenseError::Truncated { needed: 0 })?;
        out.write_u16::<LittleEndian>(email_len)?;
        out.write_all(email_bytes)?;

        let n_serials = u8::try_from(self.bound_serials.len())
            .map_err(|_| LicenseError::Truncated { needed: 0 })?;
        out.write_u8(n_serials)?;
        for sn in &self.bound_serials {
            if !sn.is_ascii() {
                return Err(LicenseError::SerialNotAscii);
            }
            let sn_len = u8::try_from(sn.len())
                .map_err(|_| LicenseError::Truncated { needed: 0 })?;
            out.write_u8(sn_len)?;
            out.write_all(sn.as_bytes())?;
        }

        Ok(out)
    }

    /// Deserialize from the canonical byte layout. The caller is
    /// responsible for verifying the signature *before* trusting any
    /// field returned here.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LicenseError> {
        let mut cur = Cursor::new(bytes);

        let mut magic = [0u8; 4];
        read_exact(&mut cur, &mut magic)?;
        if magic != PAYLOAD_MAGIC {
            return Err(LicenseError::BadMagic(magic));
        }

        let payload_ver = cur.read_u8().map_err(io_truncate)?;
        if payload_ver != PAYLOAD_VERSION {
            return Err(LicenseError::PayloadVersion {
                got: payload_ver,
                expected: PAYLOAD_VERSION,
            });
        }

        let lt_byte = cur.read_u8().map_err(io_truncate)?;
        let license_type = LicenseType::from_u8(lt_byte)?;

        let major_version = cur.read_u32::<LittleEndian>().map_err(io_truncate)?;
        let purchased_unix = cur.read_i64::<LittleEndian>().map_err(io_truncate)?;

        let mut license_id = [0u8; 16];
        read_exact(&mut cur, &mut license_id)?;

        let email_len = cur.read_u16::<LittleEndian>().map_err(io_truncate)? as usize;
        let mut email_bytes = vec![0u8; email_len];
        read_exact(&mut cur, &mut email_bytes)?;
        let email = String::from_utf8(email_bytes).map_err(|_| LicenseError::EmailNotUtf8)?;

        let n_serials = cur.read_u8().map_err(io_truncate)? as usize;
        let mut bound_serials = Vec::with_capacity(n_serials);
        for _ in 0..n_serials {
            let sn_len = cur.read_u8().map_err(io_truncate)? as usize;
            let mut sn_bytes = vec![0u8; sn_len];
            read_exact(&mut cur, &mut sn_bytes)?;
            if !sn_bytes.is_ascii() {
                return Err(LicenseError::SerialNotAscii);
            }
            // Safe: ASCII bytes are valid UTF-8.
            bound_serials.push(String::from_utf8(sn_bytes).unwrap());
        }

        Ok(Self {
            license_type,
            major_version,
            purchased_unix,
            license_id,
            email,
            bound_serials,
        })
    }
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), LicenseError> {
    r.read_exact(buf).map_err(|_| LicenseError::Truncated { needed: buf.len() })
}

fn io_truncate(_e: std::io::Error) -> LicenseError {
    LicenseError::Truncated { needed: 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> Payload {
        Payload {
            license_type: LicenseType::Duo,
            major_version: 1,
            purchased_unix: 1_780_000_000,
            license_id: [0xAB; 16],
            email: "alice@example.com".to_string(),
            bound_serials: vec!["C02XK1XHJG5J".to_string(), "FVH213XHQ9".to_string()],
        }
    }

    #[test]
    fn roundtrip_duo() {
        let p = sample_payload();
        let bytes = p.to_bytes().unwrap();
        let back = Payload::from_bytes(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn roundtrip_grant_single_serial() {
        let p = Payload {
            license_type: LicenseType::Grant,
            major_version: 1,
            purchased_unix: 1_780_000_001,
            license_id: [0; 16],
            email: "grant@rsf.org".to_string(),
            bound_serials: vec!["C02XK1XHJG5J".to_string()],
        };
        let bytes = p.to_bytes().unwrap();
        let back = Payload::from_bytes(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = sample_payload().to_bytes().unwrap();
        bytes[0] = b'X';
        assert!(matches!(
            Payload::from_bytes(&bytes),
            Err(LicenseError::BadMagic(_))
        ));
    }

    #[test]
    fn rejects_unknown_license_type() {
        let mut bytes = sample_payload().to_bytes().unwrap();
        bytes[5] = 99; // license_type field is at offset 5
        assert!(matches!(
            Payload::from_bytes(&bytes),
            Err(LicenseError::UnknownLicenseType(99))
        ));
    }

    #[test]
    fn rejects_truncated() {
        let bytes = sample_payload().to_bytes().unwrap();
        let truncated = &bytes[..bytes.len() - 5];
        assert!(matches!(
            Payload::from_bytes(truncated),
            Err(LicenseError::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_non_ascii_serial() {
        let bad = Payload {
            license_type: LicenseType::Single,
            major_version: 1,
            purchased_unix: 0,
            license_id: [0; 16],
            email: "x@y.z".to_string(),
            bound_serials: vec!["café-serial".to_string()],
        };
        assert!(matches!(bad.to_bytes(), Err(LicenseError::SerialNotAscii)));
    }
}
