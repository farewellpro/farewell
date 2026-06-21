//! End-to-end vault roundtrip against a physically-connected YubiKey.
//!
//! Validates the full cryptographic chain:
//!
//!     passphrase ─KDF─► passphrase_key ─┐
//!                                       ├─► combine ─► KWK ─► master_key ─► chunks
//!     YubiKey hmac-secret(salt) ────────┘
//!
//! Usage:
//!     cargo run --example yubikey_vault_e2e -p farewell_format --release [-- --pin <PIN>]
//!
//! Expect ~6 touches on the YubiKey across the run:
//!   - 2× at enroll (PIN UV + UP)
//!   - 2× at initial enroll-time hmac-secret (PIN UV + UP)
//!   - 2× at the unlock-time hmac-secret after reopen (PIN UV + UP)
//!
//! The vault file is created in a temp directory and deleted at the end.

use std::env;
use std::fs;

use farewell_crypto::rng;
use farewell_fido2::HidAuthenticator;
use farewell_format::{
    enroll_hw_key, LevelEnrollment, LevelSpec, Vault, VaultBuilder,
};

const PASSPHRASE: &[u8] = b"correct horse battery staple";
const USER_HANDLE: &[u8] = b"farewell-e2e-user";
const VAULT_NAME: &str = "yubikey-e2e.vault";
const FILE_NAME: &str = "manifesto.txt";
const FILE_CONTENT: &[u8] =
    b"This text is encrypted under a key derived from \
      both a passphrase AND the YubiKey's hmac-secret output. \
      Neither alone is enough to decrypt this file.";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let pin = parse_pin(&args);

    let tmpdir = std::env::temp_dir().join(format!(
        "farewell-e2e-{}",
        std::process::id()
    ));
    fs::create_dir_all(&tmpdir)?;
    let path = tmpdir.join(VAULT_NAME);

    println!("== Farewell vault E2E with real YubiKey ==");
    println!();
    println!("Vault file: {}", path.display());
    println!("Passphrase: <fixed test value>");
    println!();
    println!("This will exercise the full vault stack:");
    println!("  enroll → build → write → close → reopen → read → verify");
    println!();
    println!("Expect 6 touches on the YubiKey.");
    println!();

    // ---- Phase 1: open authenticator ----
    println!("[1/7] Opening authenticator…");
    let mut auth = HidAuthenticator::open_first("farewell.foundation")?;
    if let Some(p) = &pin {
        auth.set_pin(p.clone());
        println!("       PIN supplied (clientPin assumed).");
    } else {
        println!("       No PIN supplied. If the key has clientPin: true, enrolment will fail.");
    }

    // ---- Phase 2: enroll credential and capture initial hmac_output ----
    println!();
    println!("[2/7] Enrolling credential + capturing initial hmac-secret.");
    println!("       Touch the YubiKey when it blinks (up to 4 times here).");
    let vault_salt: [u8; 32] = rng::bytes(32)?.as_slice().try_into()?;
    let (cred_id, hmac_output) = enroll_hw_key(&mut auth, &vault_salt, USER_HANDLE)?;
    println!("       OK — credential is {} bytes.", cred_id.len());
    println!("       cred (hex prefix): {}", hex_short(&cred_id));
    println!("       hmac_output (hex prefix): {}", hex_short(&hmac_output));

    // ---- Phase 3: build vault ----
    println!();
    println!("[3/7] Building vault on disk (K=1, single level)…");
    let mut enrollment = LevelEnrollment::passphrase_only();
    enrollment.push(cred_id.clone(), hmac_output)?;
    let spec = LevelSpec {
        passphrase: PASSPHRASE.to_vec(),
        enrollment,
    };
    let mut vault = VaultBuilder::new(&path, vec![spec])?
        .with_salt(vault_salt)
        .total_chunks(16)
        .build()?;
    println!("       OK — vault file size: {} bytes",
        fs::metadata(&path)?.len());

    // The freshly-built vault is unmounted (no level mounted yet).
    // We need to re-open it to actually store a file. Drop and reopen.
    drop(vault);

    // ---- Phase 4: re-open with passphrase + YubiKey, add a file ----
    println!();
    println!("[4/7] Re-opening with passphrase + YubiKey. TOUCH THE KEY (~2×).");
    vault = Vault::open(
        &path,
        PASSPHRASE.to_vec(),
        Some(&mut auth),
    )?;
    println!("       OK — vault unlocked.");

    println!();
    println!("[5/7] Adding file '{FILE_NAME}' ({} bytes)…", FILE_CONTENT.len());
    vault.add_file(FILE_NAME, FILE_CONTENT.to_vec())?;
    let listed: Vec<String> =
        vault.list().iter().map(|e| e.name.clone()).collect();
    println!("       OK — vault now contains: {:?}", listed);
    drop(vault);

    // ---- Phase 6: re-open fresh, read the file back ----
    println!();
    println!("[6/7] Re-opening from disk (cold reopen). TOUCH THE KEY (~2×).");
    let mut vault2 = Vault::open(
        &path,
        PASSPHRASE.to_vec(),
        Some(&mut auth),
    )?;
    let recovered = vault2.read_file(FILE_NAME)?;
    println!("       OK — read {} bytes back.", recovered.len());

    // ---- Phase 7: verify ----
    println!();
    println!("[7/7] Verifying content matches…");
    if recovered == FILE_CONTENT {
        println!("       OK — bytes match exactly.");
    } else {
        return Err(format!(
            "MISMATCH: expected {} bytes, got {} bytes\nexpected start: {:?}\ngot start:      {:?}",
            FILE_CONTENT.len(),
            recovered.len(),
            &FILE_CONTENT[..32.min(FILE_CONTENT.len())],
            &recovered[..32.min(recovered.len())]
        )
        .into());
    }

    // Cleanup.
    drop(vault2);
    fs::remove_file(&path).ok();
    fs::remove_dir(&tmpdir).ok();

    println!();
    println!("== ALL CHECKS PASSED ==");
    println!();
    println!("The full vault stack is validated against real hardware:");
    println!("  • CTAP2 hmac-secret extension works on this YubiKey.");
    println!("  • Enrollment captures a stable hmac_output for the vault salt.");
    println!("  • Cold unlock recovers the master key correctly.");
    println!("  • Encrypted file content decrypts byte-for-byte.");
    Ok(())
}

fn parse_pin(args: &[String]) -> Option<String> {
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--pin" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        i += 1;
    }
    None
}

fn hex_short(bytes: &[u8]) -> String {
    let n = bytes.len().min(16);
    let mut s = String::with_capacity(n * 2 + 4);
    for b in &bytes[..n] {
        s.push_str(&format!("{:02x}", b));
    }
    if bytes.len() > n {
        s.push_str("...");
    }
    s
}
