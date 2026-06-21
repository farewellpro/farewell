//! End-to-end probe of a real FIDO2 authenticator.
//!
//! Usage:
//!     cargo run --example yubikey_probe -p farewell_fido2 [-- --pin <PIN>]
//!
//! This opens the first connected FIDO device, enrolls a fresh
//! credential, runs hmac-secret twice on the same salt to check
//! determinism, then runs it once with a different salt to check
//! independence. Each prompt asks you to touch the key.
//!
//! The enrolled credential is left on the authenticator. YubiKeys
//! support hundreds of non-resident credentials in their key wrapping
//! pool, so there is no leak. To clear it later, run
//! `ykman fido reset` (destructive — wipes all FIDO data on the key).

use std::env;

use farewell_fido2::{Authenticator, HidAuthenticator, HMAC_SALT_LEN};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let pin = parse_pin(&args);

    println!("== Farewell FIDO2 probe ==");
    println!();
    println!("This will:");
    println!("  1. Open the first connected FIDO2 authenticator");
    println!("  2. Enroll a new non-discoverable credential (you'll be asked to touch the key)");
    println!("  3. Run hmac-secret twice with the same salt → expect identical output");
    println!("  4. Run hmac-secret with a different salt → expect different output");
    println!();

    println!("[1/5] Opening authenticator...");
    let mut auth = HidAuthenticator::open_first("farewell.foundation")?;
    if let Some(p) = pin {
        println!("       Setting CTAP2 PIN");
        auth.set_pin(p);
    }
    println!("       OK (rp_id = {})", auth.rp_id());
    println!();

    println!("[2/5] Enrolling a credential. TOUCH THE KEY when it blinks.");
    let cred = auth.enroll(b"farewell-probe-handle")?;
    println!("       OK — credential ID is {} bytes", cred.len());
    println!("       cred (hex prefix): {}", hex_short(&cred));
    println!();

    let salt_a: [u8; HMAC_SALT_LEN] = [0xA5; HMAC_SALT_LEN];
    let salt_b: [u8; HMAC_SALT_LEN] = [0xB7; HMAC_SALT_LEN];

    println!("[3/5] hmac-secret with salt_a, attempt 1. TOUCH THE KEY.");
    let (used_1, out_1) = auth.challenge_response(&[cred.clone()], &salt_a)?;
    println!("       OK — used cred matches: {}", used_1 == cred);
    println!("       output (hex prefix): {}", hex_short(&out_1));
    println!();

    println!("[4/5] hmac-secret with salt_a, attempt 2 (determinism check). TOUCH THE KEY.");
    let (_, out_2) = auth.challenge_response(&[cred.clone()], &salt_a)?;
    println!("       output (hex prefix): {}", hex_short(&out_2));
    println!();

    let determinism_ok = out_1 == out_2;
    println!("[5/5] hmac-secret with salt_b (salt independence). TOUCH THE KEY.");
    let (_, out_3) = auth.challenge_response(&[cred.clone()], &salt_b)?;
    println!("       output (hex prefix): {}", hex_short(&out_3));
    let independence_ok = out_1 != out_3;
    println!();

    println!("== Results ==");
    println!("  Determinism (same salt → same output):    {}", check(determinism_ok));
    println!("  Independence (different salt → different): {}", check(independence_ok));

    if determinism_ok && independence_ok {
        println!();
        println!("All checks passed. The authenticator implements hmac-secret correctly");
        println!("and is suitable for use with Farewell.");
        Ok(())
    } else {
        Err("hmac-secret behaviour does not match expectations".into())
    }
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

fn check(ok: bool) -> &'static str {
    if ok {
        "OK"
    } else {
        "FAIL"
    }
}
