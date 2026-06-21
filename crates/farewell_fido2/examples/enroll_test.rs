//! Isolated YubiKey enrolment reproduction.
//!
//! Exactly the two FIDO2 operations Farewell does at enrolment, with a
//! log around each — nothing else (no KDF, no vault format, no app). Use
//! it to pin down why the SECOND touch "does nothing".
//!
//! Run it from YOUR terminal (so you can touch the key + type the PIN):
//!
//!   cargo run --release -p farewell_fido2 --example enroll_test
//!
//! It prompts for the PIN (typed into this process's stdin — not argv,
//! not logged), then asks for two touches. Paste the whole output back.

use std::io::{self, BufRead, Write};
use std::time::Instant;

use farewell_fido2::{Authenticator, HidAuthenticator, HMAC_SALT_LEN};

fn main() {
    eprint!("YubiKey PIN (leave blank if none): ");
    io::stderr().flush().ok();
    let mut pin = String::new();
    io::stdin().lock().read_line(&mut pin).unwrap();
    let pin = pin.trim_end_matches(['\n', '\r']).to_string();

    println!("Opening the key…");
    let mut auth = match HidAuthenticator::open_first("farewell.foundation") {
        Ok(a) => a,
        Err(e) => {
            println!("open failed: {e}");
            return;
        }
    };
    if !pin.is_empty() {
        auth.set_pin(pin);
    }

    println!("\n[1/2] make_credential — TOUCH the key now (it should blink)…");
    let t = Instant::now();
    let cred = match auth.enroll(b"farewell-enroll-test") {
        Ok(c) => c,
        Err(e) => {
            println!("    make_credential FAILED after {:?}: {e}", t.elapsed());
            return;
        }
    };
    println!("    OK in {:?} (credential id = {} bytes)", t.elapsed(), cred.len());

    println!(
        "\n[2/2] get_assertion (hmac-secret) — TOUCH the key AGAIN now (it should blink again)…"
    );
    let salt = [0x42u8; HMAC_SALT_LEN];
    let t = Instant::now();
    match auth.challenge_response(&[cred.clone()], &salt) {
        Ok((_, out)) => {
            println!("    OK in {:?} (hmac-secret = {} bytes)", t.elapsed(), out.len());
            println!("\n=> BOTH steps succeeded. Enrolment FIDO flow is fine.");
        }
        Err(e) => {
            println!("    get_assertion FAILED after {:?}: {e}", t.elapsed());
            println!("\n=> The SECOND operation is the problem. Error above is the clue.");
        }
    }
}
