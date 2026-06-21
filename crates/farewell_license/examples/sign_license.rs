//! Tiny SRL-side reference signer.
//!
//! Generates a fresh P-256 keypair (so each run is self-contained),
//! signs a sample Duo license, and prints both keys + the token.
//! Useful for:
//!
//! - Smoke-testing the workspace after changes (`cargo run --example
//!   sign_license -p farewell_license --features dev-keygen`).
//! - End-to-end test of `farewell activate` (pass `--sn <real-sn>`
//!   to bind the license to this Mac, then run `farewell activate -`
//!   with the printed token).
//! - Bootstrapping early development before the real signing
//!   infrastructure exists.
//!
//! **This is NOT the production signer.** The real one will live in a
//! separate repo, sign with a YubiKey-bound key, and run via a Stripe
//! webhook batch job.
//!
//! Usage:
//!
//! ```text
//! # Default: two placeholder serials
//! cargo run --example sign_license -p farewell_license --features dev-keygen
//!
//! # Bind to this Mac's real serial(s):
//! cargo run --example sign_license -p farewell_license --features dev-keygen -- \
//!     --sn LV6M5Q6WYC --sn ANOTHER-SN --email alice@example.com
//! ```

use farewell_license::dev_keygen::{generate_keypair, sign_payload};
use farewell_license::{LicenseType, Payload, MAJOR_VERSION_CURRENT};

fn main() {
    let args = parse_args();

    let (sk, pk) = generate_keypair();

    let payload = Payload {
        license_type: LicenseType::Duo,
        major_version: MAJOR_VERSION_CURRENT,
        purchased_unix: now_unix(),
        license_id: rand_license_id(),
        email: args.email,
        bound_serials: args.serials,
    };

    let token = sign_payload(&sk, &payload).expect("sign");

    println!("# Sample license bundle");
    println!();
    println!("public_key  : {}", hex::encode(pk));
    println!("secret_key  : {}  (KEEP SECRET)", hex::encode(sk));
    println!();
    println!("payload     : {:#?}", payload);
    println!();
    println!("token       : {token}");
}

struct Args {
    email: String,
    serials: Vec<String>,
}

fn parse_args() -> Args {
    let mut email = "alice@example.com".to_string();
    let mut serials: Vec<String> = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--sn" => {
                if let Some(v) = it.next() {
                    serials.push(v);
                } else {
                    eprintln!("--sn requires a value");
                    std::process::exit(2);
                }
            }
            "--email" => {
                if let Some(v) = it.next() {
                    email = v;
                } else {
                    eprintln!("--email requires a value");
                    std::process::exit(2);
                }
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!("usage: sign_license [--sn SERIAL]... [--email EMAIL]");
                std::process::exit(2);
            }
        }
    }
    if serials.is_empty() {
        // Default placeholders if user didn't supply any (smoke test mode).
        serials.push("C02XK1XHJG5J".to_string());
        serials.push("FVH213XHQ9".to_string());
    }
    Args { email, serials }
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn rand_license_id() -> [u8; 16] {
    use rand::RngCore as _;
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}
