//! Diagnostic: dump info from the first connected FIDO2 authenticator,
//! including whether ClientPin is set and what extensions are
//! supported. Read-only — does NOT touch the key or require any
//! interaction beyond plugging it in.
//!
//! Usage: `cargo run --example yubikey_info -p farewell_fido2`

use ctap_hid_fido2::{fidokey::get_info::InfoOption, Cfg, FidoKeyHidFactory};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let devs = ctap_hid_fido2::get_fidokey_devices();
    if devs.is_empty() {
        return Err("no FIDO devices detected".into());
    }
    let info = devs.into_iter().next().unwrap();
    println!(
        "Device: vid=0x{:04x} pid=0x{:04x}",
        info.vid, info.pid
    );

    let dev = FidoKeyHidFactory::create_by_params(&[info.param], &Cfg::init())?;

    println!();
    println!("--- get_info() ---");
    match dev.get_info() {
        Ok(i) => println!("{}", i),
        Err(e) => println!("error: {e:?}"),
    }

    println!();
    println!("--- Options ---");
    for opt in [
        InfoOption::ClientPin,
        InfoOption::Plat,
        InfoOption::Rk,
        InfoOption::Up,
        InfoOption::Uv,
        InfoOption::MakeCredUvNotRqd,
        InfoOption::AlwaysUv,
    ] {
        match dev.enable_info_option(&opt) {
            Ok(result) => println!("{:?}: {:?}", opt, result),
            Err(e) => println!("{:?}: error: {:?}", opt, e),
        }
    }

    println!();
    println!("--- get_pin_retries() ---");
    match dev.get_pin_retries() {
        Ok(n) => println!("PIN retries left: {n}"),
        Err(e) => println!("error: {e:?}"),
    }
    Ok(())
}
