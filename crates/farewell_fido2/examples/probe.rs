//! Read-only YubiKey reachability probe.
//!
//! Strictly non-destructive: enumerates connected FIDO HID devices and
//! reads CTAP2 `get_info` + PIN-retry count. NO touch, NO PIN entry, NO
//! credential creation, NO writes of any kind. Used once to confirm this
//! environment can reach the key before building the FIDO2 app path.
//!
//! Run:  cargo run -p farewell_fido2 --example probe

use ctap_hid_fido2::{get_fidokey_devices, Cfg, FidoKeyHidFactory};

fn main() {
    let devices = get_fidokey_devices();
    println!("FIDO HID devices visible: {}", devices.len());
    for d in &devices {
        println!(
            "  - {:?}  vid={:04x} pid={:04x}  {}",
            d.product_string, d.vid, d.pid, d.info
        );
    }
    if devices.is_empty() {
        println!("\n=> No device reachable from this environment (sandbox may block USB/HID,\n   or no key is plugged). The hardware path will have to be validated\n   from your own terminal.");
        return;
    }

    let cfg = Cfg::init();
    let dev = match FidoKeyHidFactory::create(&cfg) {
        Ok(d) => d,
        Err(e) => {
            println!("\ncreate() failed: {e}");
            return;
        }
    };

    match dev.get_info() {
        Ok(info) => {
            println!("\nCTAP versions : {:?}", info.versions);
            println!("extensions    : {:?}", info.extensions);
            let hmac = info.extensions.iter().any(|e| e == "hmac-secret");
            println!("hmac-secret   : {}  <- Farewell requires this", hmac);
            if let Some((_, v)) = info.options.iter().find(|(k, _)| k == "clientPin") {
                println!("clientPin set : {v}");
            }
        }
        Err(e) => println!("\nget_info failed: {e}"),
    }

    match dev.get_pin_retries() {
        Ok(n) => println!("PIN retries   : {n}"),
        Err(e) => println!("PIN retries   : (unavailable: {e})"),
    }

    println!("\n=> Reachable. Read-only probe complete; nothing on the key was modified.");
}
