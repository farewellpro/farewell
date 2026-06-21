//! End-to-end integration test: generate keypair, sign a license,
//! store it to a file, load it back, verify against the local serial
//! (injected via `StaticSerialReader`).

use farewell_license::dev_keygen::{generate_keypair, sign_payload};
use farewell_license::{
    verify_for_this_mac, FileLicenseStore, LicenseStore, LicenseType, Payload,
    StaticSerialReader, MAJOR_VERSION_CURRENT,
};

#[test]
fn end_to_end_duo_two_macs() {
    let (sk, pk) = generate_keypair();

    let payload = Payload {
        license_type: LicenseType::Duo,
        major_version: MAJOR_VERSION_CURRENT,
        purchased_unix: 1_780_000_000,
        license_id: [0x99; 16],
        email: "alice@example.com".to_string(),
        bound_serials: vec!["LAPTOP-SN".to_string(), "DESKTOP-SN".to_string()],
    };
    let token = sign_payload(&sk, &payload).unwrap();

    // Save the token to a tmp store (simulates user dropping the
    // .flw file into the app at first launch).
    let tmp = std::env::temp_dir().join(format!("farewell_test_{}.flw", std::process::id()));
    let store = FileLicenseStore::new(&tmp);
    store.save(&token).unwrap();

    // Reload (simulates app reading the license on subsequent launches).
    let loaded = store.load().unwrap().expect("expected a license");

    // Verify on the laptop.
    let laptop = StaticSerialReader::new("LAPTOP-SN");
    let v_laptop = verify_for_this_mac(&loaded, &pk, &laptop).unwrap();
    assert_eq!(v_laptop.payload().email, "alice@example.com");
    assert_eq!(v_laptop.payload().license_type, LicenseType::Duo);

    // Verify on the desktop (other authorized Mac).
    let desktop = StaticSerialReader::new("DESKTOP-SN");
    verify_for_this_mac(&loaded, &pk, &desktop).unwrap();

    // Verify refused on a third, unauthorized Mac.
    let intruder = StaticSerialReader::new("BORROWED-MAC-SN");
    let err = verify_for_this_mac(&loaded, &pk, &intruder).unwrap_err();
    assert!(
        format!("{err}").contains("not authorized"),
        "unexpected error: {err}"
    );

    // Cleanup.
    store.clear().unwrap();
    assert!(store.load().unwrap().is_none());
}

#[test]
fn grant_is_bound_to_one_mac() {
    let (sk, pk) = generate_keypair();
    let payload = Payload {
        license_type: farewell_license::LicenseType::Grant,
        major_version: MAJOR_VERSION_CURRENT,
        purchased_unix: 1_780_000_000,
        license_id: [0xAA; 16],
        email: "grant-recipient@frontline.example".to_string(),
        bound_serials: vec!["GRANT-MAC-SN".to_string()],
    };
    let token = sign_payload(&sk, &payload).unwrap();

    // The granted Mac unlocks.
    let granted = StaticSerialReader::new("GRANT-MAC-SN");
    let v = verify_for_this_mac(&token, &pk, &granted).unwrap();
    assert!(matches!(
        v.payload().license_type,
        farewell_license::LicenseType::Grant
    ));

    // Any other Mac is refused — a Grant is no longer honor-system.
    let other = StaticSerialReader::new("SOME-OTHER-MAC");
    assert!(verify_for_this_mac(&token, &pk, &other).is_err());
}
