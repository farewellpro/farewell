//! Farewell development CLI.
//!
//! Not the production interface. The production product is the menu-bar
//! macOS app and the Linux tray app. This CLI exists so the Rust core can
//! be exercised end-to-end during development and audit, and so integration
//! tests have something to drive.
//!
//! ```text
//! farewell init   <vault>   --size <MiB> [--hw-keys N]
//! farewell add    <vault>   <name> [--from <path>]  [--use-hw]
//! farewell list   <vault>                            [--use-hw]
//! farewell read   <vault>   <name> [--to <path>]    [--use-hw]
//! farewell delete <vault>   <name>                   [--use-hw]
//! ```
//!
//! HW key flags (global):
//!   --use-hw            Open the connected FIDO2 device for this op.
//!   --hw-pin-stdin      Advanced/scripting only: read YubiKey PIN as
//!                       the first line of stdin (before any passphrase).
//!
//! By default, the PIN is read interactively from /dev/tty using a
//! masked prompt — never via argv (visible in `ps`), and never persisted.

use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use farewell_crypto::rng;
use farewell_fido2::HidAuthenticator;
use farewell_license::LicenseStore as _;
use farewell_format::{
    enroll_hw_key, migrate_vault, LevelEnrollment, LevelSpec, MigrateCapacity, MigratePhase, Vault,
    VaultBuilder, CHUNK_PLAINTEXT_LEN, CHUNK_STORED_LEN,
};

#[derive(Parser, Debug)]
#[command(
    name = "farewell",
    version,
    about = "Development CLI for the Farewell vault core",
    long_about = "Farewell is a nation-state grade encrypted file vault. \
                  This CLI is a development aid; the production product is the menu-bar app."
)]
struct Cli {
    /// Read passphrase(s) as line(s) from stdin instead of prompting.
    /// Intended for scripting and automated testing only.
    #[arg(long, global = true)]
    passphrase_stdin: bool,

    /// Open the connected FIDO2 hardware key for this operation. Required
    /// for vaults created with K≥1 enrolled hardware keys. The PIN, when
    /// the key has one set, is prompted interactively (masked, never
    /// persisted) unless --hw-pin-stdin is also passed.
    #[arg(long, global = true)]
    use_hw: bool,

    /// ADVANCED / SCRIPTING ONLY. Read the YubiKey PIN as the FIRST line
    /// of stdin, before any passphrase. The PIN bytes pass through the
    /// stdin pipe of the calling process — use only when the source of
    /// stdin is itself a trusted, non-logging context (e.g., a fd from
    /// a password manager). For interactive use, omit this flag and let
    /// the CLI prompt you on /dev/tty.
    #[arg(long, global = true)]
    hw_pin_stdin: bool,

    /// Anti-rollback guard. If set, refuse to proceed when the mounted
    /// level's manifest counter is below this value. Record the counter
    /// you see after each write (it is printed at the start of `list`),
    /// then pass it here on next mount to detect substitution of the
    /// vault file with an older snapshot. See THREAT_MODEL §5.6.
    #[arg(long, global = true)]
    expect_counter: Option<u64>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new vault file.
    Init {
        /// Path to the vault file to create (must not already exist).
        vault: PathBuf,
        /// Plaintext capacity in MiB.
        #[arg(long, default_value_t = 1)]
        size: u64,
        /// Hardware keys to enroll (0 to 3). Each enrolled key
        /// is independently sufficient at unlock when its credential is
        /// presented. 0 = passphrase-only mode.
        #[arg(long, default_value_t = 0)]
        hw_keys: u8,
        /// Generate a strong EFF-diceware passphrase for each level
        /// instead of prompting. The generated passphrase is printed to
        /// stderr — WRITE IT DOWN, there is no recovery.
        #[arg(long, default_value_t = false)]
        generate: bool,
    },
    /// Add (or replace) a file in the vault.
    Add {
        /// Vault file.
        vault: PathBuf,
        /// Name under which the file is stored.
        name: String,
        /// Source path. Use `-` for stdin.
        #[arg(long, default_value = "-")]
        from: String,
    },
    /// List files in the vault.
    List {
        /// Vault file.
        vault: PathBuf,
    },
    /// Read a file from the vault.
    Read {
        /// Vault file.
        vault: PathBuf,
        /// Name of the file in the vault.
        name: String,
        /// Destination path. Use `-` for stdout.
        #[arg(long, default_value = "-")]
        to: String,
    },
    /// Securely delete a file from the vault.
    Delete {
        /// Vault file.
        vault: PathBuf,
        /// Name of the file to delete.
        name: String,
    },
    /// Re-encrypt a vault into a NEW file (crypto-agility / rotation).
    ///
    /// Opens the source read-only, builds a fresh vault at `dest` (new salt +
    /// keys, current format), streams + verifies every file, and leaves the
    /// source untouched. `dest` must not already exist. The atomic swap /
    /// disposal of the old file is the caller's job (the GUI does it; here you
    /// get two separate files so you can diff them).
    Migrate {
        /// Source vault file.
        vault: PathBuf,
        /// Destination path (must not exist).
        dest: PathBuf,
        /// Shrink the destination to just fit the current contents (+ margin),
        /// instead of keeping the source's capacity.
        #[arg(long, default_value_t = false, conflicts_with = "chunks")]
        shrink: bool,
        /// Exact destination capacity in chunks (advanced). Default: same as
        /// the source.
        #[arg(long)]
        chunks: Option<u64>,
    },
    /// Show public metadata about a vault (does not require unlock).
    ///
    /// Reads only the header and its signature. Displays:
    ///   - format version
    ///   - total chunks / on-disk size
    ///   - wipe threshold and current failed-attempts count
    ///   - header signature validity (one-shot anti-tampering)
    ///   - vault fingerprint (BLAKE3 of ML-DSA verifying key)
    ///
    /// The fingerprint is a stable, public identifier: record it after
    /// vault creation, compare it later to detect substitution.
    Info {
        /// Vault file.
        vault: PathBuf,
    },
    /// Install a license token (.flw file) onto this Mac.
    ///
    /// Reads the supplied license, verifies its Ed25519 signature
    /// against the public key embedded in this build, checks that the
    /// hardware serial number of this Mac is bound by the license,
    /// and — if all checks pass — stores the token in the user
    /// Application Support directory. Entirely offline (no network).
    ///
    /// If verification fails because this Mac's serial number is not
    /// in the license, the message tells you which serials are. Email
    /// licenses@farewell.pro with your Stripe order number to request
    /// a free re-issue (see CHARTER §10.4).
    Activate {
        /// The license key you received by email (paste it, quoted), OR a
        /// path to a .flw license file, OR "-" to read from stdin.
        license_file: String,

        /// Override the embedded Ed25519 verifying key with a 64-hex
        /// string. Hidden flag for testing license issuance flows
        /// before the production key is generated and embedded.
        #[arg(long, hide = true)]
        public_key_hex: Option<String>,
    },
    /// Show the currently-installed license on this Mac.
    ///
    /// If no license is installed, prints a hint pointing to
    /// `farewell activate`. If a license is installed but its
    /// signature no longer verifies (key rotated, file tampered),
    /// reports that explicitly. Entirely offline.
    LicenseStatus {
        /// Override the embedded Ed25519 verifying key. Same purpose
        /// as on `activate`. Hidden.
        #[arg(long, hide = true)]
        public_key_hex: Option<String>,
    },
}

#[derive(Clone)]
struct AuthOptions {
    use_hw: bool,
    pin: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let stdin_mode = cli.passphrase_stdin;
    let expect_counter = cli.expect_counter;

    // Read the HW PIN once, up-front. Default: interactive masked prompt
    // on /dev/tty (via rpassword). Opt-in: --hw-pin-stdin reads from stdin.
    let hw_pin = read_hw_pin(cli.hw_pin_stdin, cli.use_hw)?;
    let auth_opts = AuthOptions {
        use_hw: cli.use_hw,
        pin: hw_pin,
    };

    match cli.command {
        Command::Init {
            vault,
            size,
            hw_keys,
            generate,
        } => cmd_init(vault, size, hw_keys, generate, stdin_mode, &auth_opts),
        Command::Add { vault, name, from } => cmd_add(
            vault,
            name,
            from,
            stdin_mode,
            &auth_opts,
            expect_counter,
        ),
        Command::List { vault } => {
            cmd_list(vault, stdin_mode, &auth_opts, expect_counter)
        }
        Command::Read { vault, name, to } => cmd_read(
            vault,
            name,
            to,
            stdin_mode,
            &auth_opts,
            expect_counter,
        ),
        Command::Delete { vault, name } => cmd_delete(
            vault,
            name,
            stdin_mode,
            &auth_opts,
            expect_counter,
        ),
        Command::Migrate {
            vault,
            dest,
            shrink,
            chunks,
        } => cmd_migrate(vault, dest, shrink, chunks, stdin_mode, &auth_opts),
        Command::Info { vault } => cmd_info(vault, stdin_mode, &auth_opts),
        Command::Activate {
            license_file,
            public_key_hex,
        } => cmd_activate(license_file, public_key_hex),
        Command::LicenseStatus { public_key_hex } => cmd_license_status(public_key_hex),
    }
}

/// Resolve the Ed25519 public key to verify license tokens against.
/// Defaults to the constant baked into `farewell_license` at build
/// time. The `--public-key-hex` flag overrides for dev / testing.
fn resolve_pubkey(hex_opt: Option<String>) -> Result<Vec<u8>> {
    if let Some(hex_str) = hex_opt {
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| anyhow!("--public-key-hex is not valid hex: {e}"))?;
        // SEC1 P-256: 65-byte uncompressed (0x04 || X || Y) or 33-byte compressed.
        if bytes.len() != 65 && bytes.len() != 33 {
            anyhow::bail!(
                "--public-key-hex must be a P-256 SEC1 key (65 or 33 bytes), got {}",
                bytes.len()
            );
        }
        Ok(bytes)
    } else {
        Ok(farewell_license::MAJOR_VERSION_1_PUBKEY.to_vec())
    }
}

/// `farewell activate <file>`
///
/// Reads, verifies against this Mac's hardware serial, and (on success)
/// saves the license to the user's Application Support directory.
fn cmd_activate(license_file: String, public_key_hex: Option<String>) -> Result<()> {
    let pubkey = resolve_pubkey(public_key_hex)?;

    // Accept three forms: "-" (stdin), an existing file path (.flw), or the
    // pasted license key itself as the argument.
    let token = if license_file == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        buf
    } else if std::path::Path::new(&license_file).is_file() {
        std::fs::read_to_string(&license_file)
            .map_err(|e| anyhow!("could not read license file {license_file:?}: {e}"))?
    } else {
        // Treat the argument as the pasted license key.
        license_file.clone()
    };

    let reader = farewell_license::MacosSerialReader;
    let verified = farewell_license::verify_for_this_mac(&token, &pubkey, &reader)
        .map_err(|e| anyhow!("license rejected: {e}"))?;

    let store = farewell_license::FileLicenseStore::default_for_user()
        .map_err(|e| anyhow!("could not locate license store: {e}"))?;
    store
        .save(&token)
        .map_err(|e| anyhow!("could not save license: {e}"))?;

    let p = verified.payload();
    println!("License accepted and installed:");
    println!("  email          : {}", p.email);
    println!("  type           : {:?}", p.license_type);
    println!("  major version  : {}", p.major_version);
    println!("  purchased UNIX : {}", p.purchased_unix);
    println!("  bound Macs     : {}", p.bound_serials.len());
    for sn in &p.bound_serials {
        println!("                   - {sn}");
    }
    println!("  stored at      : {}", store.path().display());

    Ok(())
}

/// `farewell license-status`
///
/// Loads any stored license and re-verifies it. Useful for support
/// ("can you check `farewell license-status` and paste the output?")
/// and for the user's own confidence that their activation is still
/// healthy.
fn cmd_license_status(public_key_hex: Option<String>) -> Result<()> {
    let pubkey = resolve_pubkey(public_key_hex)?;

    let store = farewell_license::FileLicenseStore::default_for_user()
        .map_err(|e| anyhow!("could not locate license store: {e}"))?;

    let token = match store.load().map_err(|e| anyhow!("read failed: {e}"))? {
        Some(t) => t,
        None => {
            println!("No license installed.");
            println!("Run: farewell activate <license.flw>");
            println!("(file location would be: {})", store.path().display());
            return Ok(());
        }
    };

    let reader = farewell_license::MacosSerialReader;
    match farewell_license::verify_for_this_mac(&token, &pubkey, &reader) {
        Ok(v) => {
            let p = v.payload();
            println!("License OK on this Mac.");
            println!("  email          : {}", p.email);
            println!("  type           : {:?}", p.license_type);
            println!("  major version  : {}", p.major_version);
            println!("  purchased UNIX : {}", p.purchased_unix);
            println!("  stored at      : {}", store.path().display());
        }
        Err(e) => {
            println!("License present but FAILS verification on this Mac:");
            println!("  {e}");
            println!();
            println!("If you replaced your Mac or had its logic board");
            println!("repaired, email licenses@farewell.pro with your");
            println!("Stripe order number to request a free re-issue.");
            std::process::exit(2);
        }
    }

    Ok(())
}

/// Read the YubiKey CTAP2 PIN.
///
/// Default (interactive): prompts on `/dev/tty` via `rpassword`, with
/// echo disabled. Bytes never appear in argv, in shell history, or on
/// stdin — they go straight from the kernel TTY driver into the Rust
/// `String` we control, and are zeroized when that string is dropped.
///
/// Opt-in (`--hw-pin-stdin`): reads the first line of stdin. Intended
/// for headless scripting; the caller is responsible for ensuring stdin
/// is not logged or visible to other processes.
fn read_hw_pin(hw_pin_stdin: bool, use_hw: bool) -> Result<Option<String>> {
    if !use_hw {
        return Ok(None);
    }
    if hw_pin_stdin {
        let stdin = io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        let pin = line.trim_end_matches(['\n', '\r']).to_string();
        return Ok(if pin.is_empty() { None } else { Some(pin) });
    }
    let pin = rpassword::prompt_password("YubiKey PIN: ")?;
    Ok(if pin.is_empty() { None } else { Some(pin) })
}

fn open_authenticator(opts: &AuthOptions) -> Result<Option<HidAuthenticator>> {
    if !opts.use_hw {
        return Ok(None);
    }
    let mut auth = HidAuthenticator::open_first("farewell.foundation")
        .with_context(|| "opening FIDO2 device (is your key plugged in?)")?;
    if let Some(p) = &opts.pin {
        auth.set_pin(p.clone());
    }
    Ok(Some(auth))
}

fn open_vault(
    path: &PathBuf,
    stdin_mode: bool,
    auth_opts: &AuthOptions,
    expect_counter: Option<u64>,
) -> Result<Vault> {
    let passphrase = read_passphrase(false, stdin_mode)?;
    let mut auth = open_authenticator(auth_opts)?;
    let v = Vault::open(path, passphrase, auth.as_mut())?;
    if let Some(min) = expect_counter {
        v.require_counter_at_least(min)?;
    }
    Ok(v)
}

/// Obtain a level's passphrase, enforcing the strength policy. With
/// `generate`, a strong EFF-diceware passphrase is generated and printed
/// (write it down — no recovery). Otherwise the user is prompted; a weak
/// passphrase is refused (re-prompted interactively, error in stdin mode).
fn obtain_passphrase(generate: bool, stdin_mode: bool) -> Result<Vec<u8>> {
    if generate {
        let pw = farewell_passphrase::generate_default()
            .map_err(|e| anyhow!("passphrase generation failed: {e}"))?;
        eprintln!("  Generated passphrase — WRITE IT DOWN (there is no recovery):");
        eprintln!();
        eprintln!("      {pw}");
        eprintln!();
        return Ok(pw.into_bytes());
    }
    loop {
        let pw = read_passphrase(true, stdin_mode)?;
        let as_str = String::from_utf8_lossy(&pw);
        let est = farewell_passphrase::estimate(&as_str);
        if est.score >= farewell_passphrase::MIN_SCORE {
            return Ok(pw);
        }
        let hint = est
            .feedback
            .unwrap_or_else(|| "use several random words, or --generate".to_string());
        if stdin_mode {
            return Err(anyhow!(
                "passphrase too weak (strength {}/4): {hint}",
                est.score
            ));
        }
        eprintln!(
            "Passphrase too weak (strength {}/4). {hint}\n\
             Try again with more entropy (e.g. 5+ random words), or re-run `init --generate`.",
            est.score
        );
    }
}

fn read_passphrase(confirm: bool, stdin_mode: bool) -> Result<Vec<u8>> {
    if stdin_mode {
        let stdin = io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        let pass = line.trim_end_matches(['\n', '\r']).to_string();
        if confirm {
            let mut line2 = String::new();
            io::stdin().lock().read_line(&mut line2)?;
            let again = line2.trim_end_matches(['\n', '\r']).to_string();
            if pass != again {
                return Err(anyhow!("passphrases do not match"));
            }
        }
        if pass.is_empty() {
            return Err(anyhow!("passphrase cannot be empty"));
        }
        return Ok(pass.into_bytes());
    }

    let pass = rpassword::prompt_password("Passphrase: ")?;
    if confirm {
        let again = rpassword::prompt_password("Confirm:    ")?;
        if pass != again {
            return Err(anyhow!("passphrases do not match"));
        }
    }
    if pass.is_empty() {
        return Err(anyhow!("passphrase cannot be empty"));
    }
    Ok(pass.into_bytes())
}

fn chunks_for_mib(mib: u64) -> u64 {
    let bytes = mib * 1024 * 1024;
    let data_chunks = bytes.div_ceil(CHUNK_PLAINTEXT_LEN as u64);
    data_chunks + 1
}

/// `farewell migrate <vault> <dest> [--shrink | --chunks N]`
///
/// Re-encrypts the source into a fresh vault at `dest`. The source is left
/// untouched; on any failure the partial destination is removed.
fn cmd_migrate(
    src: PathBuf,
    dest: PathBuf,
    shrink: bool,
    chunks: Option<u64>,
    stdin_mode: bool,
    auth_opts: &AuthOptions,
) -> Result<()> {
    if dest.exists() {
        anyhow::bail!("destination {dest:?} already exists; choose a new path");
    }
    let passphrase = read_passphrase(false, stdin_mode)?;
    let mut auth = open_authenticator(auth_opts)?;
    let hw_handle: Option<&[u8]> = if auth.is_some() {
        Some(b"farewell-L0-K0")
    } else {
        None
    };
    let capacity = match (shrink, chunks) {
        (true, _) => MigrateCapacity::ShrinkToFit,
        (false, Some(n)) => MigrateCapacity::Exact(n),
        (false, None) => MigrateCapacity::Same,
    };

    let mut last_phase: Option<MigratePhase> = None;
    let report = migrate_vault(
        &src,
        &dest,
        passphrase,
        auth.as_mut(),
        hw_handle,
        capacity,
        |phase, done, total| {
            if last_phase != Some(phase) {
                let label = match phase {
                    MigratePhase::Allocate => "allocating destination",
                    MigratePhase::Copy => "copying files",
                    MigratePhase::Verify => "verifying",
                };
                eprintln!("  {label}…");
                last_phase = Some(phase);
            }
            let _ = (done, total);
        },
    );

    let report = match report {
        Ok(r) => r,
        Err(e) => {
            // Never leave a partial destination behind.
            let _ = fs::remove_file(&dest);
            return Err(anyhow!("migration failed: {e}"));
        }
    };

    let on_disk = report.new_total_chunks * CHUNK_STORED_LEN as u64;
    eprintln!(
        "Migrated {} file(s), {} bytes → {dest:?}\n  \
         capacity: {} chunks (~{} MiB on disk); counter {} → {}",
        report.files,
        report.bytes,
        report.new_total_chunks,
        on_disk / (1024 * 1024),
        report.old_counter,
        report.new_counter,
    );
    eprintln!(
        "  The source is unchanged. Verify {dest:?} opens, then delete the old \
         file yourself (the GUI automates this swap)."
    );
    Ok(())
}

fn cmd_init(
    path: PathBuf,
    size_mib: u64,
    hw_keys: u8,
    generate: bool,
    stdin_mode: bool,
    auth_opts: &AuthOptions,
) -> Result<()> {
    if path.exists() {
        return Err(anyhow!("{} already exists", path.display()));
    }
    if hw_keys > 3 {
        return Err(anyhow!("--hw-keys must be 0 to 3 (got {hw_keys})"));
    }
    if hw_keys > 0 && !auth_opts.use_hw {
        return Err(anyhow!(
            "--hw-keys {hw_keys} requires --use-hw to access the FIDO2 device"
        ));
    }

    let total = chunks_for_mib(size_mib).max(2);
    let on_disk = total * CHUNK_STORED_LEN as u64 + 16384;
    eprintln!(
        "Creating vault: {} chunks ({} MiB plaintext, {} HW key(s), {} bytes on disk).",
        total, size_mib, hw_keys, on_disk
    );
    eprintln!();

    // If we're enrolling HW keys, open the authenticator and generate
    // the vault salt up-front so we can derive the FIDO salt before
    // building.
    let mut auth = open_authenticator(auth_opts)?;
    let vault_salt: Option<[u8; 32]> = if hw_keys > 0 {
        let bytes = rng::bytes(32)?;
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes);
        Some(s)
    } else {
        None
    };

    let passphrase = obtain_passphrase(generate, stdin_mode)?;
    let mut enrollment = LevelEnrollment::passphrase_only();
    if hw_keys > 0 {
        let auth_ref = auth.as_mut().expect("auth must be Some when hw_keys > 0");
        let salt = vault_salt.expect("vault_salt set when hw_keys > 0");
        for k in 0..hw_keys {
            if !stdin_mode {
                eprintln!(
                    "  Enrolling HW key {} of {}. TOUCH the YubiKey when it blinks.",
                    k + 1,
                    hw_keys
                );
            }
            let user_handle = format!("farewell-K{k}").into_bytes();
            let (cred, hmac_out) = enroll_hw_key(auth_ref, &salt, &user_handle)
                .with_context(|| format!("enrolling HW key {}", k + 1))?;
            enrollment.push(cred, hmac_out)?;
        }
    }
    let level_specs = vec![LevelSpec { passphrase, enrollment }];

    let mut builder = VaultBuilder::new(&path, level_specs)?.total_chunks(total);
    if let Some(salt) = vault_salt {
        builder = builder.with_salt(salt);
    }
    let _ = builder
        .build()
        .with_context(|| format!("creating vault at {}", path.display()))?;

    eprintln!();
    eprintln!("Done.");
    eprintln!();
    eprintln!("Reminder: there is no recovery. If you forget the passphrase, or lose");
    eprintln!("a required hardware key, the vault is unrecoverable. By design.");
    Ok(())
}

fn cmd_add(
    path: PathBuf,
    name: String,
    from: String,
    stdin_mode: bool,
    auth_opts: &AuthOptions,
    expect_counter: Option<u64>,
) -> Result<()> {
    let mut vault = open_vault(&path, stdin_mode, auth_opts, expect_counter)?;

    let data = if from == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        fs::read(&from).with_context(|| format!("reading {}", from))?
    };

    vault.add_file(&name, data)?;
    eprintln!("Stored '{}' in {}.", name, path.display());
    if let Some(c) = vault.counter() {
        eprintln!(
            "Manifest counter: {c}  (record this; use --expect-counter {c} next mount to detect rollback)"
        );
    }
    Ok(())
}

fn cmd_list(
    path: PathBuf,
    stdin_mode: bool,
    auth_opts: &AuthOptions,
    expect_counter: Option<u64>,
) -> Result<()> {
    let vault = open_vault(&path, stdin_mode, auth_opts, expect_counter)?;
    if let Some(c) = vault.counter() {
        eprintln!("Manifest counter: {c}");
    }
    let entries = vault.list();
    if entries.is_empty() {
        eprintln!("(empty vault)");
        return Ok(());
    }
    for e in entries {
        println!("{:>12}  {}", e.size, e.name);
    }
    Ok(())
}

fn cmd_read(
    path: PathBuf,
    name: String,
    to: String,
    stdin_mode: bool,
    auth_opts: &AuthOptions,
    expect_counter: Option<u64>,
) -> Result<()> {
    let mut vault = open_vault(&path, stdin_mode, auth_opts, expect_counter)?;
    let data = vault.read_file(&name)?;
    if to == "-" {
        io::stdout().write_all(&data)?;
    } else {
        fs::write(&to, &data).with_context(|| format!("writing {}", to))?;
        eprintln!("Wrote {} bytes to {}.", data.len(), to);
    }
    Ok(())
}

fn cmd_delete(
    path: PathBuf,
    name: String,
    stdin_mode: bool,
    auth_opts: &AuthOptions,
    expect_counter: Option<u64>,
) -> Result<()> {
    let mut vault = open_vault(&path, stdin_mode, auth_opts, expect_counter)?;
    vault.delete_file(&name)?;
    eprintln!("Securely deleted '{}'.", name);
    if let Some(c) = vault.counter() {
        eprintln!(
            "Manifest counter: {c}  (record this; use --expect-counter {c} next mount to detect rollback)"
        );
    }
    Ok(())
}

/// Display public metadata about a vault. No passphrase, no HW key, no
/// unlock. Reads only the header and its one-shot signature.
fn cmd_info(path: PathBuf, stdin_mode: bool, auth_opts: &AuthOptions) -> Result<()> {
    use std::fs;

    if !path.exists() {
        return Err(anyhow!("{} does not exist", path.display()));
    }
    let on_disk = fs::metadata(&path)
        .with_context(|| format!("stat {}", path.display()))?
        .len();

    // v0.5: the metadata blob is AEAD-encrypted and the file carries no
    // plaintext header — so `info` cannot reveal anything (not even
    // "this is a Farewell vault") without the passphrase. This is by
    // design (THREAT_MODEL §6.9): nothing leaks before authentication.
    eprintln!(
        "Note: vault metadata is encrypted. Unlocking it requires the passphrase\n\
         (v0.5 leaks nothing about the file before authentication)."
    );
    let passphrase = read_passphrase(false, stdin_mode)?;
    let mut auth = open_authenticator(auth_opts)?;
    // Reaching Ok here also means the ML-DSA-87 attestation verified
    // during open (Metadata::open) — the file has not been tampered with.
    let vault = Vault::open(&path, passphrase, auth.as_mut())
        .context("opening vault (wrong passphrase, or not a Farewell vault)")?;

    let fingerprint = vault.fingerprint();
    let fingerprint_hex = bytes_to_hex(&fingerprint);
    let fingerprint_short = format!(
        "{}-{}-{}-{}",
        &fingerprint_hex[0..8],
        &fingerprint_hex[8..16],
        &fingerprint_hex[16..24],
        &fingerprint_hex[24..32],
    );
    let (usable, free) = vault.space().unwrap_or((0, 0));

    println!("File:               {}", path.display());
    println!("On-disk size:       {} bytes", on_disk);
    println!("Format version:     0x{:04X}", farewell_format::FORMAT_VERSION);
    println!("Total chunks:       {}", vault.total_chunks());
    println!(
        "Mounted level:      {} bytes usable, {} bytes free",
        usable, free
    );
    if let Some(counter) = vault.counter() {
        println!("Manifest counter:   {}", counter);
    }
    println!("Attestation:        VALID (ML-DSA-87 verified at open)");
    println!("Vault fingerprint:");
    println!("  short  → {}", fingerprint_short);
    println!("  full   → {}", fingerprint_hex);
    println!();
    println!(
        "Record this fingerprint after vault creation. If it changes between\nopenings, the file has been substituted."
    );
    Ok(())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
