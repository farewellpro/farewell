// swift-tools-version:6.0
//
// SwiftPM manifest for the Swift side of Farewell.
//
// For now: one executable target (`FarewellHelloBridge`) that links
// against `libfarewell_mount.a` (built separately by Cargo) via the
// `FarewellMountFFI` system-library wrapper. This is the minimal
// bridge to validate the Rust → Swift toolchain end-to-end.
//
// Future targets will include:
//   - `FarewellApp` (menu bar + onboarding)
//   - `FarewellFSModule` (.appex containing the FSKit module)
//
// Build:
//   1. cargo build -p farewell_mount --release    (from repo root)
//   2. swift build -c release                     (from this dir)
//   3. ./.build/release/FarewellHelloBridge
//
// A convenience script in scripts/bridge-test.sh does both.

import PackageDescription

let package = Package(
    name: "Farewell",
    platforms: [
        // FSKit requires macOS 15 (Sequoia). We pin to that here so
        // (a) the FSKit appex can share this manifest later, and
        // (b) the Rust staticlib (built for the host SDK, currently
        // macOS 26) doesn't trigger "object file built for newer
        // macOS version" linker warnings.
        .macOS(.v15)
    ],
    targets: [
        // Wraps the C header + tells SPM to link `libfarewell_mount`.
        // The .a itself is located via `unsafeFlags(-L...)` on the
        // executable below.
        .systemLibrary(
            name: "FarewellMountFFI",
            path: "Sources/FarewellMountFFI"
        ),

        // Smoke-test executable. Linked against the Rust staticlib
        // built by Cargo in `<repo-root>/target/release/`.
        .executableTarget(
            name: "FarewellHelloBridge",
            dependencies: ["FarewellMountFFI"],
            linkerSettings: [
                // SwiftPM does not have native support for locating
                // libraries outside of standard system paths, so we
                // pass the search path through to the linker.
                // `-L../target/release` is relative to the package
                // root (i.e. the `swift/` directory).
                .unsafeFlags([
                    "-L../target/release"
                ])
            ]
        ),
        // v0.18 demo: open a real vault, stat a file, read it.
        // Validates the lifecycle + read surface of the FFI.
        .executableTarget(
            name: "FarewellReadDemo",
            dependencies: ["FarewellMountFFI"],
            linkerSettings: [
                .unsafeFlags([
                    "-L../target/release"
                ])
            ]
        ),
        // v0.18 Phase B demo: exercise create/write/truncate/rename
        // /delete via the FFI, with read-after-write verification at
        // every step.
        .executableTarget(
            name: "FarewellWriteDemo",
            dependencies: ["FarewellMountFFI"],
            linkerSettings: [
                .unsafeFlags([
                    "-L../target/release"
                ])
            ]
        ),
        // v0.18 Phase C demo: print vault info (total chunks, counter,
        // fingerprint) and the file listing via readdir callback.
        .executableTarget(
            name: "FarewellInfoDemo",
            dependencies: ["FarewellMountFFI"],
            linkerSettings: [
                .unsafeFlags([
                    "-L../target/release"
                ])
            ]
        ),
        // v0.19.A: SwiftUI app. File browser MVP — opens a vault,
        // lists its files. No viewer yet (clicking a file does
        // nothing in this iteration; viewers land in v0.19.B+).
        // The eventual production app keeps this target's name.
        .executableTarget(
            name: "FarewellApp",
            dependencies: ["FarewellMountFFI"],
            linkerSettings: [
                .unsafeFlags([
                    "-L../target/release"
                ])
            ]
        ),
    ]
)
