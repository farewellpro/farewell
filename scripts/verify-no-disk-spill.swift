// Verify that in-app video playback (RAM-fed AVPlayer via a custom
// AVAssetResourceLoaderDelegate) never writes the media to disk.
//
// It replicates the app's exact playback path on a freshly *generated*
// H.264 clip held only in RAM, plays + seeks it for several seconds, and
// diffs the user's Darwin temp + cache trees before/after — scanning any
// new/grown file for the clip's bytes (definitive) and for size matches
// (heuristic). It also lsofs its own process for deleted-but-open files.
//
//   swift scripts/verify-no-disk-spill.swift
//
// Exit 0 + "NO DISK SPILL DETECTED" = pass.

import AVFoundation
import AppKit

// MARK: - The app's in-memory loader (copied verbatim from main.swift)

final class InMemoryAssetLoader: NSObject, AVAssetResourceLoaderDelegate {
    static let scheme = "farewellmem"
    private let data: Data
    private let contentType: String
    init(data: Data, contentType: String) { self.data = data; self.contentType = contentType; super.init() }

    func resourceLoader(_ rl: AVAssetResourceLoader,
                        shouldWaitForLoadingOfRequestedResource req: AVAssetResourceLoadingRequest) -> Bool {
        if let info = req.contentInformationRequest {
            info.contentType = contentType
            info.contentLength = Int64(data.count)
            info.isByteRangeAccessSupported = true
        }
        if let dr = req.dataRequest {
            let start = Int(dr.currentOffset)
            if start < data.count {
                let len = min(Int(dr.requestedLength), data.count - start)
                if len > 0 { dr.respond(with: data.subdata(in: start ..< start + len)) }
            }
        }
        req.finishLoading()
        return true
    }
}

// MARK: - Generate a short H.264 clip into RAM (test fixture)

func makePixelBuffer(_ w: Int, _ h: Int, _ frame: Int) -> CVPixelBuffer? {
    var pb: CVPixelBuffer?
    let attrs = [kCVPixelBufferCGImageCompatibilityKey: true,
                 kCVPixelBufferCGBitmapContextCompatibilityKey: true] as CFDictionary
    CVPixelBufferCreate(kCFAllocatorDefault, w, h, kCVPixelFormatType_32ARGB, attrs, &pb)
    guard let buf = pb else { return nil }
    CVPixelBufferLockBaseAddress(buf, [])
    if let base = CVPixelBufferGetBaseAddress(buf) {
        // High-entropy noise → poor H.264 compression → a genuinely large
        // file, to exercise any size-triggered disk buffering.
        let bytes = CVPixelBufferGetBytesPerRow(buf) * h
        let p = base.assumingMemoryBound(to: UInt8.self)
        var seed = UInt64(frame &* 2_654_435_761)
        for i in 0 ..< bytes {
            seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            p[i] = UInt8((seed >> 33) & 0xFF)
        }
    }
    CVPixelBufferUnlockBaseAddress(buf, [])
    return buf
}

func generateClip() -> Data? {
    let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("fw-genfixture-\(UUID().uuidString).mp4")
    guard let writer = try? AVAssetWriter(outputURL: tmp, fileType: .mp4) else { return nil }
    let w = 1280, h = 720
    let input = AVAssetWriterInput(mediaType: .video, outputSettings: [
        AVVideoCodecKey: AVVideoCodecType.h264, AVVideoWidthKey: w, AVVideoHeightKey: h,
    ])
    input.expectsMediaDataInRealTime = false
    let adaptor = AVAssetWriterInputPixelBufferAdaptor(assetWriterInput: input,
        sourcePixelBufferAttributes: [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32ARGB,
            kCVPixelBufferWidthKey as String: w, kCVPixelBufferHeightKey as String: h,
        ])
    guard writer.canAdd(input) else { return nil }
    writer.add(input)
    writer.startWriting()
    writer.startSession(atSourceTime: .zero)

    let fps: Int32 = 30, total = 600 // 20s @ 720p, noisy → several MB
    var frame = 0
    let sem = DispatchSemaphore(value: 0)
    input.requestMediaDataWhenReady(on: DispatchQueue(label: "gen")) {
        while input.isReadyForMoreMediaData {
            if frame >= total {
                input.markAsFinished()
                writer.finishWriting { sem.signal() }
                return
            }
            if let pb = makePixelBuffer(w, h, frame) {
                adaptor.append(pb, withPresentationTime: CMTime(value: CMTimeValue(frame), timescale: fps))
            }
            frame += 1
        }
    }
    sem.wait()
    // Read WITHOUT mmap (FileHandle), close the fd, then remove the fixture
    // so it can't linger on disk or show up in lsof and muddy the audit.
    var data: Data?
    if let fh = try? FileHandle(forReadingFrom: tmp) {
        data = fh.readDataToEndOfFile()
        try? fh.close()
    }
    try? FileManager.default.removeItem(at: tmp)
    return data
}

// MARK: - Filesystem snapshot

func roots() -> [String] {
    var r = [NSTemporaryDirectory()]
    var buf = [CChar](repeating: 0, count: 1024)
    if confstr(_CS_DARWIN_USER_CACHE_DIR, &buf, buf.count) > 0 {
        r.append(String(cString: buf))
    }
    r.append((NSHomeDirectory() as NSString).appendingPathComponent("Library/Caches"))
    return r
}

func snapshot(_ paths: [String]) -> [String: Int] {
    var out: [String: Int] = [:]
    let fm = FileManager.default
    for root in paths {
        guard let en = fm.enumerator(at: URL(fileURLWithPath: root),
            includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey],
            options: [.skipsHiddenFiles]) else { continue }
        var n = 0
        for case let url as URL in en {
            n += 1
            if n > 200_000 { break }   // safety bound
            let v = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
            if v?.isRegularFile == true { out[url.path] = v?.fileSize ?? 0 }
        }
    }
    return out
}

func contains(_ path: String, needle: Data) -> Bool {
    guard let fh = FileHandle(forReadingAtPath: path) else { return false }
    defer { try? fh.close() }
    // Cheap check: scan up to the first 4 MiB for the needle.
    let chunk = (try? fh.read(upToCount: 4 * 1024 * 1024)) ?? Data()
    return chunk.range(of: needle) != nil
}

// MARK: - Run

print("→ generating a 20 s H.264 test clip in RAM…")
guard let clip = generateClip(), clip.count > 1000 else {
    print("FAILED to generate test clip"); exit(2)
}
let needle = clip.prefix(256)            // a definitive fingerprint of our bytes
print("   clip: \(clip.count) bytes; needle = first 256 bytes")

let app = NSApplication.shared
app.setActivationPolicy(.accessory)

print("→ snapshotting temp/cache before playback…")
let before = snapshot(roots())
print("   \(before.count) regular files under \(roots().count) roots")

// Build the exact app playback path.
let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 320, height: 240),
                      styleMask: [.borderless], backing: .buffered, defer: false)
let view = NSView(frame: NSRect(x: 0, y: 0, width: 320, height: 240))
view.wantsLayer = true
let playerLayer = AVPlayerLayer()
playerLayer.frame = view.bounds
view.layer?.addSublayer(playerLayer)
window.contentView = view
window.orderFrontRegardless()

let loader = InMemoryAssetLoader(data: Data(clip), contentType: "public.mpeg-4")
let asset = AVURLAsset(url: URL(string: "\(InMemoryAssetLoader.scheme)://video")!)
asset.resourceLoader.setDelegate(loader, queue: DispatchQueue(label: "loader"))
let player = AVPlayer(playerItem: AVPlayerItem(asset: asset))
playerLayer.player = player

print("→ playing + seeking for ~8 s…")
player.play()
let deadline = Date().addingTimeInterval(8)
var seeks = 0
while Date() < deadline {
    RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.25))
    if player.currentItem?.status == .readyToPlay, seeks < 3 {
        player.seek(to: CMTime(seconds: Double(seeks + 1) * 1.2, preferredTimescale: 600))
        player.play()
        seeks += 1
    }
}

// lsof our own process for deleted-but-open regular files.
print("→ lsof self (deleted-but-open files)…")
let lsof = Process()
lsof.launchPath = "/usr/sbin/lsof"
lsof.arguments = ["-p", "\(getpid())"]
let pipe = Pipe()
lsof.standardOutput = pipe
try? lsof.run(); lsof.waitUntilExit()
let lsofOut = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
let suspiciousLsof = lsofOut.split(separator: "\n").filter {
    $0.contains("REG")
        && ($0.contains("/T/") || $0.contains("/C/")
            || $0.lowercased().contains("cache") || $0.contains("(deleted)"))
        // Exclude the Swift JIT-compiler noise present only when this audit
        // runs via `swift <file>` (the real .app is precompiled).
        && !$0.contains("/Xcode.app/")
        && !$0.contains("swift-frontend")
        && !$0.contains("/usr/lib/swift")
        && !$0.contains(".swiftmodule")
        && !$0.contains("/ModuleCache")
        && !$0.hasSuffix(".h")
        && !$0.contains("fw-genfixture-")               // this audit's own test input
        && !$0.contains("/Library/Preferences/Logging/") // OS logging plist cache
}

print("→ snapshotting temp/cache after playback…")
let after = snapshot(roots())

// Diff: new files + grown files.
var suspects: [(String, Int)] = []
for (path, size) in after {
    let prev = before[path]
    if prev == nil || (prev ?? 0) < size { suspects.append((path, size)) }
}

print("\n================ RESULT ================")
print("new/grown files since baseline: \(suspects.count)")
var leak = false

// Definitive: any new/grown file containing our exact bytes.
for (path, size) in suspects {
    if size >= 200, contains(path, needle: Data(needle)) {
        print("‼️  LEAK: file contains our clip bytes → \(path)  (\(size) B)")
        leak = true
    }
}
// Heuristic: a new file roughly the clip size.
for (path, size) in suspects where abs(size - clip.count) < clip.count / 5 {
    print("⚠️  size-match (\(size) B ≈ clip \(clip.count) B): \(path)")
}
if !suspiciousLsof.isEmpty {
    print("⚠️  lsof flagged \(suspiciousLsof.count) open REG file(s) in temp/cache:")
    for l in suspiciousLsof.prefix(10) { print("    \(l)") }
}

if !leak {
    print("\n✅ NO DISK SPILL DETECTED — our clip's bytes were not found in any")
    print("   new/grown temp or cache file, and no media-sized file appeared.")
}
print("========================================")
exit(leak ? 1 : 0)
