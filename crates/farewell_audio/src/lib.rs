//! In-process audio decoding for the Farewell in-app viewer.
//!
//! The in-app viewer is the **only** path to vault content, and decrypted
//! bytes must never touch disk. So we decode audio **in RAM, in our own
//! (audited, pure-Rust) code** via [Symphonia] — not the OS codecs — and
//! hand interleaved PCM to the Swift layer, which streams it into
//! `AVAudioEngine`. No temp file, no `AVAsset` URL, no disk trace.
//!
//! Supported (via the features enabled in `Cargo.toml`): MP3, AAC/M4A,
//! ALAC, FLAC, Vorbis/Ogg, WAV, AIFF, CAF, PCM/ADPCM. Unsupported inputs
//! fail cleanly at [`AudioDecoder::open`].
//!
//! [Symphonia]: https://github.com/pdeljanov/Symphonia

#![forbid(unsafe_code)]

use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};

// Symphonia 0.6 reworked its module layout (probe → formats::probe, the
// decoder trait → codecs::audio::AudioDecoder, sample buffers → the audio
// module's GenericAudioBufferRef). We alias the trait to avoid clashing with
// our own `AudioDecoder` struct.
use symphonia::core::codecs::audio::{AudioDecoder as SymAudioDecoder, AudioDecoderOptions};
use symphonia::core::errors::Error as SymError;
use symphonia::core::formats::probe::Hint;
use symphonia::core::formats::{FormatOptions, FormatReader, SeekMode, SeekTo, TrackType};
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::units::Timestamp;

/// Why opening an audio stream failed.
#[derive(Debug)]
pub enum AudioError {
    /// The container/codec isn't one we decode, or the stream is malformed.
    Unsupported,
}

/// A streaming PCM decoder over an in-memory audio file.
///
/// Pull interleaved `f32` frames with [`read`](Self::read); seek with
/// [`seek`](Self::seek). Decoding is lazy (packet by packet), so a long
/// recording never fully materializes as PCM in RAM.
pub struct AudioDecoder {
    format: Box<dyn FormatReader>,
    decoder: Box<dyn SymAudioDecoder>,
    track_id: u32,
    /// Output sample rate (Hz).
    pub sample_rate: u32,
    /// Channel count.
    pub channels: u16,
    /// Total frames if the container declares it, else 0 (unknown).
    pub total_frames: u64,
    /// Interleaved f32 decoded but not yet consumed by `read`.
    leftover: Vec<f32>,
    leftover_pos: usize,
}

impl AudioDecoder {
    /// Probe `bytes` and set up a decoder for its default audio track.
    ///
    /// This is the trust boundary for untrusted media: a file handed to the
    /// in-app viewer may be fully attacker-controlled. The underlying codecs
    /// (Symphonia) are third-party and can panic on malformed input (e.g. an
    /// arithmetic overflow in the AAC/ADTS header parser). We catch any such
    /// panic and report it as [`AudioError::Unsupported`] rather than letting
    /// it unwind into our callers (and, ultimately, abort the app).
    pub fn open(bytes: Vec<u8>) -> Result<Self, AudioError> {
        catch_unwind(AssertUnwindSafe(|| Self::open_inner(bytes)))
            .unwrap_or(Err(AudioError::Unsupported))
    }

    fn open_inner(bytes: Vec<u8>) -> Result<Self, AudioError> {
        let mss = MediaSourceStream::new(Box::new(Cursor::new(bytes)), Default::default());
        // In 0.6 `probe` returns the `FormatReader` directly.
        let format = symphonia::default::get_probe()
            .probe(
                &Hint::new(),
                mss,
                FormatOptions::default(),
                MetadataOptions::default(),
            )
            .map_err(|_| AudioError::Unsupported)?;

        let track = format
            .default_track(TrackType::Audio)
            .ok_or(AudioError::Unsupported)?;
        let track_id = track.id;
        // Total playable frames now live on the Track (was codec_params.n_frames).
        let total_frames = track.num_frames.unwrap_or(0);

        // Codec params are now an enum; pull the audio variant.
        let params = track
            .codec_params
            .as_ref()
            .and_then(|c| c.audio())
            .ok_or(AudioError::Unsupported)?;

        let sample_rate = params.sample_rate.ok_or(AudioError::Unsupported)?;
        let channels = params
            .channels
            .as_ref()
            .map(|c| c.count() as u16)
            .filter(|&c| c >= 1)
            .ok_or(AudioError::Unsupported)?;

        let decoder = symphonia::default::get_codecs()
            .make_audio_decoder(params, &AudioDecoderOptions::default())
            .map_err(|_| AudioError::Unsupported)?;

        Ok(Self {
            format,
            decoder,
            track_id,
            sample_rate,
            channels,
            total_frames,
            leftover: Vec::new(),
            leftover_pos: 0,
        })
    }

    /// Fill `out` with up to `out.len()` interleaved `f32` samples
    /// (`channels` per frame). Returns the number written; `0` means
    /// end-of-stream.
    pub fn read(&mut self, out: &mut [f32]) -> usize {
        // A malformed packet can panic inside a third-party codec mid-stream;
        // treat that as end-of-stream (return what we have) rather than
        // crashing playback.
        catch_unwind(AssertUnwindSafe(|| self.read_inner(out))).unwrap_or(0)
    }

    fn read_inner(&mut self, out: &mut [f32]) -> usize {
        let mut written = 0;
        while written < out.len() {
            // Drain anything left from the previously decoded packet.
            if self.leftover_pos < self.leftover.len() {
                let avail = self.leftover.len() - self.leftover_pos;
                let n = (out.len() - written).min(avail);
                out[written..written + n]
                    .copy_from_slice(&self.leftover[self.leftover_pos..self.leftover_pos + n]);
                self.leftover_pos += n;
                written += n;
                continue;
            }

            // Decode the next packet belonging to our track.
            self.leftover.clear();
            self.leftover_pos = 0;
            let packet = loop {
                // 0.6: next_packet yields Option; None is a clean EOF.
                match self.format.next_packet() {
                    Ok(Some(p)) if p.track_id == self.track_id => break p,
                    Ok(Some(_)) => continue,  // a packet from another track
                    Ok(None) => return written, // end of stream
                    Err(_) => return written, // read error → stop cleanly
                }
            };

            match self.decoder.decode(&packet) {
                Ok(audio_buf) => {
                    // leftover was cleared just above; append the interleaved f32.
                    audio_buf.copy_to_vec_interleaved::<f32>(&mut self.leftover);
                }
                // A single corrupt packet shouldn't kill playback — skip it.
                Err(SymError::DecodeError(_)) => continue,
                Err(_) => return written,
            }
        }
        written
    }

    /// Seek so the next [`read`](Self::read) starts at `frame` (sample
    /// index within the track). Returns `true` on success.
    pub fn seek(&mut self, frame: u64) -> bool {
        catch_unwind(AssertUnwindSafe(|| self.seek_inner(frame))).unwrap_or(false)
    }

    fn seek_inner(&mut self, frame: u64) -> bool {
        let ok = self
            .format
            .seek(
                SeekMode::Accurate,
                SeekTo::Timestamp {
                    // frame is a sample index; fits an i64 for any real recording.
                    ts: Timestamp::new(frame as i64),
                    track_id: self.track_id,
                },
            )
            .is_ok();
        if ok {
            self.decoder.reset();
            self.leftover.clear();
            self.leftover_pos = 0;
        }
        ok
    }
}

/// Decode `bytes` fully and return `buckets` peak-amplitude values in `0.0..=1.0`
/// for drawing a waveform. Each output bucket is the maximum absolute sample
/// (across channels) over its slice of the recording, then the whole curve is
/// normalized by its global peak so quiet files still render.
///
/// RAM is bounded regardless of length: we accumulate a fine peak envelope
/// (one value per ~2048 frames) — a few hundred KB even for a long recording —
/// then downsample that to `buckets`. Returns `None` on an undecodable input or
/// `buckets == 0`.
pub fn compute_waveform(bytes: Vec<u8>, buckets: usize) -> Option<Vec<f32>> {
    if buckets == 0 {
        return None;
    }
    let mut dec = AudioDecoder::open(bytes).ok()?;
    let ch = dec.channels.max(1) as usize;

    const FRAMES_PER_FINE: usize = 2048;
    let mut fine: Vec<f32> = Vec::new();
    let mut cur_peak = 0f32;
    let mut frames_in_fine = 0usize;

    // Read in interleaved blocks that are a whole number of frames.
    let mut buf = vec![0f32; 4096 * ch];
    loop {
        let n = dec.read(&mut buf);
        if n == 0 {
            break;
        }
        let mut i = 0;
        while i + ch <= n {
            let mut p = 0f32;
            for c in 0..ch {
                p = p.max(buf[i + c].abs());
            }
            cur_peak = cur_peak.max(p);
            frames_in_fine += 1;
            if frames_in_fine >= FRAMES_PER_FINE {
                fine.push(cur_peak);
                cur_peak = 0.0;
                frames_in_fine = 0;
            }
            i += ch;
        }
    }
    if frames_in_fine > 0 {
        fine.push(cur_peak);
    }
    if fine.is_empty() {
        return Some(vec![0.0; buckets]);
    }

    // Downsample the fine envelope to `buckets` (max over each group).
    let n = fine.len();
    let mut out = vec![0f32; buckets];
    for (b, slot) in out.iter_mut().enumerate() {
        let start = b * n / buckets;
        let end = (((b + 1) * n / buckets).max(start + 1)).min(n);
        let mut peak = 0f32;
        for &v in &fine[start..end] {
            peak = peak.max(v);
        }
        *slot = peak;
    }

    // Normalize by the global peak so quiet recordings are still visible.
    let gmax = out.iter().copied().fold(0f32, f32::max);
    if gmax > 0.0 {
        for v in &mut out {
            *v = (*v / gmax).clamp(0.0, 1.0);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 16-bit PCM WAV in memory.
    fn tiny_wav(sr: u32, ch: u16, frames: u32) -> Vec<u8> {
        let bits: u16 = 16;
        let block_align: u16 = ch * bits / 8;
        let byte_rate: u32 = sr * block_align as u32;
        let data_len: u32 = frames * block_align as u32;
        let mut v = Vec::new();
        v.extend_from_slice(b"RIFF");
        v.extend_from_slice(&(36 + data_len).to_le_bytes());
        v.extend_from_slice(b"WAVE");
        v.extend_from_slice(b"fmt ");
        v.extend_from_slice(&16u32.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes()); // PCM
        v.extend_from_slice(&ch.to_le_bytes());
        v.extend_from_slice(&sr.to_le_bytes());
        v.extend_from_slice(&byte_rate.to_le_bytes());
        v.extend_from_slice(&block_align.to_le_bytes());
        v.extend_from_slice(&bits.to_le_bytes());
        v.extend_from_slice(b"data");
        v.extend_from_slice(&data_len.to_le_bytes());
        for i in 0..frames {
            let s = ((i as f32 * 0.05).sin() * 1000.0) as i16;
            for _ in 0..ch {
                v.extend_from_slice(&s.to_le_bytes());
            }
        }
        v
    }

    #[test]
    fn decodes_a_wav_stream() {
        let mut d = AudioDecoder::open(tiny_wav(44_100, 2, 1000)).unwrap();
        assert_eq!(d.sample_rate, 44_100);
        assert_eq!(d.channels, 2);

        let mut buf = vec![0f32; 4096];
        let mut total = 0usize;
        loop {
            let n = d.read(&mut buf);
            if n == 0 {
                break;
            }
            total += n;
        }
        // 1000 frames × 2 channels = 2000 interleaved samples.
        assert_eq!(total, 2000);
    }

    #[test]
    fn rejects_non_audio() {
        assert!(AudioDecoder::open(b"definitely not audio".to_vec()).is_err());
    }

    #[test]
    fn waveform_has_requested_buckets_and_is_normalized() {
        // A loud sine over 8000 frames → a non-trivial envelope.
        let peaks = compute_waveform(tiny_wav(8_000, 1, 8_000), 100).unwrap();
        assert_eq!(peaks.len(), 100);
        assert!(peaks.iter().all(|&v| (0.0..=1.0).contains(&v)));
        // Normalized: at least one bucket reaches (near) the peak.
        assert!(peaks.iter().cloned().fold(0f32, f32::max) > 0.9);
        // A non-audio input yields no waveform.
        assert!(compute_waveform(b"nope".to_vec(), 100).is_none());
        // Zero buckets is rejected.
        assert!(compute_waveform(tiny_wav(8_000, 1, 100), 0).is_none());
    }

    /// Regression: a fuzz-found input that overflows the AAC/ADTS header parser
    /// inside Symphonia (`symphonia-codec-aac/src/adts.rs`). Must be a clean
    /// `Err`, never a panic. Found by `fuzz/fuzz_targets/audio_decode.rs`.
    #[test]
    fn malformed_aac_does_not_panic() {
        let crash = [
            0xb8u8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8,
            0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xb8, 0xff, 0xf1, 0x6a,
            0xff, 0xff, 0xff, 0x18, 0x01, 0x00, 0x00, 0xfe, 0xff, 0xdb, 0xff, 0x00, 0x00,
        ];
        // The whole point: this returns Err instead of unwinding/aborting.
        assert!(AudioDecoder::open(crash.to_vec()).is_err());
    }

    /// Regression: a crafted AAC that decodes far enough to OPEN, then panics
    /// inside Symphonia 0.6's AAC section-data parser during `read`
    /// (`aac/ics/mod.rs:246`, reported upstream as pdeljanov/Symphonia#512).
    /// Our `read`/`seek` wrap the decoder in `catch_unwind`, so the panic must
    /// surface as a clean end-of-stream (0 samples), never a crash. Found by
    /// `fuzz/fuzz_targets/audio_decode.rs`.
    #[test]
    fn malformed_aac_decode_does_not_panic() {
        let crash: [u8; 164] = [
            0xff, 0xf3, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x80, 0x01, 0xff, 0xf8, 0xff, 0xf8, 0xff,
            0xef, 0x01, 0xe9, 0x00, 0x00, 0xff, 0xf8, 0x00, 0xc4, 0x12, 0x01, 0x80, 0x3d, 0xff,
            0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x56, 0x00, 0x00, 0x00, 0x01,
            0x20, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2b, 0x2b, 0x2b, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xf8, 0xff, 0xf8, 0xf7, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x5d, 0x00, 0x00, 0x00, 0x01, 0x7f, 0x7f, 0xff, 0x30, 0xf8, 0x00,
            0x80, 0x01, 0xff, 0xf8, 0xff, 0xf8, 0x28, 0xef, 0xff, 0xcf,
        ];
        if let Ok(mut d) = AudioDecoder::open(crash.to_vec()) {
            // Drive the same path the player does: read in chunks, seek, read.
            let mut buf = vec![0f32; 4096];
            for _ in 0..256 {
                if d.read(&mut buf) == 0 {
                    break;
                }
            }
            d.seek(1000);
            let _ = d.read(&mut buf); // must not panic
        }
    }

    #[test]
    fn seek_then_read_works() {
        let mut d = AudioDecoder::open(tiny_wav(8_000, 1, 4000)).unwrap();
        assert!(d.seek(2000));
        let mut buf = vec![0f32; 512];
        assert!(d.read(&mut buf) > 0);
    }
}
