//! Optional advisory audio fingerprint.
//!
//! Stored alongside the cryptographic SHA-256 of the WAV bytes, never as a
//! replacement for it. The SHA-256 proves the bytes did not change. This
//! fingerprint adds a perceptual layer: it summarises the spectral envelope
//! of the audio so a third party who only has a re-encoded copy can still
//! ask "does this sound like the recording the bundle claims?" The verifier
//! displays it; the CLI's optional `verify --acoustic` mode re-derives it
//! from the in-bundle WAV and compares for exact match.
//!
//! Algorithm `gw-spectral-v1`:
//! 1. Decode WAV to f32 mono samples, normalised to `[-1, 1]`.
//! 2. Take at most the first 60 seconds (defined as a hard ceiling).
//! 3. Frame at 4096 samples, no overlap.
//! 4. Per frame: apply a Hann window, run a 4096-point FFT, take the power
//!    spectrum across the first 2048 bins (positive frequencies).
//! 5. Aggregate the power spectrum into 16 equal-width linear bands across
//!    the positive frequencies. Convert each band's energy to natural log
//!    after a small floor to avoid `log(0)`.
//! 6. For each band emit `1` if its log-energy exceeds the median log-energy
//!    across all 16 bands of the frame, `0` otherwise. 16 bits per frame.
//! 7. Concatenate frame bits into a big-endian bit stream, pack into bytes,
//!    base64-encode.
//!
//! Not collision-resistant. Not a security primitive. The field carries a
//! `note` string repeating this disclaimer.

use std::io::Cursor;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rustfft::num_complex::Complex32;
use rustfft::{Fft, FftPlanner};
use serde::{Deserialize, Serialize};

use crate::error::WitnessCoreError;

/// Algorithm identifier baked into the manifest. Bumping this string requires
/// also updating the schema enum and the CLI re-derivation path.
pub const ALGORITHM: &str = "gw-spectral-v1";
/// Disclaimer note repeated inside the manifest so a reviewer pulling raw
/// JSON sees the advisory framing alongside the value.
pub const NOTE: &str =
    "advisory perceptual fingerprint, not a security primitive. the SHA-256 in the audio asset \
     entry remains the cryptographic guarantee; this field summarises spectral envelope only.";

/// Cap analysis at the first 60 seconds of audio.
const MAX_SECONDS: usize = 60;
/// Frame size in samples. 4096 at 16 kHz is 256 ms; coarser than perceptual
/// hashing literature uses, but stable and cheap.
const FRAME_SIZE: usize = 4096;
/// Number of log-spaced bands per frame.
const BANDS: usize = 16;
/// Hard ceiling on output length, expressed in frames. 720 frames at 4096
/// samples covers about 3 minutes at 16 kHz, beyond the audio cap above.
/// The cap exists only to bound JSON size if the cap is ever raised.
const MAX_FRAMES: usize = 720;
/// Floor used before `ln` to keep silent bands finite without underflowing.
const POWER_FLOOR: f32 = 1e-12;

/// The serialized assertion. Lives at `gemma.witness.audio_fingerprint` in
/// the manifest when present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudioFingerprint {
    /// Identifier for the algorithm that produced [`Self::value`].
    pub algorithm: String,
    /// Base64-encoded packed bitstream. See module docs for the layout.
    pub value: String,
    /// Human-readable disclaimer repeated inside the field itself.
    pub note: String,
}

/// Compute the advisory fingerprint for a WAV byte buffer.
///
/// # Errors
/// Returns [`WitnessCoreError::AudioDecode`] when the input does not parse
/// as a WAV file the supported decoder understands. The asset hash in the
/// manifest still pins the original bytes; this only signals that the
/// advisory check could not run.
pub fn compute(wav_bytes: &[u8]) -> Result<AudioFingerprint, WitnessCoreError> {
    let samples = decode_to_mono_f32(wav_bytes)?;
    let bits = spectral_bits(&samples);
    let packed = pack_bits(&bits);
    let value = BASE64.encode(&packed);
    Ok(AudioFingerprint {
        algorithm: ALGORITHM.to_string(),
        value,
        note: NOTE.to_string(),
    })
}

/// Outcome of recomputing the fingerprint and comparing it to a claimed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcousticCheck {
    /// Algorithm string the manifest claims. Recorded so the caller can flag
    /// a mismatch between the claimed algorithm and the one this build can
    /// recompute.
    pub claimed_algorithm: String,
    /// True when the algorithm matches and the recomputed value equals the
    /// claimed value byte for byte.
    pub matches: bool,
    /// True only when [`Self::claimed_algorithm`] equals [`ALGORITHM`].
    pub algorithm_supported: bool,
}

/// Recompute the fingerprint and check it against a manifest claim.
///
/// `claimed` is the [`AudioFingerprint`] embedded in the bundle's manifest.
///
/// # Errors
/// Same as [`compute`].
pub fn verify_against(
    claimed: &AudioFingerprint,
    wav_bytes: &[u8],
) -> Result<AcousticCheck, WitnessCoreError> {
    if claimed.algorithm != ALGORITHM {
        return Ok(AcousticCheck {
            claimed_algorithm: claimed.algorithm.clone(),
            matches: false,
            algorithm_supported: false,
        });
    }
    let recomputed = compute(wav_bytes)?;
    Ok(AcousticCheck {
        claimed_algorithm: claimed.algorithm.clone(),
        matches: recomputed.value == claimed.value,
        algorithm_supported: true,
    })
}

fn decode_to_mono_f32(wav_bytes: &[u8]) -> Result<Vec<f32>, WitnessCoreError> {
    let cursor = Cursor::new(wav_bytes);
    let mut reader = hound::WavReader::new(cursor).map_err(|source| WitnessCoreError::AudioDecode {
        detail: format!("hound rejected the WAV header: {source}. the file may be a non-PCM format the advisory check does not handle."),
    })?;
    let spec = reader.spec();
    let channels = spec.channels.max(1) as usize;
    let sample_rate = spec.sample_rate as usize;
    if sample_rate == 0 {
        return Err(WitnessCoreError::AudioDecode {
            detail: "WAV header reports sample_rate=0".to_string(),
        });
    }
    let max_samples_per_channel = MAX_SECONDS.saturating_mul(sample_rate);
    let max_interleaved = max_samples_per_channel.saturating_mul(channels);

    let interleaved: Vec<f32> = match spec.sample_format {
        hound::SampleFormat::Int => {
            let bps = spec.bits_per_sample as u32;
            let denom = match bps {
                8 => i32::from(i8::MAX) as f32,
                16 => i32::from(i16::MAX) as f32,
                24 => 8_388_607.0,
                32 => i32::MAX as f32,
                other => {
                    return Err(WitnessCoreError::AudioDecode {
                        detail: format!("unsupported integer PCM width: {other} bits"),
                    });
                }
            };
            let mut out = Vec::new();
            for sample in reader.samples::<i32>().take(max_interleaved) {
                let s = sample.map_err(|err| WitnessCoreError::AudioDecode {
                    detail: format!("integer PCM sample read failed: {err}"),
                })?;
                out.push((s as f32) / denom);
            }
            out
        }
        hound::SampleFormat::Float => {
            let mut out = Vec::new();
            for sample in reader.samples::<f32>().take(max_interleaved) {
                let s = sample.map_err(|err| WitnessCoreError::AudioDecode {
                    detail: format!("float PCM sample read failed: {err}"),
                })?;
                out.push(s);
            }
            out
        }
    };

    if interleaved.is_empty() {
        return Err(WitnessCoreError::AudioDecode {
            detail: "WAV contained no audio samples".to_string(),
        });
    }

    if channels == 1 {
        return Ok(interleaved);
    }
    let frames = interleaved.len() / channels;
    let mut mono = Vec::with_capacity(frames);
    for frame_index in 0..frames {
        let base = frame_index * channels;
        let mut acc = 0.0_f32;
        for c in 0..channels {
            acc += interleaved[base + c];
        }
        mono.push(acc / channels as f32);
    }
    Ok(mono)
}

fn hann_window(size: usize) -> Vec<f32> {
    let mut w = Vec::with_capacity(size);
    let n = size as f32;
    for i in 0..size {
        let v = 0.5 * (1.0 - ((2.0 * std::f32::consts::PI * i as f32) / (n - 1.0)).cos());
        w.push(v);
    }
    w
}

fn spectral_bits(samples: &[f32]) -> Vec<bool> {
    let mut planner = FftPlanner::<f32>::new();
    let fft: Arc<dyn Fft<f32>> = planner.plan_fft_forward(FRAME_SIZE);
    let window = hann_window(FRAME_SIZE);

    let mut bits: Vec<bool> = Vec::new();
    let mut frame: Vec<Complex32> = vec![Complex32::new(0.0, 0.0); FRAME_SIZE];

    let usable_bins = FRAME_SIZE / 2;
    let bin_per_band = usable_bins / BANDS;
    if bin_per_band == 0 {
        return bits;
    }

    let mut frame_count = 0;
    let mut offset = 0;
    while offset + FRAME_SIZE <= samples.len() && frame_count < MAX_FRAMES {
        for (i, slot) in frame.iter_mut().enumerate() {
            *slot = Complex32::new(samples[offset + i] * window[i], 0.0);
        }
        fft.process(&mut frame);

        let mut band_energy = [0.0_f32; BANDS];
        for (band, energy_slot) in band_energy.iter_mut().enumerate() {
            let start_bin = band * bin_per_band;
            let end_bin = if band == BANDS - 1 {
                usable_bins
            } else {
                start_bin + bin_per_band
            };
            let mut acc = 0.0_f32;
            for bin in &frame[start_bin..end_bin] {
                acc += bin.norm_sqr();
            }
            *energy_slot = (acc.max(POWER_FLOOR)).ln();
        }

        let mut sorted = band_energy;
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = (sorted[BANDS / 2 - 1] + sorted[BANDS / 2]) / 2.0;

        for energy in &band_energy {
            bits.push(*energy > median);
        }

        offset += FRAME_SIZE;
        frame_count += 1;
    }

    bits
}

fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, b) in bits.iter().enumerate() {
        if *b {
            out[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_wav(sample_rate: u32, seconds: f32, frequency_hz: f32) -> Vec<u8> {
        let spec = hound::WavSpec {
            channels: 1,
            sample_rate,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };
        let mut buffer: Vec<u8> = Vec::new();
        {
            let cursor = Cursor::new(&mut buffer);
            let mut writer = hound::WavWriter::new(cursor, spec).expect("init wav writer");
            let total = (sample_rate as f32 * seconds) as usize;
            let two_pi = 2.0 * std::f32::consts::PI;
            for i in 0..total {
                let t = i as f32 / sample_rate as f32;
                let s = (two_pi * frequency_hz * t).sin();
                writer
                    .write_sample((s * 32_000.0) as i16)
                    .expect("write sample");
            }
            writer.finalize().expect("finalize wav");
        }
        buffer
    }

    #[test]
    fn deterministic_for_same_bytes() {
        let wav = synth_wav(16_000, 1.0, 440.0);
        let a = compute(&wav).expect("compute a");
        let b = compute(&wav).expect("compute b");
        assert_eq!(a, b, "same bytes must produce identical fingerprint");
        assert_eq!(a.algorithm, ALGORITHM);
    }

    #[test]
    fn different_audio_produces_different_fingerprint() {
        let a = compute(&synth_wav(16_000, 1.0, 440.0)).expect("a");
        let b = compute(&synth_wav(16_000, 1.0, 2_000.0)).expect("b");
        assert_ne!(a.value, b.value, "different tones must differ");
    }

    #[test]
    fn verify_against_round_trips_match() {
        let wav = synth_wav(16_000, 1.0, 440.0);
        let claim = compute(&wav).expect("compute");
        let check = verify_against(&claim, &wav).expect("verify");
        assert!(check.matches);
        assert!(check.algorithm_supported);
    }

    #[test]
    fn verify_against_detects_substituted_audio() {
        let wav_a = synth_wav(16_000, 1.0, 440.0);
        let wav_b = synth_wav(16_000, 1.0, 2_000.0);
        let claim_for_a = compute(&wav_a).expect("compute a");
        let check = verify_against(&claim_for_a, &wav_b).expect("verify");
        assert!(!check.matches, "substituted audio must fail acoustic check");
    }

    #[test]
    fn verify_against_flags_unknown_algorithm() {
        let wav = synth_wav(16_000, 1.0, 440.0);
        let foreign = AudioFingerprint {
            algorithm: "some-future-algo-v2".to_string(),
            value: "AAAA".to_string(),
            note: "n/a".to_string(),
        };
        let check = verify_against(&foreign, &wav).expect("verify");
        assert!(!check.matches);
        assert!(!check.algorithm_supported);
    }

    #[test]
    fn decode_handles_stereo_by_averaging() {
        let spec = hound::WavSpec {
            channels: 2,
            sample_rate: 16_000,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };
        let mut buffer: Vec<u8> = Vec::new();
        {
            let cursor = Cursor::new(&mut buffer);
            let mut writer = hound::WavWriter::new(cursor, spec).expect("init wav writer");
            for i in 0..16_000 {
                let t = i as f32 / 16_000.0;
                let s = (2.0 * std::f32::consts::PI * 440.0 * t).sin();
                writer.write_sample((s * 32_000.0) as i16).expect("L");
                writer.write_sample((s * 32_000.0) as i16).expect("R");
            }
            writer.finalize().expect("finalize");
        }
        let samples = decode_to_mono_f32(&buffer).expect("decode stereo");
        assert!(!samples.is_empty());
        let mono = synth_wav(16_000, 1.0, 440.0);
        let mono_samples = decode_to_mono_f32(&mono).expect("decode mono");
        assert_eq!(
            samples.len(),
            mono_samples.len(),
            "mono and averaged-stereo frame counts must match"
        );
    }
}
