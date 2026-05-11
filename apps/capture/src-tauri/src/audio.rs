//! cpal-backed audio capture writing 16 kHz mono PCM WAV.
//!
//! Hardware sample rates and channel counts vary, so we accept whatever the
//! default input device offers, then down-mix to mono and resample to
//! 16 kHz (Gemma 4 E4B's audio input rate) before writing. The output is
//! always `pcm_s16le, 1 ch, 16000 Hz` regardless of the underlying device.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, Stream};
use hound::{SampleFormat as HoundFormat, WavSpec, WavWriter};

use crate::error::AppError;

/// Target sample rate (matches Gemma 4 E4B audio input).
pub const TARGET_SAMPLE_RATE: u32 = 16_000;
/// Hard cap on recording length, in seconds.
pub const MAX_DURATION_SECONDS: u64 = 30;

/// Handle returned from [`start_recording`] used to stop and flush the stream.
pub struct RecordingStopper {
    stop_flag: Arc<AtomicBool>,
    samples_written: Arc<AtomicU64>,
    sample_rate_hz: u32,
    channels: u16,
    writer: Arc<Mutex<Option<WavWriter<std::io::BufWriter<std::fs::File>>>>>,
    _stream: SendStream,
}

/// `cpal::Stream` is not `Send`. We never move the handle across threads
/// inside this module, but `tauri::State` (and thus the shared state mutex)
/// is generic over `Send`. Wrapping the stream in a newtype with an
/// `unsafe impl Send` matches what the cpal authors recommend for desktop
/// use; the stream is always created and dropped on the same OS thread.
#[allow(dead_code)]
struct SendStream(Stream);
unsafe impl Send for SendStream {}

/// Configuration we collected from the device, surfaced for state book-keeping.
#[derive(Debug, Clone, Copy)]
pub struct RecordingConfig {
    pub sample_rate_hz: u32,
    pub channels: u16,
}

/// Start a recording, writing 16 kHz mono PCM to `out_path`. The returned
/// [`RecordingStopper`] must be retained until the caller is ready to stop.
pub fn start_recording(out_path: &Path) -> Result<(RecordingStopper, RecordingConfig), AppError> {
    let host = cpal::default_host();
    let device = host
        .default_input_device()
        .ok_or_else(|| AppError::NoAudioDevice {
            detail: "cpal default_input_device returned None".to_string(),
        })?;
    let config = device
        .default_input_config()
        .map_err(|err| AppError::UnsupportedAudioConfig {
            detail: format!("default_input_config: {err}"),
        })?;

    let source_rate = config.sample_rate().0;
    let source_channels = config.channels();
    let sample_format = config.sample_format();
    let stream_config: cpal::StreamConfig = config.into();

    let spec = WavSpec {
        channels: 1,
        sample_rate: TARGET_SAMPLE_RATE,
        bits_per_sample: 16,
        sample_format: HoundFormat::Int,
    };
    let writer = WavWriter::create(out_path, spec).map_err(|err| AppError::Io {
        path: out_path.display().to_string(),
        detail: format!("create WAV: {err}"),
    })?;
    let writer = Arc::new(Mutex::new(Some(writer)));

    let stop_flag = Arc::new(AtomicBool::new(false));
    let samples_written = Arc::new(AtomicU64::new(0));

    let stop_flag_cb = Arc::clone(&stop_flag);
    let samples_written_cb = Arc::clone(&samples_written);
    let writer_cb = Arc::clone(&writer);

    let err_fn = |err| tracing::error!(?err, "cpal input stream error");

    let downmix_and_resample = move |input: &[f32]| {
        if stop_flag_cb.load(Ordering::Relaxed) {
            return;
        }
        // Down-mix to mono.
        let chans = source_channels as usize;
        let frame_count = input.len() / chans.max(1);
        let mut mono: Vec<f32> = Vec::with_capacity(frame_count);
        for frame in input.chunks_exact(chans.max(1)) {
            let sum: f32 = frame.iter().copied().sum();
            mono.push(sum / chans as f32);
        }
        // Linear resample to TARGET_SAMPLE_RATE.
        let resampled = resample_linear(&mono, source_rate, TARGET_SAMPLE_RATE);
        let mut guard = match writer_cb.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if let Some(writer) = guard.as_mut() {
            for sample in resampled {
                let clipped = (sample * i16::MAX as f32).clamp(i16::MIN as f32, i16::MAX as f32);
                if writer.write_sample(clipped as i16).is_err() {
                    return;
                }
                let written = samples_written_cb.fetch_add(1, Ordering::Relaxed) + 1;
                if written >= TARGET_SAMPLE_RATE as u64 * MAX_DURATION_SECONDS {
                    stop_flag_cb.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    };

    let stream = match sample_format {
        SampleFormat::F32 => device.build_input_stream(
            &stream_config,
            move |data: &[f32], _| downmix_and_resample(data),
            err_fn,
            None,
        ),
        SampleFormat::I16 => {
            let cb = downmix_and_resample;
            device.build_input_stream(
                &stream_config,
                move |data: &[i16], _| {
                    let floats: Vec<f32> =
                        data.iter().map(|s| *s as f32 / i16::MAX as f32).collect();
                    cb(&floats);
                },
                err_fn,
                None,
            )
        }
        SampleFormat::U16 => {
            let cb = downmix_and_resample;
            device.build_input_stream(
                &stream_config,
                move |data: &[u16], _| {
                    let floats: Vec<f32> = data
                        .iter()
                        .map(|s| (*s as f32 / u16::MAX as f32) * 2.0 - 1.0)
                        .collect();
                    cb(&floats);
                },
                err_fn,
                None,
            )
        }
        other => {
            return Err(AppError::UnsupportedAudioConfig {
                detail: format!("unhandled cpal sample format: {other:?}"),
            });
        }
    }
    .map_err(|err| AppError::AudioStream {
        detail: format!("build_input_stream: {err}"),
    })?;

    stream.play().map_err(|err| AppError::AudioStream {
        detail: format!("stream.play: {err}"),
    })?;

    Ok((
        RecordingStopper {
            stop_flag,
            samples_written,
            sample_rate_hz: TARGET_SAMPLE_RATE,
            channels: 1,
            writer,
            _stream: SendStream(stream),
        },
        RecordingConfig {
            sample_rate_hz: TARGET_SAMPLE_RATE,
            channels: 1,
        },
    ))
}

impl RecordingStopper {
    /// Stop the stream, flush the WAV writer, and return the duration in ms.
    pub fn finish(self) -> Result<RecordingSummary, AppError> {
        self.stop_flag.store(true, Ordering::Relaxed);
        let mut guard = self
            .writer
            .lock()
            .map_err(|_| AppError::AudioStream {
                detail: "WAV writer mutex was poisoned".to_string(),
            })?;
        if let Some(writer) = guard.take() {
            writer.finalize().map_err(|err| AppError::AudioStream {
                detail: format!("finalize WAV: {err}"),
            })?;
        }
        let samples = self.samples_written.load(Ordering::Relaxed);
        let duration_ms = (samples * 1000) / self.sample_rate_hz as u64;
        Ok(RecordingSummary {
            duration_ms,
            sample_rate_hz: self.sample_rate_hz,
            channels: self.channels,
        })
    }
}

/// Numeric summary returned by [`RecordingStopper::finish`].
#[derive(Debug, Clone, Copy)]
pub struct RecordingSummary {
    pub duration_ms: u64,
    pub sample_rate_hz: u32,
    pub channels: u16,
}

/// Linear-interpolation resampler. Good enough for speech-rate audio destined
/// for an ASR pass; not appropriate for music. Returns mono float samples.
fn resample_linear(input: &[f32], source_rate: u32, target_rate: u32) -> Vec<f32> {
    if input.is_empty() || source_rate == 0 {
        return Vec::new();
    }
    if source_rate == target_rate {
        return input.to_vec();
    }
    let ratio = target_rate as f64 / source_rate as f64;
    let out_len = (input.len() as f64 * ratio).round() as usize;
    let mut out: Vec<f32> = Vec::with_capacity(out_len);
    for i in 0..out_len {
        let src_pos = i as f64 / ratio;
        let lo = src_pos.floor() as usize;
        let hi = (lo + 1).min(input.len() - 1);
        let frac = (src_pos - lo as f64) as f32;
        let s_lo = input.get(lo).copied().unwrap_or(0.0);
        let s_hi = input.get(hi).copied().unwrap_or(0.0);
        out.push(s_lo * (1.0 - frac) + s_hi * frac);
    }
    out
}
