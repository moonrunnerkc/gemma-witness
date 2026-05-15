//! `witness` command-line tool. Test driver for the witness pipeline.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use witness_core::bundle_builder::paths as bundle_paths;
use witness_core::bundle_zip::read_bundle;
use witness_core::manifest::Manifest;
use witness_core::{verify_audio_fingerprint, verify_bundle, AcousticCheck, VerificationReport};
use witness_inference::{run_full_pipeline, InferenceClient, PipelineResult, DEFAULT_ENDPOINT};

#[derive(Debug, Parser)]
#[command(
    name = "witness",
    version,
    about = "Gemma.Witness command-line driver."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Send a transcript to the local sidecar and emit a structured incident report as JSON.
    Structure {
        /// Path to a UTF-8 transcript file.
        #[arg(long)]
        transcript: PathBuf,
        /// Override the sidecar endpoint.
        #[arg(long, default_value = DEFAULT_ENDPOINT)]
        endpoint: String,
        /// Path to the JSON Schema used to constrain the model output.
        /// Defaults to `spec/incident-schema.json` resolved relative to the workspace.
        #[arg(long)]
        schema: Option<PathBuf>,
    },
    /// Run the full multimodal pipeline (transcribe + structure + image analysis + consistency).
    Pipeline {
        /// Path to a WAV file.
        #[arg(long)]
        audio: PathBuf,
        /// One or more image paths. Pass `--image` once per image.
        #[arg(long = "image")]
        images: Vec<PathBuf>,
        /// Override the sidecar endpoint.
        #[arg(long, default_value = DEFAULT_ENDPOINT)]
        endpoint: String,
        /// Path to the JSON Schema for the structured incident report.
        #[arg(long)]
        schema: Option<PathBuf>,
    },
    /// Verify a sealed `.witness` bundle: signature, asset hashes, and model fingerprint.
    /// Exit code 0 if every check passes, 1 otherwise. The structured report is emitted on stdout.
    Verify {
        /// Path to the .witness bundle.
        #[arg(long)]
        bundle: PathBuf,
        /// Path to known-fingerprints.json. Defaults to `apps/verifier/known-fingerprints.json`.
        #[arg(long)]
        fingerprints: Option<PathBuf>,
        /// Re-derive the advisory audio fingerprint from the in-bundle WAV
        /// and report whether it matches the manifest's claim. Adds an
        /// `acoustic` field to the JSON output. Never affects the exit code,
        /// since acoustic fingerprints are advisory, not cryptographic.
        #[arg(long, default_value_t = false)]
        acoustic: bool,
    },
}

fn default_schema_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("../../spec/incident-schema.json")
}

fn default_fingerprints_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("../../apps/verifier/known-fingerprints.json")
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(exit) => exit,
        Err(err) => {
            eprintln!("witness: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Command::Structure {
            transcript,
            endpoint,
            schema,
        } => structure(transcript, endpoint, schema)
            .await
            .map(|()| ExitCode::SUCCESS),
        Command::Pipeline {
            audio,
            images,
            endpoint,
            schema,
        } => pipeline(audio, images, endpoint, schema)
            .await
            .map(|()| ExitCode::SUCCESS),
        Command::Verify {
            bundle,
            fingerprints,
            acoustic,
        } => verify(bundle, fingerprints, acoustic),
    }
}

fn verify(
    bundle: PathBuf,
    fingerprints_path: Option<PathBuf>,
    acoustic: bool,
) -> anyhow::Result<ExitCode> {
    let fp_path = fingerprints_path.unwrap_or_else(default_fingerprints_path);
    let fp_raw = std::fs::read_to_string(&fp_path).map_err(|source| {
        anyhow::anyhow!(
            "could not read known-fingerprints at {:?}: {}. pass --fingerprints to override.",
            fp_path,
            source
        )
    })?;
    let fp_doc: serde_json::Value = serde_json::from_str(&fp_raw).map_err(|source| {
        anyhow::anyhow!(
            "known-fingerprints at {:?} did not parse as JSON: {}",
            fp_path,
            source
        )
    })?;
    let known: Vec<witness_core::KnownFingerprint> = fp_doc
        .get("fingerprints")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "known-fingerprints at {:?} has no `fingerprints` array",
                fp_path
            )
        })?
        .iter()
        .filter_map(|entry| {
            let model_id = entry.get("model_id").and_then(|s| s.as_str())?;
            let revision = entry.get("revision").and_then(|s| s.as_str())?;
            let sha256 = entry.get("sha256").and_then(|s| s.as_str())?;
            Some(witness_core::KnownFingerprint {
                model_id: model_id.to_string(),
                revision: revision.to_string(),
                sha256: sha256.to_string(),
            })
        })
        .collect();
    if known.is_empty() {
        anyhow::bail!(
            "known-fingerprints at {:?} contained no sha256 entries; refusing to verify.",
            fp_path
        );
    }

    let report: VerificationReport = verify_bundle(&bundle, &known).map_err(|source| {
        anyhow::anyhow!(
            "could not verify bundle at {:?}: {}. confirm the file exists and is a .witness archive.",
            bundle,
            source
        )
    })?;

    let acoustic_summary = if acoustic {
        Some(run_acoustic_check(&bundle)?)
    } else {
        None
    };

    let mut serializable = serde_json::json!({
        "bundle": bundle.display().to_string(),
        "manifest_parsed": report.manifest_parsed,
        "signature_valid": report.signature_valid,
        "assets_untampered": report.assets_untampered,
        "model_fingerprint_known": report.model_fingerprint_known,
        "details": report.details,
        "ok": report.is_ok(),
    });
    if let Some(ref summary) = acoustic_summary {
        serializable["acoustic"] = serde_json::to_value(summary)?;
    }
    println!("{}", serde_json::to_string_pretty(&serializable)?);
    eprintln!(
        "witness: verify {} (signature={}, assets={}, fingerprint={})",
        if report.is_ok() { "ok" } else { "FAIL" },
        report.signature_valid,
        report.assets_untampered,
        report.model_fingerprint_known
    );
    if let Some(summary) = acoustic_summary {
        eprintln!("witness: acoustic {}", summary.line());
    }
    Ok(if report.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Outcome of the advisory acoustic re-derivation invoked by `verify --acoustic`.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum AcousticSummary {
    /// The bundle did not carry an audio_fingerprint assertion.
    Absent,
    /// Re-derivation succeeded and matched the manifest's claim.
    Matched { algorithm: String },
    /// Re-derivation succeeded but the value differs from the manifest's claim.
    Mismatched { algorithm: String, detail: String },
    /// Manifest carries a fingerprint produced by an algorithm this build
    /// does not implement.
    UnsupportedAlgorithm { claimed_algorithm: String },
    /// Re-derivation failed (e.g., audio decode error). Cryptographic
    /// checks above are unaffected.
    DecodeFailed { detail: String },
}

impl AcousticSummary {
    fn line(&self) -> String {
        match self {
            AcousticSummary::Absent => {
                "no advisory fingerprint embedded in this bundle".to_string()
            }
            AcousticSummary::Matched { algorithm } => {
                format!("re-derived {algorithm} matches manifest claim")
            }
            AcousticSummary::Mismatched {
                algorithm, detail, ..
            } => format!("MISMATCH under {algorithm}: {detail}"),
            AcousticSummary::UnsupportedAlgorithm { claimed_algorithm } => format!(
                "manifest claims algorithm {claimed_algorithm}, which this CLI build does not implement"
            ),
            AcousticSummary::DecodeFailed { detail } => {
                format!("could not re-derive: {detail}")
            }
        }
    }
}

fn run_acoustic_check(bundle: &std::path::Path) -> anyhow::Result<AcousticSummary> {
    let entries = read_bundle(bundle).map_err(|source| {
        anyhow::anyhow!(
            "could not open bundle at {bundle:?} for acoustic check: {source}. \
             cryptographic verification reported separately."
        )
    })?;
    let manifest_bytes = entries.get(bundle_paths::MANIFEST).ok_or_else(|| {
        anyhow::anyhow!("bundle at {bundle:?} is missing manifest.json for acoustic check")
    })?;
    let manifest: Manifest = serde_json::from_slice(manifest_bytes)
        .map_err(|source| anyhow::anyhow!("acoustic: manifest did not parse as JSON: {source}"))?;
    let Some(claim) = manifest.assertions.audio_fingerprint.as_ref() else {
        return Ok(AcousticSummary::Absent);
    };
    let Some(audio_bytes) = entries.get(bundle_paths::AUDIO) else {
        return Ok(AcousticSummary::DecodeFailed {
            detail: format!(
                "manifest names audio fingerprint but {} is missing from the zip",
                bundle_paths::AUDIO
            ),
        });
    };
    let check: AcousticCheck = match verify_audio_fingerprint(claim, audio_bytes) {
        Ok(c) => c,
        Err(err) => {
            return Ok(AcousticSummary::DecodeFailed {
                detail: err.to_string(),
            });
        }
    };
    if !check.algorithm_supported {
        return Ok(AcousticSummary::UnsupportedAlgorithm {
            claimed_algorithm: check.claimed_algorithm,
        });
    }
    if check.matches {
        Ok(AcousticSummary::Matched {
            algorithm: check.claimed_algorithm,
        })
    } else {
        Ok(AcousticSummary::Mismatched {
            algorithm: check.claimed_algorithm,
            detail: "recomputed fingerprint differs from manifest claim. the audio inside the bundle may have been substituted, or the algorithm constants have drifted.".to_string(),
        })
    }
}

async fn pipeline(
    audio_path: PathBuf,
    image_paths: Vec<PathBuf>,
    endpoint: String,
    schema_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    let schema_path = schema_path.unwrap_or_else(default_schema_path);
    let schema = load_schema(&schema_path)?;
    let outcome: PipelineResult =
        run_full_pipeline(&audio_path, &image_paths, &schema, &endpoint).await?;
    let pretty = serde_json::to_string_pretty(&outcome)?;
    println!("{pretty}");
    eprintln!(
        "witness: pipeline ok (images={}, total_latency_ms={}, verdict={})",
        outcome.images.len(),
        outcome.total_latency_ms,
        outcome.consistency.verdict
    );
    Ok(())
}

fn load_schema(schema_path: &PathBuf) -> anyhow::Result<serde_json::Value> {
    let schema_raw = std::fs::read_to_string(schema_path).map_err(|source| {
        anyhow::anyhow!(
            "could not read schema at {:?}: {}. pass --schema or restore spec/incident-schema.json.",
            schema_path,
            source
        )
    })?;
    serde_json::from_str(&schema_raw).map_err(|source| {
        anyhow::anyhow!(
            "schema at {:?} did not parse as JSON: {}",
            schema_path,
            source
        )
    })
}

async fn structure(
    transcript_path: PathBuf,
    endpoint: String,
    schema_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    let schema_path = schema_path.unwrap_or_else(default_schema_path);
    let transcript = std::fs::read_to_string(&transcript_path).map_err(|source| {
        anyhow::anyhow!(
            "could not read transcript at {:?}: {}. confirm the file exists and is utf-8.",
            transcript_path,
            source
        )
    })?;
    let schema = load_schema(&schema_path)?;
    let client = InferenceClient::with_endpoint(&endpoint)?;
    let outcome = client.structure_incident(&transcript, &schema).await?;
    let pretty = serde_json::to_string_pretty(&outcome.report)?;
    println!("{pretty}");
    eprintln!(
        "witness: ok (retries_used={}, latency_ms={})",
        outcome.retries_used, outcome.latency_ms
    );
    Ok(())
}
