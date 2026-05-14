//! `witness` command-line tool. Test driver for the witness pipeline.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use witness_core::{verify_bundle, VerificationReport};
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
        } => structure(transcript, endpoint, schema).await.map(|()| ExitCode::SUCCESS),
        Command::Pipeline {
            audio,
            images,
            endpoint,
            schema,
        } => pipeline(audio, images, endpoint, schema).await.map(|()| ExitCode::SUCCESS),
        Command::Verify {
            bundle,
            fingerprints,
        } => verify(bundle, fingerprints),
    }
}

fn verify(bundle: PathBuf, fingerprints_path: Option<PathBuf>) -> anyhow::Result<ExitCode> {
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
    let known: Vec<String> = fp_doc
        .get("fingerprints")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "known-fingerprints at {:?} has no `fingerprints` array",
                fp_path
            )
        })?
        .iter()
        .filter_map(|entry| entry.get("sha256").and_then(|s| s.as_str()).map(String::from))
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

    let serializable = serde_json::json!({
        "bundle": bundle.display().to_string(),
        "manifest_parsed": report.manifest_parsed,
        "signature_valid": report.signature_valid,
        "assets_untampered": report.assets_untampered,
        "model_fingerprint_known": report.model_fingerprint_known,
        "details": report.details,
        "ok": report.is_ok(),
    });
    println!("{}", serde_json::to_string_pretty(&serializable)?);
    eprintln!(
        "witness: verify {} (signature={}, assets={}, fingerprint={})",
        if report.is_ok() { "ok" } else { "FAIL" },
        report.signature_valid,
        report.assets_untampered,
        report.model_fingerprint_known
    );
    Ok(if report.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
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
