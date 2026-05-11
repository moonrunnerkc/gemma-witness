//! `witness` command-line tool. Test driver for the witness pipeline.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use witness_inference::{
    run_full_pipeline, InferenceClient, PipelineResult, DEFAULT_ENDPOINT,
};

#[derive(Debug, Parser)]
#[command(name = "witness", version, about = "Gemma.Witness command-line driver.")]
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
}

fn default_schema_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("../../spec/incident-schema.json")
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
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("witness: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Structure {
            transcript,
            endpoint,
            schema,
        } => structure(transcript, endpoint, schema).await,
        Command::Pipeline {
            audio,
            images,
            endpoint,
            schema,
        } => pipeline(audio, images, endpoint, schema).await,
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
        anyhow::anyhow!("schema at {:?} did not parse as JSON: {}", schema_path, source)
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
