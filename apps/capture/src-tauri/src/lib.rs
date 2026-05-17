//! Tauri 2 capture-app library entry point.

use std::sync::Arc;

use specta_typescript::Typescript;
use tauri::Manager;
use tauri_specta::{collect_commands, Builder};
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

pub mod audio;
pub mod commands;
mod error;
mod sidecar;
mod state;

use crate::commands::audio_commands::{start_recording_cmd, stop_recording_cmd};
use crate::commands::device::{discard_capture_cmd, initialize_device};
use crate::commands::image_commands::pick_images_cmd;
use crate::commands::inference_commands::run_inference_cmd;
use crate::commands::seal_commands::{reveal_bundle_cmd, seal_bundle_cmd};
use crate::state::{CaptureState, SharedState};

fn specta_builder() -> Builder<tauri::Wry> {
    Builder::<tauri::Wry>::new().commands(collect_commands![
        initialize_device,
        start_recording_cmd,
        stop_recording_cmd,
        pick_images_cmd,
        run_inference_cmd,
        seal_bundle_cmd,
        reveal_bundle_cmd,
        discard_capture_cmd
    ])
}

/// Export TypeScript bindings for the Tauri commands.
///
/// Called automatically on debug builds inside [`run()`] and also exposed
/// as a standalone binary (`export_bindings`) so CI and package scripts can
/// generate the file without launching the full UI.
#[cfg(debug_assertions)]
pub fn export_bindings() {
    specta_builder()
        .export(Typescript::default(), "../src/bindings.ts")
        .expect("failed to export TypeScript bindings");
}

/// Build and run the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(debug_assertions)]
    export_bindings();

    let shared: SharedState = Arc::new(Mutex::new(CaptureState::default()));
    let builder = specta_builder();
    let sidecar_holder = sidecar::ManagedSidecarHolder(sidecar::ensure_sidecar());

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(shared)
        .manage(sidecar_holder)
        .setup(|app| {
            install_tracing_subscriber(app.handle())?;
            Ok(())
        })
        .invoke_handler(builder.invoke_handler())
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|handle, event| {
        if let tauri::RunEvent::ExitRequested { .. } = event {
            if let Some(holder) = handle.try_state::<sidecar::ManagedSidecarHolder>() {
                holder.shutdown();
            }
        }
    });
}

/// Install a `tracing_subscriber` writing to `app_local_data_dir/logs/<date>.log`.
/// Filtering honors `RUST_LOG` per `EnvFilter::from_default_env()`.
///
/// Audit finding T-4: previously `tracing-subscriber` was a dependency but
/// no subscriber was ever installed, so the single `tracing::error!` call
/// inside the cpal stream error callback dropped silently. Initializing
/// here gives the security event store a real destination.
fn install_tracing_subscriber(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = app.path().app_local_data_dir()?;
    let logs_dir = data_dir.join("logs");
    std::fs::create_dir_all(&logs_dir)?;
    let date = chrono::Utc::now().format("%Y-%m-%d");
    let log_path = logs_dir.join(format!("{date}.log"));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,gemma_witness_capture_lib=debug"));
    let subscriber_install = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::sync::Mutex::new(file))
        .with_ansi(false)
        .try_init();
    if let Err(err) = subscriber_install {
        // A second initialization attempt (e.g., in `cargo test` parallel
        // contexts) is non-fatal. Log to stderr so the test harness picks it
        // up, but allow the app to continue.
        eprintln!("tracing_subscriber already initialized: {err}");
    }
    Ok(())
}
