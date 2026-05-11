//! Tauri 2 capture-app library entry point.

use std::sync::Arc;

use specta_typescript::Typescript;
use tauri_specta::{collect_commands, Builder};
use tokio::sync::Mutex;

pub mod audio;
pub mod commands;
mod error;
mod state;

use crate::commands::audio_commands::{start_recording_cmd, stop_recording_cmd};
use crate::commands::device::initialize_device;
use crate::commands::image_commands::pick_images_cmd;
use crate::commands::inference_commands::run_inference_cmd;
use crate::commands::seal_commands::seal_bundle_cmd;
use crate::state::{CaptureState, SharedState};

fn specta_builder() -> Builder<tauri::Wry> {
    Builder::<tauri::Wry>::new().commands(collect_commands![
        initialize_device,
        start_recording_cmd,
        stop_recording_cmd,
        pick_images_cmd,
        run_inference_cmd,
        seal_bundle_cmd
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

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(shared)
        .invoke_handler(builder.invoke_handler())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
