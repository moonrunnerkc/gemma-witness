//! Tauri 2 capture-app library entry point.

use std::sync::Arc;

use tokio::sync::Mutex;

pub mod audio;
mod commands;
mod error;
mod state;

use crate::commands::audio_commands::{start_recording_cmd, stop_recording_cmd};
use crate::commands::device::initialize_device;
use crate::commands::image_commands::pick_images_cmd;
use crate::commands::inference_commands::run_inference_cmd;
use crate::commands::seal_commands::seal_bundle_cmd;
use crate::state::{CaptureState, SharedState};

/// Build and run the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let shared: SharedState = Arc::new(Mutex::new(CaptureState::default()));
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(shared)
        .invoke_handler(tauri::generate_handler![
            initialize_device,
            start_recording_cmd,
            stop_recording_cmd,
            pick_images_cmd,
            run_inference_cmd,
            seal_bundle_cmd
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
