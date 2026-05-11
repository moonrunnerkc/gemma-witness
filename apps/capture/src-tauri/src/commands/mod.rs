//! Tauri commands. Thin wrappers that translate typed app state into the
//! JSON the frontend receives. Heavy lifting lives in `witness-core` and
//! `witness-inference`.

pub mod audio_commands;
pub mod device;
pub mod image_commands;
pub mod inference_commands;
pub mod seal_commands;
