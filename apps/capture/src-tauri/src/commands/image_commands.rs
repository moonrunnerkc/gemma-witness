//! `pick_images` Tauri command.
//!
//! The picker hardens against several attacks landed under audit findings
//! T-3 (image picker scope) and T-8 (aggregate cap):
//!
//! 1. Canonicalize each picked path; reject paths outside the user-content
//!    allowlist (`~/Pictures`, `~/Documents`, `~/Desktop`, `~/Downloads`).
//! 2. Use `symlink_metadata` and reject symlinks. A symlinked `id_ed25519`
//!    renamed to `id.png` would otherwise sneak through the extension check.
//! 3. Sniff the file's magic bytes; refuse anything that does not start with
//!    a JPEG or PNG header. The extension is advisory; the bytes decide.
//! 4. Enforce a per-file cap (10 MiB) AND a sum-across-files cap (20 MiB).
//! 5. Copy bytes into a per-capture staging directory under
//!    `app_local_data_dir/staged-images/` so the inference pipeline and the
//!    seal step read the same bytes even if the user's source-of-truth file
//!    is later swapped or sync'd over (audit T-1/V-3).

use std::path::{Path, PathBuf};

use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::error::AppError;
use crate::state::{PickedImage, SharedState};

/// Image extensions accepted by the capture flow.
const ALLOWED_EXTENSIONS: &[&str] = &["jpg", "jpeg", "png"];
/// Maximum per-file size, in bytes.
const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
/// Maximum aggregate bytes across all picked images.
const MAX_TOTAL_BYTES: u64 = 20 * 1024 * 1024;
/// Maximum number of images per call.
const MAX_FILES: usize = 4;

#[derive(Debug, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct PickedImages {
    pub paths: Vec<String>,
    pub count: u32,
}

#[tauri::command]
#[specta::specta]
pub async fn pick_images_cmd(
    app: AppHandle,
    state: State<'_, SharedState>,
) -> Result<PickedImages, AppError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .add_filter("Images", ALLOWED_EXTENSIONS)
        .pick_files(move |paths| {
            let _ = tx.send(paths);
        });

    let selection = rx.await.map_err(|err| AppError::ImageRejected {
        detail: format!("dialog channel closed: {err}"),
    })?;

    let raw_paths = selection.unwrap_or_default();
    if raw_paths.is_empty() {
        return Ok(PickedImages {
            paths: Vec::new(),
            count: 0,
        });
    }
    if raw_paths.len() > MAX_FILES {
        return Err(AppError::ImageRejected {
            detail: format!(
                "selected {} files but the limit is {MAX_FILES}",
                raw_paths.len()
            ),
        });
    }

    let allowlist = user_content_allowlist();
    let data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|err| AppError::Io {
            path: "(app_local_data_dir)".to_string(),
            detail: err.to_string(),
        })?;
    let staging_dir = data_dir
        .join("staged-images")
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&staging_dir).map_err(|err| {
        AppError::io_relative(
            &data_dir,
            &staging_dir,
            format!("create staging dir: {err}"),
        )
    })?;

    let mut accepted: Vec<PickedImage> = Vec::with_capacity(raw_paths.len());
    let mut total_bytes: u64 = 0;
    for (i, entry) in raw_paths.into_iter().enumerate() {
        let path = entry.into_path().map_err(|err| AppError::ImageRejected {
            detail: format!("could not resolve dialog path: {err}"),
        })?;
        let staged = validate_and_stage(&path, &staging_dir, &allowlist, i, &mut total_bytes)?;
        accepted.push(PickedImage {
            staged_path: staged,
        });
    }

    let display_paths: Vec<String> = accepted
        .iter()
        .map(|p| crate::error::relativize_for_frontend(&data_dir, &p.staged_path))
        .collect();

    {
        let mut guard = state.lock().await;
        guard.picked_images = accepted;
    }

    Ok(PickedImages {
        count: u32::try_from(display_paths.len()).unwrap_or(u32::MAX),
        paths: display_paths,
    })
}

fn validate_and_stage(
    source: &Path,
    staging_dir: &Path,
    allowlist: &[PathBuf],
    index: usize,
    running_total: &mut u64,
) -> Result<PathBuf, AppError> {
    // 1. Symlink rejection. `symlink_metadata` does not follow links.
    let link_meta = std::fs::symlink_metadata(source).map_err(|err| AppError::ImageRejected {
        detail: format!("could not stat {}: {err}", source.display()),
    })?;
    if link_meta.file_type().is_symlink() {
        return Err(AppError::ImageRejected {
            detail: format!(
                "{} is a symlink. the picker accepts only regular files so a renamed link cannot smuggle a non-image into the bundle.",
                source.display()
            ),
        });
    }
    if !link_meta.file_type().is_file() {
        return Err(AppError::ImageRejected {
            detail: format!(
                "{} is not a regular file (got {:?})",
                source.display(),
                link_meta.file_type()
            ),
        });
    }

    // 2. Extension check.
    let ext = source
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| AppError::ImageRejected {
            detail: format!("file {} has no extension", source.display()),
        })?;
    if !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
        return Err(AppError::ImageRejected {
            detail: format!(
                "file {} has extension {ext}; only jpg, jpeg, png are accepted",
                source.display()
            ),
        });
    }

    // 3. Canonicalize and check against the user-content allowlist. This
    //    guards against `~/.ssh/id_ed25519.pub` being picked via a relative
    //    path or a working-directory rename.
    let canonical = source
        .canonicalize()
        .map_err(|err| AppError::ImageRejected {
            detail: format!("could not canonicalize {}: {err}", source.display()),
        })?;
    let within_allowlist = allowlist
        .iter()
        .any(|allowed| canonical.starts_with(allowed));
    if !within_allowlist {
        return Err(AppError::ImageRejected {
            detail: format!(
                "{} is outside the user-content allowlist (~/Pictures, ~/Documents, ~/Desktop, ~/Downloads). \
                 move the image into one of those folders, or copy it there first.",
                source.display()
            ),
        });
    }

    // 4. Per-file and aggregate size caps. Sample once via metadata to avoid
    //    a TOCTOU window between metadata and the bytes we read for magic-byte
    //    sniffing; the staged bytes are what actually get hashed.
    let meta = std::fs::metadata(&canonical).map_err(|err| AppError::ImageRejected {
        detail: format!(
            "could not stat canonical path {}: {err}",
            canonical.display()
        ),
    })?;
    if meta.len() > MAX_FILE_BYTES {
        return Err(AppError::ImageRejected {
            detail: format!(
                "file {} is {} bytes; per-file limit is {MAX_FILE_BYTES}",
                source.display(),
                meta.len()
            ),
        });
    }
    let new_total =
        running_total
            .checked_add(meta.len())
            .ok_or_else(|| AppError::ImageRejected {
                detail: format!(
                    "aggregate image size overflowed u64 while adding {} bytes",
                    meta.len()
                ),
            })?;
    if new_total > MAX_TOTAL_BYTES {
        return Err(AppError::ImageRejected {
            detail: format!(
                "aggregate image size {new_total} bytes exceeds the cap of {MAX_TOTAL_BYTES} bytes. \
                 pick fewer or smaller images."
            ),
        });
    }
    *running_total = new_total;

    // 5. Read the bytes and sniff magic. The extension was advisory; the
    //    header bytes decide.
    let bytes = std::fs::read(&canonical).map_err(|err| AppError::ImageRejected {
        detail: format!("could not read {}: {err}", canonical.display()),
    })?;
    let mime = detect_image_mime(&bytes).ok_or_else(|| AppError::ImageRejected {
        detail: format!(
            "{} does not start with a JPEG or PNG magic header. \
             a renamed file (or a key/log/db dressed up with an image extension) cannot be sent to the model.",
            source.display()
        ),
    })?;
    let staged_extension = match mime {
        "image/png" => "png",
        _ => "jpg",
    };
    let staged_name = format!("img-{index}.{staged_extension}");
    let staged_path = staging_dir.join(staged_name);
    std::fs::write(&staged_path, &bytes).map_err(|err| AppError::ImageRejected {
        detail: format!(
            "could not write staged copy to {}: {err}",
            staged_path.display()
        ),
    })?;
    Ok(staged_path)
}

/// Build the allowlist of directories from which images may be picked.
/// Resolution uses the `dirs` crate so the same code works on macOS, Linux,
/// and Windows; missing directories are skipped so a portable account
/// without all four still works as long as one is present.
fn user_content_allowlist() -> Vec<PathBuf> {
    let candidates = [
        dirs::picture_dir(),
        dirs::document_dir(),
        dirs::desktop_dir(),
        dirs::download_dir(),
    ];
    candidates
        .into_iter()
        .flatten()
        .filter_map(|p| p.canonicalize().ok())
        .collect()
}

/// Magic-byte sniff. Re-implemented here (rather than reused from
/// `analyze_image.rs:detect_mime`) so the picker can refuse the file before
/// any inference code touches it. Returns `None` when the bytes do not start
/// with a recognised JPEG or PNG header.
pub fn detect_image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    #[test]
    fn detect_image_mime_recognises_jpeg_and_png() {
        assert_eq!(
            detect_image_mime(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]),
            Some("image/jpeg")
        );
        assert_eq!(
            detect_image_mime(&[
                0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D
            ]),
            Some("image/png")
        );
    }

    #[test]
    fn detect_image_mime_rejects_unknown_headers() {
        assert_eq!(detect_image_mime(b"PK\x03\x04zip-bytes"), None);
        assert_eq!(detect_image_mime(b"-----BEGIN PRIVATE KEY-----"), None);
        assert_eq!(detect_image_mime(b""), None);
    }

    #[test]
    fn validate_and_stage_rejects_file_outside_allowlist() {
        let stage = tempdir().unwrap();
        let stage_dir = stage.path().join("staging");
        std::fs::create_dir_all(&stage_dir).unwrap();

        let scratch = tempdir().unwrap();
        let jpeg_path = write_file(scratch.path(), "x.jpg", &[0xFF, 0xD8, 0xFF, 0x00]);

        // Allowlist points at a *different* directory.
        let other = tempdir().unwrap();
        let allow: Vec<PathBuf> = vec![other.path().canonicalize().unwrap()];
        let mut total = 0u64;
        let err = validate_and_stage(&jpeg_path, &stage_dir, &allow, 0, &mut total)
            .expect_err("path outside allowlist must be rejected");
        match err {
            AppError::ImageRejected { detail } => {
                assert!(detail.contains("allowlist"), "detail: {detail}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn validate_and_stage_rejects_non_image_magic() {
        let stage = tempdir().unwrap();
        let stage_dir = stage.path().join("staging");
        std::fs::create_dir_all(&stage_dir).unwrap();

        // Place the input inside the allowlist directory so we exercise the
        // magic-byte gate specifically.
        let allow_dir = tempdir().unwrap();
        let allow = vec![allow_dir.path().canonicalize().unwrap()];
        let path = write_file(allow_dir.path(), "looks-like.jpg", b"PK\x03\x04zip-bytes");

        let mut total = 0u64;
        let err = validate_and_stage(&path, &stage_dir, &allow, 0, &mut total)
            .expect_err("non-image magic bytes must be rejected");
        match err {
            AppError::ImageRejected { detail } => {
                assert!(
                    detail.contains("JPEG") || detail.contains("PNG"),
                    "detail: {detail}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn validate_and_stage_enforces_aggregate_cap() {
        let stage = tempdir().unwrap();
        let stage_dir = stage.path().join("staging");
        std::fs::create_dir_all(&stage_dir).unwrap();
        let allow_dir = tempdir().unwrap();
        let allow = vec![allow_dir.path().canonicalize().unwrap()];

        // Synthesize a 6 MiB jpeg-headed blob. With a 20 MiB aggregate cap,
        // the fourth file in a sequence must be refused.
        let mut blob = vec![0xFFu8, 0xD8, 0xFF, 0x00];
        blob.resize(6 * 1024 * 1024, 0x42);
        let p1 = write_file(allow_dir.path(), "a.jpg", &blob);
        let p2 = write_file(allow_dir.path(), "b.jpg", &blob);
        let p3 = write_file(allow_dir.path(), "c.jpg", &blob);
        let p4 = write_file(allow_dir.path(), "d.jpg", &blob);

        let mut total = 0u64;
        validate_and_stage(&p1, &stage_dir, &allow, 0, &mut total).expect("ok 1");
        validate_and_stage(&p2, &stage_dir, &allow, 1, &mut total).expect("ok 2");
        validate_and_stage(&p3, &stage_dir, &allow, 2, &mut total).expect("ok 3");
        let err = validate_and_stage(&p4, &stage_dir, &allow, 3, &mut total)
            .expect_err("4 x 6 MiB exceeds 20 MiB cap");
        match err {
            AppError::ImageRejected { detail } => {
                assert!(detail.contains("aggregate"), "detail: {detail}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
