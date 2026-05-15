//! Read and write `.witness` ZIP archives deterministically.
//!
//! Every entry is STORED (uncompressed), the entry list is sorted by path
//! before writing, and modification timestamps are pinned to the lowest
//! value the ZIP format admits. Two seals of the same logical payload
//! therefore produce byte-identical files.

use std::collections::BTreeMap;
use std::io::{Read, Seek, Write};
use std::path::Path;

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::error::WitnessCoreError;

/// Hard cap on the uncompressed size of any single ZIP entry. 100 MiB is
/// orders of magnitude over the largest legitimate witness asset (a 30-s WAV
/// at 16 kHz mono is under 2 MiB; a JPEG capped to 10 MiB; reasoning trace is
/// tens of KB). Per-entry cap stops a single hostile entry from exhausting
/// memory, and combined with [`MAX_BUNDLE_DECOMPRESSED_BYTES`] bounds the
/// total work the verifier will perform on an untrusted bundle.
pub const MAX_ENTRY_DECOMPRESSED_BYTES: u64 = 100 * 1024 * 1024;

/// Hard cap on the sum of all decompressed entries in a bundle. 200 MiB
/// accommodates four 10 MiB images plus the rest of a legitimate bundle with
/// large headroom, while still bounding the worst-case zip-bomb.
pub const MAX_BUNDLE_DECOMPRESSED_BYTES: u64 = 200 * 1024 * 1024;

/// One entry destined for the ZIP. `data` is the raw bytes that will be
/// written and later hashed.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub path: String,
    pub data: Vec<u8>,
}

/// Write a deterministic ZIP archive to `out_path`.
///
/// Entries are sorted by `path` before writing. Compression is STORED.
/// Modification times are pinned to 1980-01-01 (the ZIP format floor).
///
/// # Errors
/// Returns [`WitnessCoreError::ZipWrite`] on any IO or zip-library failure.
pub fn write_bundle(out_path: &Path, entries: &[ZipEntry]) -> Result<(), WitnessCoreError> {
    let file = std::fs::File::create(out_path).map_err(|source| WitnessCoreError::ZipWrite {
        path: out_path.to_path_buf(),
        detail: "could not create output zip; check directory permissions".to_string(),
        source,
    })?;
    write_bundle_to_writer(file, entries).map_err(|err| match err {
        WitnessCoreError::ZipWrite { detail, source, .. } => WitnessCoreError::ZipWrite {
            path: out_path.to_path_buf(),
            detail,
            source,
        },
        other => other,
    })
}

/// Same as [`write_bundle`] but writes to an arbitrary seekable writer.
pub fn write_bundle_to_writer<W: Write + Seek>(
    writer: W,
    entries: &[ZipEntry],
) -> Result<(), WitnessCoreError> {
    let mut sorted: Vec<&ZipEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));

    let mut zip = ZipWriter::new(writer);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o644);

    for entry in &sorted {
        zip.start_file(&entry.path, options).map_err(io_zip_err)?;
        zip.write_all(&entry.data)
            .map_err(|source| WitnessCoreError::ZipWrite {
                path: std::path::PathBuf::from(&entry.path),
                detail: "failed writing entry bytes".to_string(),
                source,
            })?;
    }
    zip.finish().map_err(io_zip_err)?;
    Ok(())
}

/// Read every entry of a `.witness` ZIP into memory.
///
/// Returns a map keyed by in-zip path so callers can pull `manifest.json`,
/// `signature.json`, and any asset by name.
///
/// Enforces the following safety invariants against hostile input:
/// - Per-entry decompressed size is capped at
///   [`MAX_ENTRY_DECOMPRESSED_BYTES`] via a bounded reader.
/// - Total decompressed size across all entries is capped at
///   [`MAX_BUNDLE_DECOMPRESSED_BYTES`].
/// - Entry names are validated to reject path traversal (`..`), absolute
///   paths (`/...`), backslashes, embedded NULs, and non-UTF-8 names that a
///   downstream extractor could rewrite.
/// - Duplicate entry names cause the read to fail. Different ZIP parsers
///   resolve duplicates inconsistently; refusing them eliminates the
///   ambiguity entirely.
///
/// # Errors
/// Returns [`WitnessCoreError::ZipRead`] on any IO or zip-library failure,
/// [`WitnessCoreError::UnsafeZipEntry`] on entry-name validation failure or
/// duplicate, and [`WitnessCoreError::ZipTooLarge`] when any size cap is
/// breached.
pub fn read_bundle(path: &Path) -> Result<BTreeMap<String, Vec<u8>>, WitnessCoreError> {
    let file = std::fs::File::open(path).map_err(|source| WitnessCoreError::ZipRead {
        path: path.to_path_buf(),
        detail: "could not open bundle; check the file exists and is readable".to_string(),
        source,
    })?;
    let mut archive = ZipArchive::new(file).map_err(|err| zip_to_read_err(path, err))?;

    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut total_decompressed: u64 = 0;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|err| zip_to_read_err(path, err))?;

        let raw_name = entry.name_raw();
        let name = std::str::from_utf8(raw_name)
            .map_err(|_| WitnessCoreError::UnsafeZipEntry {
                detail: "ZIP entry name was not valid UTF-8".to_string(),
            })?
            .to_string();
        validate_entry_name(&name)?;

        if out.contains_key(&name) {
            return Err(WitnessCoreError::UnsafeZipEntry {
                detail: format!(
                    "ZIP contains duplicate entry name {name:?}. \
                     refusing to read: different ZIP parsers resolve duplicates inconsistently."
                ),
            });
        }

        // Bound per-entry read at MAX_ENTRY_DECOMPRESSED_BYTES + 1 so we can
        // detect overrun without trusting entry.size(), which is attacker-
        // controlled in the central directory.
        let mut buffer = Vec::new();
        let mut bounded = (&mut entry).take(MAX_ENTRY_DECOMPRESSED_BYTES + 1);
        bounded
            .read_to_end(&mut buffer)
            .map_err(|source| WitnessCoreError::ZipRead {
                path: path.to_path_buf(),
                detail: format!("failed reading entry {name}"),
                source,
            })?;
        if buffer.len() as u64 > MAX_ENTRY_DECOMPRESSED_BYTES {
            return Err(WitnessCoreError::ZipTooLarge {
                detail: format!(
                    "ZIP entry {name:?} exceeds the per-entry decompressed cap of {} bytes. \
                     refusing to read: bundle may be a zip-bomb or otherwise malformed.",
                    MAX_ENTRY_DECOMPRESSED_BYTES
                ),
            });
        }

        total_decompressed = total_decompressed.saturating_add(buffer.len() as u64);
        if total_decompressed > MAX_BUNDLE_DECOMPRESSED_BYTES {
            return Err(WitnessCoreError::ZipTooLarge {
                detail: format!(
                    "ZIP total decompressed size exceeded the bundle cap of {} bytes. \
                     refusing to read: bundle may be a zip-bomb or otherwise malformed.",
                    MAX_BUNDLE_DECOMPRESSED_BYTES
                ),
            });
        }

        out.insert(name, buffer);
    }
    Ok(out)
}

/// Validate an in-zip entry name against the safety constraints required of
/// every reader and downstream extractor.
fn validate_entry_name(name: &str) -> Result<(), WitnessCoreError> {
    if name.is_empty() {
        return Err(WitnessCoreError::UnsafeZipEntry {
            detail: "ZIP entry name is empty".to_string(),
        });
    }
    if name.contains('\0') {
        return Err(WitnessCoreError::UnsafeZipEntry {
            detail: format!("ZIP entry name {name:?} contains a NUL byte"),
        });
    }
    if name.starts_with('/') {
        return Err(WitnessCoreError::UnsafeZipEntry {
            detail: format!(
                "ZIP entry name {name:?} is an absolute path. \
                 conforming bundles use only relative POSIX paths."
            ),
        });
    }
    if name.contains('\\') {
        return Err(WitnessCoreError::UnsafeZipEntry {
            detail: format!(
                "ZIP entry name {name:?} contains a backslash. \
                 conforming bundles use only forward-slash POSIX paths."
            ),
        });
    }
    for segment in name.split('/') {
        if segment == ".." {
            return Err(WitnessCoreError::UnsafeZipEntry {
                detail: format!(
                    "ZIP entry name {name:?} contains a parent-directory traversal. \
                     refusing to read: this would ZIP-slip any downstream extractor."
                ),
            });
        }
    }
    Ok(())
}

fn io_zip_err(err: zip::result::ZipError) -> WitnessCoreError {
    WitnessCoreError::ZipWrite {
        path: std::path::PathBuf::new(),
        detail: format!("zip error: {err}"),
        source: std::io::Error::other(err.to_string()),
    }
}

fn zip_to_read_err(path: &Path, err: zip::result::ZipError) -> WitnessCoreError {
    WitnessCoreError::ZipRead {
        path: path.to_path_buf(),
        detail: format!("zip error: {err}"),
        source: std::io::Error::other(err.to_string()),
    }
}
