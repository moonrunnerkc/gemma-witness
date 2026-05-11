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
/// # Errors
/// Returns [`WitnessCoreError::ZipRead`] on any IO or zip-library failure.
pub fn read_bundle(path: &Path) -> Result<BTreeMap<String, Vec<u8>>, WitnessCoreError> {
    let file = std::fs::File::open(path).map_err(|source| WitnessCoreError::ZipRead {
        path: path.to_path_buf(),
        detail: "could not open bundle; check the file exists and is readable".to_string(),
        source,
    })?;
    let mut archive = ZipArchive::new(file).map_err(|err| zip_to_read_err(path, err))?;

    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|err| zip_to_read_err(path, err))?;
        let name = entry.name().to_string();
        let mut buffer = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut buffer)
            .map_err(|source| WitnessCoreError::ZipRead {
                path: path.to_path_buf(),
                detail: format!("failed reading entry {name}"),
                source,
            })?;
        out.insert(name, buffer);
    }
    Ok(out)
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
