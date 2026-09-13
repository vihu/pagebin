//! Bounded ZIP extraction into memory; archives never touch storage directly.

use super::{InputError, MAX_SITE_FILES, SitePath, UploadedFile};
use axum::body::Bytes;
use std::io::{Cursor, Read};
use zip::ZipArchive;

/// Unpacks regular files whose declared sizes fit within `cap` bytes in total.
///
/// # Errors
/// Rejects unreadable archives, symlinks, too many entries, declared sizes
/// beyond the cap, and entries whose bytes exceed their declared size.
pub(super) fn extract(
    bytes: &[u8],
    cap: usize,
) -> std::result::Result<Vec<UploadedFile>, InputError> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(|_| InputError::Archive)?;
    if archive.len() > MAX_SITE_FILES {
        return Err(InputError::FileCount);
    }
    let mut files = Vec::new();
    let mut declared_total = 0_usize;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|_| InputError::Archive)?;
        if entry.is_dir() {
            continue;
        }
        if entry.is_symlink() {
            return Err(InputError::Archive);
        }
        // Validate the raw name before any shared directory is stripped away.
        if SitePath::parse(entry.name()).is_none() {
            return Err(InputError::Filename);
        }
        let declared = usize::try_from(entry.size()).map_err(|_| InputError::Size)?;
        declared_total = declared_total
            .checked_add(declared)
            .filter(|total| *total <= cap)
            .ok_or(InputError::Size)?;
        let limit = u64::try_from(declared)
            .map_err(|_| InputError::Size)?
            .saturating_add(1);
        let mut content = Vec::new();
        entry
            .by_ref()
            .take(limit)
            .read_to_end(&mut content)
            .map_err(|_| InputError::Archive)?;
        if content.len() != declared {
            return Err(InputError::Archive);
        }
        files.push(UploadedFile {
            filename: entry.name().to_owned(),
            bytes: Bytes::from(content),
        });
    }
    strip_shared_directory(&mut files);
    Ok(files)
}

/// Strips one directory that every file shares, the shape `zip -r` produces.
fn strip_shared_directory(files: &mut [UploadedFile]) {
    let Some(prefix) = files
        .first()
        .and_then(|file| file.filename.split_once('/'))
        .map(|(directory, _)| format!("{directory}/"))
    else {
        return;
    };
    let shared = files
        .iter()
        .all(|file| file.filename.len() > prefix.len() && file.filename.starts_with(&prefix));
    if shared {
        for file in files {
            file.filename.drain(..prefix.len());
        }
    }
}
