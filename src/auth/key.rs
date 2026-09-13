//! Exclusive, permission-checked persistence of the cookie master key.

use super::MASTER_KEY_BYTES;
#[cfg(unix)]
use super::tokens;
use crate::error::{AppError, Result};
use axum_extra::extract::cookie::Key;
use std::path::Path;
#[cfg(unix)]
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

#[cfg(unix)]
const KEY_FILENAME: &str = "secret.key";
#[cfg(unix)]
const KEY_PERMISSIONS: u32 = 0o600;
#[cfg(unix)]
const OWNER_READ: u32 = 0o400;
#[cfg(unix)]
const PERMISSION_BITS: u32 = 0o7777;

/// Derives the cookie key from a configured or safely persisted master key.
///
/// # Errors
/// Returns an error if safe persistence, loading, or OS randomness fails.
pub(super) fn load(data_dir: &Path, provided: Option<[u8; MASTER_KEY_BYTES]>) -> Result<Key> {
    let master = match provided {
        Some(master) => master,
        None => load_persisted(data_dir)?,
    };
    Ok(Key::derive_from(&master))
}

#[cfg(unix)]
fn load_persisted(data_dir: &Path) -> Result<[u8; MASTER_KEY_BYTES]> {
    let path = data_dir.join(KEY_FILENAME);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => read_existing(&path, &metadata),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            let master = tokens::random_bytes::<MASTER_KEY_BYTES>()?;
            let mut file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(KEY_PERMISSIONS)
                .open(&path)
            {
                Ok(file) => file,
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(&path).map_err(AppError::storage)?;
                    return read_existing(&path, &metadata);
                }
                Err(source) => return Err(AppError::storage(source)),
            };
            let metadata = file.metadata().map_err(AppError::storage)?;
            validate_metadata(&metadata)?;
            validate_opened(&path, &file, &metadata)?;
            file.write_all(&master).map_err(AppError::storage)?;
            file.sync_all().map_err(AppError::storage)?;
            validate_opened(&path, &file, &metadata)?;
            // A failed/incomplete creation is left intact, never repaired at boot.
            File::open(data_dir)
                .and_then(|directory| directory.sync_all())
                .map_err(AppError::storage)?;
            Ok(master)
        }
        Err(source) => Err(AppError::storage(source)),
    }
}

#[cfg(not(unix))]
fn load_persisted(_data_dir: &Path) -> Result<[u8; MASTER_KEY_BYTES]> {
    // Portable std cannot enforce a private ACL or compare opened file identity.
    Err(AppError::storage(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "persisted signing keys require Unix; configure PAGEBIN_SECRET",
    )))
}

#[cfg(unix)]
fn read_existing(path: &Path, metadata: &Metadata) -> Result<[u8; MASTER_KEY_BYTES]> {
    validate_metadata(metadata)?;
    if metadata.len() != MASTER_KEY_BYTES as u64 {
        return Err(invalid_key());
    }
    let mut file = File::open(path).map_err(AppError::storage)?;
    // Compare fstat with lstat before reading: never read a substituted inode.
    validate_opened(path, &file, metadata)?;
    let mut master = [0; MASTER_KEY_BYTES];
    file.read_exact(&mut master).map_err(AppError::storage)?;
    let mut trailing = [0];
    if file.read(&mut trailing).map_err(AppError::storage)? != 0 {
        return Err(invalid_key());
    }
    validate_opened(path, &file, metadata)?;
    Ok(master)
}

#[cfg(unix)]
fn validate_metadata(metadata: &Metadata) -> Result<()> {
    let permissions = metadata.mode() & PERMISSION_BITS;
    if !metadata.is_file() || permissions & !KEY_PERMISSIONS != 0 || permissions & OWNER_READ == 0 {
        return Err(invalid_key());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_opened(path: &Path, file: &File, expected: &Metadata) -> Result<()> {
    let opened = file.metadata().map_err(AppError::storage)?;
    let current = fs::symlink_metadata(path).map_err(AppError::storage)?;
    validate_metadata(&opened)?;
    validate_metadata(&current)?;
    if opened.dev() != expected.dev()
        || opened.ino() != expected.ino()
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
    {
        return Err(invalid_key());
    }
    Ok(())
}

#[cfg(unix)]
fn invalid_key() -> AppError {
    AppError::storage(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid signing key file",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::{KEY_FILENAME, KEY_PERMISSIONS, MASTER_KEY_BYTES, load};
    use std::{
        fs::{self, Permissions},
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

    #[test]
    fn auth_key_is_created_private_and_reused_across_loads() {
        let directory = tempfile::tempdir().unwrap();
        let first = load(directory.path(), None).unwrap();
        let metadata = fs::metadata(directory.path().join(KEY_FILENAME)).unwrap();
        assert_eq!(metadata.len(), MASTER_KEY_BYTES as u64);
        assert_eq!(metadata.mode() & 0o777, KEY_PERMISSIONS);
        assert!(load(directory.path(), None).unwrap() == first);
    }

    #[test]
    fn auth_key_rejects_wrong_length_or_unreadable_files_without_repair() {
        for (length, mode) in [
            (MASTER_KEY_BYTES - 1, KEY_PERMISSIONS),
            (MASTER_KEY_BYTES + 1, KEY_PERMISSIONS),
            (MASTER_KEY_BYTES, 0o644),
            (MASTER_KEY_BYTES, 0o000),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(KEY_FILENAME);
            fs::write(&path, vec![42_u8; length]).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
            assert!(load(directory.path(), None).is_err());
            let metadata = fs::metadata(&path).unwrap();
            assert_eq!(metadata.len(), length as u64);
            assert_eq!(metadata.mode() & 0o7777, mode);
        }
    }
}
