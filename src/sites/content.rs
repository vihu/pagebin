//! Exclusively owned staging and content paths with narrow explicit cleanup.

use super::{SiteFile, Slug};
use crate::{AppError, Result};
use std::{
    fs::Metadata,
    io::ErrorKind,
    path::{Path, PathBuf},
};
use tokio::{fs, io::AsyncWriteExt};

const MAX_STAGING_ATTEMPTS: usize = 8;
#[cfg(unix)]
const DIRECTORY_MODE: u32 = 0o700;
#[cfg(unix)]
const CONTENT_MODE: u32 = 0o644;

/// Tracks only paths exclusively created by one publication job.
pub(super) struct Content {
    data_root: PathBuf,
    staging_directory: PathBuf,
    staging_removed: bool,
    installed_directory: Option<PathBuf>,
    preserve_installed: bool,
}

/// The outcome of exclusively creating a publication destination.
pub(super) enum Destination {
    /// This operation owns the new, empty directory.
    Created,
    /// Some existing path owns the name and must remain untouched.
    Occupied,
}

#[derive(Debug, thiserror::Error)]
enum ContentError {
    #[error("storage path is not of the required type")]
    UnsafePath,
    #[error("staging name attempt limit reached")]
    StagingExhausted,
    #[error("publication content ownership is incomplete")]
    MissingDestination,
}

impl Content {
    /// Exclusively creates private staging beneath initialized storage.
    ///
    /// # Errors
    /// Returns an error for unsafe parents, entropy, or filesystem failures.
    pub(super) async fn new(data_root: &Path) -> Result<Self> {
        validate_storage(data_root).await?;
        for _ in 0..MAX_STAGING_ATTEMPTS {
            let staging_directory = data_root.join("tmp").join(Slug::generate()?.as_str());
            match directory_builder(false).create(&staging_directory).await {
                Ok(()) => {
                    return Ok(Self {
                        data_root: data_root.to_owned(),
                        staging_directory,
                        staging_removed: false,
                        installed_directory: None,
                        preserve_installed: false,
                    });
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(AppError::publishing(error)),
            }
        }
        Err(AppError::publishing(ContentError::StagingExhausted))
    }

    /// Writes new regular files, recording ownership before any content write.
    ///
    /// # Errors
    /// Returns an error on unsafe parents or create/write/flush failure.
    pub(super) async fn write(&mut self, files: &[SiteFile]) -> Result {
        validate_storage(&self.data_root).await?;
        validate_directory(&self.staging_directory).await?;
        for input in files {
            let path = self.staging_directory.join(input.filename.as_str());
            if let Some(parent) = path
                .parent()
                .filter(|parent| *parent != self.staging_directory)
            {
                directory_builder(true)
                    .create(parent)
                    .await
                    .map_err(AppError::publishing)?;
            }
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(CONTENT_MODE);
            let mut file = options.open(path).await.map_err(AppError::publishing)?;
            file.write_all(&input.bytes)
                .await
                .map_err(AppError::publishing)?;
            file.flush().await.map_err(AppError::publishing)?;
        }
        Ok(())
    }

    /// Exclusively creates a destination without adopting any existing path.
    ///
    /// # Errors
    /// Returns an error for unsafe storage or other filesystem failures.
    pub(super) async fn reserve_destination(&mut self, directory: PathBuf) -> Result<Destination> {
        validate_storage(&self.data_root).await?;
        match directory_builder(false).create(&directory).await {
            Ok(()) => {
                self.installed_directory = Some(directory);
                Ok(Destination::Created)
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(Destination::Occupied),
            Err(error) => Err(AppError::publishing(error)),
        }
    }

    /// Moves the whole staging directory onto the reserved, empty destination.
    ///
    /// # Errors
    /// Returns an error for changed path types or a failed rename.
    pub(super) async fn install(&mut self) -> Result {
        validate_storage(&self.data_root).await?;
        validate_directory(&self.staging_directory).await?;
        let directory = self
            .installed_directory
            .as_ref()
            .ok_or_else(|| AppError::publishing(ContentError::MissingDestination))?;
        validate_directory(directory).await?;
        fs::rename(&self.staging_directory, directory)
            .await
            .map_err(AppError::publishing)?;
        self.staging_removed = true;
        Ok(())
    }

    /// Moves the whole staging directory over an existing site directory.
    ///
    /// # Errors
    /// Returns an error for unsafe storage or a failed rename.
    pub(super) async fn swap_into(&mut self, destination: &Path) -> Result<PathBuf> {
        validate_storage(&self.data_root).await?;
        validate_directory(&self.staging_directory).await?;
        validate_directory(destination).await?;
        let parked = self.staging_directory.with_extension("old");
        fs::rename(destination, &parked)
            .await
            .map_err(AppError::publishing)?;
        if let Err(error) = fs::rename(&self.staging_directory, destination).await {
            fs::rename(&parked, destination)
                .await
                .map_err(AppError::publishing)?;
            return Err(AppError::publishing(error));
        }
        self.staging_removed = true;
        Ok(parked)
    }

    /// Restores the parked directory after a failed post-swap step.
    ///
    /// # Errors
    /// Returns an error if either rename fails; staged content is then retained.
    pub(super) async fn swap_back(&mut self, destination: &Path, parked: &Path) -> Result {
        fs::rename(destination, &self.staging_directory)
            .await
            .map_err(AppError::publishing)?;
        fs::rename(parked, destination)
            .await
            .map_err(AppError::publishing)?;
        self.staging_removed = false;
        Ok(())
    }

    /// Preserves installed bytes before attempting a possibly uncertain commit.
    pub(super) const fn preserve_installed(&mut self) {
        self.preserve_installed = true;
    }

    /// Removes owned staging and an unused reservation after a definite failure.
    ///
    /// # Errors
    /// Returns an error for changed paths or removal failure; retains unknowns.
    pub(super) async fn cleanup(self) -> Result {
        validate_storage(&self.data_root).await?;
        let unused = !self.preserve_installed && !self.staging_removed;
        let reserved = match self.installed_directory.filter(|_| unused) {
            Some(directory) => fs::remove_dir(&directory)
                .await
                .map_err(AppError::publishing),
            None => Ok(()),
        };
        let staging = if self.staging_removed {
            Ok(())
        } else {
            fs::remove_dir_all(&self.staging_directory)
                .await
                .map_err(AppError::publishing)
        };
        reserved.and(staging)
    }
}

/// Requires metadata obtained without following the final path component.
///
/// # Errors
/// Returns an error for symlinks and all non-directory types.
pub(super) fn check_directory(metadata: &Metadata) -> Result {
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(AppError::publishing(ContentError::UnsafePath))
    }
}

/// Requires the initialized storage directories to retain their types.
///
/// # Errors
/// Returns metadata failures or rejects non-directory and symlink paths.
pub(super) async fn validate_storage(data_root: &Path) -> Result {
    for directory in [data_root, &data_root.join("sites"), &data_root.join("tmp")] {
        validate_directory(directory).await?;
    }
    Ok(())
}

/// Checks a directory's final component without following a symlink.
///
/// # Errors
/// Returns metadata failures or rejects a non-directory path.
pub(super) async fn validate_directory(directory: &Path) -> Result {
    check_directory(
        &fs::symlink_metadata(directory)
            .await
            .map_err(AppError::publishing)?,
    )
}

fn directory_builder(recursive: bool) -> fs::DirBuilder {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(DIRECTORY_MODE);
    builder.recursive(recursive);
    builder
}
