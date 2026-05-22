use crate::SandboxAuditError;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WritableRootMapping {
    pub host_root: PathBuf,
    pub staged_root: PathBuf,
}

#[derive(Debug)]
pub struct WritableRootTransaction {
    mappings: Vec<WritableRootMapping>,
}

impl WritableRootTransaction {
    pub fn start(
        event_dir: &Path,
        writable_roots: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, SandboxAuditError> {
        let stage_root = event_dir.join("stage");
        let mut seen = BTreeSet::new();
        let mut mappings = Vec::new();
        for host_root in writable_roots {
            if !seen.insert(host_root.clone()) || !host_root.exists() {
                continue;
            }
            if stage_root.starts_with(&host_root) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "sandbox audit records dir {} must not be inside writable root {}",
                        event_dir.display(),
                        host_root.display()
                    ),
                )
                .into());
            }
            let staged_root = stage_root.join(format!("root-{}", mappings.len()));
            copy_path(&host_root, &staged_root)?;
            mappings.push(WritableRootMapping {
                host_root,
                staged_root,
            });
        }
        Ok(Self { mappings })
    }

    pub fn mappings(&self) -> &[WritableRootMapping] {
        &self.mappings
    }

    pub fn commit(&self) -> Result<(), SandboxAuditError> {
        for mapping in &self.mappings {
            sync_path(&mapping.staged_root, &mapping.host_root)?;
        }
        Ok(())
    }
}

fn copy_path(source: &Path, destination: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(source)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, destination)?;
        #[cfg(windows)]
        {
            if source.is_dir() {
                std::os::windows::fs::symlink_dir(target, destination)?;
            } else {
                std::os::windows::fs::symlink_file(target, destination)?;
            }
        }
        return Ok(());
    }
    if metadata.is_dir() {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_path(&entry.path(), &destination.join(entry.file_name()))?;
        }
        fs::set_permissions(destination, metadata.permissions())?;
        return Ok(());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, destination)?;
    fs::set_permissions(destination, metadata.permissions())?;
    Ok(())
}

fn sync_path(source: &Path, destination: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() || metadata.is_file() {
        replace_file_like_path(source, destination, &metadata)?;
        return Ok(());
    }
    if metadata.is_dir() {
        sync_directory(source, destination)?;
        fs::set_permissions(destination, metadata.permissions())?;
        return Ok(());
    }
    Ok(())
}

fn sync_directory(source: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir_all(destination)?;
    let mut source_names = BTreeSet::new();
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        source_names.insert(name.clone());
        sync_path(&entry.path(), &destination.join(name))?;
    }
    for entry in fs::read_dir(destination)? {
        let entry = entry?;
        if !source_names.contains(&entry.file_name()) {
            remove_path(&entry.path())?;
        }
    }
    Ok(())
}

fn replace_file_like_path(
    source: &Path,
    destination: &Path,
    metadata: &fs::Metadata,
) -> io::Result<()> {
    if destination.exists() || fs::symlink_metadata(destination).is_ok() {
        remove_path(destination)?;
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(source)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, destination)?;
        #[cfg(windows)]
        {
            if source.is_dir() {
                std::os::windows::fs::symlink_dir(target, destination)?;
            } else {
                std::os::windows::fs::symlink_file(target, destination)?;
            }
        }
    } else {
        fs::copy(source, destination)?;
        fs::set_permissions(destination, metadata.permissions())?;
    }
    Ok(())
}

fn remove_path(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}
