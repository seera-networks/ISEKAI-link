//! Writing long-lived secrets to disk.
//!
//! Two things live here that a plain `fs::write` does not give:
//!
//! **The permissions are set before the content exists.** Writing and then
//! calling `set_permissions` leaves a window — however short — in which the
//! file holds a private key or a refresh token and is readable by anyone on the
//! machine. Creating it `0600` closes that window rather than narrowing it.
//!
//! **The replacement is atomic.** A write interrupted partway leaves a
//! truncated file where a valid one used to be; for a token store that means the
//! next start finds unreadable JSON and asks the operator to sign in again, and
//! for a key it means the Endpoint's identity is gone. Writing a temporary file
//! beside the target and renaming over it means the target is either the old
//! contents or the new ones.
//!
//! **Windows is not covered by the first part.** `set_permissions` there only
//! toggles the read-only flag, and restricting the ACL needs the Win32 security
//! APIs. The file inherits the directory's ACL instead, so on Windows the
//! protection is whatever the containing directory provides — which is the same
//! situation the Endpoint key beside it has always been in, and worth fixing for
//! both together rather than for one.

use std::path::{Path, PathBuf};

use anyhow::Context as _;

/// Write `contents` to `path`, owner-only and atomically.
pub fn write_secret(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let temp = temp_beside(path);
    // Any leftover from an interrupted earlier write: `create_new` below fails
    // on an existing file, which is what makes the mode it asks for binding.
    let _ = std::fs::remove_file(&temp);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    {
        use std::io::Write as _;
        let mut file = options
            .open(&temp)
            .with_context(|| format!("failed to create {}", temp.display()))?;
        file.write_all(contents)
            .with_context(|| format!("failed to write {}", temp.display()))?;
        // Before the rename, or a crash can leave the name pointing at content
        // that never reached the disk.
        file.sync_all()
            .with_context(|| format!("failed to flush {}", temp.display()))?;
    }
    std::fs::rename(&temp, path)
        .with_context(|| format!("failed to move {} into place", temp.display()))?;
    Ok(())
}

/// A temporary name in the same directory, so the rename stays on one
/// filesystem — across filesystems it is a copy, and no longer atomic.
fn temp_beside(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("isekai-secret-{}-{name}", std::process::id()))
    }

    #[test]
    fn writes_the_contents() {
        let path = scratch("plain");
        let _ = std::fs::remove_file(&path);
        write_secret(&path, b"shhh").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"shhh");
        let _ = std::fs::remove_file(&path);
    }

    /// Replacing has to work as often as writing does — a token store is
    /// rewritten on every refresh.
    #[test]
    fn replaces_an_existing_file() {
        let path = scratch("replace");
        let _ = std::fs::remove_file(&path);
        write_secret(&path, b"first").unwrap();
        write_secret(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        let _ = std::fs::remove_file(&path);
    }

    /// The permissions come from the create, so they hold for the contents and
    /// not just for the moment afterwards.
    #[cfg(unix)]
    #[test]
    fn the_file_is_owner_only_from_the_start() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = scratch("mode");
        let _ = std::fs::remove_file(&path);
        write_secret(&path, b"secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        // And a replacement does not widen it back.
        write_secret(&path, b"secret again").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        let _ = std::fs::remove_file(&path);
    }

    /// A temporary left by an interrupted write must not stop the next one.
    #[test]
    fn a_leftover_temporary_does_not_block_the_write() {
        let path = scratch("leftover");
        let _ = std::fs::remove_file(&path);
        std::fs::write(temp_beside(&path), b"junk").unwrap();
        write_secret(&path, b"fresh").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"fresh");
        let _ = std::fs::remove_file(&path);
    }
}
