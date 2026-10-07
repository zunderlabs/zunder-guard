// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Where the client key comes from: a file only its owner can read, or the
//! first line of standard input. Never a command-line argument and never
//! the environment, on any network: there is no code path for either.
//!
//! The same discipline as Zunder's own runner (its
//! `ApiWalletKey::from_reader`): this module reads into one fixed buffer,
//! never grown or copied, wiped whatever the outcome; at most
//! [`MAX_KEY_INPUT`] bytes; no error contains any of what was read. With
//! `--key-stdin` the bytes also pass through the standard library's own
//! input buffer, which is not wiped (the MCP messages that follow overwrite
//! it); a key file avoids that.

#[cfg(not(windows))]
use std::fs;
use std::{
    io::{BufRead, Read},
    path::Path,
};

use zeroize::Zeroizing;

use crate::sign::ClientKey;

/// Most bytes accepted: a key is 64 hex digits, 66 with `0x`, plus a
/// newline or other whitespace.
pub const MAX_KEY_INPUT: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("the key file cannot be read")]
    Unreadable,
    #[error("the key file must be a regular file, not a link or a directory")]
    NotRegular,
    #[error(
        "the key file must be readable by its owner only (chmod 600; on Windows, let zunder-guard client add --out write it); others can read it now"
    )]
    TooOpen,
    #[error("the key file must hold one private key: 64 hex digits, optionally prefixed with 0x")]
    Malformed,
    #[error("nothing was read")]
    Empty,
    #[error("key files are supported on Unix and Windows only; use --key-stdin")]
    Unsupported,
}

/// Read the key from `path`: a regular file (not a symbolic link) with no
/// permission bits for the group or others (0600 or 0400).
///
/// The checks are made on the file that was opened, not only on the path:
/// the path must name, without a link, the same file (device and inode),
/// so it cannot be swapped between the check and the read.
pub fn from_file(path: &Path) -> Result<ClientKey, KeyError> {
    // Windows: open first, sharing read only (nobody can change, rename or
    // delete the file while it is open) and not following a reparse point,
    // then check the ACL of the file that is open and read it.
    #[cfg(windows)]
    {
        let mut file = zunder_venue::owner_only::open_for_reading(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::InvalidInput {
                KeyError::NotRegular
            } else {
                KeyError::Unreadable
            }
        })?;
        check_permissions(path)?;
        read_all(&mut file)
    }
    #[cfg(not(windows))]
    from_file_unix(path)
}

#[cfg(not(windows))]
fn from_file_unix(path: &Path) -> Result<ClientKey, KeyError> {
    let link = fs::symlink_metadata(path).map_err(|_| KeyError::Unreadable)?;
    if !link.file_type().is_file() {
        return Err(KeyError::NotRegular);
    }
    let mut file = fs::File::open(path).map_err(|_| KeyError::Unreadable)?;
    let opened = file.metadata().map_err(|_| KeyError::Unreadable)?;
    if !opened.file_type().is_file() || !same_file(&link, &opened) {
        return Err(KeyError::NotRegular);
    }
    let after = fs::symlink_metadata(path).map_err(|_| KeyError::Unreadable)?;
    if !after.file_type().is_file() || !same_file(&after, &opened) {
        return Err(KeyError::NotRegular);
    }
    check_permissions(&opened)?;
    read_all(&mut file)
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(any(unix, windows)))]
fn same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn check_permissions(meta: &fs::Metadata) -> Result<(), KeyError> {
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(KeyError::TooOpen);
    }
    Ok(())
}

/// Windows: the file's ACL allows no one but this user, the owner, SYSTEM
/// and Administrators (`zunder_venue::owner_only`).
#[cfg(windows)]
fn check_permissions(path: &Path) -> Result<(), KeyError> {
    match zunder_venue::owner_only::check(path) {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err(KeyError::TooOpen),
        Err(_) => Err(KeyError::Unreadable),
    }
}

#[cfg(not(any(unix, windows)))]
fn check_permissions(_meta: &fs::Metadata) -> Result<(), KeyError> {
    Err(KeyError::Unsupported)
}

/// Read a whole stream holding one key.
pub fn read_all(reader: &mut impl Read) -> Result<ClientKey, KeyError> {
    let mut buffer = Zeroizing::new([0u8; MAX_KEY_INPUT + 1]);
    let mut filled = 0;
    loop {
        let Some(space) = buffer.get_mut(filled..) else {
            return Err(KeyError::Malformed);
        };
        if space.is_empty() {
            return Err(KeyError::Malformed);
        }
        match reader.read(space) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(KeyError::Unreadable),
        }
    }
    parse(buffer.get(..filled).ok_or(KeyError::Malformed)?)
}

/// Read the first line of `reader` as the key and leave the rest (the MCP
/// messages) unread. Byte by byte up to the newline, into a fixed buffer:
/// nothing after the newline is consumed.
pub fn read_first_line(reader: &mut impl BufRead) -> Result<ClientKey, KeyError> {
    let mut buffer = Zeroizing::new([0u8; MAX_KEY_INPUT + 1]);
    let mut filled = 0;
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(KeyError::Unreadable),
        };
        if available.is_empty() {
            break;
        }
        let (take, done) = match available.iter().position(|byte| *byte == b'\n') {
            Some(at) => (at, true),
            None => (available.len(), false),
        };
        let slot = buffer
            .get_mut(filled..filled + take)
            .ok_or(KeyError::Malformed)?;
        slot.copy_from_slice(available.get(..take).ok_or(KeyError::Malformed)?);
        filled += take;
        reader.consume(if done { take + 1 } else { take });
        if done {
            break;
        }
    }
    parse(buffer.get(..filled).ok_or(KeyError::Malformed)?)
}

fn parse(input: &[u8]) -> Result<ClientKey, KeyError> {
    let text = std::str::from_utf8(input).map_err(|_| KeyError::Malformed)?;
    if text.trim().is_empty() {
        return Err(KeyError::Empty);
    }
    ClientKey::from_hex(text).map_err(|_| KeyError::Malformed)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{BufReader, Write},
    };

    use super::*;

    const KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
    const ADDRESS: &str = "0x14791697260e4c9a71f18484c9f997b308e59325";

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zunder-guard-mcp-key-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_first_line_is_the_key_and_the_rest_stays() {
        let input = format!("{KEY}\n{{\"jsonrpc\":\"2.0\"}}\n");
        let mut reader = BufReader::with_capacity(7, input.as_bytes());
        let key = read_first_line(&mut reader).unwrap();
        assert_eq!(key.address().to_hex(), ADDRESS);
        let mut rest = String::new();
        reader.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "{\"jsonrpc\":\"2.0\"}\n");
    }

    #[test]
    fn bad_first_lines_are_refused_without_echo() {
        let long = format!("{}\n", "a".repeat(MAX_KEY_INPUT + 10));
        for input in ["\n", "", "0x0123\n", long.as_str()] {
            let error = read_first_line(&mut BufReader::new(input.as_bytes())).unwrap_err();
            assert!(matches!(error, KeyError::Empty | KeyError::Malformed));
            assert!(!error.to_string().contains("0123"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_must_be_private_and_regular() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp("file");
        let path = dir.join("client.key");
        let mut file = fs::File::create(&path).unwrap();
        writeln!(file, "{KEY}").unwrap();
        drop(file);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(from_file(&path).unwrap_err(), KeyError::TooOpen);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(from_file(&path).unwrap_err(), KeyError::TooOpen);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(from_file(&path).unwrap().address().to_hex(), ADDRESS);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(from_file(&path).unwrap().address().to_hex(), ADDRESS);

        // A link to a private file is refused: the link could be swapped.
        let link = dir.join("link.key");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(from_file(&link).unwrap_err(), KeyError::NotRegular);
        assert_eq!(from_file(&dir).unwrap_err(), KeyError::NotRegular);
        assert_eq!(
            from_file(&dir.join("missing")).unwrap_err(),
            KeyError::Unreadable
        );

        // Two keys in one file.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, format!("{KEY}\n{KEY}\n")).unwrap();
        let error = from_file(&path).unwrap_err();
        assert_eq!(error, KeyError::Malformed);
        assert!(!format!("{error:?} {error}").contains("0123"));
        let _ = fs::remove_dir_all(&dir);
    }

    /// Windows: what `zunder-guard client add --out` writes (an ACL with
    /// this user alone) is read; once Everyone may read it, it is refused.
    #[cfg(windows)]
    #[test]
    fn a_key_file_must_be_private_and_regular_on_windows() {
        let dir = temp("file-windows");
        let path = dir.join("client.key");
        let mut file = zunder_venue::owner_only::create(&path).unwrap();
        writeln!(file, "{KEY}").unwrap();
        drop(file);
        assert_eq!(from_file(&path).unwrap().address().to_hex(), ADDRESS);
        assert_eq!(from_file(&dir).unwrap_err(), KeyError::NotRegular);
        assert_eq!(
            from_file(&dir.join("missing")).unwrap_err(),
            KeyError::Unreadable
        );
        let granted = std::process::Command::new("icacls")
            .arg(&path)
            .args(["/grant", "*S-1-1-0:R"])
            .output()
            .unwrap();
        assert!(granted.status.success());
        assert_eq!(from_file(&path).unwrap_err(), KeyError::TooOpen);
        let _ = fs::remove_dir_all(&dir);
    }
}
