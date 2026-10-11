// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Where the pilot client's key comes from: a file only its owner can read
//! (`zunder-guard client add --out`, or `init --client-key-out`), or
//! standard input. Never an argument, never the environment: there is no
//! code path for either. The key is read into one fixed buffer that is
//! wiped whatever happens, and no error repeats any of what was read.

use std::{fs, io::Read, path::Path};

use zeroize::Zeroizing;

use crate::hlsign::Key;

/// Most bytes accepted: 64 hex digits, `0x`, a newline and some slack.
const MAX_KEY_INPUT: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    Unreadable,
    NotRegular,
    TooOpen,
    Malformed,
    Unsupported,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KeyError::Unreadable => "the client key cannot be read",
            KeyError::NotRegular => {
                "the client key file must be a regular file, not a link or a directory"
            }
            KeyError::TooOpen => {
                "the client key file must be readable by its owner only (chmod 600)"
            }
            KeyError::Malformed => {
                "the client key must be one private key: 64 hex digits, optionally prefixed with 0x"
            }
            KeyError::Unsupported => "key files are supported on Unix only; use --key-stdin",
        })
    }
}

impl std::error::Error for KeyError {}

/// Read the key from `path`: a regular file, not a link, with no permission
/// bits for the group or others (0600 or 0400). The checks are made on the
/// file that was opened, so the path cannot be swapped between the check
/// and the read.
pub fn from_file(path: &Path) -> Result<Key, KeyError> {
    let link = fs::symlink_metadata(path).map_err(|_| KeyError::Unreadable)?;
    if !link.file_type().is_file() {
        return Err(KeyError::NotRegular);
    }
    let mut file = fs::File::open(path).map_err(|_| KeyError::Unreadable)?;
    let opened = file.metadata().map_err(|_| KeyError::Unreadable)?;
    if !opened.file_type().is_file() || !same_file(&link, &opened) {
        return Err(KeyError::NotRegular);
    }
    check_permissions(&opened)?;
    from_reader(&mut file)
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
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

#[cfg(not(unix))]
fn check_permissions(_meta: &fs::Metadata) -> Result<(), KeyError> {
    Err(KeyError::Unsupported)
}

/// Read a whole stream holding one key (a key file, or standard input).
pub fn from_reader(reader: &mut impl Read) -> Result<Key, KeyError> {
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

fn parse(text: &[u8]) -> Result<Key, KeyError> {
    let trimmed = text.trim_ascii();
    let digits = trimmed.strip_prefix(b"0x").unwrap_or(trimmed);
    if digits.len() != 64 {
        return Err(KeyError::Malformed);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    for (slot, pair) in bytes.iter_mut().zip(digits.chunks_exact(2)) {
        let high = hex_value(pair[0]).ok_or(KeyError::Malformed)?;
        let low = hex_value(pair[1]).ok_or(KeyError::Malformed)?;
        *slot = (high << 4) | low;
    }
    Key::from_bytes(&bytes).ok_or(KeyError::Malformed)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SDK_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";

    #[test]
    fn a_key_is_read_from_a_stream_with_or_without_0x() {
        let expected = Key::from_hex(SDK_KEY).unwrap().address();
        let mut with = format!("{SDK_KEY}\n").into_bytes();
        let key = from_reader(&mut with.as_slice()).unwrap();
        assert_eq!(key.address(), expected);
        let without = SDK_KEY.trim_start_matches("0x").as_bytes().to_vec();
        assert_eq!(
            from_reader(&mut without.as_slice()).unwrap().address(),
            expected
        );
        with.clear();
        for bad in [
            "",
            "0x12",
            "zz23456789012345678901234567890123456789012345678901234567890123",
        ] {
            assert_eq!(
                from_reader(&mut bad.as_bytes()).err(),
                Some(KeyError::Malformed),
                "{bad}"
            );
        }
        // Too long a stream is refused without reading it all.
        let long = vec![b'a'; 4096];
        assert_eq!(
            from_reader(&mut long.as_slice()).err(),
            Some(KeyError::Malformed)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_must_be_private_and_regular() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "zunder-pilot-key-{}-{}",
            std::process::id(),
            crate::now_ms()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.key");
        fs::write(&path, format!("{SDK_KEY}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(from_file(&path).err(), Some(KeyError::TooOpen));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(from_file(&path).err(), Some(KeyError::TooOpen));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(from_file(&path).is_ok());
        let link = dir.join("link.key");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(from_file(&link).err(), Some(KeyError::NotRegular));
        assert_eq!(from_file(&dir).err(), Some(KeyError::NotRegular));
        assert_eq!(
            from_file(&dir.join("missing")).err(),
            Some(KeyError::Unreadable)
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
