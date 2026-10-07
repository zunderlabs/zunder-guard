// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Reading the API wallet key from standard input: one fixed buffer, never
//! grown or copied, wiped whatever the outcome; at most
//! [`MAX_KEY_INPUT`] bytes; no error contains any of what was read.

use std::{io::Read, path::Path};

use thiserror::Error;
use zeroize::Zeroizing;
use zunder_guard_core::sign::GuardKey;

/// Most bytes accepted: a key is 64 hex digits, 66 with `0x`, plus a
/// newline or other whitespace.
pub const MAX_KEY_INPUT: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyReadError {
    #[error("nothing was read from {0}")]
    Empty(&'static str),
    #[error("{0} could not be read")]
    Unreadable(&'static str),
    #[error("{0} must hold one private key: 64 hex digits, optionally prefixed with 0x")]
    Malformed(&'static str),
    /// The key file's place or permissions (never its contents).
    #[error("{0}")]
    File(String),
}

/// Read one key from `reader` until its end. `name` says where it came
/// from in errors.
pub fn read_key(reader: &mut impl Read, name: &'static str) -> Result<GuardKey, KeyReadError> {
    let mut buffer = Zeroizing::new([0u8; MAX_KEY_INPUT + 1]);
    let mut filled = 0;
    loop {
        let Some(space) = buffer.get_mut(filled..) else {
            return Err(KeyReadError::Malformed(name));
        };
        if space.is_empty() {
            return Err(KeyReadError::Malformed(name));
        }
        match reader.read(space) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(KeyReadError::Unreadable(name)),
        }
    }
    let input = buffer.get(..filled).ok_or(KeyReadError::Malformed(name))?;
    let text = std::str::from_utf8(input).map_err(|_| KeyReadError::Malformed(name))?;
    if text.trim().is_empty() {
        return Err(KeyReadError::Empty(name));
    }
    GuardKey::from_hex(text).map_err(|_| KeyReadError::Malformed(name))
}

/// Read one line holding a key from `reader` (the non-interactive init,
/// where more may follow). Wiped after parsing.
pub fn key_from_text(text: &str, name: &'static str) -> Result<GuardKey, KeyReadError> {
    if text.trim().is_empty() {
        return Err(KeyReadError::Empty(name));
    }
    GuardKey::from_hex(text).map_err(|_| KeyReadError::Malformed(name))
}

/// Read the key from a file only its owner can read. In a container,
/// where platform secret mounts are often world-readable and Guard is the
/// only user, a file nobody else can write is accepted, with the warning
/// returned beside the key. A file group or others can write is refused
/// everywhere.
pub fn key_from_file(
    path: &Path,
    container: bool,
) -> Result<(GuardKey, Option<String>), KeyReadError> {
    use zunder_venue::owner_only::{self, Openness};
    if !path.exists() {
        return Err(KeyReadError::File(format!(
            "no key: {} does not exist",
            path.display()
        )));
    }
    // Windows: open first, sharing read only and not following a link, so
    // the file whose ACL is checked below is the one that is read. Windows
    // has no container leniency: Guard on Windows is never the only user.
    #[cfg(windows)]
    let _ = container;
    #[cfg(windows)]
    let container = false;
    #[cfg(windows)]
    let mut opened = Some(
        owner_only::open_for_reading(path)
            .map_err(|error| KeyReadError::File(format!("reading {}: {error}", path.display())))?,
    );
    #[cfg(not(windows))]
    let mut opened: Option<std::fs::File> = None;
    let mut warning = None;
    match owner_only::check(path).map_err(KeyReadError::File)? {
        None => {}
        Some(Openness::Writable(why)) => {
            return Err(KeyReadError::File(format!(
                "{}: {why}: refused (chmod 600 it; on Windows let zunder-guard write it, or keep the key in the Credential Manager)",
                path.display()
            )));
        }
        Some(Openness::Readable(why)) if container => {
            warning = Some(format!(
                "{}: {why}; accepted because Guard runs in a container where it is the only user",
                path.display()
            ));
        }
        Some(Openness::Readable(why)) => {
            return Err(KeyReadError::File(format!(
                "{}: {why}: refused (chmod 600 it; on Windows let zunder-guard write it, or keep the key in the Credential Manager)",
                path.display()
            )));
        }
    }
    let mut file = match opened.take() {
        Some(file) => file,
        None => std::fs::File::open(path)
            .map_err(|error| KeyReadError::File(format!("reading {}: {error}", path.display())))?,
    };
    Ok((read_key(&mut file, "the key file")?, warning))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";

    #[test]
    fn a_piped_key_is_read_and_bad_input_refused_without_echo() {
        let key = read_key(&mut format!("{KEY}\n").as_bytes(), "standard input").unwrap();
        assert_eq!(
            key.address().to_hex(),
            "0x14791697260e4c9a71f18484c9f997b308e59325"
        );
        let cases: Vec<(Vec<u8>, KeyReadError)> = vec![
            (Vec::new(), KeyReadError::Empty("standard input")),
            (
                format!("{KEY}\n{KEY}\n").into_bytes(),
                KeyReadError::Malformed("standard input"),
            ),
            (
                vec![b' '; MAX_KEY_INPUT + 1],
                KeyReadError::Malformed("standard input"),
            ),
            (
                [KEY.as_bytes(), &[0xff]].concat(),
                KeyReadError::Malformed("standard input"),
            ),
        ];
        for (input, expected) in cases {
            let error = read_key(&mut input.as_slice(), "standard input").unwrap_err();
            assert_eq!(error, expected);
            assert!(!format!("{error} {error:?}").contains("0123456789"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_must_be_private_outside_containers() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::testdir::TestDir::new("key-file");
        let path = dir.path().join("api-wallet-key");
        std::fs::write(&path, format!("{KEY}\n")).unwrap();
        let set = |mode: u32| {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        set(0o600);
        let (key, warning) = key_from_file(&path, false).unwrap();
        assert_eq!(
            key.address().to_hex(),
            "0x14791697260e4c9a71f18484c9f997b308e59325"
        );
        assert!(warning.is_none());
        // Readable by others: refused on bare metal, warned in a container.
        set(0o644);
        assert!(matches!(
            key_from_file(&path, false),
            Err(KeyReadError::File(_))
        ));
        let (_, warning) = key_from_file(&path, true).unwrap();
        assert!(warning.unwrap().contains("container"));
        set(0o440);
        assert!(key_from_file(&path, false).is_err());
        assert!(key_from_file(&path, true).is_ok());
        // Writable by group or others: refused everywhere.
        for mode in [0o620, 0o602, 0o666] {
            set(mode);
            assert!(key_from_file(&path, true).is_err(), "{mode:o}");
            assert!(key_from_file(&path, false).is_err(), "{mode:o}");
        }
        // Missing: refused; no error ever shows the key.
        set(0o600);
        let missing = key_from_file(&dir.path().join("nothing"), false).unwrap_err();
        assert!(!missing.to_string().contains("0123456789"));
    }
}
