// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Files only their owner can read: where keys live on disk.
//!
//! - **Unix**: mode 0600, created new. A file that group or others can
//!   write is refused; one with any other permission bit for group or
//!   others (`0o077`) is "readable by others", which only a caller that
//!   accepts it (Guard in a container) may still use.
//! - **Windows**: access is an ACL. A file is created inside a new folder
//!   whose ACL grants the current user alone (inherited by what is created
//!   in it), then hard-linked to its place and the folder removed: the file
//!   never exists with a wider ACL, not even for a moment, and an existing
//!   file is never replaced. A file is accepted only when it is owned by the
//!   user (or SYSTEM or Administrators) and every entry that allows access
//!   names the user, SYSTEM or Administrators (OWNER RIGHTS only when the
//!   owner is the user): the circle that can read a 0600 file on Unix. The
//!   ACL is read as SDDL, whose identifiers do not depend on the display
//!   language, and parsed by an allowlist: any entry type, flag or
//!   condition it does not know is refused. Permissions are queried on the
//!   open file handle with Windows' GetSecurityInfo, through safe wrappers.
//!   System tools used for creation and SID resolution are invoked by absolute
//!   path under `%SystemRoot%\System32`.
//!
//! [`check_sddl`] and [`unix_openness`] are text and number processing,
//! tested on every platform; the Windows paths are tested on Windows (the
//! public repository's CI).

use std::{fs, io, path::Path};

/// Why a file is not owner-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Openness {
    /// Others can write it, change its permissions or take it over.
    Writable(String),
    /// Others can read it (and no more than that).
    Readable(String),
}

/// Create `path` new (an existing file is never replaced), readable and
/// writable by its owner only.
pub fn create(path: &Path) -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(windows)]
    {
        windows::create(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "owner-only files are supported on Unix and Windows only",
        ))
    }
}

/// Check that only the owner can read `path`. `Ok(None)`: owner-only.
/// `Ok(Some(_))`: why it is open (the caller decides; [`Openness::Writable`]
/// must always be refused). An error reading the permissions: `Err`.
pub fn check(path: &Path) -> Result<Option<Openness>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|error| format!("{}: {error}", path.display()))?
            .permissions()
            .mode();
        Ok(unix_openness(mode))
    }
    #[cfg(windows)]
    {
        let file =
            open_for_reading(path).map_err(|error| format!("{}: {error}", path.display()))?;
        check_opened(&file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(format!(
            "{}: owner-only files are checked on Unix and Windows only",
            path.display()
        ))
    }
}

/// Windows: open a plain file with read-only sharing and without following a
/// final reparse point. Observed ancestor links are also refused; concurrent
/// ancestor mutations are not excluded by that observation. Call [`check_opened`]
/// before reading, so permission checks and key bytes refer to the same handle.
#[cfg(windows)]
pub fn open_for_reading(path: &Path) -> io::Result<fs::File> {
    windows::open_for_reading(path)
}

/// Windows: check permissions on this open file, without resolving its pathname.
/// Use the same file for subsequent reads. The strict allowlist is shared with
/// [`check`]; errors and unknown descriptors fail closed.
#[cfg(windows)]
pub fn check_opened(file: &fs::File) -> Result<Option<Openness>, String> {
    windows::check_plain(file).map_err(|error| error.to_string())?;
    let sddl = windows::sddl(file).map_err(|error| error.to_string())?;
    let user = windows::user_sid()?;
    let local_admin = if sddl.contains("LA") {
        windows::local_admin_sid()?
    } else {
        None
    };
    Ok(check_sddl(&sddl, &user, local_admin.as_deref()).err())
}

/// Unix mode bits: group or other write first, then any other bit for
/// group or others.
pub fn unix_openness(mode: u32) -> Option<Openness> {
    if mode & 0o022 != 0 {
        Some(Openness::Writable(format!(
            "group or others can write it (mode {:o})",
            mode & 0o777
        )))
    } else if mode & 0o077 != 0 {
        Some(Openness::Readable(format!(
            "group or others have access to it (mode {:o})",
            mode & 0o777
        )))
    } else {
        None
    }
}

/// SIDs that may hold access besides the user (as root may read a 0600
/// file on Unix): SYSTEM and the Administrators group, in their SDDL
/// aliases and numeric forms.
const TRUSTED: &[&str] = &["SY", "S-1-5-18", "BA", "S-1-5-32-544"];
const OWNER_RIGHTS: &[&str] = &["OW", "S-1-3-4"];
/// ACE flags understood here; anything else is refused.
const KNOWN_FLAGS: &[&str] = &["OI", "CI", "NP", "IO", "ID", "SA", "FA"];
/// Access rights that read and nothing more; any other right (or an
/// unknown one, or a hex mask with any other bit) counts as write.
const READ_ONLY_RIGHTS: &[&str] = &["FR", "GR", "GX", "FX", "RC", "LO", "SW"];
/// The bits of a hex mask that only read: FILE_READ_DATA, FILE_READ_EA,
/// FILE_EXECUTE, FILE_READ_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE,
/// GENERIC_EXECUTE, GENERIC_READ.
const READ_ONLY_MASK: u32 = 0x0000_0001
    | 0x0000_0008
    | 0x0000_0020
    | 0x0000_0080
    | 0x0002_0000
    | 0x0010_0000
    | 0x2000_0000
    | 0x8000_0000;

fn sid_in(sid: &str, set: &[&str]) -> bool {
    set.iter().any(|known| sid.eq_ignore_ascii_case(known))
}

/// One ACE's text between its brackets, split into its six fields. Refused
/// when it has a seventh (a condition or resource attribute) or quotes.
fn ace_fields(ace: &str) -> Result<[&str; 6], Openness> {
    if ace.contains('"') || ace.contains('(') {
        return Err(Openness::Writable(format!(
            "its ACL has a conditional entry ({ace}), which is not checked here"
        )));
    }
    let fields: Vec<&str> = ace.split(';').collect();
    <[&str; 6]>::try_from(fields.as_slice()).map_err(|_| {
        Openness::Writable(format!("its ACL has an entry not understood here ({ace})"))
    })
}

/// Whether `rights` (SDDL rights: two-letter codes or a hex mask) can do
/// more than read.
fn rights_write(rights: &str) -> bool {
    if let Some(hex) = rights
        .strip_prefix("0x")
        .or_else(|| rights.strip_prefix("0X"))
    {
        return u32::from_str_radix(hex, 16).map_or(true, |mask| mask & !READ_ONLY_MASK != 0);
    }
    if rights.is_empty() || !rights.len().is_multiple_of(2) || !rights.is_ascii() {
        return true;
    }
    (0..rights.len())
        .step_by(2)
        .any(|at| !READ_ONLY_RIGHTS.contains(&&rights[at..at + 2]))
}

/// Split the security descriptor into its parts, aware of brackets and
/// quotes (conditional entries may contain both). Returns the owner and
/// the DACL's text, or why the descriptor is not understood.
fn owner_and_dacl(sddl: &str) -> Result<(String, String), Openness> {
    let mut owner = String::new();
    let mut dacl: Option<String> = None;
    let mut part: Option<char> = None;
    let mut current = String::new();
    let mut depth = 0usize;
    let mut quoted = false;
    let chars: Vec<char> = sddl.chars().collect();
    let mut at = 0;
    fn finish(
        part: Option<char>,
        text: &mut String,
        owner: &mut String,
        dacl: &mut Option<String>,
    ) {
        match part {
            Some('O') => *owner = std::mem::take(text),
            Some('D') => *dacl = Some(std::mem::take(text)),
            _ => text.clear(),
        }
    }
    while at < chars.len() {
        let c = chars[at];
        if quoted {
            if c == '"' {
                quoted = false;
            }
            current.push(c);
        } else if c == '"' {
            quoted = true;
            current.push(c);
        } else if c == '(' {
            depth += 1;
            current.push(c);
        } else if c == ')' {
            depth = depth.checked_sub(1).ok_or_else(|| {
                Openness::Writable("its security descriptor is not understood here".into())
            })?;
            current.push(c);
        } else if depth == 0
            && matches!(c, 'O' | 'G' | 'D' | 'S')
            && chars.get(at + 1) == Some(&':')
        {
            finish(part, &mut current, &mut owner, &mut dacl);
            part = Some(c);
            at += 2;
            continue;
        } else {
            current.push(c);
        }
        at += 1;
    }
    if quoted || depth != 0 {
        return Err(Openness::Writable(
            "its security descriptor is not understood here".into(),
        ));
    }
    finish(part, &mut current, &mut owner, &mut dacl);
    let dacl = dacl.ok_or_else(|| Openness::Writable("it has no access control list".into()))?;
    Ok((owner, dacl))
}

/// Check a file's security descriptor in SDDL against `user` (the current
/// user's SID, `S-1-5-21-…`). `local_admin` is what the alias `LA` (this
/// machine's built-in Administrator account) stands for, resolved on the
/// machine; `LA` counts as the user only when it is exactly the user's SID.
/// An allowlist:
///
/// - the owner (`O:`) must be the user, SYSTEM or Administrators (an owner
///   can rewrite the ACL at will);
/// - the DACL must be present and protected or not, with known flags only
///   (`P`, `AI`, `AR`); `NO_ACCESS_CONTROL` means everyone;
/// - every entry must be a plain allow (`A`) or deny (`D`) entry with
///   known flags and exactly six fields (no conditions, callbacks, object
///   or audit entries);
/// - allow entries that apply to the file (not `IO`) must name the user,
///   SYSTEM, Administrators, or OWNER RIGHTS while the owner is the user;
///   for anyone else they are [`Openness::Writable`] when their rights do
///   more than read, [`Openness::Readable`] otherwise;
/// - at least one allow entry must name the user (or OWNER RIGHTS with the
///   user as owner): a file its owner cannot read is no use as a key file.
pub fn check_sddl(sddl: &str, user: &str, local_admin: Option<&str>) -> Result<(), Openness> {
    let (owner, dacl) = owner_and_dacl(sddl)?;
    let is_user_sid = |sid: &str| {
        sid.eq_ignore_ascii_case(user)
            || (sid.eq_ignore_ascii_case("LA")
                && local_admin.is_some_and(|la| la.eq_ignore_ascii_case(user)))
    };
    let owner_is_user = is_user_sid(&owner);
    if !owner_is_user && !sid_in(&owner, TRUSTED) {
        return Err(Openness::Writable(format!(
            "it is owned by {} (only you, SYSTEM or Administrators may own a key file)",
            if owner.is_empty() {
                "nobody known"
            } else {
                &owner
            }
        )));
    }
    if dacl.starts_with("NO_ACCESS_CONTROL") {
        return Err(Openness::Writable("it has no access control list".into()));
    }
    let (flags, entries) = dacl.split_at(dacl.find('(').unwrap_or(dacl.len()));
    let mut rest = flags;
    while !rest.is_empty() {
        let Some(next) = ["P", "AI", "AR"]
            .iter()
            .find(|flag| rest.starts_with(*flag))
        else {
            return Err(Openness::Writable(format!(
                "its ACL has flags not understood here ({flags})"
            )));
        };
        rest = &rest[next.len()..];
    }
    let mut user_can_read = false;
    let mut entries = entries;
    while !entries.is_empty() {
        let Some(inner) = entries.strip_prefix('(') else {
            return Err(Openness::Writable("its ACL is not understood here".into()));
        };
        // The ACE ends at the first ')' (ace_fields refuses brackets and
        // quotes inside, so a conditional entry never gets this far).
        let end = inner
            .find(')')
            .ok_or_else(|| Openness::Writable("its ACL is not understood here".into()))?;
        let ace = &inner[..end];
        entries = &inner[end + 1..];
        let [kind, flags, rights, object, inherit_object, sid] = ace_fields(ace)?;
        if !object.is_empty() || !inherit_object.is_empty() {
            return Err(Openness::Writable(format!(
                "its ACL has an object entry ({ace})"
            )));
        }
        // Two-letter tokens, never substrings: "OIOI" holds no "IO".
        if !flags.is_ascii() || !flags.len().is_multiple_of(2) {
            return Err(Openness::Writable(format!(
                "its ACL has an entry with flags not understood here ({ace})"
            )));
        }
        let tokens: Vec<&str> = (0..flags.len())
            .step_by(2)
            .map(|at| &flags[at..at + 2])
            .collect();
        if tokens.iter().any(|token| !KNOWN_FLAGS.contains(token)) {
            return Err(Openness::Writable(format!(
                "its ACL has an entry with flags not understood here ({ace})"
            )));
        }
        match kind {
            "D" => continue,
            "A" => {}
            _ => {
                return Err(Openness::Writable(format!(
                    "its ACL has an entry of a kind not checked here ({ace})"
                )));
            }
        }
        if tokens.contains(&"IO") {
            continue; // inherit-only: applies to children, not to this file
        }
        let is_user = is_user_sid(sid) || (owner_is_user && sid_in(sid, OWNER_RIGHTS));
        if is_user {
            user_can_read = true;
            continue;
        }
        if sid_in(sid, TRUSTED) {
            continue;
        }
        let who = if sid_in(sid, OWNER_RIGHTS) {
            "OWNER RIGHTS (the owner is not you)".to_owned()
        } else {
            sid.to_owned()
        };
        return Err(if rights_write(rights) {
            Openness::Writable(format!(
                "its ACL lets {who} change it (only you, SYSTEM and Administrators may have access)"
            ))
        } else {
            Openness::Readable(format!(
                "its ACL lets {who} read it (only you, SYSTEM and Administrators may have access)"
            ))
        });
    }
    if !user_can_read {
        return Err(Openness::Readable(
            "its ACL does not let you read it".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
mod windows {
    use std::{
        fs, io,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        process::Command,
    };

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

    /// A Windows tool by absolute path, never found through PATH.
    fn system32(tool: &str) -> PathBuf {
        let root = std::env::var_os("SystemRoot")
            .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
        root.join("System32").join(tool)
    }

    fn run(command: &mut Command, what: &str) -> io::Result<String> {
        let output = command.output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "{what} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// The current user's SID: `whoami /user /fo csv /nh` prints
    /// `"domain\user","S-1-5-21-…"`, in any display language.
    pub fn user_sid() -> Result<String, String> {
        let text = run(
            Command::new(system32("whoami.exe")).args(["/user", "/fo", "csv", "/nh"]),
            "whoami /user",
        )
        .map_err(|error| error.to_string())?;
        text.trim()
            .rsplit(',')
            .next()
            .map(|field| field.trim().trim_matches('"').to_owned())
            .filter(|sid| {
                sid.starts_with("S-1-")
                    && sid
                        .bytes()
                        .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
            })
            .ok_or_else(|| format!("whoami /user printed no SID: {}", text.trim()))
    }

    /// A new folder next to `path` whose ACL grants the user alone, also to
    /// everything created in it; the file is created there, linked to
    /// `path` (never replacing a file) and the folder removed.
    pub fn create(path: &Path) -> io::Result<fs::File> {
        let sid = user_sid().map_err(io::Error::other)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let folder = parent.join(format!(".owner-only-{}", unique_suffix()?));
        fs::create_dir(&folder)?;
        let result = (|| {
            run(
                Command::new(system32("icacls.exe"))
                    .arg(&folder)
                    .args(["/inheritance:r", "/grant:r"])
                    .arg(format!("*{sid}:(OI)(CI)F"))
                    .arg("/q"),
                "icacls",
            )?;
            let inside = folder.join("file");
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&inside)?;
            // The entry it inherited from the folder becomes its own, so a
            // later change to the inheritance above cannot widen it.
            run(
                Command::new(system32("icacls.exe"))
                    .arg(&inside)
                    .args(["/inheritance:d", "/q"]),
                "icacls",
            )?;
            // Nothing is written into it before its ACL is known to be right.
            match super::check_opened(&file) {
                Ok(None) => {}
                Ok(Some(open)) => {
                    return Err(io::Error::other(format!(
                        "the new file is not owner-only: {open:?}"
                    )));
                }
                Err(error) => return Err(io::Error::other(error)),
            }
            fs::hard_link(&inside, path)?;
            // Linked into place: the temporary name and folder go if they can;
            // a leftover is the same owner-only file under a second name.
            if let Err(error) = fs::remove_file(&inside) {
                eprintln!(
                    "WARNING: could not remove {} ({error}); it is a second name of the new key file: delete it",
                    inside.display()
                );
            }
            Ok(file)
        })();
        let _ = fs::remove_file(folder.join("file"));
        if fs::remove_dir(&folder).is_err() && folder.exists() {
            eprintln!(
                "WARNING: could not remove the temporary folder {}: delete it",
                folder.display()
            );
        }
        result
    }

    /// A name unique next to the key for this moment: the process id and
    /// the time. It need not be secret: the folder's ACL protects what is
    /// in it, and `create_dir` refuses a folder that already exists.
    fn unique_suffix() -> io::Result<String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        Ok(format!("{}-{nanos}", std::process::id()))
    }

    pub fn open_for_reading(path: &Path) -> io::Result<fs::File> {
        // Refuse links observed in the supplied spelling. This is path hygiene,
        // not an identity guarantee during concurrent namespace changes. ACLs
        // and subsequent bytes are checked through the opened file handle.
        let absolute = std::path::absolute(path)?;
        for ancestor in absolute.ancestors().skip(1) {
            if ancestor.parent().is_none() {
                break; // the drive's root
            }
            let attributes = fs::symlink_metadata(ancestor)?.file_attributes();
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is a link or junction", ancestor.display()),
                ));
            }
        }
        open_final(&absolute)
    }

    // Separate from the ancestor observations so native tests can deterministically
    // substitute the namespace between observation, opening and ACL validation.
    fn open_final(path: &Path) -> io::Result<fs::File> {
        let file = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        check_plain(&file)?;
        Ok(file)
    }

    pub fn check_plain(file: &fs::File) -> io::Result<()> {
        let attributes = file.metadata()?.file_attributes();
        if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a plain file (a link, junction or folder)",
            ));
        }
        Ok(())
    }

    /// Query only owner and DACL on the existing handle. No pathname is
    /// supplied to the security API, and no privileged SACL access is requested.
    pub fn sddl(file: &fs::File) -> io::Result<String> {
        use windows_permissions::{
            constants::{SeObjectType::SE_FILE_OBJECT, SecurityInformation},
            wrappers::{ConvertSecurityDescriptorToStringSecurityDescriptor, GetSecurityInfo},
        };
        let information = SecurityInformation::Owner | SecurityInformation::Dacl;
        let descriptor = GetSecurityInfo(file, SE_FILE_OBJECT, information)?;
        ConvertSecurityDescriptorToStringSecurityDescriptor(&descriptor, information)?
            .into_string()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the ACL is not valid Unicode"))
    }

    /// Resolve LA independently of the key path. RID 500 alone is insufficient:
    /// local-machine and domain Administrator accounts have different SID prefixes.
    pub fn local_admin_sid() -> Result<Option<String>, String> {
        let text = run(
            Command::new(system32(r"WindowsPowerShell\v1.0\powershell.exe")).args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "try { ([Security.Principal.SecurityIdentifier]'LA').Value } catch { '' }",
            ]),
            "resolving the local Administrator SID",
        )
        .map_err(|error| error.to_string())?;
        let sid = text.trim();
        if sid.is_empty() {
            return Ok(None);
        }
        if sid.starts_with("S-1-")
            && sid
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
        {
            Ok(Some(sid.to_owned()))
        } else {
            Err("Windows returned an invalid local Administrator SID".into())
        }
    }

    #[cfg(test)]
    mod native_tests {
        use super::*;
        use crate::owner_only::{Openness, check, check_opened};

        fn directory(name: &str) -> PathBuf {
            let path = std::env::temp_dir()
                .join(format!("owner-only-{name}-{}", unique_suffix().unwrap()));
            fs::create_dir(&path).unwrap();
            path
        }

        fn junction(link: &Path, target: &Path) {
            let output = Command::new(system32("cmd.exe"))
                .args(["/d", "/c", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "junction fixture failed: {output:?}"
            );
            assert_ne!(
                fs::symlink_metadata(link).unwrap().file_attributes()
                    & FILE_ATTRIBUTE_REPARSE_POINT,
                0,
                "fixture is not a junction"
            );
        }

        #[test]
        fn final_symlinks_and_observed_parent_junctions_are_refused() {
            let dir = directory("links");
            let target = dir.join("target");
            fs::create_dir(&target).unwrap();
            let key = target.join("key");
            drop(create(&key).unwrap());
            let link = dir.join("key-link");
            std::os::windows::fs::symlink_file(&key, &link)
                .expect("the native CI runner must support the symlink fixture");
            assert_eq!(
                open_for_reading(&link).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert!(check(&link).is_err());
            let alias = dir.join("parent-link");
            junction(&alias, &target);
            assert_eq!(
                open_for_reading(&alias.join("key")).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            fs::remove_file(link).unwrap();
            fs::remove_dir(alias).unwrap();
            fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        fn the_open_file_cannot_be_written_renamed_or_deleted() {
            let dir = directory("sharing");
            let key = dir.join("key");
            drop(create(&key).unwrap());
            let file = open_for_reading(&key).unwrap();
            assert_eq!(check_opened(&file).unwrap(), None);
            assert!(fs::write(&key, b"synthetic replacement").is_err());
            assert!(fs::rename(&key, dir.join("renamed")).is_err());
            assert!(fs::remove_file(&key).is_err());
            drop(file);
            // Reciprocal sharing: an already-open writer or DELETE handle
            // prevents the restrictive reader from opening at all.
            for access in [0x4000_0000, 0x0001_0000] {
                let conflicting = fs::OpenOptions::new()
                    .access_mode(access)
                    .open(&key)
                    .unwrap();
                assert!(open_for_reading(&key).is_err(), "access mask {access:#x}");
                drop(conflicting);
                drop(open_for_reading(&key).unwrap());
            }
            fs::rename(&key, dir.join("renamed")).unwrap();
            fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        fn a_restrictive_decoy_never_approves_the_open_permissive_target() {
            let dir = directory("substitution");
            let permissive = dir.join("permissive");
            let restrictive = dir.join("restrictive");
            fs::create_dir(&permissive).unwrap();
            fs::create_dir(&restrictive).unwrap();
            for path in [&permissive, &restrictive] {
                let mut file = create(&path.join("key")).unwrap();
                use std::io::Write;
                file.write_all(b"synthetic fixture, never a private key")
                    .unwrap();
            }
            run(
                Command::new(system32("icacls.exe"))
                    .arg(permissive.join("key"))
                    .args(["/grant", "*S-1-1-0:R", "/q"]),
                "fixture ACL",
            )
            .unwrap();
            let alias = dir.join("observed-parent");
            // Simulate a junction substituted after ancestor observation.
            junction(&alias, &permissive);
            let file = open_final(&alias.join("key")).unwrap();
            // The same supplied spelling now names a restrictive decoy, while
            // the held File still refers to the permissive synthetic target.
            fs::remove_dir(&alias).unwrap();
            junction(&alias, &restrictive);
            assert_eq!(check(&restrictive.join("key")).unwrap(), None);
            assert!(matches!(
                check_opened(&file).unwrap(),
                Some(Openness::Readable(_))
            ));
            // No key bytes are consumed when this held handle is too open.
            drop(file);
            fs::remove_dir(alias).unwrap();
            fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        fn a_native_null_dacl_is_refused() {
            use windows_permissions::{
                constants::{SeObjectType::SE_FILE_OBJECT, SecurityInformation},
                wrappers::SetSecurityInfo,
            };
            let dir = directory("null-dacl");
            let key = dir.join("key");
            drop(create(&key).unwrap());
            // READ_CONTROL | WRITE_DAC: sufficient to install the synthetic
            // null DACL and query it, without privileged SACL access.
            let mut file = fs::OpenOptions::new()
                .access_mode(0x0006_0000)
                .open(&key)
                .unwrap();
            SetSecurityInfo(
                &mut file,
                SE_FILE_OBJECT,
                SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            assert!(matches!(
                check_opened(&file).unwrap(),
                Some(Openness::Writable(_))
            ));
            drop(file);
            fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const USER: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
    const OTHER: &str = "S-1-5-21-1004336348-1177238915-682003330-1002";

    #[test]
    fn a_profile_file_with_user_system_and_administrators_is_owner_only() {
        // What a new file in %LOCALAPPDATA% inherits by default.
        let sddl = format!("O:{USER}G:{USER}D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{USER})");
        assert_eq!(check_sddl(&sddl, USER, None), Ok(()));
        // What `create` leaves: the user alone, inherited from the folder.
        let sddl = format!("O:{USER}G:{USER}D:(A;ID;FA;;;{USER})");
        assert_eq!(check_sddl(&sddl, USER, None), Ok(()));
        // Owned by Administrators (an elevated prompt), the user allowed.
        let sddl = format!("O:BAG:SYD:PAI(A;;FA;;;{USER})(A;;FA;;;BA)");
        assert_eq!(check_sddl(&sddl, USER, None), Ok(()));
    }

    #[test]
    fn anyone_else_is_refused_and_write_rights_are_writable() {
        for other in ["WD", "BU", "AU", "IU", "AN", OTHER, "S-1-1-0"] {
            let read = format!("O:{USER}D:PAI(A;;FA;;;{USER})(A;;FR;;;{other})");
            assert!(
                matches!(check_sddl(&read, USER, None), Err(Openness::Readable(text)) if text.contains(other)),
                "{other} reading was not Readable"
            );
            for rights in [
                "FA", "FW", "GA", "GW", "WD", "WO", "SD", "FRFW", "0x1f01ff", "0x2", "XX",
            ] {
                let write = format!("O:{USER}D:PAI(A;;FA;;;{USER})(A;;{rights};;;{other})");
                assert!(
                    matches!(check_sddl(&write, USER, None), Err(Openness::Writable(_))),
                    "{other} with {rights} was not Writable"
                );
            }
        }
        // A read-only hex mask is Readable.
        let sddl = format!("O:{USER}D:(A;;FA;;;{USER})(A;;0x120089;;;BU)");
        assert!(matches!(
            check_sddl(&sddl, USER, None),
            Err(Openness::Readable(_))
        ));
    }

    #[test]
    fn the_owner_must_be_the_user_system_or_administrators() {
        let sddl = format!("O:{OTHER}D:(A;;FA;;;{USER})");
        assert!(
            matches!(check_sddl(&sddl, USER, None), Err(Openness::Writable(text)) if text.contains("owned by"))
        );
        let sddl = format!("D:(A;;FA;;;{USER})");
        assert!(matches!(
            check_sddl(&sddl, USER, None),
            Err(Openness::Writable(_))
        ));
        // OWNER RIGHTS counts as the user only when the user owns the file.
        let sddl = format!("O:{USER}D:(A;;FA;;;OW)");
        assert_eq!(check_sddl(&sddl, USER, None), Ok(()));
        let sddl = format!("O:BAD:(A;;FA;;;{USER})(A;;FA;;;OW)");
        assert!(
            matches!(check_sddl(&sddl, USER, None), Err(Openness::Writable(text)) if text.contains("OWNER RIGHTS"))
        );
    }

    #[test]
    fn flags_are_tokens_rights_rp_lc_write_and_la_is_the_builtin_administrator() {
        // "OIOI" holds no inherit-only token: the entry applies and is refused.
        let sddl = format!("O:{USER}D:(A;;FA;;;{USER})(A;OIOI;FR;;;BU)");
        assert!(check_sddl(&sddl, USER, None).is_err());
        let sddl = format!("O:{USER}D:(A;;FA;;;{USER})(A;OIC;FR;;;BU)");
        assert!(check_sddl(&sddl, USER, None).is_err());
        for rights in ["RP", "LC", "FRRP"] {
            let sddl = format!("O:{USER}D:(A;;FA;;;{USER})(A;;{rights};;;BU)");
            assert!(
                matches!(check_sddl(&sddl, USER, None), Err(Openness::Writable(_))),
                "{rights}"
            );
        }
        // The built-in Administrator (RID 500) appears as LA, as owner and in entries.
        // LA counts as the user only when it resolves to exactly the user's SID.
        let admin = "S-1-5-21-1004336348-1177238915-682003330-500";
        assert_eq!(check_sddl("O:LAD:(A;;FA;;;LA)", admin, Some(admin)), Ok(()));
        assert!(check_sddl("O:LAD:(A;;FA;;;LA)", admin, None).is_err());
        assert!(check_sddl("O:LAD:(A;;FA;;;LA)", USER, Some(admin)).is_err());
        let other_admin = "S-1-5-21-9-9-9-500";
        assert!(check_sddl("O:LAD:(A;;FA;;;LA)", admin, Some(other_admin)).is_err());
    }

    #[test]
    fn deny_and_inherit_only_entries_do_not_open_a_file() {
        let sddl = format!("O:{USER}D:P(D;;FA;;;WD)(A;OICIIO;FA;;;BU)(A;;FA;;;{USER})");
        assert_eq!(check_sddl(&sddl, USER, None), Ok(()));
    }

    #[test]
    fn unknown_entries_conditions_and_odd_descriptors_are_refused() {
        let cases = [
            // No DACL, or one that lets everyone in, or allows nobody.
            format!("O:{USER}G:{USER}"),
            format!("O:{USER}D:NO_ACCESS_CONTROL"),
            format!("O:{USER}D:P"),
            // Conditional and callback entries, with brackets and quotes inside.
            format!(
                r#"O:{USER}D:(A;;FA;;;{USER})(XA;;FA;;;WD;(@User.x == "a)b(A;;FA;;;{USER})"))"#
            ),
            format!("O:{USER}D:(A;;FA;;;{USER})(ZA;;FA;;;WD;(Member_of {{SID(BA)}}))"),
            // Object and audit entries in the DACL, unknown flags.
            format!("O:{USER}D:(A;;FA;;;{USER})(OA;;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;WD)"),
            format!("O:{USER}D:(A;;FA;;;{USER})(AU;SA;FA;;;WD)"),
            format!("O:{USER}D:(A;ZZ;FA;;;{USER})"),
            format!("O:{USER}D:XX(A;;FA;;;{USER})"),
            // Unbalanced text.
            format!("O:{USER}D:(A;;FA;;;{USER}"),
            format!(r#"O:{USER}D:(A;;FA;;;{USER})(A;;FR;;;"WD)"#),
            // The user cannot read it.
            format!("O:{USER}D:(A;;FA;;;SY)"),
        ];
        for sddl in cases {
            assert!(check_sddl(&sddl, USER, None).is_err(), "accepted: {sddl}");
        }
    }

    #[test]
    fn a_sacl_after_the_dacl_is_not_read_as_entries() {
        let sddl = format!("O:{USER}D:P(A;;FA;;;{USER})S:(AU;SA;FA;;;WD)");
        assert_eq!(check_sddl(&sddl, USER, None), Ok(()));
    }

    #[test]
    fn unix_modes_follow_the_old_rules() {
        assert_eq!(unix_openness(0o100600), None);
        assert_eq!(unix_openness(0o100400), None);
        assert_eq!(unix_openness(0o100700), None);
        for mode in [0o100640, 0o100604, 0o100610, 0o100601, 0o100650] {
            assert!(
                matches!(unix_openness(mode), Some(Openness::Readable(_))),
                "{mode:o}"
            );
        }
        for mode in [0o100620, 0o100602, 0o100666] {
            assert!(
                matches!(unix_openness(mode), Some(Openness::Writable(_))),
                "{mode:o}"
            );
        }
    }

    #[test]
    fn create_makes_an_owner_only_file_and_never_replaces_one() {
        let dir = std::env::temp_dir().join(format!("owner-only-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        fs::remove_file(&path).ok();
        drop(create(&path).unwrap());
        assert_eq!(check(&path).unwrap(), None);
        assert_eq!(
            create(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        // Nothing left behind next to it.
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(windows)]
    #[test]
    fn on_windows_others_reading_is_readable_and_links_are_refused() {
        let dir = std::env::temp_dir().join(format!("owner-only-open-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        fs::remove_file(&path).ok();
        drop(create(&path).unwrap());
        assert!(open_for_reading(&path).is_ok());
        let granted = std::process::Command::new("icacls")
            .arg(&path)
            .args(["/grant", "*S-1-1-0:R"])
            .output()
            .unwrap();
        assert!(granted.status.success());
        assert!(matches!(check(&path).unwrap(), Some(Openness::Readable(_))));
        let granted = std::process::Command::new("icacls")
            .arg(&path)
            .args(["/grant", "*S-1-1-0:W"])
            .output()
            .unwrap();
        assert!(granted.status.success());
        assert!(matches!(check(&path).unwrap(), Some(Openness::Writable(_))));
        assert!(open_for_reading(&dir).is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
