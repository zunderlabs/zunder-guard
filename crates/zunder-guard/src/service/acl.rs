// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Narrow service ACL contract, independent of Win32 for regression tests.
use super::{Result, refused};

/// The one security descriptor Guard writes for a protected service file:
/// owned by Administrators, inheritance off, full control for Administrators
/// and SYSTEM, and for the service's virtual account read-only (`FR`) or,
/// for `mutable` runtime files such as `runtime\guard.toml`, modify
/// (`0x1301bf`: read, write, execute, delete; no ACL or owner change).
/// [`check`] admits exactly this shape; installer-written files use the same.
pub fn service_file_sddl(service_sid: &str, mutable: bool) -> Result<String> {
    let numeric = service_sid.strip_prefix("S-1-5-80-").is_some_and(|rest| {
        rest.split('-')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    });
    if !numeric {
        return Err(refused("invalid virtual service identity"));
    }
    let rights = if mutable { "0x1301bf" } else { "FR" };
    Ok(format!(
        "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;{rights};;;{service_sid})"
    ))
}

/// Authenticated Users (`AU`, `S-1-5-11`): the only identity besides
/// Administrators, SYSTEM and the service that may hold an entry on the two
/// shared anchors (`public_read`), and only read and list, exactly as the
/// installer's `Set-ZgBaseAcl` grants. Everyone, Anonymous, Guests, Users and
/// any other identity are refused there too.
const AUTHENTICATED_USERS: [&str; 2] = ["AU", "S-1-5-11"];

/// Admit a protected service path's owner and DACL (SDDL). `public_read`
/// marks the two shared anchors, where Authenticated Users may read.
pub fn check(sddl: &str, service_sid: &str, mutable: bool, public_read: bool) -> Result<()> {
    let d = sddl
        .find("D:")
        .ok_or_else(|| refused("service file has no DACL"))?;
    let head = &sddl[..d];
    let owner = head
        .strip_prefix("O:")
        .ok_or_else(|| refused("service file has no owner"))?;
    let owner = owner.split("G:").next().unwrap_or(owner);
    let admins = ["SY", "BA", "S-1-5-18", "S-1-5-32-544"];
    if !admins.contains(&owner) && !(mutable && owner == service_sid) {
        return Err(refused("service file has an untrusted owner"));
    }
    let mut body = &sddl[d + 2..];
    if let Some(at) = body.find("S:") {
        body = &body[..at];
    }
    let at = body.find('(').ok_or_else(|| refused("empty service ACL"))?;
    let flags = &body[..at];
    if !["P", "PAI", "PAR", "PARAI"].contains(&flags)
        && !(mutable && ["", "AI", "AR", "ARAI"].contains(&flags))
    {
        return Err(refused("service ACL must disable inheritance"));
    }
    let mut rest = &body[at..];
    let mut readable = false;
    while !rest.is_empty() {
        let tail = rest
            .strip_prefix('(')
            .ok_or_else(|| refused("malformed service ACL"))?;
        let end = tail
            .find(')')
            .ok_or_else(|| refused("malformed service ACE"))?;
        let f: Vec<_> = tail[..end].split(';').collect();
        if f.len() != 6
            || f[0] != "A"
            || !["", "OICI", "CI", "OI", "ID", "OICIID"].contains(&f[1])
            || !f[3].is_empty()
            || !f[4].is_empty()
        {
            return Err(refused("unsupported service ACL entry"));
        }
        let rights = match f[2] {
            "FA" => 0x001f01ff,
            "FR" => 0x00120089,
            "FRFX" => 0x001200a9,
            "0x1301bf" => 0x001301bf,
            hex if hex.starts_with("0x") => u32::from_str_radix(&hex[2..], 16)
                .map_err(|_| refused("unknown service ACL rights"))?,
            _ => return Err(refused("unknown service ACL rights")),
        };
        let read_only = rights & !0x001200a9 == 0;
        if f[5] == service_sid {
            if !mutable && !read_only {
                return Err(refused("service may write immutable admission data"));
            }
            readable |= rights & 1 != 0;
        } else if !admins.contains(&f[5])
            && !(public_read && read_only && AUTHENTICATED_USERS.contains(&f[5]))
        {
            return Err(refused("service ACL grants another identity access"));
        }
        rest = &tail[end + 1..];
    }
    if !readable && !public_read {
        return Err(refused("service SID lacks read permission"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const SID: &str = "S-1-5-80-1-2-3-4-5";
    #[test]
    fn service_reads_immutable_but_cannot_write_it() {
        let base = format!("O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;{SID})");
        assert!(check(&base, SID, false, false).is_ok());
        assert!(check(&base.replace(";;FR;", ";;FA;"), SID, false, false).is_err());
        assert!(check(&base.replace(";;FR;", ";;FA;"), SID, true, false).is_ok());
        for changed in [
            base.replace("D:P", "D:AI"),
            base.replace("O:BA", "O:BU"),
            format!("{base}(A;;FR;;;BU)"),
            format!("{base}(A;;FA;;;WD)"),
            base.replace("(A;;FR", "(XA;;FR"),
        ] {
            assert!(check(&changed, SID, false, false).is_err(), "{changed}");
        }
    }

    #[test]
    fn shared_anchors_admit_read_for_authenticated_users_only() {
        // What the installer's Set-ZgBaseAcl writes: this folder only, read and list.
        let base = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;AU)";
        assert!(check(base, SID, false, true).is_ok());
        assert!(check(&base.replace(";;;AU)", ";;;S-1-5-11)"), SID, false, true).is_ok());
        // The CI fixture's earlier inheritable form is the same identity and rights.
        assert!(
            check(
                &base.replace("(A;;0x1200a9", "(A;OICI;0x1200a9"),
                SID,
                false,
                true
            )
            .is_ok()
        );
        // No public entry at all is fine; the service then needs none to read it.
        let private = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        assert!(check(private, SID, false, true).is_ok());
        // Everyone, Anonymous, Guests, Users, Interactive or another account: refused, even read-only.
        for other in [
            "WD",
            "S-1-1-0",
            "AN",
            "S-1-5-7",
            "BG",
            "S-1-5-32-546",
            "BU",
            "IU",
            "S-1-5-21-1-2-3-1001",
        ] {
            let sddl = base.replace(";;;AU)", &format!(";;;{other})"));
            assert!(check(&sddl, SID, false, true).is_err(), "{other}");
        }
        // Authenticated Users may never write, and get nothing outside the anchors.
        for rights in ["FA", "0x1201bf", "0x1200af", "FW"] {
            let sddl = base.replace("0x1200a9;;;AU", &format!("{rights};;;AU"));
            assert!(check(&sddl, SID, false, true).is_err(), "{rights}");
        }
        assert!(check(base, SID, false, false).is_err());
    }

    #[test]
    fn written_service_files_are_exactly_what_admission_accepts() {
        let config = service_file_sddl(SID, true).unwrap();
        assert_eq!(
            config,
            format!("O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1301bf;;;{SID})")
        );
        assert!(check(&config, SID, true, false).is_ok());
        // Modify is never admitted where admission data must be immutable.
        assert!(check(&config, SID, false, false).is_err());
        let immutable = service_file_sddl(SID, false).unwrap();
        assert!(check(&immutable, SID, false, false).is_ok());
        // Written for one service, refused for another.
        assert!(check(&config, "S-1-5-80-6-7-8-9-10", true, false).is_err());
        for sid in [
            "",
            "S-1-5-21-1-2-3-1001",
            "S-1-5-18",
            "S-1-5-80-1)(A;;FA;;;WD",
            "S-1-5-80-",
            "S-1-5-80-1--2",
            "SY",
        ] {
            assert!(service_file_sddl(sid, true).is_err(), "{sid}");
        }
    }

    #[test]
    fn an_owner_only_config_for_the_installing_user_is_refused() {
        // What `init` used to leave in runtime\guard.toml: zunder_venue's
        // owner-only file, owned by Administrators (an elevated installer)
        // or the user, granting only the installing user. The service's
        // virtual account cannot read it and admission refuses it.
        let user = "S-1-5-21-1004336348-1177238915-682003330-500";
        for owner in ["BA", user] {
            let sddl = format!("O:{owner}G:SYD:PAI(A;;FA;;;{user})");
            let error = check(&sddl, SID, true, false).unwrap_err().to_string();
            assert!(
                error.contains("untrusted owner") || error.contains("another identity"),
                "{owner}: {error}"
            );
        }
        // Run as SYSTEM, the owner-only file names SY alone: still no service read.
        let error = check("O:SYG:SYD:PAI(A;;FA;;;SY)", SID, true, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("lacks read"), "{error}");
    }
}
