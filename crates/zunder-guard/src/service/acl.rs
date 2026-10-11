// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Narrow service ACL contract, independent of Win32 for regression tests.
use super::{Result, refused};

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
        } else if !admins.contains(&f[5]) && !(public_read && read_only) {
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
}
