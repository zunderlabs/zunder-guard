// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Windows SCM credential boundary. No interactive-user profile, saved login
//! password, plaintext file, shell decryption or SYSTEM trading process.
use super::{Result, ServiceBinding, ServiceIdentity, refused};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
};
use windows::{
    Security::Cryptography::{CryptographicBuffer, DataProtection::DataProtectionProvider},
    core::{Array, HSTRING},
};
use windows_permissions::{
    constants::{SeObjectType::SE_FILE_OBJECT, SecurityInformation},
    utilities::current_process_sid,
    wrappers::{
        ConvertSecurityDescriptorToStringSecurityDescriptor, ConvertSidToStringSid,
        GetSecurityInfo, LookupAccountName,
    },
};
use winreg::{
    RegKey,
    enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY},
};
use zeroize::Zeroizing;

fn platform(binding: &ServiceBinding) -> Result<(&str, &str)> {
    match &binding.identity {
        ServiceIdentity::Windows {
            service_name,
            service_sid,
        } => Ok((service_name, service_sid)),
        _ => Err(refused("binding is not a Windows SCM service")),
    }
}
fn current_sid() -> Result<String> {
    let sid = current_process_sid()?;
    ConvertSidToStringSid(&sid)?
        .into_string()
        .map_err(|_| refused("invalid process SID"))
}
fn registry_string(path: &str, name: &str) -> Result<String> {
    Ok(RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY)?
        .get_value(name)?)
}
fn machine_root() -> Result<PathBuf> {
    Ok(PathBuf::from(registry_string(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        "Common AppData",
    )?)
    .join("ZunderGuard"))
}
fn binary_root() -> Result<PathBuf> {
    Ok(PathBuf::from(registry_string(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
        "ProgramFilesDir",
    )?)
    .join("ZunderGuard"))
}
fn root(binding: &ServiceBinding) -> Result<PathBuf> {
    Ok(machine_root()?.join(&binding.credential_id))
}
fn credential_path(binding: &ServiceBinding) -> Result<PathBuf> {
    Ok(root(binding)?.join("credential.dpapi"))
}

/// Safe native token query, not PATH/whoami or an environment-provided identity.
pub fn verify_service_identity(binding: &ServiceBinding) -> Result<()> {
    let (name, expected) = platform(binding)?;
    let (sid, _, _) = LookupAccountName(None::<&std::ffi::OsStr>, format!(r"NT SERVICE\{name}"))?;
    let resolved = ConvertSidToStringSid(&sid)?
        .into_string()
        .map_err(|_| refused("invalid service SID"))?;
    if resolved != expected || current_sid()? != expected {
        return Err(refused(
            "process is not the admitted virtual service account",
        ));
    }
    Ok(())
}

fn open_checked(path: &Path, sid: &str, mutable: bool, directory: bool) -> Result<File> {
    open_checked_kind(path, sid, mutable, directory, false)
}
fn open_checked_kind(
    path: &Path,
    sid: &str,
    mutable: bool,
    directory: bool,
    public_read: bool,
) -> Result<File> {
    for ancestor in path.ancestors() {
        if fs::symlink_metadata(ancestor)?.file_attributes() & 0x400 != 0 {
            return Err(refused("service path has a reparse ancestor"));
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000 | 0x02000000)
        .open(path)?;
    let attrs = file.metadata()?.file_attributes();
    if attrs & 0x400 != 0 || (attrs & 0x10 != 0) != directory {
        return Err(refused(
            "service path is a reparse point or unexpected file type",
        ));
    }
    let flags = SecurityInformation::Owner | SecurityInformation::Dacl;
    let sd = GetSecurityInfo(&file, SE_FILE_OBJECT, flags)?;
    let sddl = ConvertSecurityDescriptorToStringSecurityDescriptor(&sd, flags)?
        .into_string()
        .map_err(|_| refused("invalid ACL encoding"))?;
    super::acl::check(&sddl, sid, mutable, public_read)?;
    Ok(file)
}

pub fn validate_paths(binding: &ServiceBinding, binding_path: &Path) -> Result<()> {
    binding.validate_shape()?;
    let (_, sid) = platform(binding)?;
    let root = fs::canonicalize(root(binding)?)?;
    let binaries = fs::canonicalize(binary_root()?.join(&binding.credential_id))?;
    if fs::canonicalize(binding_path)? != root.join("binding.json")
        || binding.home != root.join("runtime")
        || binding.config != binding.home.join("guard.toml")
        || binding.executable != binaries.join("zunder-guard.exe")
    {
        return Err(refused(
            "service paths differ from the protected machine layout",
        ));
    }
    // Keep each directory handle open until its children are checked. No
    // delete sharing means a checked directory cannot be renamed under us.
    let _data_base = open_checked_kind(&machine_root()?, sid, false, true, true)?;
    let _binary_base = open_checked_kind(&binary_root()?, sid, false, true, true)?;
    let _root = open_checked(&root, sid, false, true)?;
    let _bin = open_checked(&binaries, sid, false, true)?;
    let _metadata = open_checked(binding_path, sid, false, false)?;
    let _exe = open_checked(&binding.executable, sid, false, false)?;
    let _config = open_checked(&binding.config, sid, true, false)?;
    let _state = open_checked(&binding.home, sid, true, true)?;
    Ok(())
}

/// WER exclusions alone do not disable LocalDumps. Fail closed for both
/// per-image/global LocalDumps and managed WER policy before plaintext exists.
pub fn enforce_no_core_dumps() -> Result<()> {
    let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let wer = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting";
    let excluded = machine.open_subkey_with_flags(
        format!(r"{wer}\ExcludedApplications"),
        KEY_READ | KEY_WOW64_64KEY,
    )?;
    if excluded.get_value::<u32, _>("zunder-guard.exe")? != 1 {
        return Err(refused("Windows Error Reporting exclusion is not enabled"));
    }
    for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        for path in [
            format!(r"{wer}\LocalDumps"),
            r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting".into(),
        ] {
            match RegKey::predef(hive).open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY) {
                Ok(_) => {
                    return Err(refused(
                        "managed WER or LocalDumps policy prevents service secret admission",
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(refused("could not verify Windows crash dump policy")),
            }
        }
    }
    Ok(())
}

fn protect(bytes: &[u8]) -> Result<Vec<u8>> {
    let provider = DataProtectionProvider::CreateOverloadExplicit(&HSTRING::from("LOCAL=machine"))
        .map_err(|_| refused("machine data protection unavailable"))?;
    let input = CryptographicBuffer::CreateFromByteArray(bytes)
        .map_err(|_| refused("credential buffer unavailable"))?;
    let encrypted = provider
        .ProtectAsync(&input)
        .and_then(|op| op.join())
        .map_err(|_| refused("machine credential protection failed"))?;
    let mut output = Array::new();
    CryptographicBuffer::CopyToByteArray(&encrypted, &mut output)
        .map_err(|_| refused("protected credential copy failed"))?;
    Ok(output.to_vec())
}
fn unprotect(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let provider = DataProtectionProvider::new()
        .map_err(|_| refused("machine data protection unavailable"))?;
    let input = CryptographicBuffer::CreateFromByteArray(bytes)
        .map_err(|_| refused("protected credential buffer unavailable"))?;
    let decrypted = provider
        .UnprotectAsync(&input)
        .and_then(|op| op.join())
        .map_err(|_| refused("machine credential decryption failed"))?;
    let mut output = Array::new();
    CryptographicBuffer::CopyToByteArray(&decrypted, &mut output)
        .map_err(|_| refused("credential copy failed"))?;
    let key = Zeroizing::new(output.to_vec());
    output.iter_mut().for_each(|byte| *byte = 0);
    Ok(key)
}

pub fn provision(binding: &ServiceBinding, key: &Zeroizing<Vec<u8>>, replace: bool) -> Result<()> {
    enforce_no_core_dumps()?;
    binding.validate()?;
    binding.check_key(key)?;
    let path = credential_path(binding)?;
    let (_, sid) = platform(binding)?;
    let existing = open_checked(&path, sid, false, false)?;
    if existing.metadata()?.len() != 0 && !replace {
        return Err(refused("service credential already exists"));
    }
    drop(existing);
    let mut payload = Zeroizing::new(binding.digest()?.into_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(key);
    let encrypted = protect(&payload)?;
    write_trusted(&path, sid, &encrypted, false, || Ok(()))?;
    Ok(())
}
pub fn read(binding: &ServiceBinding) -> Result<Zeroizing<Vec<u8>>> {
    enforce_no_core_dumps()?;
    verify_service_identity(binding)?;
    let (_, sid) = platform(binding)?;
    let mut file = open_checked(&credential_path(binding)?, sid, false, false)?;
    if file.metadata()?.len() > 16384 {
        return Err(refused("protected credential is oversized"));
    }
    let mut encrypted = Vec::new();
    file.read_to_end(&mut encrypted)?;
    let payload = unprotect(&encrypted)?;
    let newline = payload
        .iter()
        .position(|b| *b == b'\n')
        .ok_or_else(|| refused("credential binding missing"))?;
    if payload[..newline] != *binding.digest()?.as_bytes() {
        return Err(refused("credential belongs to another service binding"));
    }
    let key = Zeroizing::new(payload[newline + 1..].to_vec());
    binding.check_key(&key)?;
    Ok(key)
}
pub fn check(binding: &ServiceBinding) -> Result<()> {
    enforce_no_core_dumps()?;
    binding.validate()?;
    let (_, sid) = platform(binding)?;
    let file = open_checked(&credential_path(binding)?, sid, false, false)?;
    if file.metadata()?.len() == 0 {
        return Err(refused("service credential has not been provisioned"));
    }
    Ok(())
}
pub fn remove(binding: &ServiceBinding) -> Result<()> {
    require_stopped(binding)?;
    let (_, sid) = platform(binding)?;
    let path = credential_path(binding)?;
    let checked = open_checked(&path, sid, false, false)?;
    drop(checked);
    fs::remove_file(path)?;
    Ok(())
}

/// The owned Job handle is never inherited. Key delivery happens only after
/// this function returns; an assignment failure can leave only a keyless child.
pub fn contain_child(child: &mut std::process::Child) -> Result<win32job::Job> {
    let mut limits = win32job::ExtendedLimitInfo::new();
    limits.limit_kill_on_job_close();
    let job = win32job::Job::create_with_limit_info(&limits)
        .map_err(|_| refused("could not create service process containment"))?;
    if job.assign_process(child.as_raw_handle() as isize).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(refused(
            "could not contain service child; no key was delivered",
        ));
    }
    Ok(job)
}

use std::{
    process::Stdio,
    sync::{Arc, OnceLock, mpsc},
    time::{Duration, Instant},
};
use windows_service::{
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
static START: OnceLock<(ServiceBinding, PathBuf)> = OnceLock::new();

/// Ignore SCM's raw argument pointers. All arguments were parsed by the safe
/// CLI before dispatch; unlike define_windows_service!, no unsafe macro is needed.
extern "system" fn scm_entry(_count: u32, _arguments: *mut *mut u16) {
    if let Some((binding, path)) = START.get() {
        // SCM status is the authoritative result; no credential details logged.
        let _ = scm_session(binding, path);
    }
}

pub fn run(binding: &ServiceBinding, path: &Path) -> Result<()> {
    let (name, _) = platform(binding)?;
    START
        .set((binding.clone(), path.to_owned()))
        .map_err(|_| refused("service dispatcher already initialized"))?;
    service_dispatcher::start(name, scm_entry).map_err(|_| {
        refused("SCM dispatcher failed; run this command through its registered Windows service")
    })?;
    Ok(())
}

fn scm_session(binding: &ServiceBinding, path: &Path) -> Result<()> {
    let (name, _) = platform(binding)?;
    let (send, stop) = mpsc::channel();
    let stop_intent = Arc::new(super::lifecycle::StopIntent::default());
    let handler_intent = stop_intent.clone();
    let status = service_control_handler::register(name, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if handler_intent.accept_stop() {
                let _ = send.send(());
                ServiceControlHandlerResult::NoError
            } else {
                // ERROR_SERVICE_CANNOT_ACCEPT_CTRL: recovery/exit already
                // committed. Never acknowledge a stop we can no longer honor.
                ServiceControlHandlerResult::Other(1061)
            }
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(|_| refused("SCM control handler failed"))?;
    let reported_stopped = std::cell::Cell::new(false);
    let report = |state: ServiceState, failure: bool| -> Result<()> {
        // SCM closes the status context on STOPPED: never report it twice.
        if state == ServiceState::Stopped {
            reported_stopped.set(true);
        }
        let pending = matches!(
            state,
            ServiceState::StartPending | ServiceState::StopPending
        );
        status
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: if state == ServiceState::Running {
                    ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
                } else {
                    ServiceControlAccept::empty()
                },
                exit_code: if failure {
                    ServiceExitCode::ServiceSpecific(1)
                } else {
                    ServiceExitCode::Win32(0)
                },
                checkpoint: u32::from(pending),
                wait_hint: if pending {
                    Duration::from_secs(30)
                } else {
                    Duration::ZERO
                },
                process_id: None,
            })
            .map_err(|_| refused("SCM status update failed"))
    };
    let result = (|| {
        report(ServiceState::StartPending, false)?;
        let admitted = (|| {
            validate_paths(binding, path)?;
            enforce_no_core_dumps()?;
            verify_service_identity(binding)?;
            binding.validate_journal()?;
            check(binding)?;
            Ok(())
        })();
        if admitted.is_err() {
            // Admission failures are permanent until reviewed; report a stopped
            // service without recovery-triggering failure. No credential was read.
            // A nonzero stopped status is visible in SCM. The installed service
            // has non-crash failure actions disabled, so this never loops.
            report(ServiceState::Stopped, true)?;
            return admitted;
        }
        if stop_intent.is_stopping() {
            report(ServiceState::Stopped, false)?;
            return Ok(());
        }
        let mut child = binding
            .child_command(path)
            .env(
                "SystemRoot",
                registry_string(
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                    "SystemRoot",
                )?,
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let job = contain_child(&mut child)?;
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| refused("service child has no owned stdin"))?;
        let key = read(binding)?;
        if stop_intent.is_stopping() {
            drop(key);
            drop(input);
            drop(job);
            let _ = child.wait();
            report(ServiceState::Stopped, false)?;
            return Ok(());
        }
        input.write_all(&key)?;
        input.write_all(b"\n")?;
        input.flush()?;
        drop(key);
        report(ServiceState::Running, false)?;
        loop {
            if let Some(exit) = child.try_wait()? {
                drop(input);
                drop(job);
                use super::lifecycle::{ChildExit, ExitDisposition};
                let child_exit = if exit.success() {
                    ChildExit::Success
                } else if exit.code() == Some(75) {
                    ChildExit::Transient
                } else {
                    ChildExit::Failure
                };
                // These checks may overlap an incoming control. The final
                // decision below uses the handler's same mutex, not the queue.
                let admitted = child_exit == ChildExit::Transient
                    && binding.validate_journal().is_ok()
                    && check(binding).is_ok();
                let disposition = stop_intent.finish_child(child_exit, admitted, || {
                    // Job/key/pipe are gone. Hold the decision lock until this
                    // irreversible handoff; no accepted Stop can be overtaken.
                    std::process::exit(75);
                });
                let failed = matches!(
                    disposition,
                    ExitDisposition::Failed | ExitDisposition::RecoveryRequested
                );
                report(ServiceState::Stopped, failed)?;
                return if failed {
                    Err(refused(
                        "service child failed; inspect runtime readiness and admission",
                    ))
                } else {
                    Ok(())
                };
            }
            let _ = stop.recv_timeout(Duration::from_millis(200));
            if stop_intent.is_stopping() {
                report(ServiceState::StopPending, false)?;
                drop(input); // EOF reaches the same reader that consumed the key.
                let deadline = Instant::now() + Duration::from_secs(20);
                while child.try_wait()?.is_none() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(50));
                }
                drop(job); // Hard containment if graceful shutdown timed out.
                child.wait()?;
                report(ServiceState::Stopped, false)?;
                return Ok(());
            }
        }
    })();
    // Any I/O/decryption/spawn failure has dropped its Job and key buffers
    // before reporting permanent failure. Only explicit transient exit 75
    // above requests crash recovery; corrupt credentials must not loop.
    if result.is_err() && !reported_stopped.get() {
        report(ServiceState::Stopped, true)?;
    }
    result
}

/// The only Windows mainnet init exception is a pre-created protected machine
/// service layout; this creates config, never a journal or running service.
pub fn validate_setup(home: &Path, config: &Path, identity: &str) -> Result<()> {
    if identity.is_empty()
        || identity.len() > 80
        || !identity
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(refused("invalid service setup identity"));
    }
    enforce_no_core_dumps()?;
    let name = format!("ZunderGuard-{identity}");
    let (sid, _, _) = LookupAccountName(None::<&std::ffi::OsStr>, format!(r"NT SERVICE\{name}"))?;
    let sid = ConvertSidToStringSid(&sid)?
        .into_string()
        .map_err(|_| refused("invalid service SID"))?;
    let root = fs::canonicalize(machine_root()?.join(identity))?;
    if fs::canonicalize(home)? != root.join("runtime")
        || config.file_name() != Some(std::ffi::OsStr::new("guard.toml"))
        || fs::canonicalize(
            config
                .parent()
                .ok_or_else(|| refused("config parent missing"))?,
        )? != fs::canonicalize(home)?
    {
        return Err(refused("mainnet setup requires the protected service home"));
    }
    let _directory = open_checked(&root, &sid, false, true)?;
    let _runtime = open_checked(home, &sid, true, true)?;
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    if executable != fs::canonicalize(binary_root()?.join(identity).join("zunder-guard.exe"))? {
        return Err(refused(
            "service setup must run the verified machine installation",
        ));
    }
    let _image = open_checked(&executable, &sid, false, false)?;
    // An admin-only probe proves this caller can manage admission before a
    // hidden prompt is shown. It contains no credential and is removed at once.
    let probe = root.join(".provision-permission-check");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)?;
    drop(file);
    fs::remove_file(probe)?;
    Ok(())
}

/// Service-aware administrative reads retain the exact SID ACL boundary;
/// generic per-user config loading is not weakened for service management.
pub fn load_config(binding: &ServiceBinding) -> Result<crate::config::GuardConfig> {
    let (_, sid) = platform(binding)?;
    let mut file = open_checked(&binding.config, sid, true, false)?;
    if file.metadata()?.len() > 1024 * 1024 {
        return Err(refused("service config is oversized"));
    }
    let mut text = Zeroizing::new(String::new());
    file.read_to_string(&mut text)?;
    let mut config =
        crate::config::GuardConfig::parse(&text).map_err(|_| refused("invalid service config"))?;
    let base = binding
        .config
        .parent()
        .ok_or_else(|| refused("service config has no parent"))?;
    if config.state_dir.is_relative() {
        config.state_dir = base.join(&config.state_dir);
    }
    if let Some(directory) = config.emergency_dir.as_mut()
        && directory.is_relative()
    {
        *directory = base.join(&directory);
    }
    Ok(config)
}

pub fn validate_provision(binding: &ServiceBinding) -> Result<()> {
    enforce_no_core_dumps()?;
    binding.validate()?;
    admin_admission(binding)?;
    require_stopped(binding)
}

fn require_stopped(binding: &ServiceBinding) -> Result<()> {
    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let (name, _) = platform(binding)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| refused("cannot query SCM"))?;
    let service = manager
        .open_service(name, ServiceAccess::QUERY_STATUS)
        .map_err(|_| refused("cannot query registered service"))?;
    if service
        .query_status()
        .map_err(|_| refused("cannot read service status"))?
        .current_state
        != ServiceState::Stopped
    {
        return Err(refused(
            "stop the registered service before provisioning or deleting its credential",
        ));
    }
    Ok(())
}

fn admin_admission(binding: &ServiceBinding) -> Result<()> {
    if fs::canonicalize(std::env::current_exe()?)? != binding.executable {
        return Err(refused(
            "run management from the admitted machine executable",
        ));
    }
    let path = root(binding)?.join(".management-lock");
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    drop(file);
    fs::remove_file(path)?;
    Ok(())
}

pub fn validate_management_stopped(binding: &ServiceBinding) -> Result<()> {
    admin_admission(binding)?;
    require_stopped(binding)
}

fn write_trusted(
    path: &Path,
    sid: &str,
    bytes: &[u8],
    mutable: bool,
    before_write: impl FnOnce() -> Result<()>,
) -> Result<()> {
    use windows_permissions::{LocalBox, SecurityDescriptor, wrappers::SetSecurityInfo};
    let mut name = path.as_os_str().to_owned();
    name.push(".new");
    let temporary = PathBuf::from(name);
    let mut file = OpenOptions::new()
        .create_new(true)
        .access_mode(0xc00e0000)
        .share_mode(0)
        .custom_flags(0x00200000)
        .open(&temporary)?;
    let result = (|| {
        // The exact same file handle receives the DACL and payload. No key is
        // ever stored here: credentials use only this helper's ciphertext.
        let rights = if mutable { "0x1301bf" } else { "FR" };
        let descriptor: LocalBox<SecurityDescriptor> =
            format!("O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;{rights};;;{sid})").parse()?;
        SetSecurityInfo(
            &mut file,
            SE_FILE_OBJECT,
            SecurityInformation::Owner
                | SecurityInformation::Dacl
                | SecurityInformation::ProtectedDacl,
            descriptor.owner(),
            None,
            descriptor.dacl(),
            None,
        )?;
        before_write()?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(temporary);
        return Err(error.into());
    }
    Ok(())
}

pub fn write_binding(path: &Path, binding: &ServiceBinding) -> Result<()> {
    admin_admission(binding)?;
    require_stopped(binding)?;
    let (_, sid) = platform(binding)?;
    let bytes =
        serde_json::to_vec_pretty(binding).map_err(|_| refused("binding serialization failed"))?;
    write_trusted(path, sid, &bytes, false, || Ok(()))
}

pub fn write_config(
    binding: &ServiceBinding,
    expected: &crate::config::GuardConfig,
    next: &crate::config::GuardConfig,
) -> Result<()> {
    admin_admission(binding)?;
    let (_, sid) = platform(binding)?;
    next.validate()
        .map_err(|_| refused("invalid next service config"))?;
    let bytes = Zeroizing::new(
        next.to_toml()
            .map_err(|_| refused("config serialization failed"))?
            .into_bytes(),
    );
    write_trusted(&binding.config, sid, &bytes, true, || {
        if load_config(binding)? != *expected {
            return Err(refused(
                "service config changed concurrently; retry management operation",
            ));
        }
        Ok(())
    })
}

/// Retain the service/admin ACL during normal automatic licence renewal. The
/// usual per-user file helper would grant only the virtual account access,
/// preventing the administrator from managing the service after that renewal.
/// Ordinary users retain the existing owner-only implementation unchanged.
pub fn create_config_update(path: &Path, temporary: &Path) -> std::io::Result<File> {
    let sid = current_sid().map_err(std::io::Error::other)?;
    if !sid.starts_with("S-1-5-80-") {
        return zunder_venue::owner_only::create(temporary);
    }
    let create = || -> Result<File> {
        use windows_permissions::{LocalBox, SecurityDescriptor, wrappers::SetSecurityInfo};
        let config = fs::canonicalize(path)?;
        let directory = config
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| refused("service config layout is invalid"))?;
        let binding = super::load_binding(&directory.join("binding.json"))?;
        verify_service_identity(&binding)?;
        if config != binding.config {
            return Err(refused("renewal is outside the admitted config"));
        }
        let mut expected = path.as_os_str().to_owned();
        expected.push(".new");
        if temporary.as_os_str() != expected {
            return Err(refused("renewal temporary path differs"));
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .access_mode(0xc0060000)
            .share_mode(7)
            .custom_flags(0x00200000)
            .open(temporary)?;
        let descriptor: LocalBox<SecurityDescriptor> =
            format!("O:{sid}G:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;{sid})").parse()?;
        if let Err(error) = SetSecurityInfo(
            &mut file,
            SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
            None,
            None,
            descriptor.dacl(),
            None,
        ) {
            drop(file);
            let _ = fs::remove_file(temporary);
            return Err(error.into());
        }
        Ok(file)
    };
    create().map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn synthetic_machine_protection_round_trip() {
        let plaintext = Zeroizing::new(b"synthetic-only-not-a-wallet-credential".to_vec());
        let ciphertext = protect(&plaintext).expect("machine protect");
        assert!(
            !ciphertext
                .windows(plaintext.len())
                .any(|window| window == plaintext.as_slice())
        );
        assert_eq!(
            *unprotect(&ciphertext).expect("machine unprotect"),
            *plaintext
        );
        assert!(unprotect(b"invalid protected payload").is_err());
    }

    // Invoked in child processes below. It cannot start Guard or contact a venue.
    #[test]
    fn synthetic_lifecycle_probe() {
        let Ok(mode) = std::env::var("ZUNDER_SYNTHETIC_SERVICE_PROBE") else {
            return;
        };
        if mode == "descendant" {
            std::thread::sleep(Duration::from_secs(120));
            return;
        }
        let mut input = std::io::stdin();
        let mut go = [0_u8; 1];
        input.read_exact(&mut go).expect("contained before go");
        if mode == "tree" {
            let mut descendant = Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "service::windows::tests::synthetic_lifecycle_probe",
                ])
                .env("ZUNDER_SYNTHETIC_SERVICE_PROBE", "descendant")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("descendant");
            fs::write(
                std::env::var_os("ZUNDER_SYNTHETIC_SERVICE_PID_FILE").expect("pid file"),
                descendant.id().to_string(),
            )
            .expect("pid receipt");
            let _ = descendant.wait();
        } else {
            assert_eq!(
                super::super::await_parent_close(&mut input),
                "supervisor closed standard input"
            );
        }
    }

    fn probe(mode: &str, receipt: &Path) -> std::process::Child {
        Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "service::windows::tests::synthetic_lifecycle_probe",
            ])
            .env("ZUNDER_SYNTHETIC_SERVICE_PROBE", mode)
            .env("ZUNDER_SYNTHETIC_SERVICE_PID_FILE", receipt)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("probe")
    }
    fn wait_exit(child: &mut std::process::Child) {
        let until = Instant::now() + Duration::from_secs(10);
        while child.try_wait().expect("child status").is_none() {
            assert!(Instant::now() < until, "contained child did not exit");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    #[test]
    fn native_job_close_kills_child_and_descendant_and_eof_stops_child() {
        let temp = crate::testdir::TestDir::new("service-process-tree");
        let receipt = temp.path().join("descendant.pid");
        let mut child = probe("tree", &receipt);
        let job = contain_child(&mut child).expect("contain before any input");
        let mut pipe = child.stdin.take().expect("pipe");
        pipe.write_all(b"x").expect("go");
        let until = Instant::now() + Duration::from_secs(10);
        while !receipt.exists() {
            assert!(Instant::now() < until, "descendant did not start");
            std::thread::sleep(Duration::from_millis(25));
        }
        let pid: u32 = fs::read_to_string(&receipt)
            .expect("pid")
            .parse()
            .expect("numeric pid");
        drop(job);
        wait_exit(&mut child);
        drop(pipe);
        let powershell = PathBuf::from(
            registry_string(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "SystemRoot",
            )
            .expect("system root"),
        )
        .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
        let result = Command::new(powershell).args(["-NoProfile", "-NonInteractive", "-Command", &format!("if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 1 }} else {{ exit 0 }}")]).status().expect("descendant status");
        assert!(
            result.success(),
            "descendant survived closing the sole Job handle"
        );
        let mut child = probe("eof", &receipt);
        let job = contain_child(&mut child).expect("contain EOF probe");
        let mut pipe = child.stdin.take().expect("pipe");
        pipe.write_all(b"x").expect("go");
        drop(pipe);
        wait_exit(&mut child);
        assert!(child.wait().expect("wait").success());
        drop(job);
    }

    #[test]
    #[ignore = "requires elevated native Windows CI and symlink privilege"]
    fn native_protected_file_acl_round_trip_rejects_reparse_and_other_sid() {
        let temp = crate::testdir::TestDir::new("service-acl");
        let file = temp.path().join("binding.json");
        let sid = "S-1-5-80-1-2-3-4-5";
        write_trusted(&file, sid, b"public synthetic metadata", false, || Ok(()))
            .expect("protected file");
        assert!(open_checked(&file, sid, false, false).is_ok());
        assert!(open_checked(&file, "S-1-5-80-6-7-8-9-10", false, false).is_err());
        let link = temp.path().join("link.json");
        std::os::windows::fs::symlink_file(&file, &link).expect("native CI must permit symlinks");
        assert!(open_checked(&link, sid, false, false).is_err());
    }
}
