// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! `zunder-guard init`: the setup, interactive by default
//! (`deploy/guard/README.md`, "The CLI contract").
//!
//! On a terminal:
//!
//! 1. the rules, from `--rules zr1_…` or the defaults, shown for the
//!    person to keep or edit value by value (each change checked against
//!    the policy's bounds);
//! 2. the account's address;
//! 3. the mode: paper (the default; it asks which network's account to
//!    read), testnet, or mainnet typed in full, then the account address
//!    again and the equity cap (the mainnet guards; no rule looser than the
//!    mainnet ceiling);
//! 4. for testnet or mainnet, unless `--no-key`: the API wallet's key,
//!    typed without echo (the binary switches echo off itself), never shown,
//!    logged or written in plain text by Guard; checked with the venue
//!    (`userRole`) to be an API wallet of the account, which cannot
//!    withdraw;
//! 5. a new client key for the bot, shown once; only its address is kept;
//! 6. a pairing code for the browser monitor, shown once; only its hash is
//!    kept;
//! 7. the config, checked;
//! 8. the key, through a [`SecretStore`] (`systemd-creds` where available;
//!    on Windows the Credential Manager, encrypted with DPAPI for this
//!    user; otherwise a file readable by its owner only, with a warning),
//!    then the config file;
//! 9. the risk journal for paper or testnet at the account's equity now
//!    (setting up is the person's decision to start one); mainnet's waits
//!    for the person's confirmation (`journal-init`);
//! 10. the next steps.
//!
//! Without a terminal, init refuses unless `--non-interactive` is given:
//! then every answer comes from the flags (or `ZUNDER_GUARD_*`) and the key
//! from standard input.

use std::{
    fs,
    io::{self, BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
};

use rust_decimal::{Decimal, dec};
use serde_json::Value;
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use zeroize::Zeroizing;
use zunder_guard_core::{
    account::check_api_wallet_role,
    auth::AuthConfig,
    policy::{Markets, Policy, StopPolicy},
    sign::{Address, GuardKey},
};

use crate::{
    config::{GuardConfig, GuardMode, GuardNetwork},
    rules,
};

#[derive(Debug, Error)]
pub enum InitError {
    #[error("{0}")]
    Refused(String),
    #[error("input ended")]
    Eof,
    #[error("{0}")]
    Io(String),
}

fn refused<T>(text: impl Into<String>) -> Result<T, InitError> {
    Err(InitError::Refused(text.into()))
}

/// How init talks to the person.
pub trait Prompter {
    fn say(&mut self, text: &str);
    fn ask(&mut self, question: &str) -> Result<String, InitError>;
    /// Read a secret without echoing it.
    fn ask_secret(&mut self, question: &str) -> Result<Zeroizing<String>, InitError>;
}

/// The terminal: standard input and output; secrets with echo off.
pub struct TtyPrompter;

impl TtyPrompter {
    /// Refuse when standard input is not a terminal.
    pub fn new() -> Result<Self, InitError> {
        if !io::stdin().is_terminal() {
            return refused(
                "zunder-guard init is interactive: run it on a terminal, or pass --non-interactive with the key on standard input",
            );
        }
        Ok(Self)
    }
}

impl Prompter for TtyPrompter {
    fn say(&mut self, text: &str) {
        let mut out = io::stdout().lock();
        writeln!(out, "{text}").ok();
        out.flush().ok();
    }

    fn ask(&mut self, question: &str) -> Result<String, InitError> {
        {
            let mut out = io::stdout().lock();
            write!(out, "{question} ").ok();
            out.flush().ok();
        }
        let mut line = String::new();
        let read = io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|error| InitError::Io(error.to_string()))?;
        if read == 0 {
            return Err(InitError::Eof);
        }
        Ok(line.trim().to_owned())
    }

    fn ask_secret(&mut self, question: &str) -> Result<Zeroizing<String>, InitError> {
        // On the terminal itself, with echo switched off by the binary
        // (termios, through `rpassword`): the image has no `stty`. The
        // copy rpassword returns is wiped here.
        let typed = Zeroizing::new(
            rpassword::prompt_password(format!("{question} "))
                .map_err(|error| InitError::Io(error.to_string()))?,
        );
        let trimmed = typed.trim();
        if trimmed.is_empty() {
            return Err(InitError::Eof);
        }
        if trimmed.len() > MAX_SECRET {
            return refused("the key is too long");
        }
        let mut out = Zeroizing::new(String::with_capacity(MAX_SECRET));
        out.push_str(trimmed);
        Ok(out)
    }
}

/// Most bytes of a secret line: a key is 66 characters with `0x`.
const MAX_SECRET: usize = 256;

/// Read one line (or everything up to the end) into a fixed, wiped buffer:
/// never grown, never copied but once into the result, which is wiped too.
pub fn read_secret_line<R: io::Read + ?Sized>(
    reader: &mut R,
) -> Result<Zeroizing<String>, InitError> {
    let mut buffer = Zeroizing::new([0u8; MAX_SECRET]);
    let mut filled = 0;
    // The last byte read is wiped too.
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match reader.read(byte.as_mut()) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                let Some(slot) = buffer.get_mut(filled) else {
                    return Err(InitError::Refused("the key is too long".into()));
                };
                *slot = byte[0];
                filled += 1;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(InitError::Io(error.to_string())),
        }
    }
    if filled == 0 {
        return Err(InitError::Eof);
    }
    let text = std::str::from_utf8(buffer.get(..filled).unwrap_or_default())
        .map_err(|_| InitError::Refused("the key is not text".into()))?;
    let mut out = Zeroizing::new(String::with_capacity(MAX_SECRET));
    out.push_str(text.trim());
    Ok(out)
}

/// What init asks the venue: who a key is (`userRole`), and the account's
/// equity (to start the risk journal).
pub trait Venue {
    fn user_role(
        &self,
        network: GuardNetwork,
        key: Address,
    ) -> impl std::future::Future<Output = Result<Value, String>>;

    fn equity(
        &self,
        network: GuardNetwork,
        account: Address,
    ) -> impl std::future::Future<Output = Result<Decimal, String>>;
}

/// Where the API wallet key is kept, and how `run` gets it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSecret {
    pub how: String,
    pub location: PathBuf,
    pub warning: Option<String>,
    /// The shell command that pipes the key into `zunder-guard run
    /// --key-stdin`.
    pub pipe: String,
}

pub trait SecretStore {
    fn store(&self, secret: &str) -> Result<StoredSecret, String>;
}

/// The name of the stored credential.
pub const CREDENTIAL_NAME: &str = "zunder-guard-key";

/// `systemd-creds encrypt`: encrypted at rest with the machine's key (and
/// its TPM where there is one), readable only by the service it is loaded
/// into.
pub struct SystemdCreds {
    pub dir: PathBuf,
    /// Replace a stored credential (`init --force`); refused otherwise.
    pub replace: bool,
}

impl SystemdCreds {
    /// Available when `systemd-creds` runs and `dir` is writable.
    pub fn available(dir: &Path) -> bool {
        let runs = Command::new("systemd-creds")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        runs && fs::create_dir_all(dir).is_ok()
            && fs::metadata(dir).is_ok_and(|meta| !meta.permissions().readonly())
    }
}

impl SecretStore for SystemdCreds {
    fn store(&self, secret: &str) -> Result<StoredSecret, String> {
        let location = self.dir.join(CREDENTIAL_NAME);
        if location.exists() && !self.replace {
            return Err(format!(
                "{} exists (another Guard's key?); pass --force to replace it",
                location.display()
            ));
        }
        let mut child = Command::new("systemd-creds")
            .arg("encrypt")
            .arg(format!("--name={CREDENTIAL_NAME}"))
            .arg("-")
            .arg(&location)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| error.to_string())?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(secret.as_bytes())
                .map_err(|error| error.to_string())?;
        }
        let status = child.wait().map_err(|error| error.to_string())?;
        if !status.success() {
            return Err("systemd-creds encrypt failed".into());
        }
        Ok(StoredSecret {
            how: "systemd-creds".into(),
            pipe: format!(
                "systemd-creds decrypt --name={CREDENTIAL_NAME} {} -",
                location.display()
            ),
            location,
            warning: None,
        })
    }
}

/// A file only its owner can read (0600), created new. The fallback, with
/// a warning: the key lies in plain text on the disk.
pub struct OwnerOnlyFile {
    pub path: PathBuf,
    /// Replace a stored key (`init --force`); refused otherwise.
    pub replace: bool,
}

impl SecretStore for OwnerOnlyFile {
    fn store(&self, secret: &str) -> Result<StoredSecret, String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        if self.replace && fs::symlink_metadata(&self.path).is_ok() {
            fs::remove_file(&self.path).map_err(|error| error.to_string())?;
        }
        let mut file = zunder_venue::owner_only::create(&self.path)
            .map_err(|error| format!("{}: {error}", self.path.display()))?;
        file.write_all(secret.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(StoredSecret {
            how: "file (owner only)".into(),
            location: self.path.clone(),
            warning: Some(format!(
                "no encrypted key store here: the API wallet key is in {} in plain text, readable by its owner only. Run Guard as a dedicated user that owns this file, and keep the account's balance to what you are willing to risk.",
                self.path.display()
            )),
            pipe: format!("cat {}", self.path.display()),
        })
    }
}

/// The service name of Guard's entries in the Windows Credential Manager.
pub const WINDOWS_CREDENTIAL_SERVICE: &str = "zunder-guard";

/// Windows: the Credential Manager. The key is encrypted with DPAPI for
/// this user and never lies on disk in plain text; `run` reads it back
/// itself (no shell pipe on Windows), keyed by the configuration's folder,
/// so two Guards in two folders keep two keys.
///
/// `keyring` stores generic credentials with `CRED_PERSIST_ENTERPRISE` and
/// offers no other choice: on a domain machine with a roaming profile the
/// entry travels with the profile to the other machines the user signs in
/// to (still encrypted for that user). On such machines pipe the key with
/// `--key-stdin` instead. `keyring` converts the key to UTF-16 for the
/// Windows call in a buffer it does not wipe; the copies held here are
/// wiped ([`Zeroizing`]).
pub struct CredentialManager {
    /// The configuration's folder, absolute: the entry's user name.
    pub target: String,
    /// Replace a stored key (`init --force`); refused otherwise.
    pub replace: bool,
}

#[cfg(windows)]
impl SecretStore for CredentialManager {
    fn store(&self, secret: &str) -> Result<StoredSecret, String> {
        let entry = keyring::Entry::new(WINDOWS_CREDENTIAL_SERVICE, &self.target)
            .map_err(|error| format!("Credential Manager: {error}"))?;
        // Only a missing entry lets init write without --force: an entry,
        // or an error that hides whether there is one, stops it.
        if !self.replace {
            match entry.get_password().map(Zeroizing::new) {
                Err(keyring::Error::NoEntry) => {}
                Ok(_) => {
                    return Err(format!(
                        "the Credential Manager already holds a key for {} (another Guard's?); pass --force to replace it",
                        self.target
                    ));
                }
                Err(error) => return Err(format!("Credential Manager: {error}")),
            }
        }
        entry
            .set_password(secret)
            .map_err(|error| format!("Credential Manager: {error}"))?;
        Ok(StoredSecret {
            how: "Windows Credential Manager (DPAPI, this user)".into(),
            location: PathBuf::from(format!("{WINDOWS_CREDENTIAL_SERVICE}:{}", self.target)),
            warning: None,
            pipe: String::new(),
        })
    }
}

#[cfg(not(windows))]
impl SecretStore for CredentialManager {
    fn store(&self, _secret: &str) -> Result<StoredSecret, String> {
        Err("the Windows Credential Manager exists on Windows only".into())
    }
}

/// Windows: the key `init` stored for the configuration in `target`, if
/// any. Wiped when dropped.
#[cfg(windows)]
pub fn stored_windows_key(target: &str) -> Result<Option<Zeroizing<String>>, String> {
    let entry = keyring::Entry::new(WINDOWS_CREDENTIAL_SERVICE, target)
        .map_err(|error| format!("Credential Manager: {error}"))?;
    match entry.get_password() {
        Ok(key) => Ok(Some(Zeroizing::new(key))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!("Credential Manager: {error}")),
    }
}

/// What init is given on the command line (or in `ZUNDER_GUARD_*`).
#[derive(Debug, Clone, Default)]
pub struct InitOptions {
    pub config: PathBuf,
    /// Written into the config; relative to the config file's directory.
    pub state_dir: PathBuf,
    pub rules: Option<String>,
    pub non_interactive: bool,
    pub account: Option<String>,
    /// Paper mode: the network of the account it reads. A sending mode's
    /// own network otherwise (must agree when given).
    pub network: Option<GuardNetwork>,
    pub mode: Option<GuardMode>,
    /// Mainnet: the account address again, the person's confirmation.
    pub confirm_mainnet: Option<String>,
    pub equity_cap: Option<String>,
    /// Set nothing up for the key (the installer checks and stores it
    /// itself, through `key check`).
    pub no_key: bool,
    pub listen: Option<String>,
    /// The config's `ip_share` (1 when not given).
    pub ip_share: Option<rust_decimal::Decimal>,
    pub force: bool,
    /// Write the bot's client key to this new file (owner-only) instead of
    /// showing it.
    pub client_key_out: Option<PathBuf>,
    /// Refuse mainnet with this reason, before anything is written (the
    /// installer passes it where mainnet cannot be set up safely).
    pub refuse_mainnet: Option<String>,
    /// A licence key for the account, checked before anything is written.
    pub licence: Option<String>,
    /// What licences are checked against; `None`: Orcastrate's key built
    /// in (tests give their own).
    pub licence_public_key: Option<[u8; 32]>,
}

/// The `ip_share` of the config at `path`, if one exists and names one
/// (read leniently: it is about to be replaced).
fn previous_ip_share(path: &Path) -> Option<Decimal> {
    let text = fs::read_to_string(path).ok()?;
    let table: toml::Table = toml::from_str(&text).ok()?;
    table.get("ip_share")?.as_str()?.trim().parse().ok()
}

/// Write a client key to a new file only its owner can read and write
/// (`0600`, refused if the file exists): for a bot or an agent kit that
/// reads its key from a file, so the key never shows on a terminal.
pub fn write_client_key(path: &Path, key_hex: &str) -> Result<(), String> {
    let mut file = zunder_venue::owner_only::create(path).map_err(|error| {
        format!(
            "{}: {error} (an existing file is never replaced)",
            path.display()
        )
    })?;
    file.write_all(key_hex.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("writing {}: {error}", path.display()))
}

/// What init produced, for the caller and the tests. The secrets shown
/// once are not in it.
#[derive(Debug, Clone)]
pub struct InitOutcome {
    pub config: GuardConfig,
    pub stored: Option<StoredSecret>,
    pub mode: String,
}

/// Fresh randomness from the operating system.
pub fn os_random(buffer: &mut [u8]) -> Result<(), String> {
    getrandom::fill(buffer).map_err(|error| error.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `0x` and the hex digits of secret `bytes`, written straight into a
/// string that is wiped when dropped (no copy left behind).
pub fn secret_hex(bytes: &[u8]) -> Zeroizing<String> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = Zeroizing::new(String::with_capacity(2 + 2 * bytes.len()));
    out.push_str("0x");
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// The nine rules, readable.
pub fn describe(policy: &Policy) -> Vec<String> {
    let pct = |fraction: Decimal| format!("{}%", (fraction * dec!(100)).normalize());
    vec![
        format!(
            "  max leverage            {}x",
            policy.max_leverage.normalize()
        ),
        format!(
            "  max loss at the stop    {} of equity per trade",
            pct(policy.max_loss_at_stop)
        ),
        format!(
            "  stop                    required; without one: {}",
            match policy.stop {
                StopPolicy::Attach => format!("attach at {}", pct(policy.default_stop_distance)),
                StopPolicy::Refuse => "refuse".to_owned(),
            }
        ),
        format!(
            "  min liquidation distance {}",
            pct(policy.min_liquidation_distance)
        ),
        format!(
            "  max position            {} of equity",
            pct(policy.max_position_of_account)
        ),
        format!(
            "  max open risk           {} of equity",
            pct(policy.max_open_risk)
        ),
        format!("  daily loss stop         {}", pct(policy.daily_loss_stop)),
        format!("  drawdown halt           {}", pct(policy.drawdown_halt)),
        format!(
            "  markets                 {}",
            match &policy.markets {
                Markets::All => "all".to_owned(),
                Markets::Only(coins) => coins.iter().cloned().collect::<Vec<_>>().join(", "),
            }
        ),
    ]
}

/// Edit the policy value by value. An empty answer keeps a value; every
/// change is checked against the bounds and asked again when refused.
fn edit_policy(prompter: &mut dyn Prompter, mut policy: Policy) -> Result<Policy, InitError> {
    type Setter = fn(&mut Policy, &str) -> Result<(), String>;
    fn percent(text: &str) -> Result<Decimal, String> {
        let text = text.trim().trim_end_matches('%');
        Decimal::from_str(text)
            .map(|value| value / dec!(100))
            .map_err(|_| format!("`{text}` is not a number"))
    }
    let fields: [(&str, Setter); 10] = [
        ("max leverage (x)", |p, t| {
            p.max_leverage = Decimal::from_str(t.trim().trim_end_matches('x'))
                .map_err(|_| "not a number".to_owned())?;
            Ok(())
        }),
        ("max loss at the stop (%)", |p, t| {
            p.max_loss_at_stop = percent(t)?;
            Ok(())
        }),
        ("without a stop: attach or refuse", |p, t| {
            p.stop = match t.trim() {
                "attach" => StopPolicy::Attach,
                "refuse" => StopPolicy::Refuse,
                other => return Err(format!("`{other}`: attach or refuse")),
            };
            Ok(())
        }),
        ("default stop distance (%)", |p, t| {
            p.default_stop_distance = percent(t)?;
            Ok(())
        }),
        ("min liquidation distance (%)", |p, t| {
            p.min_liquidation_distance = percent(t)?;
            Ok(())
        }),
        ("max position (% of equity)", |p, t| {
            p.max_position_of_account = percent(t)?;
            Ok(())
        }),
        ("max open risk (%)", |p, t| {
            p.max_open_risk = percent(t)?;
            Ok(())
        }),
        ("daily loss stop (%)", |p, t| {
            p.daily_loss_stop = percent(t)?;
            Ok(())
        }),
        ("drawdown halt (%)", |p, t| {
            p.drawdown_halt = percent(t)?;
            Ok(())
        }),
        ("markets: all, or coins separated by commas", |p, t| {
            p.markets = if t.trim() == "all" {
                Markets::All
            } else {
                Markets::Only(
                    t.split(',')
                        .map(|coin| coin.trim().to_owned())
                        .filter(|c| !c.is_empty())
                        .collect(),
                )
            };
            Ok(())
        }),
    ];
    for (label, set) in fields {
        let mut attempts = 0;
        loop {
            let answer = prompter.ask(&format!("{label} (empty keeps it):"))?;
            if answer.is_empty() {
                break;
            }
            let mut changed = policy.clone();
            let result = set(&mut changed, &answer)
                .and_then(|()| changed.validate().map_err(|error| error.to_string()));
            match result {
                Ok(()) => {
                    policy = changed;
                    break;
                }
                Err(error) => {
                    attempts += 1;
                    prompter.say(&format!("  refused: {error}"));
                    if attempts >= 5 {
                        return refused("too many refused values");
                    }
                }
            }
        }
    }
    Ok(policy)
}

/// Run the setup.
pub async fn init(
    options: &InitOptions,
    prompter: &mut dyn Prompter,
    key_input: Option<&mut dyn io::Read>,
    venue: &impl Venue,
    store: &dyn SecretStore,
    random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>,
) -> Result<InitOutcome, InitError> {
    let interactive = !options.non_interactive;
    if options.config.exists() && !options.force {
        return refused(format!(
            "{} exists; pass --force to replace it (the old client keys stop working; the journal is kept)",
            options.config.display()
        ));
    }

    // 1. The rules.
    let mut policy = match &options.rules {
        Some(code) => rules::decode(code, &Policy::default())
            .map_err(|error| InitError::Refused(format!("the rules code is refused: {error}")))?,
        None => Policy::default(),
    };
    prompter.say(&format!(
        "Rules{}:",
        if options.rules.is_some() {
            " from the code"
        } else {
            " (defaults)"
        }
    ));
    for line in describe(&policy) {
        prompter.say(&line);
    }
    if interactive {
        let keep = prompter.ask("Keep these? [Y/edit]")?;
        if keep.eq_ignore_ascii_case("edit") || keep.eq_ignore_ascii_case("e") {
            policy = edit_policy(prompter, policy)?;
            prompter.say("Rules now:");
            for line in describe(&policy) {
                prompter.say(&line);
            }
        }
    }

    // 2. The account.
    let account_text = match (&options.account, interactive) {
        (Some(account), _) => account.clone(),
        (None, true) => prompter.ask("Hyperliquid account address (your main wallet's, 0x…):")?,
        (None, false) => return refused("--account is required with --non-interactive"),
    };
    let account = Address::from_hex(&account_text)
        .ok_or_else(|| InitError::Refused("the account must be 0x and 40 hex digits".into()))?;
    // A licence key, checked for the account before anything is asked or
    // written.
    let licence_key = match &options.licence {
        Some(key) => {
            let public = options
                .licence_public_key
                .or(zunder_guard_core::licence::LICENCE_PUBLIC_KEY);
            let now = crate::guard::Clock::now_ms(&crate::guard::SystemClock) as i64;
            crate::licence_life::check_key(key.trim(), public.as_ref(), account, now).map_err(
                |error| InitError::Refused(format!("the licence key is refused: {error}")),
            )?;
            Some(key.trim().to_owned())
        }
        None => None,
    };

    // 3. The mode. Mainnet is typed in full, then the account again.
    let mode = match (options.mode, interactive) {
        (Some(mode), _) => mode,
        (None, true) => {
            let answer = prompter.ask(
                "Mode: paper (judges, sends nothing), testnet, or mainnet (type it in full) [paper]:",
            )?;
            match answer.as_str() {
                "" | "paper" => GuardMode::Paper,
                "testnet" => GuardMode::Testnet,
                "mainnet" => GuardMode::Mainnet,
                other => return refused(format!("`{other}` is not paper, testnet or mainnet")),
            }
        }
        (None, false) => GuardMode::Paper,
    };
    if mode == GuardMode::Mainnet
        && let Some(reason) = &options.refuse_mainnet
    {
        return refused(format!("{reason}. Nothing was written."));
    }
    let network = match (mode.network(), options.network) {
        (Some(sends_to), Some(given)) if sends_to != given => {
            return refused(format!(
                "mode {} sends on {}, not {}",
                mode.name(),
                sends_to.name(),
                given.name()
            ));
        }
        (Some(sends_to), _) => sends_to,
        (None, Some(given)) => given,
        // Paper reads the account where it lives; mainnet's prices are the
        // real ones.
        (None, None) if interactive => {
            match prompter
                .ask("Paper mode reads which network's account: mainnet or testnet [mainnet]:")?
                .as_str()
            {
                "" | "mainnet" => GuardNetwork::Mainnet,
                "testnet" => GuardNetwork::Testnet,
                other => return refused(format!("`{other}` is not mainnet or testnet")),
            }
        }
        (None, None) => GuardNetwork::Mainnet,
    };
    if mode == GuardMode::Mainnet {
        // The person's explicit act: the account again, typed or given.
        let again = match (&options.confirm_mainnet, interactive) {
            (Some(confirm), _) => confirm.clone(),
            (None, true) => prompter
                .ask("Mainnet trades real money. Type the account address again to confirm:")?,
            (None, false) => {
                return refused("mainnet needs --confirm-mainnet with the account address");
            }
        };
        if Address::from_hex(&again) != Some(account) {
            return refused("the confirmation does not name the account: mainnet not set up");
        }
        let cap_text = match (&options.equity_cap, interactive) {
            (Some(cap), _) => cap.clone(),
            (None, true) => {
                prompter.ask("The most equity Guard sizes from, in USDC (at most 2500):")?
            }
            (None, false) => return refused("mainnet needs --equity-cap"),
        };
        let cap = Decimal::from_str(cap_text.trim())
            .map_err(|_| InitError::Refused(format!("`{cap_text}` is not a number")))?;
        policy.max_trading_equity_usd = Some(cap);
        policy
            .validate()
            .map_err(|error| InitError::Refused(error.to_string()))?;
        if let Err(field) = policy.within_mainnet_ceiling() {
            return refused(format!(
                "on mainnet the rules may not be looser than the mainnet ceiling (Zunder's default risk frame and Guard's pinned limits): {field} is"
            ));
        }
    }

    // 4. The API wallet key, for a sending mode: never shown; checked with
    // the venue. Mainnet's is always read once, to check it and record its
    // address (a mainnet config names its API wallet), and never stored:
    // `run` takes it on standard input at every start. `--no-key` only
    // means "do not store it" there.
    let mainnet = mode == GuardMode::Mainnet;
    let secret: Option<Zeroizing<String>> = if mode == GuardMode::Paper
        || (options.no_key && !mainnet)
    {
        None
    } else {
        Some(match key_input {
            Some(reader) => read_secret_line(reader)?,
            None if interactive => {
                prompter.ask_secret("API wallet private key (not shown while typing):")?
            }
            None if mainnet => {
                return refused(
                    "mainnet: the key comes once on standard input (--key-stdin) to be checked with the venue and to record its address; it is never stored",
                );
            }
            None => {
                return refused(
                    "with --non-interactive the key comes on standard input (--key-stdin), or pass --no-key",
                );
            }
        })
    };
    let api_wallet = match &secret {
        Some(secret) => {
            let key = GuardKey::from_hex(secret).map_err(|_| {
                InitError::Refused(
                    "that is not a private key: 64 hex digits, optionally with 0x".into(),
                )
            })?;
            let api_wallet = key.address();
            drop(key);
            let role = venue
                .user_role(network, api_wallet)
                .await
                .map_err(|error| {
                    InitError::Refused(format!("the venue could not be asked: {error}"))
                })?;
            check_api_wallet_role(&role, api_wallet, account).map_err(InitError::Refused)?;
            prompter.say(&format!(
                "Checked with Hyperliquid {}: {api_wallet} is an API wallet of {account}; it can trade and cannot withdraw.",
                network.name()
            ));
            Some(api_wallet)
        }
        None => None,
    };

    // 5. The client key, shown once.
    let mut client_secret = Zeroizing::new([0u8; 32]);
    let client = loop {
        random(client_secret.as_mut()).map_err(InitError::Io)?;
        if let Ok(client) = GuardKey::from_bytes(&client_secret) {
            break client;
        }
    };
    let client_hex = secret_hex(client_secret.as_ref());
    // The client key file, when asked for, before anything is written: a
    // config never names a client whose key went nowhere.
    if let Some(path) = &options.client_key_out {
        write_client_key(path, client_hex.as_str()).map_err(InitError::Io)?;
    }

    // 6. The pairing code, shown once.
    let (pairing_code, pairing_sha3) = pairing(random)?;

    // 7. The config, checked now and written after the key is stored: a
    // config never names a client whose setup did not finish.
    let config = GuardConfig {
        network: Some(network),
        mode,
        account: Some(account.to_hex()),
        api_wallet: api_wallet.map(|wallet| wallet.to_hex()),
        allow_mainnet: mode == GuardMode::Mainnet,
        listen: options
            .listen
            .clone()
            .unwrap_or_else(|| GuardConfig::default().listen),
        state_dir: options.state_dir.clone(),
        // A replaced config keeps its share unless a new one is given: a
        // Guard reconfigured on a shared machine must not take the whole
        // address back.
        ip_share: options
            .ip_share
            .or_else(|| previous_ip_share(&options.config))
            .unwrap_or(Decimal::ONE),
        pairing_sha3: Some(pairing_sha3),
        auth: AuthConfig {
            clients: vec![client.address().to_hex()],
            ..AuthConfig::default()
        },
        policy,
        licence: licence_key,
        ..GuardConfig::default()
    };
    config
        .validate()
        .map_err(|error| InitError::Refused(error.to_string()))?;
    let text = config
        .to_toml()
        .map_err(|error| InitError::Refused(error.to_string()))?;

    // 8. The key, through the store (never mainnet's, never with
    // `--no-key`), then the config file.
    let stored = match secret {
        Some(secret) if !mainnet && !options.no_key => {
            Some(store.store(&secret).map_err(|error| {
                InitError::Refused(format!("the API wallet key could not be stored: {error}"))
            })?)
        }
        _ => None,
    };
    if let Some(parent) = options.config.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| InitError::Io(error.to_string()))?;
    }
    let mut temporary = options.config.as_os_str().to_owned();
    temporary.push(".new");
    let temporary = PathBuf::from(temporary);
    let mut file = zunder_venue::owner_only::create(&temporary)
        .map_err(|error| InitError::Io(error.to_string()))?;
    let written = (|| {
        use std::io::Write;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, &options.config)
    })();
    if written.is_err() {
        fs::remove_file(&temporary).ok();
    }
    written.map_err(|error| InitError::Io(error.to_string()))?;

    // 9. The risk journal, at the account's equity now: setting Guard up
    // is the person's decision to start one. Mainnet's needs the person's
    // confirmation at that moment (`journal-init`), so it is left to them.
    let state_dir = if options.state_dir.is_relative() {
        options
            .config
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(&options.state_dir)
    } else {
        options.state_dir.clone()
    };
    let journal_note = match mode {
        GuardMode::Mainnet => format!(
            "start the mainnet risk journal at your go-ahead: ZUNDER_MAINNET_CONFIRM={account} zunder-guard journal-init --mode mainnet --note \"<who and why>\""
        ),
        GuardMode::Paper | GuardMode::Testnet => {
            let paper = mode == GuardMode::Paper;
            let path = state_dir.join(config.risk_journal(paper).file_name().unwrap_or_default());
            if path.exists() {
                format!("the risk journal {} is kept", path.display())
            } else {
                let equity = venue.equity(network, account).await.map_err(|error| {
                    InitError::Refused(format!("the account's equity could not be read: {error}"))
                })?;
                fs::create_dir_all(&state_dir).map_err(|error| InitError::Io(error.to_string()))?;
                let scope = config
                    .journal_scope(paper)
                    .map_err(|error| InitError::Refused(error.to_string()))?;
                zunder_venue::PersistentRisk::initialise_for(
                    &path,
                    config.policy.risk_limits(),
                    &scope,
                    zunder_core::Timestamp::from_millis(now_ms() as i64),
                    equity,
                    "zunder-guard init",
                )
                .map_err(|error| InitError::Refused(error.to_string()))?;
                format!(
                    "started the risk journal {} at equity {equity}",
                    path.display()
                )
            }
        }
    };

    // Shown once.
    prompter.say("");
    match &options.client_key_out {
        Some(path) => {
            prompter.say(&format!(
                "Client key for your bot written to {} (owner-only; Guard keeps only its address {})",
                path.display(),
                client.address()
            ));
        }
        None => {
            prompter.say("Client key for your bot (shown once; Guard keeps only its address):");
            prompter.say(&format!("  {}", client_hex.as_str()));
            prompter.say(&format!("  address {}", client.address()));
        }
    }
    prompter.say(&format!(
        "Pairing code for the browser monitor (shown once): {pairing_code}"
    ));
    if let Some(warning) = stored.as_ref().and_then(|stored| stored.warning.as_ref()) {
        prompter.say(&format!("WARNING: {warning}"));
    }

    // 10. Next steps.
    prompter.say("");
    prompter.say(&format!("Next steps ({}):", mode.name()));
    prompter.say(&format!("  - {journal_note}"));
    let run = match (&stored, mode) {
        (_, GuardMode::Paper) => "zunder-guard run".to_owned(),
        (Some(stored), _) if stored.pipe.is_empty() => {
            format!("zunder-guard run --network {}", network.name())
        }
        (Some(stored), _) => {
            let confirm = if mode == GuardMode::Mainnet {
                "ZUNDER_MAINNET_CONFIRM=<the account, set by you at your go-ahead> ".to_owned()
            } else {
                String::new()
            };
            format!(
                "{} | {confirm}zunder-guard run --network {} --key-stdin",
                stored.pipe,
                network.name()
            )
        }
        (None, GuardMode::Mainnet) => format!(
            "<your key> | ZUNDER_MAINNET_CONFIRM=<the account, set by you at your go-ahead> zunder-guard run --network {} --key-stdin (the mainnet key is never stored; it comes on standard input at every start)",
            network.name()
        ),
        (None, _) => format!(
            "<your key> | zunder-guard run --network {} --key-stdin (check it first: zunder-guard key check --key-stdin)",
            network.name()
        ),
    };
    prompter.say(&format!("  - Run Guard: {run}"));
    prompter.say(&format!(
        "  - Point the bot at http://{} (WebSocket ws://{}/ws), sign with the client key above, and keep its account address {}. ccxt: options builderFee false and refSet true; the Python SDK signs as testnet through Guard. See docs/guard.md.",
        config.listen, config.listen, account
    ));
    Ok(InitOutcome {
        config,
        stored,
        mode: mode.name().to_owned(),
    })
}

/// A pairing code for the browser monitor and its SHA3-256 (hex), which is
/// all Guard keeps.
pub fn pairing(
    random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>,
) -> Result<(String, String), InitError> {
    let mut pairing = [0u8; 16];
    random(&mut pairing).map_err(InitError::Io)?;
    let code = format!("zgp1_{}", hex(&pairing));
    let hash = hex(&Sha3_256::digest(code.as_bytes()));
    Ok((code, hash))
}

/// A new client key for a bot: its secret (shown once by the caller) and
/// its address (kept).
pub fn new_client(
    random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>,
) -> Result<(Zeroizing<String>, Address), InitError> {
    let mut secret = Zeroizing::new([0u8; 32]);
    loop {
        random(secret.as_mut()).map_err(InitError::Io)?;
        if let Ok(key) = GuardKey::from_bytes(&secret) {
            return Ok((secret_hex(secret.as_ref()), key.address()));
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque};

    #[test]
    fn secret_hex_writes_0x_and_lower_case_digits() {
        assert_eq!(super::secret_hex(&[0x01, 0xab, 0xff]).as_str(), "0x01abff");
    }

    use serde_json::json;

    use super::*;
    use crate::testdir::TestDir;

    /// The SDK's throwaway key: never a real one.
    const KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
    const API_WALLET: &str = "0x14791697260e4c9a71f18484c9f997b308e59325";
    const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";

    struct Script {
        answers: VecDeque<String>,
        secrets: VecDeque<String>,
        output: String,
    }

    impl Prompter for Script {
        fn say(&mut self, text: &str) {
            self.output.push_str(text);
            self.output.push('\n');
        }
        fn ask(&mut self, question: &str) -> Result<String, InitError> {
            self.output.push_str(question);
            self.output.push('\n');
            self.answers.pop_front().ok_or(InitError::Eof)
        }
        fn ask_secret(&mut self, question: &str) -> Result<Zeroizing<String>, InitError> {
            // What the person types is not echoed: only the question shows.
            self.output.push_str(question);
            self.output.push('\n');
            self.secrets
                .pop_front()
                .map(Zeroizing::new)
                .ok_or(InitError::Eof)
        }
    }

    fn script(answers: &[&str]) -> Script {
        Script {
            answers: answers.iter().map(|a| (*a).to_owned()).collect(),
            secrets: [KEY.to_owned()].into(),
            output: String::new(),
        }
    }

    struct FakeVenue(Value);

    impl Venue for FakeVenue {
        async fn user_role(&self, _: GuardNetwork, _: Address) -> Result<Value, String> {
            Ok(self.0.clone())
        }
        async fn equity(&self, _: GuardNetwork, _: Address) -> Result<Decimal, String> {
            Ok(dec!(1000))
        }
    }

    fn agent() -> FakeVenue {
        FakeVenue(json!({"role": "agent", "data": {"user": ACCOUNT}}))
    }

    #[derive(Default)]
    struct Kept(RefCell<Option<String>>);

    impl SecretStore for Kept {
        fn store(&self, secret: &str) -> Result<StoredSecret, String> {
            *self.0.borrow_mut() = Some(secret.to_owned());
            Ok(StoredSecret {
                how: "test".into(),
                location: PathBuf::from("/nowhere"),
                warning: None,
                pipe: "cat /nowhere".into(),
            })
        }
    }

    fn counter() -> impl FnMut(&mut [u8]) -> Result<(), String> {
        let mut next = 1u8;
        move |buffer: &mut [u8]| {
            for byte in buffer.iter_mut() {
                *byte = next;
            }
            next = next.wrapping_add(1);
            Ok(())
        }
    }

    fn options(dir: &TestDir) -> InitOptions {
        InitOptions {
            config: dir.path().join("guard.toml"),
            state_dir: PathBuf::from("."),
            ..InitOptions::default()
        }
    }

    async fn run(
        options: &InitOptions,
        prompter: &mut Script,
        venue: &FakeVenue,
        kept: &Kept,
    ) -> Result<InitOutcome, InitError> {
        init(options, prompter, None, venue, kept, &mut counter()).await
    }

    #[tokio::test]
    async fn a_testnet_setup_writes_the_config_starts_the_journal_and_never_shows_the_key() {
        let dir = TestDir::new("init-testnet");
        let mut prompter = script(&["", ACCOUNT, "testnet"]);
        let kept = Kept::default();
        let outcome = run(&options(&dir), &mut prompter, &agent(), &kept)
            .await
            .unwrap();
        assert_eq!(outcome.mode, "testnet");
        let config = GuardConfig::load(&dir.path().join("guard.toml")).unwrap();
        assert_eq!(config.mode, GuardMode::Testnet);
        assert_eq!(config.api_wallet.as_deref(), Some(API_WALLET));
        assert_eq!(config.account.as_deref(), Some(ACCOUNT));
        assert_eq!(config.policy, Policy::default());
        assert_eq!(config.auth.clients.len(), 1);
        // The journal for sending on testnet, at the venue's equity.
        assert!(dir.path().join("risk.jsonl").exists());
        // The key reached the store, and nowhere else.
        assert_eq!(kept.0.borrow().as_deref(), Some(KEY));
        let digits = &KEY[2..];
        assert!(!prompter.output.contains(digits), "{}", prompter.output);
        let written = fs::read_to_string(dir.path().join("guard.toml")).unwrap();
        assert!(!written.contains(digits));
        // The client key is shown once (bytes 0x01 from the counter), and
        // only its address is in the config.
        let client = format!("0x{}", "01".repeat(32));
        assert_eq!(prompter.output.matches(&client).count(), 1);
        assert!(!written.contains(&client[2..]));
        assert!(prompter.output.contains("--network testnet --key-stdin"));
    }

    #[tokio::test]
    async fn paper_needs_no_key_and_the_rules_can_be_edited_within_bounds() {
        let dir = TestDir::new("init-paper");
        // edit: leverage 3; loss 60% refused, then 1%; the rest kept; the
        // account; paper; mainnet's account (the default).
        let mut prompter = script(&[
            "edit", "3", "60", "1", "", "", "", "", "", "", "", "", ACCOUNT, "", "",
        ]);
        let kept = Kept::default();
        let outcome = run(&options(&dir), &mut prompter, &agent(), &kept)
            .await
            .unwrap();
        assert_eq!(outcome.config.policy.max_leverage, dec!(3));
        assert_eq!(outcome.config.policy.max_loss_at_stop, dec!(0.01));
        assert!(prompter.output.contains("refused"));
        assert_eq!(outcome.mode, "paper");
        assert_eq!(outcome.config.network, Some(GuardNetwork::Mainnet));
        assert_eq!(outcome.config.api_wallet, None);
        assert_eq!(*kept.0.borrow(), None);
        assert!(dir.path().join("risk-paper.jsonl").exists());
    }

    #[tokio::test]
    async fn rules_codes_main_keys_and_mainnet_are_checked() {
        // A rules code applied.
        let dir = TestDir::new("init-rules");
        let strict = Policy {
            max_leverage: dec!(2),
            ..Policy::default()
        };
        let with_rules = InitOptions {
            rules: Some(rules::encode(&strict)),
            ..options(&dir)
        };
        let outcome = run(
            &with_rules,
            &mut script(&["", ACCOUNT, "", ""]),
            &agent(),
            &Kept::default(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.config.policy.max_leverage, dec!(2));
        // The main wallet's own key is refused, before anything is written.
        let dir = TestDir::new("init-user");
        let user = FakeVenue(json!({"role": "user"}));
        let error = run(
            &options(&dir),
            &mut script(&["", ACCOUNT, "testnet"]),
            &user,
            &Kept::default(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("withdraw"), "{error}");
        assert!(!dir.path().join("guard.toml").exists());
        // Mainnet: typed in full, the account again, the cap. No journal
        // yet: that waits for the person's confirmation.
        let dir = TestDir::new("init-mainnet");
        let kept_mainnet = Kept::default();
        let outcome = run(
            &options(&dir),
            &mut script(&["", ACCOUNT, "mainnet", ACCOUNT, "2000"]),
            &agent(),
            &kept_mainnet,
        )
        .await
        .unwrap();
        assert!(
            kept_mainnet.0.borrow().is_none(),
            "a mainnet key is never stored"
        );
        assert!(outcome.config.allow_mainnet);
        assert_eq!(outcome.config.mode, GuardMode::Mainnet);
        // The key was checked and its address recorded, and it was not
        // stored.
        assert!(outcome.config.api_wallet.is_some());
        assert!(outcome.stored.is_none());
        assert_eq!(
            outcome.config.policy.max_trading_equity_usd,
            Some(dec!(2000))
        );
        assert!(!dir.path().join("risk-mainnet.jsonl").exists());
        // Another address as the confirmation: refused.
        let dir = TestDir::new("init-mainnet-confirm");
        let error = run(
            &options(&dir),
            &mut script(&["", ACCOUNT, "mainnet", API_WALLET, "2000"]),
            &agent(),
            &Kept::default(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("confirmation"), "{error}");
        // Where mainnet cannot be set up, it is refused before anything is
        // written.
        let dir = TestDir::new("init-mainnet-refused");
        let error = run(
            &InitOptions {
                refuse_mainnet: Some("no systemd-creds here".into()),
                ..options(&dir)
            },
            &mut script(&["", ACCOUNT, "mainnet"]),
            &agent(),
            &Kept::default(),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("no systemd-creds here"),
            "{error}"
        );
        assert!(!dir.path().join("guard.toml").exists());
        // A cap above the ceiling, or looser rules: refused.
        let dir = TestDir::new("init-mainnet-cap");
        let error = run(
            &options(&dir),
            &mut script(&["", ACCOUNT, "mainnet", ACCOUNT, "5000"]),
            &agent(),
            &Kept::default(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("2500"), "{error}");
        let dir = TestDir::new("init-mainnet-loose");
        let loose = InitOptions {
            rules: Some(rules::encode(&Policy {
                max_leverage: dec!(6),
                ..Policy::default()
            })),
            ..options(&dir)
        };
        let error = run(
            &loose,
            &mut script(&["", ACCOUNT, "mainnet", ACCOUNT, "2000"]),
            &agent(),
            &Kept::default(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("max_leverage"), "{error}");
        // An existing config is not replaced without --force.
        let dir = TestDir::new("init-exists");
        fs::write(dir.path().join("guard.toml"), "x").unwrap();
        assert!(
            run(&options(&dir), &mut script(&[]), &agent(), &Kept::default())
                .await
                .is_err()
        );
    }

    /// `--ip-share` goes into the config; a share too small for the rules'
    /// markets (0.2 with the main dex alone: `budget.rs`) is refused before
    /// anything is written.
    #[tokio::test]
    async fn init_writes_the_ip_share_and_refuses_one_too_small() {
        let kept = Kept::default();
        let dir = TestDir::new("init-ip-share");
        let shared = InitOptions {
            non_interactive: true,
            account: Some(ACCOUNT.into()),
            mode: Some(GuardMode::Testnet),
            no_key: true,
            ip_share: Some(rust_decimal::dec!(0.5)),
            ..options(&dir)
        };
        let outcome = init(
            &shared,
            &mut script(&[]),
            None,
            &agent(),
            &kept,
            &mut counter(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.config.ip_share, rust_decimal::dec!(0.5));
        let written = fs::read_to_string(dir.path().join("guard.toml")).unwrap();
        assert!(written.contains("ip_share = \"0.5\""), "{written}");
        let dir = TestDir::new("init-ip-share-small");
        let small = InitOptions {
            ip_share: Some(rust_decimal::dec!(0.2)),
            config: dir.path().join("guard.toml"),
            ..shared.clone()
        };
        let error = init(
            &small,
            &mut script(&[]),
            None,
            &agent(),
            &kept,
            &mut counter(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("ip_share 0.2"), "{error}");
        assert!(!dir.path().join("guard.toml").exists());
        // Set up again with --force and no --ip-share: the share is kept.
        let dir = TestDir::new("init-ip-share-again");
        let first = InitOptions {
            config: dir.path().join("guard.toml"),
            ..shared.clone()
        };
        init(
            &first,
            &mut script(&[]),
            None,
            &agent(),
            &kept,
            &mut counter(),
        )
        .await
        .unwrap();
        let again = InitOptions {
            ip_share: None,
            force: true,
            ..first
        };
        let outcome = init(
            &again,
            &mut script(&[]),
            None,
            &agent(),
            &kept,
            &mut counter(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.config.ip_share, rust_decimal::dec!(0.5));
    }

    /// `--licence`: a key for the account is checked and written into the
    /// config; one for another account (or forged, or expired) is refused
    /// before anything is written.
    #[tokio::test]
    async fn init_writes_a_licence_key_only_for_this_account() {
        use zunder_guard_core::licence::{Terms, issue, test_key};
        let key = |accounts: Vec<String>, expires_at_ms: i64| {
            issue(
                &Terms {
                    licensee: "Example GmbH".into(),
                    expires_at_ms,
                    features: vec!["fee_free".into()],
                    accounts,
                    builder: None,
                },
                &test_key::SEED,
            )
            .unwrap()
        };
        let later = crate::guard::Clock::now_ms(&crate::guard::SystemClock) as i64 + 86_400_000;
        let kept = Kept::default();
        let dir = TestDir::new("init-licence");
        let good = key(vec![ACCOUNT.into()], later);
        let licensed = InitOptions {
            non_interactive: true,
            account: Some(ACCOUNT.into()),
            mode: Some(GuardMode::Testnet),
            no_key: true,
            licence: Some(format!(" {good}\n")),
            licence_public_key: Some(test_key::public()),
            ..options(&dir)
        };
        let outcome = init(
            &licensed,
            &mut script(&[]),
            None,
            &agent(),
            &kept,
            &mut counter(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.config.licence.as_deref(), Some(good.as_str()));
        let written = GuardConfig::load(&dir.path().join("guard.toml")).unwrap();
        assert_eq!(written.licence.as_deref(), Some(good.as_str()));
        for bad in [
            key(
                vec!["0x0000000000000000000000000000000000000001".into()],
                later,
            ),
            key(vec![ACCOUNT.into()], later - 2 * 86_400_000),
            "zgl1_forged.key".to_owned(),
        ] {
            let dir = TestDir::new("init-licence-bad");
            let refused = InitOptions {
                licence: Some(bad),
                config: dir.path().join("guard.toml"),
                ..licensed.clone()
            };
            let error = init(
                &refused,
                &mut script(&[]),
                None,
                &agent(),
                &kept,
                &mut counter(),
            )
            .await
            .unwrap_err();
            assert!(
                error.to_string().contains("licence key is refused"),
                "{error}"
            );
            assert!(!dir.path().join("guard.toml").exists());
        }
    }

    #[tokio::test]
    async fn non_interactive_takes_flags_and_the_key_on_stdin() {
        let dir = TestDir::new("init-batch");
        let batch = InitOptions {
            non_interactive: true,
            account: Some(ACCOUNT.into()),
            mode: Some(GuardMode::Testnet),
            ..options(&dir)
        };
        let mut stdin = format!("{KEY}\n").into_bytes();
        let mut reader: &[u8] = stdin.as_slice();
        let mut prompter = script(&[]);
        let kept = Kept::default();
        let outcome = init(
            &batch,
            &mut prompter,
            Some(&mut reader),
            &agent(),
            &kept,
            &mut counter(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.mode, "testnet");
        assert!(!prompter.output.contains(&KEY[2..]));
        stdin.iter_mut().for_each(|byte| *byte = 0);
        // --no-key: the config names no API wallet; the key is checked and
        // stored by the installer.
        let dir = TestDir::new("init-batch-nokey");
        let nokey = InitOptions {
            no_key: true,
            ..InitOptions {
                config: dir.path().join("guard.toml"),
                ..batch.clone()
            }
        };
        let outcome = init(
            &nokey,
            &mut script(&[]),
            None,
            &agent(),
            &kept,
            &mut counter(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.config.api_wallet, None);
        assert!(outcome.stored.is_none());
        // Without the account: refused.
        let dir = TestDir::new("init-batch-bare");
        let bare = InitOptions {
            non_interactive: true,
            ..options(&dir)
        };
        let mut reader: &[u8] = b"";
        assert!(
            init(
                &bare,
                &mut script(&[]),
                Some(&mut reader),
                &agent(),
                &kept,
                &mut counter()
            )
            .await
            .is_err()
        );
        // Mainnet without the confirmation flag: refused.
        let dir = TestDir::new("init-batch-mainnet");
        let mainnet = InitOptions {
            non_interactive: true,
            account: Some(ACCOUNT.into()),
            mode: Some(GuardMode::Mainnet),
            equity_cap: Some("2000".into()),
            no_key: true,
            ..options(&dir)
        };
        let error = init(
            &mainnet,
            &mut script(&[]),
            None,
            &agent(),
            &kept,
            &mut counter(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("--confirm-mainnet"), "{error}");
    }

    #[test]
    fn a_secret_line_is_bounded() {
        let mut long: &[u8] = &[b'a'; 300];
        assert!(read_secret_line(&mut long).is_err());
        let mut empty: &[u8] = b"";
        assert!(matches!(read_secret_line(&mut empty), Err(InitError::Eof)));
        let mut line: &[u8] = b"  0xabc  \nrest";
        assert_eq!(read_secret_line(&mut line).unwrap().as_str(), "0xabc");
    }

    #[test]
    fn the_file_store_is_owner_only() {
        let dir = TestDir::new("init-file");
        let path = dir.path().join("secrets").join("key");
        let stored = OwnerOnlyFile {
            path: path.clone(),
            replace: false,
        }
        .store("secret")
        .unwrap();
        assert!(stored.warning.unwrap().contains("plain text"));
        // Mode 0600 on Unix, the user alone in the ACL on Windows.
        assert_eq!(zunder_venue::owner_only::check(&path).unwrap(), None);
        // Never overwritten without --force.
        assert!(
            OwnerOnlyFile {
                path: path.clone(),
                replace: false
            }
            .store("again")
            .is_err()
        );
        OwnerOnlyFile {
            path: path.clone(),
            replace: true,
        }
        .store("again")
        .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "again\n");
        assert_eq!(zunder_venue::owner_only::check(&path).unwrap(), None);
    }

    #[cfg(windows)]
    #[test]
    fn the_credential_manager_keeps_the_key_for_run() {
        // A real entry in this user's vault (the CI runner's), removed at
        // the end. A mock store would not survive a second Entry.
        let target = format!("test-{}", std::process::id());
        let stored = CredentialManager {
            target: target.clone(),
            replace: false,
        }
        .store("0xsecret")
        .unwrap();
        assert!(stored.pipe.is_empty());
        assert!(stored.warning.is_none());
        assert_eq!(
            stored_windows_key(&target).unwrap().unwrap().as_str(),
            "0xsecret"
        );
        assert!(
            CredentialManager {
                target: target.clone(),
                replace: false
            }
            .store("0xother")
            .is_err()
        );
        keyring::Entry::new(WINDOWS_CREDENTIAL_SERVICE, &target)
            .unwrap()
            .delete_credential()
            .unwrap();
        assert!(stored_windows_key(&target).unwrap().is_none());
    }
}
