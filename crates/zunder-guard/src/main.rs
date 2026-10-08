// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! `zunder-guard`: Zunder Guard's command line. See `docs/guard.md` and the
//! packaging's contract in `deploy/guard/README.md` ("The CLI contract").
//!
//! `run` is paper mode unless `--network` (or `ZUNDER_GUARD_NETWORK`) names
//! where to send, and the config's mode is the same. Testnet needs the key
//! on standard input or in a key file only its owner can read. Mainnet
//! needs, all at once, a mainnet config with every guard (`allow_mainnet`,
//! the equity cap, the account, the API wallet, no rule looser than the
//! defaults), `ZUNDER_MAINNET_CONFIRM` naming the account at this start, a
//! risk journal scoped to mainnet and the account, and the key on standard
//! input only, whose API wallet must be the config's. Everything but the
//! venue's own checks is checked before the key is read.
//!
//! Every refusal exits with status 2 and its reason on standard error.
//!
//! Windows (1.0): paper and testnet. The home is `%LOCALAPPDATA%\zunder-guard`,
//! key files are owner-only by ACL, `init` keeps a testnet key in the
//! Credential Manager (DPAPI) and `run` reads it from there, Ctrl-C, Ctrl-Break
//! and closing the console stop Guard cleanly. Mainnet is refused on Windows:
//! there is no service that hands the key over on standard input from an
//! encrypted credential, as systemd does on Linux.

use std::{
    fs,
    io::{IsTerminal, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::Value;
use zunder_core::Timestamp;
use zunder_guard::{
    config::{GuardConfig, GuardMode, GuardNetwork},
    guard::{Clock, Guard, Mode, Setup, SystemClock},
    init::{
        self, CredentialManager, InitOptions, OwnerOnlyFile, SecretStore, SystemdCreds,
        TtyPrompter, Venue,
    },
    journal::DecisionJournal,
    keyread::read_key,
    licence_life, rules, server,
    upstream::{Hyperliquid, InfoClient, Upstream},
};
use zunder_guard_core::{
    account::{check_api_wallet_role, requests},
    licence::{self, LICENCE_PUBLIC_KEY},
    sign::{Address, GuardKey, SigningNetwork},
};
use zunder_venue::{
    PersistentRisk,
    hyperliquid::{CONFIRM_VAR, MainnetConsent, VenueNetwork},
};

/// The name of the key file in Guard's home (the file store and
/// `ZUNDER_GUARD_KEY_FILE`'s default).
const KEY_FILE: &str = "api-wallet-key";

#[derive(Parser)]
#[command(
    name = "zunder-guard",
    version,
    about = "Zunder Guard: a risk firewall between your trading bot and Hyperliquid"
)]
struct Cli {
    /// Guard's home: the config, the journals, the key file.
    #[arg(long, global = true, env = "ZUNDER_GUARD_HOME")]
    home: Option<PathBuf>,
    /// The config file (default: guard.toml in the home).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ModeArg {
    Paper,
    Testnet,
    Mainnet,
}

impl ModeArg {
    fn mode(self) -> GuardMode {
        match self {
            ModeArg::Paper => GuardMode::Paper,
            ModeArg::Testnet => GuardMode::Testnet,
            ModeArg::Mainnet => GuardMode::Mainnet,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum NetworkArg {
    Testnet,
    Mainnet,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StoreArg {
    /// systemd-creds where available; on Windows the Credential Manager;
    /// otherwise an owner-only file.
    Auto,
    File,
    SystemdCreds,
    /// Windows: the Credential Manager (DPAPI, this user).
    CredentialManager,
}

#[derive(Subcommand)]
enum Command {
    /// Set Guard up: rules, account, mode, the API wallet key (checked with
    /// the venue and stored), a client key for the bot and a pairing code
    /// shown once, the risk journal. Interactive on a terminal.
    Init(InitArgs),
    /// Manage an explicitly admitted OS mainnet supervisor.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Print one configured value: network (the mode: paper, testnet or
    /// mainnet), account, listen or rules.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// The API wallet key.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Issue another client key for a bot (shown once) and a pairing code.
    /// A running Guard accepts it after a restart.
    Pair,
    /// Client keys for bots and agents.
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
    /// The MCP server for AI agents (the agent kit, `docs/guard-mcp.md`)
    /// over standard input and output, trading only through a Guard on
    /// this machine: the same code as `zunder-guard-mcp`.
    Mcp(zunder_guard_mcp::cli::Cli),
    /// Run Guard. Paper mode (judges and journals, sends nothing) unless
    /// --network says where to send.
    Run(RunArgs),
    /// Exit 0 when Guard answers on its listen address.
    Health(HealthArgs),
    /// The running Guard's status (`GET /guard/status`), for a person:
    /// mode, kill switch, risk state, equity, the fee and its approval,
    /// alerts. Reads only.
    Status(StatusArgs),
    /// Start a new risk journal at the account's equity now. A person's
    /// decision: never replaces a journal.
    JournalInit(JournalArgs),
    /// Clear a drawdown halt after a person has reviewed it. Stop Guard
    /// first.
    JournalResume(JournalArgs),
    /// Print the risk journal's records. Reads only.
    JournalShow(ShowArgs),
    /// Pull the kill switch: a running Guard opens nothing and flattens,
    /// until a person removes the kill file and restarts it.
    Kill(KillArgs),
    /// Check a config and print its rules. Reads no key, connects to
    /// nothing.
    CheckConfig,
    /// The licence key: set a new one (a running Guard applies it at its
    /// next sync, no restart), or show the one in the config.
    Licence {
        #[command(subcommand)]
        command: LicenceCommand,
    },
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Emit public admission JSON; the OS installer stores it with trusted ownership.
    Prepare {
        #[arg(long)]
        credential_id: String,
        #[arg(long)]
        confirm_mainnet: String,
        #[arg(long)]
        uid: Option<u32>,
        #[arg(long)]
        gid: Option<u32>,
        #[arg(long)]
        service_name: Option<String>,
        #[arg(long)]
        service_sid: Option<String>,
    },
    /// Store a mainnet API key only in the admitted OS secure store.
    Provision {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        confirm_mainnet: String,
        #[arg(long)]
        key_stdin: bool,
        #[arg(long)]
        replace: bool,
    },
    /// Check metadata and OS store presence without printing a key.
    Check {
        #[arg(long)]
        binding: PathBuf,
    },
    /// Entry point for the native OS supervisor.
    Run {
        #[arg(long)]
        binding: PathBuf,
    },
    /// Re-provision the verified next macOS release through a private pipe.
    MigrateCredential {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        next_binding: PathBuf,
        #[arg(long)]
        confirm_mainnet: String,
    },
    /// Explicitly admit reviewed client/risk/listen changes while stopped.
    Readmit {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        confirm_mainnet: String,
    },
    /// Set a verified licence while preserving service ownership and renewal updates.
    LicenceSet {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        key: String,
    },
    /// Report the service licence and live fee state.
    LicenceShow {
        #[arg(long)]
        binding: PathBuf,
    },
    /// Add a bot client while stopped; a separate explicit readmission follows.
    Pair {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        confirm_mainnet: String,
    },
    /// Delete exactly this installation's credential, after stopping it.
    RemoveCredential {
        #[arg(long)]
        binding: PathBuf,
    },
}

#[derive(Subcommand)]
enum LicenceCommand {
    /// Check a licence key (`zgl1_…`) for the configured account and write
    /// it into the config. A key that does not verify, has expired or is
    /// for other accounts is refused, and the config is left as it is.
    Set {
        /// The licence key from the licence email.
        key: String,
        #[command(flatten)]
        target: TargetArgs,
    },
    /// What the licence key in the config is: licensee, end, fee, accounts;
    /// and what the running Guard reports.
    Show {
        #[command(flatten)]
        target: TargetArgs,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    Get {
        #[arg(value_parser = ["network", "mode", "account", "listen", "rules"])]
        key: String,
    },
}

#[derive(Subcommand)]
enum ClientCommand {
    /// Add a client key: written to a new owner-only file, never shown.
    /// A running Guard accepts it after a restart.
    Add {
        /// The new file for the key (refused if it exists).
        #[arg(long)]
        out: PathBuf,
    },
    /// List the client addresses the config accepts, and whether the
    /// running Guard accepts the same.
    List {
        #[command(flatten)]
        target: TargetArgs,
    },
    /// Remove a client address from the config. A running Guard keeps
    /// accepting it until it is restarted: restart it at once. The last
    /// client cannot be removed (add another first).
    Revoke {
        /// The client's address (0x and 40 hex digits).
        address: String,
        #[command(flatten)]
        target: TargetArgs,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Read the key from standard input and check with the venue that it
    /// is an API wallet of the configured account; print its address,
    /// never the key. Records the address in the config.
    Check {
        #[arg(long)]
        key_stdin: bool,
    },
}

#[derive(Args)]
struct InitArgs {
    /// Ask on the terminal (the default).
    #[arg(long, conflicts_with = "non_interactive")]
    interactive: bool,
    /// No questions: answers from the flags, the key on standard input.
    #[arg(long)]
    non_interactive: bool,
    /// Set nothing up for the key (an installer checks and stores it).
    #[arg(long)]
    no_key: bool,
    /// Read the key from standard input (with --non-interactive).
    #[arg(long)]
    key_stdin: bool,
    /// Windows machine-service staging identity; prompts for its key inside Rust.
    #[arg(long, requires = "non_interactive", conflicts_with_all = ["key_stdin", "no_key"])]
    service_setup: Option<String>,
    /// Rules from the website: a `zr1_…` code.
    #[arg(long, env = "ZUNDER_GUARD_RULES")]
    rules: Option<String>,
    #[arg(long, env = "ZUNDER_GUARD_ACCOUNT")]
    account: Option<String>,
    /// The mode: paper, testnet or mainnet.
    #[arg(long, value_enum, env = "ZUNDER_GUARD_NETWORK")]
    network: Option<ModeArg>,
    /// Paper mode: the network of the account it reads (default mainnet).
    #[arg(long, value_enum)]
    account_network: Option<NetworkArg>,
    /// Mainnet: the account address again.
    #[arg(long)]
    confirm_mainnet: Option<String>,
    /// Mainnet: the most equity Guard sizes from (USDC, at most 2500).
    #[arg(long)]
    equity_cap: Option<String>,
    /// A loopback listen address for the config.
    #[arg(long)]
    listen: Option<String>,
    /// This Guard's part of the IP address's request weight, in (0, 1]:
    /// 1/N for each of N Guards on one machine (default 1).
    #[arg(long, env = "ZUNDER_GUARD_IP_SHARE", value_parser = parse_share)]
    ip_share: Option<rust_decimal::Decimal>,
    #[arg(long, value_enum, default_value = "auto")]
    key_store: StoreArg,
    /// Replace an existing config (the journal is kept).
    #[arg(long)]
    force: bool,
    /// Write the bot's client key to this new owner-only file instead of
    /// showing it.
    #[arg(long)]
    client_key_out: Option<PathBuf>,
    /// Refuse mainnet, with this reason, before anything is written (the
    /// installer passes it where mainnet cannot be set up safely).
    #[arg(long, value_name = "REASON")]
    refuse_mainnet: Option<String>,
    /// A licence key (`zgl1_…`) for the account: checked, then written into
    /// the config. A key that does not verify for it is refused.
    #[arg(long, env = "ZUNDER_GUARD_LICENCE")]
    licence: Option<String>,
}

#[derive(Args)]
struct RunArgs {
    /// Send to this network; the config's mode must be the same. Paper
    /// without it.
    #[arg(long, value_enum, env = "ZUNDER_GUARD_NETWORK")]
    network: Option<ModeArg>,
    /// Listen here instead of the config's address. Anything but loopback
    /// is warned about.
    #[arg(long, env = "ZUNDER_GUARD_LISTEN")]
    listen: Option<String>,
    /// This Guard's part of the IP address's request weight instead of the
    /// config's `ip_share`: 1/N for each of N Guards on one machine.
    #[arg(long, env = "ZUNDER_GUARD_IP_SHARE", value_parser = parse_share)]
    ip_share: Option<rust_decimal::Decimal>,
    /// Read the API wallet key from standard input.
    #[arg(long, conflicts_with = "key_file")]
    key_stdin: bool,
    /// Private supervisor pipe framing; remaining stdin controls process lifetime.
    #[arg(long, requires_all = ["key_stdin", "service_binding"])]
    supervised_stdin: bool,
    /// Immutable OS service admission; accepted only under the admitted OS identity.
    #[arg(long, requires = "supervised_stdin")]
    service_binding: Option<PathBuf>,
    /// Read it from this file (testnet only), which only its owner may
    /// read (in a container: which nobody else may write).
    #[arg(long, env = "ZUNDER_GUARD_KEY_FILE")]
    key_file: Option<PathBuf>,
    /// Running in a container (Docker's /.dockerenv is detected; Podman and
    /// others pass this).
    #[arg(long, env = "ZUNDER_GUARD_CONTAINER")]
    container: bool,
    /// On an empty home: set up paper mode from these rules and
    /// ZUNDER_GUARD_ACCOUNT first.
    #[arg(long, env = "ZUNDER_GUARD_RULES")]
    rules: Option<String>,
    #[arg(long, env = "ZUNDER_GUARD_ACCOUNT")]
    account: Option<String>,
}

#[derive(Args)]
struct HealthArgs {
    #[arg(long, env = "ZUNDER_GUARD_LISTEN")]
    listen: Option<String>,
    /// http://host:port of Guard instead.
    #[arg(long)]
    url: Option<String>,
}

/// Where the running Guard answers (default: the config's listen address).
#[derive(Args)]
struct TargetArgs {
    #[arg(long, env = "ZUNDER_GUARD_LISTEN")]
    listen: Option<String>,
    /// http://host:port of Guard instead.
    #[arg(long, conflicts_with = "listen")]
    url: Option<String>,
}

impl TargetArgs {
    /// host:port of the running Guard.
    fn resolve(&self, paths: &Paths) -> Result<String> {
        Ok(match (&self.url, &self.listen) {
            (Some(url), _) => url
                .strip_prefix("http://")
                .and_then(|rest| rest.split('/').next())
                .context("--url must be http://host:port")?
                .to_owned(),
            (None, Some(listen)) => listen.clone(),
            (None, None) => paths
                .load()
                .map_or_else(|_| GuardConfig::default().listen, |config| config.listen),
        })
    }
}

#[derive(Args)]
struct StatusArgs {
    #[command(flatten)]
    target: TargetArgs,
    /// Print the status JSON as Guard answers it.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct JournalArgs {
    /// Which journal: paper's, or the one for sending on testnet or mainnet.
    #[arg(long, value_enum)]
    mode: ModeArg,
    /// Who decided this and why; recorded in the journal.
    #[arg(long)]
    note: String,
}

#[derive(Args)]
struct ShowArgs {
    #[arg(long, value_enum)]
    mode: ModeArg,
}

#[derive(Args)]
struct KillArgs {
    #[arg(long)]
    reason: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let supervised_child = matches!(&cli.command, Command::Run(args) if args.supervised_stdin);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("zunder-guard: starting the async runtime: {error}");
            return ExitCode::from(2);
        }
    };
    let paths = Paths::new(cli.home, cli.config);
    let result = match cli.command {
        Command::Init(args) => runtime.block_on(run_init(&paths, args)),
        Command::Service { command } => service_command(&paths, command),
        Command::Config {
            command: ConfigCommand::Get { key },
        } => config_get(&paths, &key),
        Command::Key {
            command: KeyCommand::Check { key_stdin },
        } => runtime.block_on(key_check(&paths, key_stdin)),
        Command::Pair => pair(&paths),
        Command::Client {
            command: ClientCommand::Add { out },
        } => client_add(&paths, &out),
        Command::Client {
            command: ClientCommand::List { target },
        } => client_list(&paths, &target),
        Command::Client {
            command: ClientCommand::Revoke { address, target },
        } => client_revoke(&paths, &address, &target),
        Command::Mcp(args) => mcp(&args),
        Command::Run(args) => runtime.block_on(run(&paths, args)),
        Command::Health(args) => health(&args),
        Command::Status(args) => status(&paths, &args),
        Command::JournalInit(args) => runtime.block_on(journal_init(&paths, args)),
        Command::JournalResume(args) => runtime.block_on(journal_resume(&paths, args)),
        Command::JournalShow(args) => journal_show(&paths, &args),
        Command::Kill(args) => kill(&paths, &args),
        Command::CheckConfig => check_config(&paths),
        Command::Licence {
            command: LicenceCommand::Set { key, target },
        } => licence_set(&paths, &key, &target),
        Command::Licence {
            command: LicenceCommand::Show { target },
        } => licence_show(&paths, &target),
    };
    runtime.shutdown_timeout(Duration::from_secs(2));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("zunder-guard: {error:#}");
            if supervised_child && transient_service_start_failure(&error) {
                ExitCode::from(75)
            } else {
                ExitCode::from(2)
            }
        }
    }
}

/// Only typed read-only startup transport failures request native recovery.
/// Unknown refusals and HTTP authentication/client failures remain stopped.
fn transient_service_start_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<zunder_guard::upstream::UpstreamError>(),
            Some(
                zunder_guard::upstream::UpstreamError::NotSent(_)
                    | zunder_guard::upstream::UpstreamError::NoAnswer(_)
            )
        ) || matches!(
            cause.downcast_ref::<zunder_guard::upstream::UpstreamError>(),
            Some(zunder_guard::upstream::UpstreamError::Status {
                status: 429 | 500..=599,
                ..
            })
        )
    })
}

/// Guard's home and config file.
struct Paths {
    home: PathBuf,
    config: PathBuf,
}

impl Paths {
    fn new(home: Option<PathBuf>, config: Option<PathBuf>) -> Self {
        let home = home.unwrap_or_else(platform::default_home);
        let config = config.unwrap_or_else(|| home.join("guard.toml"));
        Self { home, config }
    }

    fn load(&self) -> Result<GuardConfig> {
        if !self.config.exists() {
            bail!(
                "not initialised: {} does not exist (run zunder-guard init)",
                self.config.display()
            );
        }
        Ok(GuardConfig::load(&self.config)?)
    }
}

/// The venue for init and `key check`: an info-only client.
struct VenueInfo;

impl Venue for VenueInfo {
    async fn user_role(&self, network: GuardNetwork, key: Address) -> Result<Value, String> {
        let client = InfoClient::new(network.venue()).map_err(|error| error.to_string())?;
        client
            .post(&requests::user_role(key))
            .await
            .map_err(|error| error.to_string())
    }

    async fn equity(
        &self,
        network: GuardNetwork,
        account: Address,
    ) -> Result<rust_decimal::Decimal, String> {
        equity_of(network, account)
            .await
            .map_err(|error| format!("{error:#}"))
    }
}

/// Prints and refuses every question: the non-interactive init.
struct Batch;

impl init::Prompter for Batch {
    fn say(&mut self, text: &str) {
        println!("{text}");
    }
    fn ask(&mut self, question: &str) -> Result<String, init::InitError> {
        Err(init::InitError::Refused(format!(
            "--non-interactive cannot answer: {question}"
        )))
    }
    fn ask_secret(
        &mut self,
        question: &str,
    ) -> Result<zeroize::Zeroizing<String>, init::InitError> {
        Err(init::InitError::Refused(format!(
            "--non-interactive cannot answer: {question}"
        )))
    }
}

/// Standard input as file descriptor 0 (a handle on Windows), unbuffered:
/// `Stdin` would keep a copy of a key in its own buffer for the life of the
/// process.
fn stdin_fd() -> Result<fs::File> {
    if std::io::stdin().is_terminal() {
        bail!("the key comes piped on standard input; typing it would show it on the terminal");
    }
    platform::stdin_file().context("duplicating standard input")
}

/// What differs between Unix and Windows, in one place.
mod platform {
    use std::{fs, io, path::PathBuf};

    /// `~/.zunder-guard` on Unix; `%LOCALAPPDATA%\zunder-guard` on Windows
    /// (the user's own, never roamed to other machines).
    pub fn default_home() -> PathBuf {
        #[cfg(windows)]
        {
            if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                return PathBuf::from(local).join("zunder-guard");
            }
            std::env::var_os("USERPROFILE")
                .map_or_else(|| PathBuf::from("."), PathBuf::from)
                .join(".zunder-guard")
        }
        #[cfg(not(windows))]
        {
            std::env::var_os("HOME")
                .map_or_else(|| PathBuf::from("."), PathBuf::from)
                .join(".zunder-guard")
        }
    }

    pub fn stdin_file() -> io::Result<fs::File> {
        #[cfg(unix)]
        {
            use std::os::fd::AsFd;
            Ok(fs::File::from(
                std::io::stdin().as_fd().try_clone_to_owned()?,
            ))
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsHandle;
            Ok(fs::File::from(
                std::io::stdin().as_handle().try_clone_to_owned()?,
            ))
        }
    }

    /// Take over the signals that ask the process to stop, now, and
    /// return what waits for one (the name of what asked). Unix: SIGTERM
    /// (systemd, or `docker stop` with Guard as PID 1) and SIGINT.
    /// Windows: Ctrl-C, Ctrl-Break, closing the console, logoff and
    /// shutdown.
    pub fn shutdown() -> io::Result<impl std::future::Future<Output = &'static str>> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut terminate = signal(SignalKind::terminate())?;
            let mut interrupt = signal(SignalKind::interrupt())?;
            Ok(async move {
                tokio::select! {
                    _ = terminate.recv() => "SIGTERM",
                    _ = interrupt.recv() => "SIGINT",
                }
            })
        }
        #[cfg(windows)]
        {
            use tokio::signal::windows;
            let mut c = windows::ctrl_c()?;
            let mut brk = windows::ctrl_break()?;
            let mut close = windows::ctrl_close()?;
            let mut shutdown = windows::ctrl_shutdown()?;
            let mut logoff = windows::ctrl_logoff()?;
            Ok(async move {
                tokio::select! {
                    _ = c.recv() => "Ctrl-C",
                    _ = brk.recv() => "Ctrl-Break",
                    _ = close.recv() => "console closed",
                    _ = shutdown.recv() => "shutdown",
                    _ = logoff.recv() => "logoff",
                }
            })
        }
    }

    /// Mainnet is not offered on Windows in 1.0 (module docs).
    pub const NO_MAINNET: Option<&str> = if cfg!(windows) {
        Some(
            "mainnet is not offered on Windows in Guard 1.0: there is no service that hands the key over on standard input from an encrypted credential. Use Linux (the SSH installer), or paper and testnet here",
        )
    } else {
        None
    };
}

/// Windows: the key `init` keeps for this configuration in the Credential
/// Manager, parsed (the text is wiped). `None` elsewhere or when there is
/// none.
fn windows_key(config: &Path) -> Result<Option<GuardKey>> {
    #[cfg(windows)]
    {
        let Some(text) =
            init::stored_windows_key(&credential_target(config)).map_err(anyhow::Error::msg)?
        else {
            return Ok(None);
        };
        Ok(Some(
            zunder_guard::keyread::key_from_text(&text, "the Credential Manager")
                .map_err(|error| anyhow::anyhow!("{error}"))?,
        ))
    }
    #[cfg(not(windows))]
    {
        let _ = config;
        Ok(None)
    }
}

/// The configuration's folder, absolute: the name under which `init`
/// keeps a Windows key in the Credential Manager and `run` finds it.
fn credential_target(config: &Path) -> String {
    let folder = config
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    std::path::absolute(&folder)
        .unwrap_or(folder)
        .display()
        .to_string()
}

async fn run_init(paths: &Paths, args: InitArgs) -> Result<()> {
    let service_setup = args.service_setup.is_some();
    if let Some(identity) = &args.service_setup {
        if args.network != Some(ModeArg::Mainnet)
            || args.confirm_mainnet.is_none()
            || args.equity_cap.is_none()
        {
            bail!("service setup requires explicit mainnet, account confirmation and equity cap");
        }
        #[cfg(windows)]
        zunder_guard::service::windows::validate_setup(&paths.home, &paths.config, identity)?;
        #[cfg(not(windows))]
        {
            let _ = identity;
            bail!("--service-setup is for Windows SCM staging only");
        }
    }
    let options = InitOptions {
        config: paths.config.clone(),
        state_dir: PathBuf::from("."),
        rules: args.rules,
        non_interactive: args.non_interactive,
        account: args.account,
        network: args.account_network.map(|network| match network {
            NetworkArg::Testnet => GuardNetwork::Testnet,
            NetworkArg::Mainnet => GuardNetwork::Mainnet,
        }),
        mode: args.network.map(ModeArg::mode),
        confirm_mainnet: args.confirm_mainnet,
        equity_cap: args.equity_cap,
        no_key: args.no_key,
        listen: args.listen,
        ip_share: args.ip_share,
        force: args.force,
        client_key_out: args.client_key_out,
        refuse_mainnet: args.refuse_mainnet.or_else(|| {
            (!service_setup)
                .then_some(platform::NO_MAINNET)
                .flatten()
                .map(str::to_owned)
        }),
        licence: args.licence,
        licence_public_key: None,
    };
    let base = paths
        .config
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let credstore = PathBuf::from("/etc/credstore.encrypted");
    let file = OwnerOnlyFile {
        path: base.join(KEY_FILE),
        replace: args.force,
    };
    let systemd = SystemdCreds {
        dir: credstore.clone(),
        replace: args.force,
    };
    let windows = CredentialManager {
        target: credential_target(&paths.config),
        replace: args.force,
    };
    let store: &dyn SecretStore = match args.key_store {
        StoreArg::File => &file,
        StoreArg::SystemdCreds => &systemd,
        StoreArg::CredentialManager => &windows,
        StoreArg::Auto if cfg!(windows) => &windows,
        StoreArg::Auto if SystemdCreds::available(&credstore) => &systemd,
        StoreArg::Auto => &file,
    };
    let mut random = init::os_random;
    let outcome = if service_setup {
        // No plaintext ever enters PowerShell or a process argument. init
        // receives the bounded in-memory reader and still never stores mainnet.
        zunder_guard::service::enforce_no_core_dumps()?;
        let mut secret = zeroize::Zeroizing::new(
            rpassword::prompt_password("API wallet key (hidden, checked for service setup): ")?
                .into_bytes(),
        );
        secret.push(b'\n');
        let mut reader = secret.as_slice();
        init::init(
            &options,
            &mut Batch,
            Some(&mut reader),
            &VenueInfo,
            store,
            &mut random,
        )
        .await
    } else if options.non_interactive {
        let mut stdin = if args.key_stdin {
            Some(stdin_fd()?)
        } else {
            None
        };
        let reader = stdin.as_mut().map(|file| file as &mut dyn Read);
        init::init(&options, &mut Batch, reader, &VenueInfo, store, &mut random).await
    } else {
        let mut tty = TtyPrompter::new()?;
        init::init(&options, &mut tty, None, &VenueInfo, store, &mut random).await
    }?;
    eprintln!(
        "wrote {} for {} mode on {}",
        paths.config.display(),
        outcome.mode,
        outcome.config.network.map_or("?", GuardNetwork::name)
    );
    Ok(())
}

fn config_get(paths: &Paths, key: &str) -> Result<()> {
    let config = paths.load()?;
    let value = match key {
        "network" | "mode" => config.mode.name().to_owned(),
        "account" => config.account()?.to_hex(),
        "listen" => config.listen.clone(),
        "rules" => rules::encode(&config.policy),
        other => bail!("unknown key {other}"),
    };
    println!("{value}");
    Ok(())
}

async fn key_check(paths: &Paths, key_stdin: bool) -> Result<()> {
    if !key_stdin {
        bail!("key check reads the key from standard input only: pass --key-stdin");
    }
    let config = paths.load()?;
    let key = read_key(&mut stdin_fd()?, "standard input")?;
    let account = config.account()?;
    let network = config.network()?;
    let role = VenueInfo
        .user_role(network, key.address())
        .await
        .map_err(anyhow::Error::msg)?;
    check_api_wallet_role(&role, key.address(), account).map_err(anyhow::Error::msg)?;
    match config.api_wallet.as_deref().and_then(Address::from_hex) {
        Some(expected) if expected != key.address() => bail!(
            "this key's API wallet {} is not the config's {expected}",
            key.address()
        ),
        Some(_) => {}
        None => {
            GuardConfig::update(&paths.config, |config| {
                config.api_wallet = Some(key.address().to_hex());
            })?;
        }
    }
    println!("{}", key.address());
    Ok(())
}

fn pair(paths: &Paths) -> Result<()> {
    paths.load()?;
    let mut random = init::os_random;
    let (secret, address) = init::new_client(&mut random)?;
    let (code, hash) = init::pairing(&mut random)?;
    GuardConfig::update(&paths.config, |config| {
        config.auth.clients.push(address.to_hex());
        config.pairing_sha3 = Some(hash);
    })?;
    println!("Client key for your bot (shown once; Guard keeps only its address):");
    println!("  {}", secret.as_str());
    println!("  address {address}");
    println!("Pairing code for the browser monitor (shown once): {code}");
    println!("A running Guard accepts the new client after a restart.");
    Ok(())
}

fn client_add(paths: &Paths, out: &Path) -> Result<()> {
    paths.load()?;
    let mut random = init::os_random;
    let (secret, address) = init::new_client(&mut random)?;
    // The key file first: a config never names a client whose key is lost.
    init::write_client_key(out, secret.as_str()).map_err(anyhow::Error::msg)?;
    GuardConfig::update(&paths.config, |config| {
        config.auth.clients.push(address.to_hex());
    })?;
    println!(
        "client {address} added; its key is in {} (owner-only). A running Guard accepts it after a restart.",
        out.display()
    );
    Ok(())
}

/// The client addresses a `/guard/status` answer lists.
fn status_clients(status: &Value) -> Vec<Address> {
    status
        .get("clients")
        .and_then(Value::as_array)
        .map(|clients| {
            clients
                .iter()
                .filter_map(Value::as_str)
                .filter_map(Address::from_hex)
                .collect()
        })
        .unwrap_or_default()
}

/// The client addresses of the config, each with whether the running
/// Guard (if one answers on the config's address) accepts it too.
fn client_list(paths: &Paths, target: &TargetArgs) -> Result<()> {
    let config = paths.load()?;
    let target = target.resolve(paths)?;
    let running = guard_status(&target).map(|status| status_clients(&status));
    let configured: Vec<Address> = config
        .auth
        .clients
        .iter()
        .filter_map(|text| Address::from_hex(text))
        .collect();
    for client in &configured {
        let note = match &running {
            Some(running) if !running.contains(client) => {
                "  (not yet accepted by the running Guard: restart it)"
            }
            _ => "",
        };
        println!("{client}{note}");
    }
    match &running {
        None => eprintln!("no Guard answers on {target}: the list is the config's"),
        Some(running) => {
            for client in running.iter().filter(|client| !configured.contains(client)) {
                println!(
                    "{client}  (REVOKED in the config, but the running Guard still accepts it: restart it now)"
                );
            }
        }
    }
    Ok(())
}

/// Remove a client address from the config.
fn client_revoke(paths: &Paths, address: &str, target: &TargetArgs) -> Result<()> {
    let config = paths.load()?;
    let target = target.resolve(paths)?;
    let Some(revoked) = Address::from_hex(address.trim()) else {
        bail!("{address} is not an address (0x and 40 hex digits)");
    };
    let listed = |text: &String| Address::from_hex(text) == Some(revoked);
    if !config.auth.clients.iter().any(listed) {
        bail!("{revoked} is not a client of this Guard (zunder-guard client list)");
    }
    if config.auth.clients.iter().all(listed) {
        bail!(
            "{revoked} is the last client: Guard needs one. Add another first (zunder-guard client add --out FILE), then revoke this one"
        );
    }
    GuardConfig::update(&paths.config, |config| {
        config.auth.clients.retain(|text| !listed(text));
    })?;
    println!("client {revoked} removed from {}", paths.config.display());
    // A running Guard reads its clients at start only, wherever it runs.
    println!(
        "Restart Guard now: a running Guard keeps accepting {revoked} until it restarts (positions keep their stops on the venue meanwhile)."
    );
    let still_accepted =
        guard_status(&target).is_some_and(|status| status_clients(&status).contains(&revoked));
    if still_accepted {
        eprintln!("WARNING: the Guard on {target} still accepts {revoked}");
    }
    Ok(())
}

/// The running Guard's status, human-readable (or as JSON).
fn status(paths: &Paths, args: &StatusArgs) -> Result<()> {
    let target = args.target.resolve(paths)?;
    let Some(status) = guard_status(&target) else {
        bail!("no Guard answers on {target} (is it running? zunder-guard health)");
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        for line in zunder_guard::statusview::describe(&status) {
            println!("{line}");
        }
    }
    Ok(())
}

/// The agent kit's MCP server, as its own binary runs it.
fn mcp(args: &zunder_guard_mcp::cli::Cli) -> Result<()> {
    let stdin = std::io::stdin();
    // The locked stdin is buffered already: no second copy of the key.
    let mut input = stdin.lock();
    let mut server = zunder_guard_mcp::cli::build(args, &mut input)?;
    eprintln!(
        "zunder-guard mcp {}: Guard at {}, {}",
        env!("CARGO_PKG_VERSION"),
        args.guard_url,
        server.client_address().map_or_else(
            || "read-only (no client key)".to_owned(),
            |address| format!("client key {address}")
        )
    );
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    zunder_guard_mcp::protocol::serve(&mut server, &mut input, &mut output)?;
    Ok(())
}

/// Mainnet's consent, before anything else for a mainnet start.
fn consent(config: &GuardConfig) -> Result<MainnetConsent> {
    config.check_mainnet()?;
    let account = zunder_venue::hyperliquid::Address::from_hex(&config.account()?.to_hex())
        .context("the account")?;
    MainnetConsent::from_env(account).with_context(|| {
        format!(
            "mainnet needs {CONFIRM_VAR} naming the account at this start (docs/guard.md, \"Mainnet\")"
        )
    })
}

/// Whether Guard runs in a container: `--container` (or
/// `ZUNDER_GUARD_CONTAINER`), or Docker's marker file. Podman and others
/// pass the flag; an environment variable alone (`container`, set by
/// systemd-nspawn and others) does not relax the key file check.
fn in_container(flag: bool) -> bool {
    flag || Path::new("/.dockerenv").exists()
}

/// Read the key from a file only its owner can read (in a container,
/// one nobody else can write: [`zunder_guard::keyread::key_from_file`]).
fn key_from_file(path: &Path, container: bool) -> Result<GuardKey> {
    let (key, warning) = zunder_guard::keyread::key_from_file(path, container)?;
    if let Some(warning) = warning {
        eprintln!("WARNING: {warning}");
    }
    Ok(key)
}

async fn run(paths: &Paths, args: RunArgs) -> Result<()> {
    if !paths.config.exists() {
        auto_init(paths, &args).await?;
    }
    let mut config = paths.load()?;
    let overridden = args.ip_share.is_some_and(|share| share != config.ip_share);
    if let Some(share) = args.ip_share {
        config.ip_share = share;
        config.validate()?;
    }
    let budgets = config.budgets()?;
    let network = config.network()?;
    let container = in_container(args.container);
    // The mode: --network (or ZUNDER_GUARD_NETWORK) and the config agree.
    let mode = match args.network.map(ModeArg::mode) {
        None if config.mode != GuardMode::Paper => bail!(
            "the config is for {}: pass --network {} to send, or run init again for paper",
            config.mode.name(),
            config.mode.name()
        ),
        None | Some(GuardMode::Paper) => GuardMode::Paper,
        Some(mode) => mode,
    };
    let paper = mode == GuardMode::Paper;
    if let Some(binding_path) = &args.service_binding {
        let binding = zunder_guard::service::load_binding(binding_path)?;
        if binding.home != paths.home
            || binding.config != paths.config
            || mode != GuardMode::Mainnet
        {
            bail!("runtime paths or mode differ from service admission");
        }
        zunder_guard::service::verify_child(&binding)?;
        // Admit the same snapshot used below for journals, budgets and Setup,
        // after ip-share overrides; a second matching disk read is insufficient.
        binding.validate_runtime_config(&config)?;
        if args
            .listen
            .as_ref()
            .is_some_and(|listen| listen != &config.listen)
        {
            bail!("service listen override differs from the admitted runtime config");
        }
    } else if mode == GuardMode::Mainnet
        && let Some(reason) = platform::NO_MAINNET
    {
        bail!("{reason}");
    }
    // Every check of the config and the journal before the key is read.
    let venue = match mode.network() {
        None => {
            if args.key_stdin || args.key_file.is_some() {
                bail!("paper mode reads no key; pass --network to send");
            }
            None
        }
        Some(sends_to) => {
            config.require_network(sends_to)?;
            Some(match sends_to {
                GuardNetwork::Testnet => VenueNetwork::testnet(),
                GuardNetwork::Mainnet => {
                    if !args.key_stdin {
                        bail!(
                            "a mainnet key comes only on standard input (--key-stdin), as for Zunder's runner"
                        );
                    }
                    VenueNetwork::mainnet(consent(&config)?)
                }
            })
        }
    };
    if venue.is_some() && !args.key_stdin && args.key_file.is_none() {
        let default = paths.home.join(KEY_FILE);
        // Windows: the Credential Manager is looked at only when the key is
        // read, after every check of the config and the journal.
        if !default.exists() && !cfg!(windows) {
            bail!(
                "sending needs the API wallet key: --key-stdin, or --key-file (ZUNDER_GUARD_KEY_FILE){}",
                if cfg!(windows) {
                    ", or init to keep it in the Credential Manager"
                } else {
                    ""
                }
            );
        }
    }
    let journal_path = config.risk_journal(paper);
    if !journal_path.exists() {
        bail!(
            "no risk journal at {}: starting one is a person's decision (zunder-guard journal-init --mode {}, docs/guard.md)",
            journal_path.display(),
            mode.name()
        );
    }
    let risk = PersistentRisk::open_for(
        &journal_path,
        &config.policy.risk_limits(),
        &config.journal_scope(paper)?,
    )
    .context("opening the risk journal")?;
    let journal = DecisionJournal::open(&config.decision_journal(paper))?;
    let listen = match &args.listen {
        Some(listen) => listen
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .with_context(|| format!("cannot listen on {listen}"))?,
        None => config.listen_addr()?,
    };
    if !listen.ip().is_loopback() {
        eprintln!(
            "WARNING: listening on {listen}, not on localhost. Anyone who reaches this port can send orders signed with a client key. Publish it only on 127.0.0.1 or a private network."
        );
    }
    if config.ip_share < rust_decimal::Decimal::ONE || overridden {
        eprintln!(
            "ip_share {}{}: {} of the venue's 1,200 request weight a minute on this IP address; the sync every {:.1} s, bots' requests {} a second (a burst of {}), reserve for protection {} a minute",
            config.ip_share,
            if overridden {
                " (from --ip-share or ZUNDER_GUARD_IP_SHARE, not the config)"
            } else {
                ""
            },
            budgets.weight_per_minute,
            budgets.sync_interval_ms(config.sync_seconds) as f64 / 1_000.0,
            zunder_guard::budget::thousandths(budgets.requests.milli_per_second),
            budgets.requests.burst,
            budgets.reserve_per_minute,
        );
    }
    let account = config.account()?;
    let clock = SystemClock;
    // The fee of the account's network: charged when sending there, and
    // reported (never charged, never blocking) in paper mode.
    let fee_network = match network {
        GuardNetwork::Mainnet => licence::FeeNetwork::Mainnet,
        GuardNetwork::Testnet => licence::FeeNetwork::Testnet,
    };
    let (fee, fee_warning) = licence::fee_mode(
        fee_network,
        config.licence.as_deref(),
        LICENCE_PUBLIC_KEY.as_ref(),
        clock.now_ms() as i64,
        account,
    );
    if let Some(warning) = &fee_warning {
        eprintln!("WARNING: {warning}");
    }
    let mut supervised_shutdown = None;
    match venue {
        None => {
            let upstream = Hyperliquid::paper(network.venue())?;
            let setup = Setup {
                config,
                mode: Mode::Paper,
                risk,
                journal,
                fee,
                fee_warning,
                limits: Default::default(),
            };
            serve(
                setup,
                upstream,
                clock,
                listen,
                &paths.config,
                supervised_shutdown,
            )
            .await
        }
        Some(venue) => {
            let key = if args.supervised_stdin {
                let mut input = stdin_fd()?;
                let bytes = zunder_guard::service::read_key_frame(&mut input)?;
                let key = zunder_guard::keyread::key_from_text(
                    std::str::from_utf8(&bytes)?,
                    "supervisor stdin",
                )?;
                let (tx, rx) = tokio::sync::oneshot::channel();
                std::thread::spawn(move || {
                    let reason = zunder_guard::service::await_parent_close(&mut input);
                    let _ = tx.send(reason);
                });
                supervised_shutdown = Some(rx);
                key
            } else if args.key_stdin {
                read_key(&mut stdin_fd()?, "standard input")?
            } else if let Some(path) = &args.key_file {
                key_from_file(path, container)?
            } else if let Some(key) = windows_key(&paths.config)? {
                key
            } else {
                // Elsewhere, and on Windows without an entry in the Credential
                // Manager (a key stored with --key-store file): the default
                // key file, checked as any key file.
                let default = paths.home.join(KEY_FILE);
                if cfg!(windows) && !default.exists() {
                    bail!(
                        "no API wallet key for this configuration: not in the Windows Credential Manager and no {} (run zunder-guard init for testnet, or pipe the key with --key-stdin)",
                        default.display()
                    );
                }
                key_from_file(&default, container)?
            };
            // A key of another wallet stops here, before it signs anything.
            config.check_api_wallet(key.address())?;
            let upstream = Hyperliquid::sending(venue)?;
            if let Some(parent) = supervised_shutdown.as_mut() {
                tokio::select! {
                    biased;
                    _ = parent => return Ok(()),
                    checked = venue_checks(&upstream, &key, account) => checked?,
                }
            } else {
                venue_checks(&upstream, &key, account).await?;
            }
            let signing = if venue.is_mainnet() {
                SigningNetwork::Mainnet
            } else {
                SigningNetwork::Testnet
            };
            let setup = Setup {
                config,
                mode: Mode::Send {
                    key,
                    network: signing,
                },
                risk,
                journal,
                fee,
                fee_warning,
                limits: Default::default(),
            };
            serve(
                setup,
                upstream,
                clock,
                listen,
                &paths.config,
                supervised_shutdown,
            )
            .await
        }
    }
}

/// An empty home in a container: set up paper mode from
/// `ZUNDER_GUARD_RULES` and `ZUNDER_GUARD_ACCOUNT`, as `init
/// --non-interactive` would, with the same checks. Only paper: a sending
/// mode is a person's setup (`init`).
async fn auto_init(paths: &Paths, args: &RunArgs) -> Result<()> {
    let Some(rules) = &args.rules else {
        bail!(
            "not initialised: {} does not exist (run zunder-guard init, or set ZUNDER_GUARD_RULES and ZUNDER_GUARD_ACCOUNT for paper mode)",
            paths.config.display()
        );
    };
    if args.network.is_some_and(|mode| mode != ModeArg::Paper) {
        bail!(
            "an empty home sets up paper mode only; run zunder-guard init for testnet or mainnet"
        );
    }
    let options = InitOptions {
        config: paths.config.clone(),
        state_dir: PathBuf::from("."),
        rules: Some(rules.clone()),
        non_interactive: true,
        account: args.account.clone(),
        mode: Some(GuardMode::Paper),
        no_key: true,
        ip_share: args.ip_share,
        ..InitOptions::default()
    };
    let unused = OwnerOnlyFile {
        path: paths.home.join(KEY_FILE),
        replace: false,
    };
    let mut random = init::os_random;
    init::init(&options, &mut Batch, None, &VenueInfo, &unused, &mut random).await?;
    eprintln!(
        "set up paper mode in {} from the environment",
        paths.home.display()
    );
    Ok(())
}

/// `--ip-share`: a decimal such as `0.5` or `0.3333`; its bounds are the
/// config's (`GuardConfig::validate`).
fn parse_share(text: &str) -> std::result::Result<rust_decimal::Decimal, String> {
    text.trim()
        .parse::<rust_decimal::Decimal>()
        .map_err(|_| format!("`{text}` is not a decimal such as 0.5"))
}

/// The venue's own checks: the key is an API wallet of the account, and
/// the account is in standard mode.
async fn venue_checks(upstream: &Hyperliquid, key: &GuardKey, account: Address) -> Result<()> {
    let role = upstream.info(&requests::user_role(key.address())).await?;
    check_api_wallet_role(&role, key.address(), account).map_err(anyhow::Error::msg)?;
    let mode = upstream.info(&requests::user_abstraction(account)).await?;
    if mode.as_str() != Some("disabled") {
        bail!(
            "the account is in Hyperliquid's account mode {mode}; Guard judges standard mode (`disabled`) only: switch it in the web app"
        );
    }
    Ok(())
}

async fn serve<U: Upstream>(
    setup: Setup,
    upstream: U,
    clock: SystemClock,
    addr: SocketAddr,
    config_path: &Path,
    supervised_shutdown: Option<tokio::sync::oneshot::Receiver<&'static str>>,
) -> Result<()> {
    let mode = setup.mode.name();
    let auto_update = setup.config.licence_auto_update;
    // A stop asked for from here on (while the first sync or the stream's
    // start still waits) ends Guard cleanly: its journal synced.
    let shutdown = platform::shutdown().context("signal handlers")?;
    let shutdown = async move {
        match supervised_shutdown {
            Some(mut parent) => tokio::select! {
                biased;
                reason = &mut parent => reason.unwrap_or("supervisor monitor stopped"),
                reason = shutdown => reason,
            },
            None => shutdown.await,
        }
    };
    tokio::pin!(shutdown);
    let guard = Guard::new(setup, upstream, clock).map_err(anyhow::Error::msg)?;
    // A new licence key in the config (`licence set`, or a renewal) applies
    // at the next sync.
    tokio::select! {
        biased;
        reason = &mut shutdown => { guard.stopped(reason).await; return Ok(()); }
        () = guard.watch_config(config_path.to_owned()) => {}
    }
    // Renewal from Orcastrate's licence service: only when the user
    // switched it on (`licence_auto_update`).
    let renewal = auto_update.then(|| tokio::spawn(renew_forever(config_path.to_owned())));
    // After a crash: what became of actions sent before it, from the
    // venue (docs/guard.md#journals). Taken now, before anything runs;
    // recovered beside the sync, which protects and flattens meanwhile;
    // bots' requests wait until it is done; /healthz says "recovering".
    let pending = guard.pending_for_recovery().await;
    guard.set_recovering(!pending.is_empty());
    let (bound, server) = server::bind(guard.clone(), addr)
        .await
        .with_context(|| format!("listening on {addr}"))?;
    let sync = tokio::spawn(guard.clone().sync_forever());
    // The account over the venue's WebSocket: a request is judged from it
    // when it is clean, else after a read (docs/guard.md, "The account
    // stream").
    let stream = tokio::select! {
        biased;
        reason = &mut shutdown => {
            server.abort(); sync.abort();
            if let Some(renewal) = renewal { renewal.abort(); }
            guard.stopped(reason).await;
            return Ok(());
        }
        stream = guard.start_stream() => stream,
    };
    let recovery = {
        let guard = guard.clone();
        let count = pending.len();
        if count > 0 {
            eprintln!(
                "zunder-guard {mode}: recovering the outcome of {count} action(s) sent before a restart"
            );
        }
        let task = tokio::spawn({
            let guard = guard.clone();
            async move {
                guard.recover(pending).await;
            }
        });
        let abort = task.abort_handle();
        // A recovery that panicked has served bots again (its flag is
        // cleared however it ends): a person looks at the account.
        tokio::spawn(async move {
            if let Err(error) = task.await
                && error.is_panic()
            {
                guard.recovery_failed().await;
            }
        });
        abort
    };
    eprintln!("zunder-guard {mode}: listening on http://{bound} (ws://{bound}/ws)");
    let reason = shutdown.await;
    server.abort();
    sync.abort();
    recovery.abort();
    if let Some(renewal) = renewal {
        renewal.abort();
    }
    if let Some(stream) = stream {
        stream.abort();
    }
    // Its event, and every record before it, written and synced.
    guard.stopped(reason).await;
    eprintln!("zunder-guard stopped ({reason})");
    Ok(())
}

/// `GET /healthz` on Guard's listen address answers 200.
fn health(args: &HealthArgs) -> Result<()> {
    let target = match &args.url {
        Some(url) => url
            .strip_prefix("http://")
            .and_then(|rest| rest.split('/').next())
            .context("--url must be http://host:port")?
            .to_owned(),
        None => args
            .listen
            .clone()
            .unwrap_or_else(|| GuardConfig::default().listen),
    };
    let addr = healthz(&target)?;
    println!("healthy ({addr})");
    Ok(())
}

/// The status of the Guard listening on `listen`, if one answers.
fn guard_status(listen: &str) -> Option<Value> {
    let target = listen
        .replace("0.0.0.0:", "127.0.0.1:")
        .replace("[::]:", "[::1]:");
    let addr = target.to_socket_addrs().ok()?.next()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    write!(
        stream,
        "GET /guard/status HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
    )
    .ok()?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer).ok()?;
    let (_, body) = answer.split_once("\r\n\r\n")?;
    serde_json::from_str(body).ok()
}

/// Ask the Guard listening on `listen` for `/healthz`; its address when it
/// answers 200.
fn healthz(listen: &str) -> Result<std::net::SocketAddr> {
    let target = listen
        .replace("0.0.0.0:", "127.0.0.1:")
        .replace("[::]:", "[::1]:");
    let addr = target
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .with_context(|| format!("cannot resolve {target}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .with_context(|| format!("unhealthy: {addr}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
    write!(stream, "GET /healthz HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").context("unhealthy")?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer).ok();
    let status = answer.lines().next().unwrap_or("");
    if status.split_whitespace().nth(1) == Some("200") {
        Ok(addr)
    } else {
        bail!("unhealthy: {status}")
    }
}

/// The account's equity now, read from the venue's public data: the perp
/// account's value, standard mode only.
async fn equity_of(network: GuardNetwork, account: Address) -> Result<rust_decimal::Decimal> {
    let client = InfoClient::new(network.venue())?;
    let mode = client.post(&requests::user_abstraction(account)).await?;
    if mode.as_str() != Some("disabled") {
        bail!("the account is in account mode {mode}; Guard needs standard mode (`disabled`)");
    }
    let state = client.post(&requests::clearinghouse_state(account)).await?;
    let text = state
        .pointer("/marginSummary/accountValue")
        .and_then(Value::as_str)
        .context("no account value in the answer")?;
    text.parse().context("the account value is not a decimal")
}

fn checked_journal(config: &GuardConfig, mode: ModeArg) -> Result<(PathBuf, bool)> {
    let mode = mode.mode();
    if let Some(network) = mode.network() {
        config.require_network(network)?;
        if network == GuardNetwork::Mainnet {
            consent(config)?;
        }
    }
    let paper = mode == GuardMode::Paper;
    Ok((config.risk_journal(paper), paper))
}

async fn journal_init(paths: &Paths, args: JournalArgs) -> Result<()> {
    let config = paths.load()?;
    // The confirmation comes first: nothing is created for a refused start.
    let (path, paper) = checked_journal(&config, args.mode)?;
    if !paper {
        config.check_no_old_mainnet_journal()?;
    }
    if path.exists() {
        bail!(
            "{} exists; a risk journal is never replaced",
            path.display()
        );
    }
    let equity = equity_of(config.network()?, config.account()?).await?;
    fs::create_dir_all(&config.state_dir)
        .with_context(|| format!("creating {}", config.state_dir.display()))?;
    let now = Timestamp::from_millis(SystemClock.now_ms() as i64);
    PersistentRisk::initialise_for(
        &path,
        config.policy.risk_limits(),
        &config.journal_scope(paper)?,
        now,
        equity,
        &args.note,
    )?;
    println!("started {} at equity {equity}", path.display());
    Ok(())
}

async fn journal_resume(paths: &Paths, args: JournalArgs) -> Result<()> {
    let config = paths.load()?;
    let (path, paper) = checked_journal(&config, args.mode)?;
    let mut risk = PersistentRisk::open_for(
        &path,
        &config.policy.risk_limits(),
        &config.journal_scope(paper)?,
    )
    .context("opening the risk journal (stop Guard first)")?;
    risk.check_review_ready()?;
    let equity = equity_of(config.network()?, config.account()?).await?;
    let now = Timestamp::from_millis(SystemClock.now_ms() as i64);
    let state = risk.resume_after_review(now, equity, &args.note)?;
    println!("risk state after the review: {state:?} (equity {equity})");
    Ok(())
}

fn journal_show(paths: &Paths, args: &ShowArgs) -> Result<()> {
    let config = paths.load()?;
    let paper = args.mode == ModeArg::Paper;
    for record in PersistentRisk::read(&config.risk_journal(paper))? {
        println!("{}", serde_json::to_string(&record)?);
    }
    Ok(())
}

/// Write the kill file. It must work when it is needed most, so a config
/// that no longer validates still names its state directory (read leniently
/// from the file); only a config that cannot be found or read at all stops
/// it.
fn kill(paths: &Paths, args: &KillArgs) -> Result<()> {
    // How often the running Guard's sync looks: `sync_seconds`, or slower
    // with HIP-3 dexes and a smaller `ip_share`.
    let (path, listen, sync_ms) = match paths.load() {
        Ok(config) => (
            config.kill_file(),
            Some(config.listen.clone()),
            config
                .budgets()
                .map_or(config.sync_seconds * 1_000, |budgets| {
                    budgets.sync_interval_ms(config.sync_seconds)
                }),
        ),
        Err(error) => {
            let text = fs::read_to_string(&paths.config)
                .with_context(|| format!("reading {}", paths.config.display()))?;
            let table: toml::Table = toml::from_str(&text).unwrap_or_default();
            let base = paths
                .config
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
            // As `GuardConfig::load` resolves it, the default included.
            let state_dir = table
                .get("state_dir")
                .and_then(toml::Value::as_str)
                .map_or_else(
                    || base.join(GuardConfig::default().state_dir),
                    |dir| base.join(dir),
                );
            eprintln!(
                "WARNING: the config does not validate ({error:#}); writing the kill file into {} anyway",
                state_dir.display()
            );
            let listen = table
                .get("listen")
                .and_then(toml::Value::as_str)
                .map(str::to_owned);
            (
                state_dir.join("kill"),
                listen,
                GuardConfig::default().sync_seconds * 1_000,
            )
        }
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file =
        fs::File::create(&path).with_context(|| format!("writing {}", path.display()))?;
    writeln!(file, "{}", args.reason)?;
    file.sync_all()?;
    println!(
        "wrote {}: a running Guard opens nothing and flattens within {:.1} s (its next sync); remove the file and restart Guard to undo",
        path.display(),
        sync_ms as f64 / 1_000.0,
    );
    let listen = listen.unwrap_or_else(|| GuardConfig::default().listen);
    match guard_status(&listen) {
        None => eprintln!(
            "WARNING: no Guard answers on {listen}. If one runs elsewhere (another config, another home, a container), this file does not reach it: kill that one with its own config, or stop it."
        ),
        Some(status) => {
            let watched = status
                .get("kill_file")
                .and_then(Value::as_str)
                .map(PathBuf::from);
            let same = watched.as_ref().is_some_and(|watched| {
                let canonical =
                    |path: &Path| path.canonicalize().unwrap_or_else(|_| path.to_owned());
                canonical(watched) == canonical(&path)
            });
            if !same {
                eprintln!(
                    "WARNING: the Guard on {listen} watches {}, not {}: this kill does not reach it. Kill it with its own config, or stop it.",
                    watched.map_or_else(
                        || "an unknown file".to_owned(),
                        |watched| watched.display().to_string()
                    ),
                    path.display()
                );
            }
        }
    }
    Ok(())
}

/// `licence set`: check the key for the configured account, write it into
/// the config, and wait for a running Guard to report it applied.
fn licence_set(paths: &Paths, key: &str, target: &TargetArgs) -> Result<()> {
    let config = paths.load()?;
    let account = config.account()?;
    let now = SystemClock.now_ms() as i64;
    let checked = licence_life::check_key(key.trim(), LICENCE_PUBLIC_KEY.as_ref(), account, now)
        .map_err(|error| anyhow::anyhow!("licence key refused, config unchanged: {error}"))?;
    let key = key.trim().to_owned();
    GuardConfig::update(&paths.config, |config| config.licence = Some(key))?;
    println!(
        "licence for {} until {} written to {}",
        checked.licensee,
        zunder_guard::guard::utc_text(checked.expires_at_ms),
        paths.config.display()
    );
    let target = target.resolve(paths)?;
    if guard_status(&target).is_none() {
        println!("no Guard answers on {target}: it uses the key when it starts");
        return Ok(());
    }
    // The running Guard reads it at its next sync.
    let wait = Duration::from_secs(config.sync_seconds.saturating_mul(3).max(15));
    let started = std::time::Instant::now();
    while started.elapsed() < wait {
        if let Some(status) = guard_status(&target)
            && status["licence"]["licensee"].as_str() == Some(checked.licensee.as_str())
            && status["licence"]["expires_at_ms"].as_i64() == Some(checked.expires_at_ms)
        {
            println!(
                "the running Guard applied it: fee {}",
                status["fee"]["mode"].as_str().unwrap_or("?")
            );
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    println!(
        "the running Guard on {target} has not reported the new key within {} s; check zunder-guard licence show",
        wait.as_secs()
    );
    Ok(())
}

/// `licence show`: the key in the config, and the running Guard's view.
fn licence_show(paths: &Paths, target: &TargetArgs) -> Result<()> {
    let config = paths.load()?;
    let account = config.account()?;
    let now = SystemClock.now_ms() as i64;
    for line in licence_life::describe(
        config.licence.as_deref(),
        LICENCE_PUBLIC_KEY.as_ref(),
        account,
        now,
    ) {
        println!("{line}");
    }
    println!(
        "automatic renewal: {}",
        if config.licence_auto_update {
            "on (asks zunderlabs.com for a renewed key from 14 days before the end)"
        } else {
            "off (nothing is fetched; set licence_auto_update and licence_renewal_token to switch it on)"
        }
    );
    let target = target.resolve(paths)?;
    match guard_status(&target) {
        Some(status) => println!(
            "running Guard on {target}: licence {}, fee {}",
            status["licence"]["state"].as_str().unwrap_or("?"),
            status["fee"]["mode"].as_str().unwrap_or("?")
        ),
        None => println!("no Guard answers on {target}"),
    }
    Ok(())
}

/// Renewal from Orcastrate's licence service (`licence_auto_update`, off
/// by default): look every hour, ask at most every six hours while due.
async fn renew_forever(path: PathBuf) {
    tokio::time::sleep(Duration::from_secs(60)).await;
    let mut last_ask: Option<std::time::Instant> = None;
    loop {
        let may_ask =
            last_ask.is_none_or(|at| at.elapsed() >= Duration::from_millis(licence_life::RETRY_MS));
        if may_ask {
            let now = SystemClock.now_ms() as i64;
            let mut asked = false;
            let result =
                licence_life::renew_once(&path, LICENCE_PUBLIC_KEY.as_ref(), now, |body| {
                    asked = true;
                    post_renewal(body)
                })
                .await;
            if asked {
                last_ask = Some(std::time::Instant::now());
            }
            match result {
                Ok(licence_life::Renewal::Renewed {
                    licensee,
                    expires_at_ms,
                }) => eprintln!(
                    "zunder-guard: renewed licence for {licensee} until {} written to {}; applied at the next sync",
                    zunder_guard::guard::utc_text(expires_at_ms),
                    path.display()
                ),
                Ok(licence_life::Renewal::NotYet) => eprintln!(
                    "zunder-guard: the licence service has no renewed key yet; asking again in {} h",
                    licence_life::RETRY_MS / 3_600_000
                ),
                Ok(_) => {}
                Err(error) => eprintln!("zunder-guard: licence renewal: {error}"),
            }
        }
        tokio::time::sleep(Duration::from_millis(licence_life::LOOK_EVERY_MS)).await;
    }
}

/// One request to the licence service: its HTTP status and JSON answer.
async fn post_renewal(body: Value) -> std::result::Result<(u16, Value), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(licence_life::REQUEST_TIMEOUT_MS))
        .build()
        .map_err(|error| error.to_string())?;
    let mut response = client
        .post(licence_life::RENEWAL_URL)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|error| format!("asking the licence service: {}", error.without_url()))?;
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        format!(
            "reading the licence service's answer: {}",
            error.without_url()
        )
    })? {
        bytes.extend_from_slice(&chunk);
        if bytes.len() > licence_life::MAX_ANSWER_BYTES {
            return Err("the licence service's answer is too long".to_owned());
        }
    }
    let answer = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok((status, answer))
}

fn check_config(paths: &Paths) -> Result<()> {
    let config = paths.load()?;
    println!(
        "{}: valid; mode {} for an account on {}; account {}, API wallet {}, {} client(s), listening on {}",
        paths.config.display(),
        config.mode.name(),
        config.network()?.name(),
        config.account()?,
        config.api_wallet.as_deref().unwrap_or("(none: paper only)"),
        config.auth.clients.len(),
        config.listen
    );
    println!("rules: {}", rules::encode(&config.policy));
    for line in init::describe(&config.policy) {
        println!("{line}");
    }
    Ok(())
}

fn service_command(paths: &Paths, command: ServiceCommand) -> Result<()> {
    use zunder_guard::service::{self, ServiceBinding, ServiceIdentity};
    match command {
        ServiceCommand::Prepare {
            credential_id,
            confirm_mainnet,
            uid,
            gid,
            service_name,
            service_sid,
        } => {
            let config = paths.load()?;
            config.check_mainnet()?;
            if config.mode != GuardMode::Mainnet
                || config.account()?
                    != Address::from_hex(&confirm_mainnet)
                        .context("invalid mainnet confirmation address")?
            {
                bail!("service preparation needs the configured mainnet account confirmation");
            }
            let identity = match (uid, gid, service_name, service_sid) {
                (Some(uid), Some(gid), None, None) => ServiceIdentity::Macos { uid, gid },
                (None, None, Some(service_name), Some(service_sid)) => ServiceIdentity::Windows {
                    service_name,
                    service_sid,
                },
                _ => bail!("provide exactly one complete OS service identity"),
            };
            let executable = fs::canonicalize(std::env::current_exe()?)?;
            let binding = ServiceBinding {
                version: 1,
                credential_id,
                mode: "mainnet".into(),
                account: config.account()?.to_hex(),
                api_wallet: config
                    .api_wallet
                    .clone()
                    .context("mainnet API wallet missing")?,
                home: fs::canonicalize(&paths.home)?,
                config: fs::canonicalize(&paths.config)?,
                executable_sha256: service::hash_file(&executable)?,
                executable,
                admission_config_sha256: service::config_fingerprint(&config)?,
                identity,
            };
            binding.validate()?;
            println!("{}", serde_json::to_string_pretty(&binding)?);
        }
        ServiceCommand::Provision {
            binding,
            confirm_mainnet,
            key_stdin,
            replace,
        } => {
            let binding = service::load_binding(&binding)?;
            binding.validate()?;
            if Address::from_hex(&confirm_mainnet)
                .context("invalid mainnet confirmation address")?
                != Address::from_hex(&binding.account).context("invalid bound account")?
            {
                bail!("credential provisioning needs the exact admitted account confirmation");
            }
            service::validate_provision(&binding)?;
            let key = if key_stdin {
                service::read_key_frame(&mut stdin_fd()?)?
            } else {
                zeroize::Zeroizing::new(
                    rpassword::prompt_password("API wallet key (hidden): ")?.into_bytes(),
                )
            };
            service::provision(&binding, &key, replace)?;
            eprintln!(
                "Stored the API wallet credential in the OS secure store; no service was started."
            );
        }
        ServiceCommand::Check { binding } => {
            let binding = service::load_binding(&binding)?;
            service::check(&binding)?;
            eprintln!(
                "Service metadata and credential presence checked; runtime journal checks still apply at start."
            );
        }
        ServiceCommand::Run { binding } => {
            let path = fs::canonicalize(binding)?;
            let binding = service::load_binding(&path)?;
            service::run(&binding, &path)?;
        }
        ServiceCommand::MigrateCredential {
            binding,
            next_binding,
            confirm_mainnet,
        } => {
            let binding = service::load_binding(&binding)?;
            #[cfg(target_os = "macos")]
            service::macos::migrate(&binding, &next_binding, &confirm_mainnet)?;
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (binding, next_binding, confirm_mainnet);
                bail!("credential migration is a macOS release operation");
            }
        }
        ServiceCommand::Readmit {
            binding,
            confirm_mainnet,
        } => {
            let path = fs::canonicalize(binding)?;
            let mut binding = service::load_binding(&path)?;
            if Some(Address::from_hex(&confirm_mainnet).context("invalid confirmation")?)
                != Address::from_hex(&binding.account)
            {
                bail!("readmission requires the exact admitted mainnet account");
            }
            service::validate_management_stopped(&binding)?;
            let config = service::load_config(&binding)?;
            binding.admission_config_sha256 = service::config_fingerprint(&config)?;
            binding.validate()?;
            service::write_binding(&path, &binding)?;
            eprintln!(
                "Reviewed configuration re-admitted. Service remains stopped; no journal was initialized or resumed."
            );
        }
        ServiceCommand::LicenceSet { binding, key } => {
            let binding = service::load_binding(&binding)?;
            let config = binding.validate()?;
            let checked = licence_life::check_key(
                key.trim(),
                LICENCE_PUBLIC_KEY.as_ref(),
                config.account()?,
                SystemClock.now_ms() as i64,
            )
            .map_err(|_| anyhow::anyhow!("licence key refused; service config unchanged"))?;
            let mut next = config.clone();
            next.licence = Some(key.trim().to_owned());
            service::write_config(&binding, &config, &next)?;
            println!(
                "Licence for {} until {} saved with service ownership preserved. A running Guard applies it on its next sync; use service licence-show to verify.",
                checked.licensee,
                zunder_guard::guard::utc_text(checked.expires_at_ms)
            );
        }
        ServiceCommand::LicenceShow { binding } => {
            let binding = service::load_binding(&binding)?;
            let config = binding.validate()?;
            for line in licence_life::describe(
                config.licence.as_deref(),
                LICENCE_PUBLIC_KEY.as_ref(),
                config.account()?,
                SystemClock.now_ms() as i64,
            ) {
                println!("{line}");
            }
            if let Some(status) = guard_status(&config.listen) {
                println!(
                    "running licence {}, fee {}",
                    status["licence"]["state"].as_str().unwrap_or("?"),
                    status["fee"]["mode"].as_str().unwrap_or("?")
                );
            } else {
                println!("service runtime is not answering on {}", config.listen);
            }
        }
        ServiceCommand::Pair {
            binding,
            confirm_mainnet,
        } => {
            let binding = service::load_binding(&binding)?;
            if Address::from_hex(&confirm_mainnet) != Address::from_hex(&binding.account) {
                bail!("pairing requires the exact admitted mainnet account");
            }
            service::validate_management_stopped(&binding)?;
            let config = binding.validate()?;
            let mut next = config.clone();
            let (secret, address) = init::new_client(&mut init::os_random)?;
            let (code, hash) = init::pairing(&mut init::os_random)?;
            next.auth.clients.push(address.to_hex());
            next.pairing_sha3 = Some(hash);
            service::write_config(&binding, &config, &next)?;
            println!("Client key (shown once): {}", secret.as_str());
            println!("Pairing code (shown once): {code}");
            println!(
                "Service remains stopped. Explicitly readmit the client change before restarting."
            );
        }
        ServiceCommand::RemoveCredential { binding } => {
            let binding = service::load_binding(&binding)?;
            service::remove(&binding)?;
        }
    }
    Ok(())
}
