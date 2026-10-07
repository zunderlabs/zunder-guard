// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The command line. Standalone binary `zunder-guard-mcp`; the Guard
//! binary can expose the same as `zunder-guard mcp` by calling
//! [`build`] and [`crate::protocol::serve`].
//!
//! The client key is never an argument and never read from the
//! environment: `--key-file` names a file only its owner can read, and
//! `--key-stdin` reads it from the first line of standard input. Nothing
//! here reads an environment variable.

use std::{io::BufRead, path::PathBuf};

use clap::{Parser, ValueEnum};

use crate::{
    contract::Mode,
    guard::{DEFAULT_GUARD_URL, GuardClient, GuardError, GuardUrl, UrlError},
    key::{self, KeyError},
    ratelimit::SystemClock,
    tools::{Config, Server},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Network {
    Paper,
    Testnet,
    Mainnet,
}

impl From<Network> for Mode {
    fn from(network: Network) -> Self {
        match network {
            Network::Paper => Mode::Paper,
            Network::Testnet => Mode::Testnet,
            Network::Mainnet => Mode::Mainnet,
        }
    }
}

/// MCP server (stdio) with guarded trading tools on Hyperliquid through a
/// local Zunder Guard. See docs/guard-mcp.md.
#[derive(Debug, Parser)]
#[command(name = "zunder-guard-mcp", version)]
pub struct Cli {
    /// Guard's address. Loopback only.
    #[arg(long, default_value = DEFAULT_GUARD_URL)]
    pub guard_url: String,

    /// The network Guard must be running. Orders are refused when Guard
    /// runs another one. Mainnet only works with a Guard that runs mainnet.
    #[arg(long, value_enum, default_value = "paper")]
    pub network: Network,

    /// A file holding this agent's Guard client key; it must be readable by
    /// its owner only (chmod 600).
    #[arg(long, value_name = "PATH", conflicts_with = "key_stdin")]
    pub key_file: Option<PathBuf>,

    /// Read the client key from the first line of standard input; the MCP
    /// messages follow on the same input.
    #[arg(long)]
    pub key_stdin: bool,

    /// Guard's kill file (`state_dir/kill` of its config), so that the
    /// kill_switch tool can pull it. Without it the tool says how to pull
    /// it by hand.
    #[arg(long, value_name = "PATH")]
    pub kill_file: Option<PathBuf>,

    /// Mainnet only, and required there: the account Guard trades, named by
    /// a person. Every order request is refused unless Guard reports this
    /// account.
    #[arg(long, value_name = "0x…")]
    pub confirm_account: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Url(#[from] UrlError),
    #[error("the client key: {0}")]
    Key(#[from] KeyError),
    #[error("cannot set up the connection to Guard: {0}")]
    Guard(#[from] GuardError),
    #[error(
        "--network mainnet needs a client key (--key-file or --key-stdin): a read-only server has no reason to name mainnet"
    )]
    MainnetWithoutKey,
    #[error(
        "--network mainnet needs --confirm-account with the account Guard trades (0x and 40 hex digits)"
    )]
    MainnetWithoutAccount,
    #[error("--confirm-account is for mainnet only")]
    AccountWithoutMainnet,
}

/// Build the server from the command line. Reads the key (from the file,
/// or from the first line of `input` with `--key-stdin`); connects to
/// nothing yet.
pub fn build(cli: &Cli, input: &mut impl BufRead) -> Result<Server, CliError> {
    let url = GuardUrl::parse(&cli.guard_url)?;
    let key = match (&cli.key_file, cli.key_stdin) {
        (Some(path), _) => Some(key::from_file(path)?),
        (None, true) => Some(key::read_first_line(input)?),
        (None, false) => None,
    };
    let confirm_account = cli
        .confirm_account
        .as_deref()
        .map(|text| crate::sanitize::address(text).ok_or(CliError::MainnetWithoutAccount))
        .transpose()?;
    match (cli.network, &key, &confirm_account) {
        (Network::Mainnet, None, _) => return Err(CliError::MainnetWithoutKey),
        (Network::Mainnet, Some(_), None) => return Err(CliError::MainnetWithoutAccount),
        (Network::Paper | Network::Testnet, _, Some(_)) => {
            return Err(CliError::AccountWithoutMainnet);
        }
        _ => {}
    }
    let guard = GuardClient::new(url)?;
    Ok(Server::new(
        Config {
            network: cli.network.into(),
            kill_file: cli.kill_file.clone(),
            confirm_account,
            kill_confirm_wait_ms: crate::tools::KILL_CONFIRM_WAIT_MS,
        },
        guard,
        key,
        Box::new(SystemClock),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_never_an_argument() {
        let key = "0x0123456789012345678901234567890123456789012345678901234567890123";
        for flag in ["--key", "--client-key", "--private-key", "--secret"] {
            assert!(
                Cli::try_parse_from(["zunder-guard-mcp", flag, key]).is_err(),
                "{flag}"
            );
        }
        let cli = Cli::try_parse_from(["zunder-guard-mcp"]).unwrap();
        assert_eq!(cli.network, Network::Paper);
        assert_eq!(cli.guard_url, DEFAULT_GUARD_URL);
        assert!(
            Cli::try_parse_from(["zunder-guard-mcp", "--key-file", "a", "--key-stdin"]).is_err()
        );
    }

    #[test]
    fn mainnet_needs_a_key_and_a_loopback_guard() {
        let cli = Cli::try_parse_from(["zunder-guard-mcp", "--network", "mainnet"]).unwrap();
        assert!(matches!(
            build(&cli, &mut std::io::empty()),
            Err(CliError::MainnetWithoutKey)
        ));
        let cli = Cli::try_parse_from([
            "zunder-guard-mcp",
            "--guard-url",
            "https://api.hyperliquid.xyz",
        ])
        .unwrap();
        assert!(matches!(
            build(&cli, &mut std::io::empty()),
            Err(CliError::Url(UrlError::NotLoopback))
        ));
        let key_line = "0x0123456789012345678901234567890123456789012345678901234567890123\n";
        let cli = Cli::try_parse_from(["zunder-guard-mcp", "--network", "mainnet", "--key-stdin"])
            .unwrap();
        assert!(matches!(
            build(&cli, &mut key_line.as_bytes()),
            Err(CliError::MainnetWithoutAccount)
        ));
        let cli = Cli::try_parse_from([
            "zunder-guard-mcp",
            "--confirm-account",
            "0x5e9ee1089755c3435139848e47e6635505d5a13a",
        ])
        .unwrap();
        assert!(matches!(
            build(&cli, &mut std::io::empty()),
            Err(CliError::AccountWithoutMainnet)
        ));
        let cli = Cli::try_parse_from(["zunder-guard-mcp", "--key-stdin"]).unwrap();
        let input = "0x0123456789012345678901234567890123456789012345678901234567890123\n";
        let server = build(&cli, &mut input.as_bytes()).unwrap();
        assert_eq!(
            server.client_address().as_deref(),
            Some("0x14791697260e4c9a71f18484c9f997b308e59325")
        );
    }
}
