// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! `zunder-guard-mcp`: the MCP server over stdio. See `docs/guard-mcp.md`.

use std::io;

use anyhow::Result;
use clap::Parser;
use zunder_guard_mcp::{cli, protocol};

fn main() -> Result<()> {
    let args = cli::Cli::parse();
    let stdin = io::stdin();
    // The locked stdin is buffered already: no second copy of the key.
    let mut input = stdin.lock();
    let mut server = cli::build(&args, &mut input)?;
    // Standard output is the protocol: everything else goes to standard
    // error. Never the key: only its address.
    eprintln!(
        "zunder-guard-mcp {}: Guard at {}, network {}, {}",
        env!("CARGO_PKG_VERSION"),
        args.guard_url,
        match args.network {
            cli::Network::Paper => "paper",
            cli::Network::Testnet => "testnet",
            cli::Network::Mainnet => "mainnet",
        },
        server.client_address().map_or_else(
            || "read-only (no client key)".to_owned(),
            |address| { format!("client key {address}") }
        )
    );
    let stdout = io::stdout();
    let mut output = stdout.lock();
    protocol::serve(&mut server, &mut input, &mut output)?;
    Ok(())
}
