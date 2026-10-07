// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! `zunder-license`: issues Zunder Guard licence keys (`docs/guard.md`,
//! "Issuing licence keys"). The token format lives in one place,
//! `zunder_guard_core::licence`; this is only its command line.
//!
//! - `keygen`: a new ed25519 signing key. The private key goes to standard
//!   output once, for the issuer to put into a secret store themselves;
//!   the public key, to embed in Guard as
//!   `LICENCE_PUBLIC_KEY_HEX`, goes to standard error. Nothing is written to
//!   disk.
//! - `issue`: reads the private key from standard input only (never a flag,
//!   a file or the environment), prints the token. The key is never stored.
//! - `verify`: checks a token against a public key and prints its terms.

use std::{
    fs,
    io::{IsTerminal, Read},
    process::ExitCode,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;
use zunder_core::Timestamp;
use zunder_guard_core::licence::{self, BuilderOverride, Terms};

#[derive(Parser)]
#[command(
    name = "zunder-license",
    version,
    about = "Issue Zunder Guard licence keys (Orcastrate)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make a signing key: the private key to standard output (once), the
    /// public key to standard error.
    Keygen,
    /// Issue a licence key, signed with the private key read from standard
    /// input.
    Issue {
        #[arg(long)]
        licensee: String,
        /// The day the licence ends (YYYY-MM-DD, at 00:00 UTC).
        #[arg(long)]
        expires: String,
        /// Comma-separated: fee_free.
        #[arg(long, value_delimiter = ',')]
        features: Vec<String>,
        /// The accounts the licence is for, comma-separated (0x and 40 hex
        /// digits each; at least one). Guard honours it only on these.
        #[arg(long, value_delimiter = ',', required = true)]
        accounts: Vec<String>,
        /// Another builder for this licensee's orders.
        #[arg(long, requires = "builder_fee")]
        builder: Option<String>,
        /// That builder's fee in tenths of a basis point (at most 100).
        #[arg(long)]
        builder_fee: Option<u64>,
    },
    /// Check a licence key against a public key and print its terms.
    Verify {
        /// The public key, 0x and 64 hex digits.
        #[arg(long)]
        public_key: String,
        /// Also check that the licence is for this account.
        #[arg(long)]
        account: Option<String>,
        token: String,
    },
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse32(text: &str, what: &str) -> Result<Zeroizing<[u8; 32]>> {
    let digits = text.trim();
    let digits = digits.strip_prefix("0x").unwrap_or(digits);
    if digits.len() != 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{what} must be 64 hex digits, optionally with 0x");
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[2 * index..2 * index + 2], 16)
            .with_context(|| format!("{what} is not hex"))?;
    }
    Ok(out)
}

/// The private key from standard input: one fixed buffer, wiped; a
/// terminal is refused, so the key is never typed where it shows.
fn private_key_from_stdin() -> Result<Zeroizing<[u8; 32]>> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        bail!(
            "pipe the private key on standard input (from a secret store); typing it would show it"
        );
    }
    #[cfg(unix)]
    let mut file = {
        use std::os::fd::AsFd;
        fs::File::from(stdin.as_fd().try_clone_to_owned()?)
    };
    #[cfg(windows)]
    let mut file = {
        use std::os::windows::io::AsHandle;
        fs::File::from(stdin.as_handle().try_clone_to_owned()?)
    };
    let mut buffer = Zeroizing::new([0u8; 257]);
    let mut filled = 0;
    loop {
        let Some(space) = buffer.get_mut(filled..) else {
            bail!("standard input holds more than a key");
        };
        if space.is_empty() {
            bail!("standard input holds more than a key");
        }
        match file.read(space)? {
            0 => break,
            read => filled += read,
        }
    }
    let text = std::str::from_utf8(&buffer[..filled]).context("the key is not text")?;
    parse32(text, "the private key")
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Keygen => {
            let mut secret = Zeroizing::new([0u8; 32]);
            getrandom::fill(secret.as_mut()).map_err(|error| anyhow::anyhow!("{error}"))?;
            let public = licence::public_key_of(&secret);
            if std::io::stdout().is_terminal() {
                eprintln!(
                    "WARNING: the private key is printed to this terminal; pipe it into a secret store instead, and clear the scrollback."
                );
            }
            let private = zunder_guard::init::secret_hex(secret.as_ref());
            println!("{}", private.as_str());
            eprintln!("public key: 0x{}", hex(&public));
            eprintln!(
                "embed in crates/zunder-guard-core/src/licence.rs (a reviewed change): pub const LICENCE_PUBLIC_KEY_HEX: Option<&str> = Some(\"0x{}\");",
                hex(&public)
            );
            eprintln!("store the private key yourself, in a secret store, and nowhere on disk");
            Ok(())
        }
        Command::Issue {
            licensee,
            expires,
            features,
            accounts,
            builder,
            builder_fee,
        } => {
            let date: Vec<&str> = expires.split('-').collect();
            let [year, month, day] = date.as_slice() else {
                bail!("--expires is YYYY-MM-DD");
            };
            let at = Timestamp::from_utc_ymd(year.parse()?, month.parse()?, day.parse()?)
                .context("--expires is not a date")?;
            let terms = Terms {
                licensee,
                expires_at_ms: at.as_millis(),
                features,
                accounts,
                builder: builder.map(|address| BuilderOverride {
                    address: address.to_ascii_lowercase(),
                    fee_tenths_bp: builder_fee.unwrap_or(0),
                }),
            };
            let secret = private_key_from_stdin()?;
            let token = licence::issue(&terms, &secret)?;
            println!("{token}");
            Ok(())
        }
        Command::Verify {
            public_key,
            account,
            token,
        } => {
            let public = parse32(&public_key, "--public-key")?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| {
                    i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
                });
            let mut licence = licence::verify(&token, &public, now)?;
            if licence.accounts.is_empty() {
                anyhow::bail!(
                    "the key names no account (issued before 7 Oct 2026): Guard honours it for none"
                );
            }
            if let Some(account) = account {
                let account = zunder_guard_core::sign::Address::from_hex(&account)
                    .context("--account is not an address")?;
                licence = licence.for_account(account)?;
            }
            let accounts: Vec<String> = licence
                .accounts
                .iter()
                .map(zunder_guard_core::sign::Address::to_hex)
                .collect();
            println!(
                "valid: licensee {}, expires at {} ms, fee free {}, builder {:?}, accounts [{}]",
                licence.licensee,
                licence.expires_at_ms,
                licence.fee_free,
                licence.builder,
                accounts.join(", ")
            );
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("zunder-license: {error:#}");
            ExitCode::from(2)
        }
    }
}
