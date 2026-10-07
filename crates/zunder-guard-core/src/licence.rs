// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! LICENCE-KEY FUNCTIONALITY (Elastic License 2.0, "Limitations": the
//! licensee may not move, change, disable or circumvent the licence key
//! functionality, nor remove or obscure the functionality it protects).
//!
//! Guard is source-available under the Elastic License 2.0. The builder fee
//! is how Guard is paid for: 0.02% (`f = 20` tenths of a basis point,
//! decided 6 Oct 2026) on **every order Guard sends**: the
//! entries and exits it forwards, the bot's reduce-only closes, stops and
//! take profits, and Guard's own protective stops, closes and flattens.
//! Everything about it is in this module:
//!
//! - **Where.** [`ORCASTRATE_BUILDER`] on mainnet; on testnet only when
//!   [`ORCASTRATE_TESTNET_BUILDER`] is set (a builder on testnet needs its
//!   own approval there). Paper mode reports the fee it would charge on the
//!   network whose account it reads, and never blocks.
//! - **Approval.** The user approves the fee once with the main wallet
//!   (`approveBuilderFee`, which Guard itself always refuses to forward).
//!   Guard reads the approval with the `maxBuilderFee` info request at
//!   start and then periodically ([`FeeState`]). Hyperliquid refuses an
//!   order that carries a builder the user has not approved, so the field
//!   goes on an order only while the approval is confirmed: entries wait
//!   for it (`fee_not_approved`), exits never do. Safety beats revenue.
//! - **Exceptions**, where the venue has no builder field: `modify` and
//!   `batchModify` (the venue's modify carries an order without one),
//!   cancels, leverage and margin updates. Documented in `docs/guard.md`.
//! - **Licence keys.** Running without the fee takes a licence key with the
//!   `fee_free` feature; a key may also name another builder (mainnet
//!   only). A key is `zgl1_` + base64url(payload JSON) + `.` +
//!   base64url(ed25519 signature over the payload's bytes), verified offline
//!   against the public key compiled in ([`LICENCE_PUBLIC_KEY_HEX`]).
//!   Nothing phones home. The payload: `{"licensee": "...", "expires_at_ms":
//!   1798761600000, "features": ["fee_free"], "accounts": ["0x.."],
//!   "builder": {"address": "0x..", "fee_tenths_bp": 10}}`, the builder
//!   optional; unknown fields are refused. A key is good only for the
//!   accounts it names (Guard's own account must be one of them); a key
//!   that names none, as every key issued before 7 Oct 2026, is good for
//!   none. A missing, malformed, forged or expired key, or one for other
//!   accounts, never blocks trading: Guard falls back to the fee and warns
//!   ([`fee_mode`]).
//! - **Lifecycle.** A running Guard checks the key's expiry before every
//!   order and at every sync: it warns [`WARN_DAYS`] before ([`expiry_stage`])
//!   and falls back to the fee at the first order after it expires
//!   ([`FeeState::switch_mode`]: entries then wait for the fee's approval,
//!   exits never do). A new key written into `guard.toml` (`zunder-guard
//!   licence set`) applies at the next sync, without a restart. Fetching a
//!   renewed key from Orcastrate (`licence_auto_update`) is off unless the
//!   user switches it on: by default nothing phones home.
//!
//! The mainnet builder is set; the testnet builder is still `None`, so
//! testnet sends no builder field. The licence verification public key is
//! [`LICENCE_PUBLIC_KEY_HEX`]. Each is set by a reviewed change.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::{
    action::{Action, Builder, Grouping, OrderKind, Tif},
    policy::Policy,
    sign::Address,
};

/// The builder fee on every order Guard sends: 0.02%, in tenths of a basis
/// point as Hyperliquid encodes it (decided 6 Oct 2026).
pub const BUILDER_FEE_TENTHS_BP: u64 = 20;

/// Orcastrate's builder address on mainnet. The
/// venue accepts a builder only with at least 100 USDC of perps account
/// value; until it is funded, entries that carry the field are refused and
/// Guard reports it as the builder's side, not the user's.
pub const ORCASTRATE_BUILDER: Option<&str> = Some("0x0f50112710913B51A5D037795e5F4EFc08deBf2a");

/// A builder address on testnet, for testing the fee there: none, so
/// testnet runs without a fee.
pub const ORCASTRATE_TESTNET_BUILDER: Option<&str> = None;

/// Where a user approves the fee with their main wallet.
pub const APPROVE_URL: &str = "https://zunderlabs.com/approve";

/// The ed25519 public key licences are signed with, as `zunder-license
/// keygen` prints it (64 hex digits, optionally with `0x`): Orcastrate's
/// production key (`docs/guard.md`). A malformed value fails the
/// build.
pub const LICENCE_PUBLIC_KEY_HEX: Option<&str> =
    Some("0x7e298d8aa9921205f1ef0995b8dc6fedd86a4365fe183825127f8cd56a82af46");

/// [`LICENCE_PUBLIC_KEY_HEX`] as bytes, decoded at compile time.
pub const LICENCE_PUBLIC_KEY: Option<[u8; 32]> = match LICENCE_PUBLIC_KEY_HEX {
    Some(hex) => Some(public_key_from_hex(hex)),
    None => None,
};

/// Decode 64 hex digits (optionally `0x`-prefixed) at compile time; a
/// malformed constant stops the build.
const fn public_key_from_hex(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    let start = if bytes.len() == 66 && bytes[0] == b'0' && bytes[1] == b'x' {
        2
    } else {
        0
    };
    if bytes.len() - start != 64 {
        panic!("LICENCE_PUBLIC_KEY_HEX must be 64 hex digits");
    }
    let mut out = [0u8; 32];
    let mut index = 0;
    while index < 32 {
        let high = hex_digit(bytes[start + 2 * index]);
        let low = hex_digit(bytes[start + 2 * index + 1]);
        out[index] = high * 16 + low;
        index += 1;
    }
    out
}

const fn hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("LICENCE_PUBLIC_KEY_HEX must be 64 hex digits"),
    }
}

/// The test licence key pair: for tests only, never the production key (a
/// test fails if [`LICENCE_PUBLIC_KEY_HEX`] is ever set to it). Its seed is
/// public, so a key it signs proves nothing.
#[doc(hidden)]
pub mod test_key {
    /// The test signing key's seed.
    pub const SEED: [u8; 32] = [7u8; 32];

    /// The test public key.
    pub fn public() -> [u8; 32] {
        super::public_key_of(&SEED)
    }
}

/// How many days before a licence expires Guard warns: once at each.
pub const WARN_DAYS: [i64; 3] = [14, 7, 1];

/// One day in milliseconds.
pub const DAY_MS: i64 = 86_400_000;

/// Whole days left until `expires_at_ms` at `now_ms`, rounded up (`1`
/// for anything under a day; `0` once expired).
pub fn days_left(expires_at_ms: i64, now_ms: i64) -> i64 {
    if now_ms >= expires_at_ms {
        return 0;
    }
    (expires_at_ms - now_ms + DAY_MS - 1) / DAY_MS
}

/// The warning a licence expiring at `expires_at_ms` is due at `now_ms`:
/// the smallest of [`WARN_DAYS`] it is within (`Some(14)` from 14 days
/// before, `Some(7)`, `Some(1)` in its last day); `None` before the first
/// and once expired.
pub fn expiry_stage(expires_at_ms: i64, now_ms: i64) -> Option<i64> {
    if now_ms >= expires_at_ms {
        return None;
    }
    let left = expires_at_ms - now_ms;
    WARN_DAYS
        .iter()
        .rev()
        .find(|days| left <= *days * DAY_MS)
        .copied()
}

/// The prefix of a version 1 licence key.
pub const PREFIX: &str = "zgl1_";
/// Longest licence key accepted.
pub const MAX_KEY_LEN: usize = 4_096;
/// Most builder fee Hyperliquid allows on perps: 0.1%, 100 tenths of a bp.
pub const MAX_BUILDER_FEE_TENTHS_BP: u64 = 100;
// Guard's own fee is within the venue's maximum, checked at compile time.
const _: () = assert!(BUILDER_FEE_TENTHS_BP <= MAX_BUILDER_FEE_TENTHS_BP);

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LicenceError {
    #[error("no licence public key is built into this Guard yet")]
    NoPublicKey,
    #[error("a licence key starts with `zgl1_`")]
    Prefix,
    #[error("the licence key is longer than {MAX_KEY_LEN} characters")]
    TooLong,
    #[error("the licence key is malformed")]
    Malformed,
    #[error("the licence key's signature does not verify: it was not issued by Orcastrate")]
    Forged,
    #[error("the licence for {licensee} expired at {expires_at_ms}")]
    Expired {
        licensee: String,
        expires_at_ms: i64,
    },
    #[error("the licence's builder is invalid")]
    Builder,
    #[error("a licence names between 1 and {MAX_ACCOUNTS} accounts, each an address")]
    Accounts,
    #[error("the licence for {licensee} is not for account {account} (it names {named})")]
    NotForAccount {
        licensee: String,
        account: String,
        named: String,
    },
}

/// The most accounts one licence may name.
/// (50 fit a key of [`MAX_KEY_LEN`] with the longest licensee and another
/// builder; a test issues one.)
pub const MAX_ACCOUNTS: usize = 50;

/// A licence's other builder, in the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuilderOverride {
    pub address: String,
    pub fee_tenths_bp: u64,
}

/// What a licence key says: the payload, in this field order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    pub licensee: String,
    pub expires_at_ms: i64,
    pub features: Vec<String>,
    /// The accounts the licence is for (`0x` and 40 hex digits, lowercase
    /// when issued). Missing in keys issued before 7 Oct 2026: good for
    /// none.
    #[serde(default)]
    pub accounts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder: Option<BuilderOverride>,
}

/// The features a licence may carry.
pub const FEATURES: &[&str] = &["fee_free"];

/// Issue a licence key for `terms`, signed with the ed25519 secret key
/// `secret` (Orcastrate's; `zunder-license issue`). Refuses
/// terms Guard would not accept: an empty licensee, an unknown feature, a
/// builder that is no address or above the venue's maximum fee.
pub fn issue(terms: &Terms, secret: &[u8; 32]) -> Result<String, LicenceError> {
    if terms.licensee.trim().is_empty() || terms.licensee.len() > 200 {
        return Err(LicenceError::Malformed);
    }
    if terms
        .features
        .iter()
        .any(|feature| !FEATURES.contains(&feature.as_str()))
    {
        return Err(LicenceError::Malformed);
    }
    if let Some(builder) = &terms.builder
        && (Address::from_hex(&builder.address).is_none()
            || builder.fee_tenths_bp > MAX_BUILDER_FEE_TENTHS_BP)
    {
        return Err(LicenceError::Builder);
    }
    let accounts = accounts_of(&terms.accounts)?;
    if accounts.is_empty() {
        return Err(LicenceError::Accounts);
    }
    let terms = Terms {
        accounts: accounts.iter().map(Address::to_hex).collect(),
        ..terms.clone()
    };
    let payload = serde_json::to_vec(&terms).map_err(|_| LicenceError::Malformed)?;
    let signing = ed25519_dalek::SigningKey::from_bytes(secret);
    let signature = ed25519_dalek::Signer::sign(&signing, &payload);
    let key = format!(
        "{PREFIX}{}.{}",
        URL_SAFE_NO_PAD.encode(&payload),
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    if key.len() > MAX_KEY_LEN {
        return Err(LicenceError::TooLong);
    }
    Ok(key)
}

/// The accounts a licence names, parsed: each an address, at most
/// [`MAX_ACCOUNTS`], none twice.
fn accounts_of(named: &[String]) -> Result<Vec<Address>, LicenceError> {
    if named.len() > MAX_ACCOUNTS {
        return Err(LicenceError::Accounts);
    }
    let mut accounts = Vec::with_capacity(named.len());
    for text in named {
        let account = Address::from_hex(text).ok_or(LicenceError::Accounts)?;
        if accounts.contains(&account) {
            return Err(LicenceError::Accounts);
        }
        accounts.push(account);
    }
    Ok(accounts)
}

/// The public key of an ed25519 secret key: what Guard embeds in
/// [`LICENCE_PUBLIC_KEY`].
pub fn public_key_of(secret: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(secret)
        .verifying_key()
        .to_bytes()
}

/// A verified licence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Licence {
    pub licensee: String,
    pub expires_at_ms: i64,
    pub fee_free: bool,
    pub builder: Option<Builder>,
    /// The accounts it is good for; empty (an older key): none.
    pub accounts: Vec<Address>,
}

impl Licence {
    /// The licence, if it is good for `account`.
    pub fn for_account(self, account: Address) -> Result<Self, LicenceError> {
        if self.accounts.contains(&account) {
            return Ok(self);
        }
        let named = if self.accounts.is_empty() {
            "no account".to_owned()
        } else {
            self.accounts
                .iter()
                .map(Address::to_hex)
                .collect::<Vec<_>>()
                .join(", ")
        };
        Err(LicenceError::NotForAccount {
            licensee: self.licensee,
            account: account.to_hex(),
            named,
        })
    }
}

/// Verify `key` against `public_key` at `now_ms`.
pub fn verify(key: &str, public_key: &[u8; 32], now_ms: i64) -> Result<Licence, LicenceError> {
    let key = key.trim();
    if key.len() > MAX_KEY_LEN {
        return Err(LicenceError::TooLong);
    }
    let body = key.strip_prefix(PREFIX).ok_or(LicenceError::Prefix)?;
    let (payload_b64, signature_b64) = body.split_once('.').ok_or(LicenceError::Malformed)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| LicenceError::Malformed)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| LicenceError::Malformed)?;
    let signature = Signature::from_slice(&signature).map_err(|_| LicenceError::Malformed)?;
    let verifying = VerifyingKey::from_bytes(public_key).map_err(|_| LicenceError::Forged)?;
    verifying
        .verify_strict(&payload, &signature)
        .map_err(|_| LicenceError::Forged)?;
    let payload: Terms = serde_json::from_slice(&payload).map_err(|_| LicenceError::Malformed)?;
    if now_ms >= payload.expires_at_ms {
        return Err(LicenceError::Expired {
            licensee: payload.licensee,
            expires_at_ms: payload.expires_at_ms,
        });
    }
    let builder = match payload.builder {
        None => None,
        Some(builder) => {
            let address = Address::from_hex(&builder.address).ok_or(LicenceError::Builder)?;
            if builder.fee_tenths_bp > MAX_BUILDER_FEE_TENTHS_BP {
                return Err(LicenceError::Builder);
            }
            Some(Builder {
                address: address.to_hex(),
                fee_tenths_bp: builder.fee_tenths_bp,
            })
        }
    };
    let accounts = accounts_of(&payload.accounts).map_err(|_| LicenceError::Malformed)?;
    Ok(Licence {
        fee_free: payload.features.iter().any(|feature| feature == "fee_free"),
        licensee: payload.licensee,
        expires_at_ms: payload.expires_at_ms,
        builder,
        accounts,
    })
}

/// Which builder field Guard attaches, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeMode {
    /// Orcastrate's builder field (or the one a licence names).
    Builder(Builder),
    /// A valid licence with `fee_free`.
    FeeFree { licensee: String },
    /// No fee in this setting: testnet without a testnet builder, or no
    /// builder account yet. The text says which.
    Off(String),
}

impl FeeMode {
    /// The builder field this mode charges.
    pub fn builder(&self) -> Option<&Builder> {
        match self {
            FeeMode::Builder(builder) => Some(builder),
            FeeMode::FeeFree { .. } | FeeMode::Off(_) => None,
        }
    }
}

/// The network the fee is for: where Guard sends, or in paper mode the
/// network whose account it reads (the fee it would charge there).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeNetwork {
    Mainnet,
    Testnet,
}

fn builder_at(address: &str) -> Option<Builder> {
    Address::from_hex(address).map(|address| Builder {
        address: address.to_hex(),
        fee_tenths_bp: BUILDER_FEE_TENTHS_BP,
    })
}

/// The fee mode on `network` for Guard's `account` with the licence key
/// `key`, if any, checked against `public_key` at `now_ms` and against the
/// accounts it names. The second value is a warning to show: a key that
/// did not verify, or is not for `account`. A bad key never stops Guard: it
/// falls back to the fee.
pub fn fee_mode(
    network: FeeNetwork,
    key: Option<&str>,
    public_key: Option<&[u8; 32]>,
    now_ms: i64,
    account: Address,
) -> (FeeMode, Option<String>) {
    fee_mode_with(
        network,
        key,
        public_key,
        now_ms,
        account,
        ORCASTRATE_BUILDER,
        ORCASTRATE_TESTNET_BUILDER,
    )
}

/// [`fee_mode`] with the builder addresses given (the tests' own).
pub fn fee_mode_with(
    network: FeeNetwork,
    key: Option<&str>,
    public_key: Option<&[u8; 32]>,
    now_ms: i64,
    account: Address,
    mainnet_builder: Option<&str>,
    testnet_builder: Option<&str>,
) -> (FeeMode, Option<String>) {
    let licence = key.map(|key| match public_key {
        Some(public_key) => {
            verify(key, public_key, now_ms).and_then(|licence| licence.for_account(account))
        }
        None => Err(LicenceError::NoPublicKey),
    });
    let warning = match &licence {
        Some(Err(error)) => Some(format!(
            "licence key not used ({error}); Guard runs with the builder fee"
        )),
        _ => None,
    };
    let licence = licence.and_then(Result::ok);
    if let Some(licence) = &licence
        && licence.fee_free
    {
        return (
            FeeMode::FeeFree {
                licensee: licence.licensee.clone(),
            },
            warning,
        );
    }
    let builder = match network {
        // A licence's other builder is a mainnet account.
        FeeNetwork::Mainnet => licence
            .and_then(|licence| licence.builder)
            .or_else(|| mainnet_builder.and_then(builder_at)),
        FeeNetwork::Testnet => testnet_builder.and_then(builder_at),
    };
    match (builder, network) {
        (Some(builder), _) => (FeeMode::Builder(builder), warning),
        (None, FeeNetwork::Mainnet) => (
            FeeMode::Off(
                "Orcastrate's builder account does not exist yet: no builder field".into(),
            ),
            warning,
        ),
        (None, FeeNetwork::Testnet) => (
            FeeMode::Off("testnet: no builder fee (no testnet builder is configured)".into()),
            warning,
        ),
    }
}

/// Whether trigger orders (stops and take profits, Guard's and the bot's,
/// and an entry sent with its stop, since the field is per action) carry
/// the builder field. On since the testnet experiment of 6 Oct 2026
/// (see `docs/guard.md#fee-licence-key-and-licence`): a resting
/// trigger placed with the field, standalone or a `normalTpsl` child, still
/// fires after the user withdraws the approval (and still pays the fee); a
/// withdrawal cancels no resting trigger; a modify keeps the builder. So no
/// stop depends on the approval once it rests, and no re-placement is
/// needed. Switching it off again is a reviewed change with a recorded
/// decision (the fee on entries would then be lost).
pub const BUILDER_ON_TRIGGERS: bool = true;

/// Whether the two cases the testnet experiment of 6 Oct 2026 did not
/// cover carry the builder field too: an entry that may rest (a limit
/// other than IOC) sent with its stops, and a `positionTpsl` action. Enabled.
/// The risk is a stop the venue might refuse to
/// activate, or to fire, after the user withdrew the approval; Guard's
/// protect pass then covers the position at its next sync, as for any
/// position without a stop (tested in memory). These cases still require
/// live testnet validation; in-memory
/// tests do not establish venue behavior. Changes require security review.
pub const BUILDER_ON_RESTING_AND_POSITION_TPSL: bool = true;

/// Recheck a confirmed approval this often: it can be withdrawn at any
/// time in the user's wallet. One `maxBuilderFee` read is 20 of the venue's
/// request weight, so this costs 4 a minute.
pub const APPROVED_RECHECK_MS: u64 = 300_000;
/// Recheck a missing or unread approval this often, so an approval given
/// meanwhile lets entries through within a minute.
pub const UNAPPROVED_RECHECK_MS: u64 = 60_000;
/// An entry refused for the fee asks for a check at the next sync, but not
/// more often than this.
pub const ON_DEMAND_RECHECK_MS: u64 = 15_000;
/// After the venue refused the builder field, Guard tries the field again
/// only once the approval it reads changes, or after this long.
pub const REFUSED_BACKOFF_MS: u64 = 600_000;
/// The longest Guard waits for a `maxBuilderFee` answer.
pub const CHECK_TIMEOUT_MS: u64 = 2_500;

/// What Guard knows of the user's approval of its builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approval {
    /// Not read yet.
    Unchecked,
    /// The venue's `maxBuilderFee` answer: the most the user approved for
    /// the builder, in tenths of a basis point.
    Read { max_tenths_bp: u64 },
    /// The venue refused an order for its builder field at `at_ms`, with
    /// `text`, while the approval last read was `last_read`. `ours`: the
    /// text points at Orcastrate's builder account rather than the user's
    /// approval.
    RefusedByVenue {
        text: String,
        at_ms: u64,
        last_read: Option<u64>,
        ours: bool,
    },
}

/// The fee as Guard runs it: the mode, whether Guard sends, and the user's
/// approval of the builder.
#[derive(Debug, Clone)]
pub struct FeeState {
    mode: FeeMode,
    sends: bool,
    approval: Approval,
    checked_at_ms: Option<u64>,
    error: Option<String>,
    /// An entry asked for a check at the next sync.
    check_requested: bool,
    builder_on_triggers: bool,
    builder_on_resting_and_position_tpsl: bool,
    /// Checks handed out ([`FeeState::begin_check`]) and the latest one
    /// recorded: an answer to an older check than one already recorded is
    /// ignored, and no second check starts while one is out (for at most
    /// twice the timeout).
    checks_issued: u64,
    checks_recorded: u64,
    issued_at_ms: u64,
}

impl FeeState {
    /// `sends`: testnet or mainnet; paper mode only reports.
    pub fn new(mode: FeeMode, sends: bool) -> Self {
        Self {
            mode,
            sends,
            approval: Approval::Unchecked,
            checked_at_ms: None,
            error: None,
            check_requested: false,
            builder_on_triggers: BUILDER_ON_TRIGGERS,
            builder_on_resting_and_position_tpsl: BUILDER_ON_RESTING_AND_POSITION_TPSL,
            checks_issued: 0,
            checks_recorded: 0,
            issued_at_ms: 0,
        }
    }

    /// Tests only (feature `test-hooks`, never in a release build): what
    /// [`BUILDER_ON_TRIGGERS`] switched the other way would do.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_builder_on_triggers(&mut self, on: bool) {
        self.builder_on_triggers = on;
    }

    /// Tests only (feature `test-hooks`): what
    /// [`BUILDER_ON_RESTING_AND_POSITION_TPSL`] switched the other way would
    /// do.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_builder_on_resting_and_position_tpsl(&mut self, on: bool) {
        self.builder_on_resting_and_position_tpsl = on;
    }

    pub fn builder_on_triggers(&self) -> bool {
        self.builder_on_triggers
    }

    pub fn mode(&self) -> &FeeMode {
        &self.mode
    }

    /// Run with `mode` from now on (a licence that expired, or a new key):
    /// the approval is read again before an entry carries a builder field
    /// (entries wait for it, exits never do). The same mode: nothing
    /// changes. Returns whether it changed.
    pub fn switch_mode(&mut self, mode: FeeMode) -> bool {
        if mode == self.mode {
            return false;
        }
        self.mode = mode;
        self.approval = Approval::Unchecked;
        self.checked_at_ms = None;
        self.error = None;
        self.check_requested = true;
        // An answer to a check issued for the old mode is not this one's.
        self.checks_recorded = self.checks_issued;
        self.issued_at_ms = 0;
        true
    }

    pub fn approval(&self) -> &Approval {
        &self.approval
    }

    /// Whether the user approved at least the mode's fee for its builder.
    pub fn approved(&self) -> bool {
        match (&self.mode, &self.approval) {
            (FeeMode::Builder(builder), Approval::Read { max_tenths_bp }) => {
                *max_tenths_bp >= builder.fee_tenths_bp
            }
            _ => false,
        }
    }

    /// The builder field Guard's orders carry now: the mode's, and only
    /// while the approval is confirmed, since the venue refuses an order
    /// with an unapproved builder and an exit must never be refused for the
    /// fee. In paper mode, the field Guard would send once the fee is
    /// approved. [`FeeState::apply`] puts it on every order action (off
    /// trigger orders only if [`BUILDER_ON_TRIGGERS`] were switched off).
    pub fn builder_for_orders(&self) -> Option<&Builder> {
        if !self.sends || self.approved() {
            self.mode.builder()
        } else {
            None
        }
    }

    /// `action` as Guard sends it (a `positionTpsl` action and a resting
    /// entry with its stops only while
    /// [`BUILDER_ON_RESTING_AND_POSITION_TPSL`] is on): an order action gets
    /// [`FeeState::builder_for_orders`] as its builder field (replacing any
    /// other), unless it holds a trigger order while
    /// [`BUILDER_ON_TRIGGERS`] is off; then it goes without one. Other
    /// actions have no builder field.
    pub fn apply(&self, action: &Action) -> Action {
        let position_tpsl =
            matches!(action, Action::Order(order) if order.grouping == Grouping::PositionTpsl);
        let builder = self.builder_for_orders().filter(|_| {
            (self.builder_on_triggers || !has_trigger(action))
                && (self.builder_on_resting_and_position_tpsl
                    || (!resting_entry_with_triggers(action) && !position_tpsl))
        });
        with_builder(action, builder)
    }

    /// Why a modify is refused while the fee is unconfirmed: the order it
    /// replaces may rest with the builder field, and whether the venue
    /// places the replacement after a withdrawn approval has not been
    /// tested (it cancels the old order first). Send a new order instead;
    /// it goes without the field.
    pub fn modify_refusal(&self) -> Option<String> {
        self.entry_refusal().map(|why| {
            format!(
                "a change by modify is not forwarded while the builder fee approval is unconfirmed (the order it replaces may carry the builder field, and the venue's handling of that after a withdrawal is not verified); the order stays as it was: cancel it and send a new one, which goes without the field. {why}"
            )
        })
    }

    /// The builder whose fee counts into each entry's risk: the mode's.
    pub fn sizing_builder(&self) -> Option<&Builder> {
        self.mode.builder()
    }

    /// Why a new entry is refused (`fee_not_approved`): Guard sends, the
    /// mode charges a fee, and the approval is not confirmed. Never in paper
    /// mode, never for exits.
    pub fn entry_refusal(&self) -> Option<String> {
        let FeeMode::Builder(builder) = &self.mode else {
            return None;
        };
        if !self.sends || self.approved() {
            return None;
        }
        let fee = format!(
            "Guard's builder fee ({}, {} tenths of a bp, builder {})",
            rate(builder.fee_tenths_bp),
            builder.fee_tenths_bp,
            builder.address
        );
        let approve = format!(
            "Approve it once with the account's main wallet at {APPROVE_URL}; until then new entries are refused"
        );
        let text = match &self.approval {
            Approval::Unchecked => match &self.error {
                Some(error) => format!(
                    "Guard could not yet read whether this account approved {fee} ({error}). {approve}"
                ),
                None => format!(
                    "Guard has not yet confirmed that this account approved {fee}. {approve}"
                ),
            },
            Approval::Read { max_tenths_bp: 0 } => {
                format!("this account has not approved {fee}. {approve}")
            }
            Approval::Read { max_tenths_bp } => format!(
                "this account approved at most {max_tenths_bp} tenths of a bp for the builder, below {fee}. {approve}"
            ),
            Approval::RefusedByVenue {
                text, ours: true, ..
            } => format!(
                "the venue refused {fee} for a reason on Orcastrate's side, not this account's approval (the venue: \"{text}\"): there is nothing for you to approve. New entries are refused until Guard finds it fixed (it tries again when the approval it reads changes, or after {} minutes)",
                REFUSED_BACKOFF_MS / 60_000
            ),
            Approval::RefusedByVenue { text, .. } => format!(
                "the venue refused an order because this account has not approved {fee} (the venue: \"{text}\"). {approve}"
            ),
        };
        Some(format!("{text}. Exits are never held back for the fee."))
    }

    /// Whether the approval check is due at `now_ms`: periodic, or asked
    /// for by an entry.
    pub fn check_due(&self, now_ms: u64) -> bool {
        if self.mode.builder().is_none() || self.check_in_flight(now_ms) {
            return false;
        }
        if self.check_requested {
            return true;
        }
        let every = if self.approved() {
            APPROVED_RECHECK_MS
        } else {
            UNAPPROVED_RECHECK_MS
        };
        self.checked_at_ms
            .is_none_or(|at| now_ms.saturating_sub(at) >= every)
    }

    /// Whether an entry refused for the fee may ask for a check now.
    pub fn on_demand_due(&self, now_ms: u64) -> bool {
        self.mode.builder().is_some()
            && !self.approved()
            && !self.check_requested
            && self
                .checked_at_ms
                .is_none_or(|at| now_ms.saturating_sub(at) >= ON_DEMAND_RECHECK_MS)
    }

    /// An entry refused for the fee: check at the next sync.
    pub fn request_check(&mut self) {
        self.check_requested = true;
    }

    /// A check is out and not yet answered (given up after twice the
    /// timeout, should its task have been dropped).
    pub fn check_in_flight(&self, now_ms: u64) -> bool {
        self.checks_recorded < self.checks_issued
            && now_ms.saturating_sub(self.issued_at_ms) < 2 * CHECK_TIMEOUT_MS
    }

    /// Hand out a check at `now_ms`: its ticket for [`FeeState::record_answer`].
    pub fn begin_check(&mut self, now_ms: u64) -> u64 {
        self.checks_issued += 1;
        self.issued_at_ms = now_ms;
        self.checks_issued
    }

    /// Record the answer to the check `ticket`, unless an answer to a later
    /// check was recorded already (answers can come back out of order).
    pub fn record_answer(
        &mut self,
        ticket: u64,
        now_ms: u64,
        answer: Result<&Value, String>,
    ) -> Option<String> {
        if ticket <= self.checks_recorded {
            return None;
        }
        self.checks_recorded = ticket;
        self.record_check(now_ms, answer)
    }

    /// The `maxBuilderFee` info request for `user` (the account's main
    /// wallet address), when the mode has a builder.
    pub fn check_request(&self, user: &str) -> Option<Value> {
        self.mode.builder().map(
            |builder| json!({"type": "maxBuilderFee", "user": user, "builder": builder.address}),
        )
    }

    /// Record a `maxBuilderFee` answer (or the error reading it) at
    /// `now_ms`. An unreadable answer keeps what Guard knew. After a refusal
    /// by the venue, the same approval read again keeps the refusal until
    /// [`REFUSED_BACKOFF_MS`] have passed. Returns a text to journal when
    /// the approval changed.
    pub fn record_check(&mut self, now_ms: u64, answer: Result<&Value, String>) -> Option<String> {
        self.checked_at_ms = Some(now_ms);
        self.check_requested = false;
        let before = self.approved();
        match answer.and_then(|value| {
            parse_max_builder_fee(value).ok_or_else(|| format!("unexpected answer {value}"))
        }) {
            Ok(max_tenths_bp) => {
                // A refusal on Orcastrate's side holds while the approval
                // reads the same, for the backoff; one on the account's side
                // ends with any read (an approval given again counts at once).
                if let Approval::RefusedByVenue {
                    at_ms,
                    last_read,
                    ours: true,
                    ..
                } = &self.approval
                    && *last_read == Some(max_tenths_bp)
                    && now_ms.saturating_sub(*at_ms) < REFUSED_BACKOFF_MS
                {
                    self.error = None;
                    return None;
                }
                let first = matches!(
                    self.approval,
                    Approval::Unchecked | Approval::RefusedByVenue { .. }
                );
                self.approval = Approval::Read { max_tenths_bp };
                self.error = None;
                let after = self.approved();
                (first || before != after).then(|| self.change_text(before, after))
            }
            Err(error) => {
                let text = format!("reading the builder fee approval: {error}");
                let new = self.error.as_deref() != Some(text.as_str());
                self.error = Some(text.clone());
                new.then_some(text)
            }
        }
    }

    /// The venue refused an order for its builder field at `now_ms`, saying
    /// `text`. Returns a text to journal when this changes what Guard knew.
    pub fn record_venue_refusal(&mut self, now_ms: u64, text: &str) -> Option<String> {
        let before = self.approved();
        let last_read = match &self.approval {
            Approval::Read { max_tenths_bp } => Some(*max_tenths_bp),
            Approval::RefusedByVenue { last_read, .. } => *last_read,
            Approval::Unchecked => None,
        };
        let changed =
            !matches!(&self.approval, Approval::RefusedByVenue { text: old, .. } if old == text);
        // Only the venue's known builder-side text is Orcastrate's to fix;
        // anything else is taken as the account's approval.
        let ours = text.to_ascii_lowercase().contains("insufficient balance");
        self.approval = Approval::RefusedByVenue {
            text: text.chars().take(200).collect(),
            at_ms: now_ms,
            last_read,
            ours,
        };
        changed.then(|| self.change_text(before, false))
    }

    fn change_text(&self, before: bool, after: bool) -> String {
        if let Approval::RefusedByVenue { text, ours, .. } = &self.approval {
            return if *ours {
                format!(
                    "the venue refused Guard's builder field for a reason on Orcastrate's side (the venue: \"{text}\"); nothing for the account to approve. New entries are refused, exits go without the field; Guard tries the field again after {} minutes or when the approval changes",
                    REFUSED_BACKOFF_MS / 60_000
                )
            } else {
                format!(
                    "the venue refused Guard's builder field: the account's approval was withdrawn or lowered (the venue: \"{text}\"). New entries are refused until it is approved again at {APPROVE_URL}; exits go without the field"
                )
            };
        }
        match (before, after) {
            (_, true) => format!(
                "builder fee approved ({}); Guard's orders carry it{}",
                self.approval_text(),
                if self.builder_on_triggers {
                    ""
                } else {
                    " (not order actions holding a stop or take profit)"
                }
            ),
            (true, false) => format!(
                "the builder fee approval was withdrawn or lowered ({}); new entries are refused until it is approved again at {APPROVE_URL}, exits go without the builder field",
                self.approval_text()
            ),
            (false, false) => format!(
                "builder fee not approved ({}); {}",
                self.approval_text(),
                if self.sends {
                    format!("new entries are refused until it is approved at {APPROVE_URL}")
                } else {
                    "paper mode never blocks".to_owned()
                }
            ),
        }
    }

    fn approval_text(&self) -> String {
        match &self.approval {
            Approval::Unchecked => "not read yet".to_owned(),
            Approval::Read { max_tenths_bp } => {
                format!("approved at most {max_tenths_bp} tenths of a bp")
            }
            Approval::RefusedByVenue { text, .. } => format!("the venue refused it: {text}"),
        }
    }

    /// For `/guard/status`: the mode, what it charges, and the approval.
    pub fn status(&self) -> Value {
        let mut out = match &self.mode {
            FeeMode::Builder(builder) => json!({
                "mode": "builder",
                "address": builder.address,
                "fee_tenths_bp": builder.fee_tenths_bp,
                "rate": rate(builder.fee_tenths_bp),
            }),
            FeeMode::FeeFree { licensee } => json!({"mode": "fee_free", "licensee": licensee}),
            FeeMode::Off(why) => json!({"mode": "off", "why": why}),
        };
        if let (Some(fields), Some(_)) = (out.as_object_mut(), self.mode.builder()) {
            let (state, max, venue) = match &self.approval {
                Approval::Unchecked => ("unchecked", None, None),
                Approval::Read { max_tenths_bp } if self.approved() => {
                    ("approved", Some(*max_tenths_bp), None)
                }
                Approval::Read { max_tenths_bp } => ("not_approved", Some(*max_tenths_bp), None),
                Approval::RefusedByVenue {
                    text,
                    last_read,
                    ours,
                    ..
                } => (
                    if *ours {
                        "refused_by_venue_builder"
                    } else {
                        "refused_by_venue"
                    },
                    *last_read,
                    Some(text.clone()),
                ),
            };
            fields.insert(
                "approval".into(),
                json!({
                    "state": state,
                    "max_tenths_bp": max,
                    "checked_at_ms": self.checked_at_ms,
                    "error": self.error,
                    "venue": venue,
                }),
            );
            fields.insert("charged".into(), json!(self.sends && self.approved()));
            fields.insert("on_triggers".into(), json!(self.builder_on_triggers));
            fields.insert("paper".into(), json!(!self.sends));
            fields.insert(
                "entries_blocked".into(),
                json!(self.entry_refusal().is_some()),
            );
            let ours = matches!(self.approval, Approval::RefusedByVenue { ours: true, .. });
            if !self.approved() && !ours {
                fields.insert("approve_url".into(), json!(APPROVE_URL));
            }
        }
        out
    }
}

/// A `maxBuilderFee` answer: the approved maximum in tenths of a basis
/// point (Hyperliquid: `1` means 0.001%); `null` is no approval.
fn parse_max_builder_fee(value: &Value) -> Option<u64> {
    match value {
        Value::Null => Some(0),
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// A fee in tenths of a basis point as a percentage: 20 is `0.02%`.
pub fn rate(fee_tenths_bp: u64) -> String {
    format!(
        "{}%",
        (Decimal::from(fee_tenths_bp) / Decimal::from(1_000u64)).normalize()
    )
}

/// The builder fee on `notional` USDC at `fee_tenths_bp`: notional × f /
/// 100,000 (a tenth of a basis point is 1/100,000).
pub fn fee_usdc(notional: Decimal, fee_tenths_bp: u64) -> Option<Decimal> {
    notional
        .checked_mul(Decimal::from(fee_tenths_bp))?
        .checked_div(Decimal::from(100_000u64))
}

/// `action` with `builder` as its builder field when it is an order action
/// (any builder field it had is replaced: only Guard's ever goes out).
/// Other actions have no builder field and are returned as they are.
pub fn with_builder(action: &Action, builder: Option<&Builder>) -> Action {
    match action {
        Action::Order(order) => {
            let mut order = order.clone();
            order.builder = builder.cloned();
            Action::Order(order)
        }
        other => other.clone(),
    }
}

/// Whether `action` is an order action holding a trigger order.
fn has_trigger(action: &Action) -> bool {
    matches!(action, Action::Order(order) if order.orders.iter().any(|order| order.is_trigger()))
}

/// Whether `action` is an entry that may rest (a limit other than IOC that
/// is not reduce-only) sent with triggers waiting for it. Such an action
/// carries the builder field only while [`BUILDER_ON_RESTING_AND_POSITION_TPSL`]
/// is on: whether the venue activates the waiting stops when the entry
/// fills after the approval was withdrawn has not been tested (only
/// children of entries that filled at once were, 6 Oct 2026). An IOC entry
/// fills or ends at once, while the approval is confirmed.
fn resting_entry_with_triggers(action: &Action) -> bool {
    has_trigger(action)
        && matches!(action, Action::Order(order) if order.orders.iter().any(|order| {
            !order.reduce_only
                && !matches!(order.kind, OrderKind::Limit { tif: Tif::Ioc })
                && !order.is_trigger()
        }))
}

/// Whether `action` is an order action of reduce-only orders alone: an
/// exit, which may go without the builder field when the venue refuses it.
pub fn exits_only(action: &Action) -> bool {
    match action {
        Action::Order(order) => {
            !order.orders.is_empty() && order.orders.iter().all(|order| order.reduce_only)
        }
        _ => false,
    }
}

/// The venue's text refusing an order for its builder field (its texts:
/// "Builder fee has not been approved.", "Builder fee is too high.",
/// "Builder has insufficient balance to be approved.", as the venue
/// words them), from the whole action or one order's
/// status; `None` when the reply refuses nothing for the builder.
pub fn builder_refusal_text(reply: &Value) -> Option<String> {
    let mentions = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .filter(|text| text.to_ascii_lowercase().contains("builder"))
            .map(str::to_owned)
    };
    if reply.get("status").and_then(Value::as_str) == Some("err") {
        return mentions(reply.get("response"));
    }
    reply
        .pointer("/response/data/statuses")
        .and_then(Value::as_array)
        .and_then(|statuses| {
            statuses
                .iter()
                .find_map(|status| mentions(status.get("error")))
        })
}

/// Whether a venue reply refuses an order for its builder field.
pub fn is_builder_refusal(reply: &Value) -> bool {
    builder_refusal_text(reply).is_some()
}

/// Whether the venue placed nothing of an order action: the whole action
/// refused, or every order's status an error. Only then may Guard send it
/// again (without the builder field) without doubling an order.
pub fn nothing_placed(reply: &Value) -> bool {
    if reply.get("status").and_then(Value::as_str) == Some("err") {
        return true;
    }
    reply
        .pointer("/response/data/statuses")
        .and_then(Value::as_array)
        .is_some_and(|statuses| {
            !statuses.is_empty() && statuses.iter().all(|status| status.get("error").is_some())
        })
}

/// The policy an entry is sized with when it carries `builder`: the builder
/// fee (tenths of a bp, so f / 10 bp) added to `fee_bps`, since it is paid
/// on the entry and again on the exit. Sizing grows only more careful.
pub fn sizing_policy(policy: &Policy, builder: Option<&Builder>) -> Policy {
    let mut policy = policy.clone();
    if let Some(builder) = builder
        && let Some(fee_bps) = Decimal::from(builder.fee_tenths_bp)
            .checked_div(Decimal::TEN)
            .and_then(|bps| policy.fee_bps.checked_add(bps))
    {
        policy.fee_bps = fee_bps;
    }
    policy
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    const DAY: i64 = DAY_MS;

    #[test]
    fn days_left_and_the_warning_stages() {
        let expires = 100 * DAY;
        // Hand-computed: 20 days before is no warning; 14 days before (to
        // the millisecond) the first; 7 the second; the last day the third.
        assert_eq!(expiry_stage(expires, expires - 20 * DAY), None);
        assert_eq!(expiry_stage(expires, expires - 14 * DAY - 1), None);
        assert_eq!(expiry_stage(expires, expires - 14 * DAY), Some(14));
        assert_eq!(expiry_stage(expires, expires - 7 * DAY - 1), Some(14));
        assert_eq!(expiry_stage(expires, expires - 7 * DAY), Some(7));
        assert_eq!(expiry_stage(expires, expires - DAY), Some(1));
        assert_eq!(expiry_stage(expires, expires - 1), Some(1));
        assert_eq!(expiry_stage(expires, expires), None);
        assert_eq!(days_left(expires, expires - 14 * DAY), 14);
        assert_eq!(days_left(expires, expires - 14 * DAY + 1), 14);
        assert_eq!(days_left(expires, expires - 13 * DAY - 1), 14);
        assert_eq!(days_left(expires, expires - 1), 1);
        assert_eq!(days_left(expires, expires), 0);
        assert_eq!(days_left(expires, expires + DAY), 0);
    }

    #[test]
    fn switching_the_mode_reads_the_approval_again() {
        let builder = Builder {
            address: "0x0000000000000000000000000000000000000001".into(),
            fee_tenths_bp: BUILDER_FEE_TENTHS_BP,
        };
        let mut fee = FeeState::new(
            FeeMode::FeeFree {
                licensee: "x".into(),
            },
            true,
        );
        assert!(fee.entry_refusal().is_none());
        assert!(!fee.switch_mode(FeeMode::FeeFree {
            licensee: "x".into()
        }));
        assert!(fee.switch_mode(FeeMode::Builder(builder.clone())));
        assert_eq!(fee.mode(), &FeeMode::Builder(builder.clone()));
        // Not approved yet: entries wait, a check is due now.
        assert!(fee.entry_refusal().is_some());
        assert!(fee.check_due(0));
        let issued = fee.begin_check(0);
        fee.record_answer(issued, 1, Ok(&json!(20)));
        assert!(fee.approved());
        assert!(fee.entry_refusal().is_none());
        let in_flight = fee.begin_check(2);
        // Back to fee-free and to the builder again: read again.
        assert!(fee.switch_mode(FeeMode::FeeFree {
            licensee: "y".into()
        }));
        assert!(fee.switch_mode(FeeMode::Builder(builder)));
        assert!(!fee.approved());
        // The old builder's in-flight approval must not approve the new mode.
        assert_eq!(fee.record_answer(in_flight, 3, Ok(&json!(20))), None);
        assert!(!fee.approved());
        let current = fee.begin_check(4);
        fee.record_answer(current, 5, Ok(&json!(20)));
        assert!(fee.approved());
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rust_decimal::dec;

    use super::*;

    /// A test signing key from a fixed seed. Never the production key:
    /// [`LICENCE_PUBLIC_KEY`] is not this key's public half.
    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sign_payload(signer: &SigningKey, payload: &str) -> String {
        let signature = signer.sign(payload.as_bytes());
        format!(
            "{PREFIX}{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    const NOW: i64 = 1_791_000_000_000;
    /// A test builder address.
    const BUILDER: &str = "0x00000000000000000000000000000000000000Bb";

    /// The account the test licences are for, and another.
    const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
    const OTHER_ACCOUNT: &str = "0x0000000000000000000000000000000000000001";

    fn account() -> Address {
        Address::from_hex(ACCOUNT).unwrap()
    }

    /// The fee mode on mainnet with the test builder, for [`ACCOUNT`].
    fn mainnet(
        key: Option<&str>,
        public: Option<&[u8; 32]>,
        now: i64,
    ) -> (FeeMode, Option<String>) {
        fee_mode_with(
            FeeNetwork::Mainnet,
            key,
            public,
            now,
            account(),
            Some(BUILDER),
            None,
        )
    }
    const FEE_FREE: &str = r#"{"licensee":"Example GmbH","expires_at_ms":1798761600000,"features":["fee_free"],"accounts":["0x5e9ee1089755c3435139848e47e6635505d5a13a"]}"#;

    #[test]
    fn a_valid_key_verifies_offline() {
        let public = signer().verifying_key().to_bytes();
        let licence = verify(&sign_payload(&signer(), FEE_FREE), &public, NOW).unwrap();
        assert_eq!(licence.licensee, "Example GmbH");
        assert!(licence.fee_free);
        assert_eq!(licence.builder, None);
    }

    #[test]
    fn expired_forged_and_malformed_keys_are_refused() {
        let public = signer().verifying_key().to_bytes();
        let key = sign_payload(&signer(), FEE_FREE);
        // Expired: at the expiry and after.
        assert!(matches!(
            verify(&key, &public, 1_798_761_600_000),
            Err(LicenceError::Expired { .. })
        ));
        // Signed by someone else.
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert_eq!(
            verify(&sign_payload(&other, FEE_FREE), &public, NOW),
            Err(LicenceError::Forged)
        );
        // The payload changed after signing (a later expiry).
        let (_, signature) = key.split_once('.').unwrap();
        let edited = FEE_FREE.replace("1798761600000", "4102444800000");
        let tampered = format!("{PREFIX}{}.{signature}", URL_SAFE_NO_PAD.encode(edited));
        assert_eq!(verify(&tampered, &public, NOW), Err(LicenceError::Forged));
        // Shapes.
        assert_eq!(verify("zgl2_x.y", &public, NOW), Err(LicenceError::Prefix));
        assert_eq!(
            verify("zgl1_nodot", &public, NOW),
            Err(LicenceError::Malformed)
        );
        assert_eq!(
            verify("zgl1_!!.??", &public, NOW),
            Err(LicenceError::Malformed)
        );
        // A signed payload with an unknown field.
        let unknown = sign_payload(
            &signer(),
            r#"{"licensee":"x","expires_at_ms":1798761600000,"features":[],"seats":5}"#,
        );
        assert_eq!(verify(&unknown, &public, NOW), Err(LicenceError::Malformed));
    }

    #[test]
    fn fee_free_only_with_a_valid_key() {
        let public = signer().verifying_key().to_bytes();
        let key = sign_payload(&signer(), FEE_FREE);
        // Valid on mainnet: fee-free.
        let (mode, warning) = mainnet(Some(&key), Some(&public), NOW);
        assert_eq!(
            mode,
            FeeMode::FeeFree {
                licensee: "Example GmbH".into()
            }
        );
        assert_eq!(warning, None);
        assert_eq!(mode.builder(), None);
        // Expired or forged: the fee, with a warning, and Guard keeps running.
        let (mode, warning) = mainnet(Some(&key), Some(&public), 1_798_761_600_000);
        assert!(!matches!(mode, FeeMode::FeeFree { .. }));
        assert!(warning.unwrap().contains("expired"));
        let forged = sign_payload(&SigningKey::from_bytes(&[9u8; 32]), FEE_FREE);
        let (mode, warning) = mainnet(Some(&forged), Some(&public), NOW);
        assert!(!matches!(mode, FeeMode::FeeFree { .. }));
        assert!(warning.unwrap().contains("not issued by Orcastrate"));
        // No public key built in yet (this phase): no key verifies.
        let (mode, warning) = mainnet(Some(&key), LICENCE_PUBLIC_KEY.as_ref(), NOW);
        assert!(!matches!(mode, FeeMode::FeeFree { .. }));
        assert!(warning.is_some());
        // Off mainnet: no fee either way.
        let (mode, _) = fee_mode_with(
            FeeNetwork::Testnet,
            None,
            Some(&public),
            NOW,
            account(),
            Some(BUILDER),
            None,
        );
        assert!(matches!(mode, FeeMode::Off(_)));
    }

    #[test]
    fn a_licence_is_good_only_for_the_accounts_it_names() {
        let public = signer().verifying_key().to_bytes();
        let key = sign_payload(&signer(), FEE_FREE);
        // For another account: the fee, and a warning naming both.
        let (mode, warning) = fee_mode_with(
            FeeNetwork::Mainnet,
            Some(&key),
            Some(&public),
            NOW,
            Address::from_hex(OTHER_ACCOUNT).unwrap(),
            Some(BUILDER),
            None,
        );
        assert_eq!(mode, FeeMode::Builder(builder()));
        let warning = warning.unwrap();
        assert!(
            warning.contains(OTHER_ACCOUNT) && warning.contains(ACCOUNT),
            "{warning}"
        );
        // A key that names no account (as every key before 7 Oct 2026):
        // good for none.
        let old = sign_payload(
            &signer(),
            r#"{"licensee":"Example GmbH","expires_at_ms":1798761600000,"features":["fee_free"]}"#,
        );
        assert!(verify(&old, &public, NOW).unwrap().accounts.is_empty());
        let (mode, warning) = mainnet(Some(&old), Some(&public), NOW);
        assert_eq!(mode, FeeMode::Builder(builder()));
        assert!(warning.unwrap().contains("no account"));
        // The account named in another case: the same account.
        let upper = FEE_FREE.replace(ACCOUNT, &ACCOUNT.to_ascii_uppercase().replace("0X", "0x"));
        let (mode, _) = mainnet(Some(&sign_payload(&signer(), &upper)), Some(&public), NOW);
        assert!(matches!(mode, FeeMode::FeeFree { .. }));
        // A named "account" that is no address: the key is malformed.
        let bad = FEE_FREE.replace(ACCOUNT, "not an address");
        assert_eq!(
            verify(&sign_payload(&signer(), &bad), &public, NOW),
            Err(LicenceError::Malformed)
        );
        // A licence for another builder is bound the same way.
        let desk = r#"{"licensee":"Desk","expires_at_ms":1798761600000,"features":[],"accounts":["0x0000000000000000000000000000000000000001"],"builder":{"address":"0x00000000000000000000000000000000000000AB","fee_tenths_bp":5}}"#;
        let (mode, _) = mainnet(Some(&sign_payload(&signer(), desk)), Some(&public), NOW);
        assert_eq!(mode, FeeMode::Builder(builder()));
    }

    #[test]
    fn a_licence_may_name_another_builder() {
        let public = signer().verifying_key().to_bytes();
        let payload = r#"{"licensee":"Desk","expires_at_ms":1798761600000,"features":[],"accounts":["0x5e9ee1089755c3435139848e47e6635505d5a13a"],"builder":{"address":"0x00000000000000000000000000000000000000AB","fee_tenths_bp":5}}"#;
        let (mode, _) = mainnet(Some(&sign_payload(&signer(), payload)), Some(&public), NOW);
        assert_eq!(
            mode,
            FeeMode::Builder(Builder {
                address: "0x00000000000000000000000000000000000000ab".into(),
                fee_tenths_bp: 5
            })
        );
        let greedy = r#"{"licensee":"Desk","expires_at_ms":1798761600000,"features":[],"builder":{"address":"0x00000000000000000000000000000000000000AB","fee_tenths_bp":101}}"#;
        assert_eq!(
            verify(&sign_payload(&signer(), greedy), &public, NOW),
            Err(LicenceError::Builder)
        );
    }

    #[test]
    fn the_most_accounts_fit_a_key_with_the_longest_licensee() {
        let secret = [7u8; 32];
        let public = public_key_of(&secret);
        let accounts: Vec<String> = (0..MAX_ACCOUNTS).map(|n| format!("0x{n:040x}")).collect();
        let terms = Terms {
            licensee: "L".repeat(200),
            expires_at_ms: 1_798_761_600_000,
            features: vec!["fee_free".into()],
            accounts: accounts.clone(),
            builder: Some(BuilderOverride {
                address: "0x00000000000000000000000000000000000000ab".into(),
                fee_tenths_bp: 100,
            }),
        };
        let key = issue(&terms, &secret).unwrap();
        assert!(key.len() <= MAX_KEY_LEN, "{}", key.len());
        assert_eq!(
            verify(&key, &public, NOW).unwrap().accounts.len(),
            MAX_ACCOUNTS
        );
        // One more is refused when issued.
        let mut more = terms;
        more.accounts.push(format!("0x{:040x}", MAX_ACCOUNTS));
        assert!(issue(&more, &secret).is_err());
    }

    #[test]
    fn issued_keys_round_trip_and_tampering_fails() {
        let secret = [7u8; 32];
        let public = public_key_of(&secret);
        assert_eq!(public, signer().verifying_key().to_bytes());
        let terms = Terms {
            licensee: "Example GmbH".into(),
            expires_at_ms: 1_798_761_600_000,
            features: vec!["fee_free".into()],
            accounts: vec![ACCOUNT.to_ascii_uppercase().replace("0X", "0x")],
            builder: Some(BuilderOverride {
                address: "0x00000000000000000000000000000000000000ab".into(),
                fee_tenths_bp: 5,
            }),
        };
        let key = issue(&terms, &secret).unwrap();
        let licence = verify(&key, &public, NOW).unwrap();
        // Issued lowercase.
        assert_eq!(licence.accounts, vec![account()]);
        assert_eq!(licence.licensee, "Example GmbH");
        assert!(licence.fee_free);
        assert_eq!(licence.builder.unwrap().fee_tenths_bp, 5);
        // Another key's public half: forged.
        assert_eq!(
            verify(&key, &public_key_of(&[8u8; 32]), NOW),
            Err(LicenceError::Forged)
        );
        // Each field changed after signing: forged.
        let (payload, signature) = key.strip_prefix(PREFIX).unwrap().split_once('.').unwrap();
        let text = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        for (from, to) in [
            ("Example GmbH", "Someone Else"),
            ("1798761600000", "4102444800000"),
            ("\"fee_free\"", "\"fee_free\",\"fee_free\""),
            ("\"fee_tenths_bp\":5", "\"fee_tenths_bp\":0"),
            (&ACCOUNT[2..], &OTHER_ACCOUNT[2..]),
        ] {
            let edited = text.replace(from, to);
            assert_ne!(edited, text);
            let tampered = format!("{PREFIX}{}.{signature}", URL_SAFE_NO_PAD.encode(edited));
            assert_eq!(
                verify(&tampered, &public, NOW),
                Err(LicenceError::Forged),
                "{from}"
            );
        }
        // Terms Guard would refuse are not issued.
        let unknown = Terms {
            features: vec!["unlimited".into()],
            ..terms.clone()
        };
        assert_eq!(issue(&unknown, &secret), Err(LicenceError::Malformed));
        // No account, a bad one, or one twice: not issued.
        for accounts in [
            vec![],
            vec!["0x123".to_owned()],
            vec![ACCOUNT.to_owned(), ACCOUNT.to_owned()],
        ] {
            let terms = Terms {
                accounts,
                ..terms.clone()
            };
            assert_eq!(issue(&terms, &secret), Err(LicenceError::Accounts));
        }
        let greedy = Terms {
            builder: Some(BuilderOverride {
                address: "0x00000000000000000000000000000000000000ab".into(),
                fee_tenths_bp: 101,
            }),
            ..terms
        };
        assert_eq!(issue(&greedy, &secret), Err(LicenceError::Builder));
    }

    #[test]
    fn the_constants_are_sound() {
        // The production public key is never the test key, whose seed is
        // in the source.
        assert_ne!(LICENCE_PUBLIC_KEY, Some(test_key::public()));
        assert_eq!(test_key::public(), signer().verifying_key().to_bytes());
        // Builder addresses, once set, are addresses.
        for address in [ORCASTRATE_BUILDER, ORCASTRATE_TESTNET_BUILDER]
            .into_iter()
            .flatten()
        {
            assert!(Address::from_hex(address).is_some(), "{address}");
        }
        // The decided fee: 0.02%, f = 20 (within the venue's 0.1% maximum:
        // a compile-time check above).
        assert_eq!(BUILDER_FEE_TENTHS_BP, 20);
        assert_eq!(rate(BUILDER_FEE_TENTHS_BP), "0.02%");
        // The compile-time decoder, on the test key's hex.
        assert_eq!(
            public_key_from_hex(
                "0xea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
            ),
            test_key::public()
        );
        // While the placeholders stand, nothing is charged and no licence
        // verifies.
        if ORCASTRATE_BUILDER.is_none() {
            let (mode, warning) = fee_mode(FeeNetwork::Mainnet, None, None, NOW, account());
            assert!(matches!(mode, FeeMode::Off(_)));
            assert_eq!(warning, None);
        }
        if LICENCE_PUBLIC_KEY.is_none() {
            let key = sign_payload(&signer(), FEE_FREE);
            let (mode, warning) = fee_mode(
                FeeNetwork::Mainnet,
                Some(&key),
                LICENCE_PUBLIC_KEY.as_ref(),
                NOW,
                account(),
            );
            assert!(!matches!(mode, FeeMode::FeeFree { .. }));
            assert!(warning.unwrap().contains("no licence public key"));
        }
    }

    fn builder() -> Builder {
        Builder {
            address: "0x00000000000000000000000000000000000000bb".into(),
            fee_tenths_bp: 20,
        }
    }

    #[test]
    fn testnet_charges_only_with_a_testnet_builder() {
        let (mode, _) = fee_mode_with(
            FeeNetwork::Testnet,
            None,
            None,
            NOW,
            account(),
            Some(BUILDER),
            None,
        );
        assert!(matches!(mode, FeeMode::Off(ref why) if why.contains("testnet")));
        let (mode, _) = fee_mode_with(
            FeeNetwork::Testnet,
            None,
            None,
            NOW,
            account(),
            None,
            Some(BUILDER),
        );
        assert_eq!(mode, FeeMode::Builder(builder()));
        // Mainnet: the mainnet builder at 20 tenths of a bp, lowercased.
        let (mode, _) = mainnet(None, None, NOW);
        assert_eq!(mode, FeeMode::Builder(builder()));
        // A fee-free licence turns it off on either network.
        let public = test_key::public();
        let key = sign_payload(&signer(), FEE_FREE);
        let (mode, _) = fee_mode_with(
            FeeNetwork::Testnet,
            Some(&key),
            Some(&public),
            NOW,
            account(),
            None,
            Some(BUILDER),
        );
        assert!(matches!(mode, FeeMode::FeeFree { .. }));
    }

    #[test]
    fn the_fee_in_usdc_and_as_a_rate() {
        // 0.02% of 10,000 USDC is 2 USDC; of 1,000,000 USDC, 200 USDC:
        // notional × 20 / 100,000.
        assert_eq!(fee_usdc(dec!(10000), 20), Some(dec!(2)));
        assert_eq!(fee_usdc(dec!(1000000), 20), Some(dec!(200)));
        // 100.3995 USDC: 100.3995 × 20 / 100,000 = 0.0200799 USDC.
        assert_eq!(fee_usdc(dec!(100.3995), 20), Some(dec!(0.0200799)));
        assert_eq!(rate(1), "0.001%");
        assert_eq!(rate(100), "0.1%");
    }

    #[test]
    fn entries_are_sized_with_the_builder_fee() {
        // Default policy: 4.5 bp fee and 1 bp slippage per side. With the
        // builder's 20 tenths of a bp (2 bp), 6.5 bp: the round trip at
        // 3,000 costs 3,000 × (6.5 + 1) × 2 / 10,000 = 4.5 USDC a unit,
        // against 3,000 × (4.5 + 1) × 2 / 10,000 = 3.3 without.
        let policy = Policy::default();
        assert_eq!(policy.round_trip_cost(dec!(3000)), Some(dec!(3.3)));
        let sized = sizing_policy(&policy, Some(&builder()));
        assert_eq!(sized.fee_bps, dec!(6.5));
        assert_eq!(sized.round_trip_cost(dec!(3000)), Some(dec!(4.5)));
        assert_eq!(sizing_policy(&policy, None), policy);
    }

    #[test]
    fn approval_gates_entries_and_the_field_never_exits() {
        let mut fee = FeeState::new(FeeMode::Builder(builder()), true);
        // Not read yet: entries wait, orders go without the field.
        assert!(fee.entry_refusal().unwrap().contains(APPROVE_URL));
        assert_eq!(fee.builder_for_orders(), None);
        assert!(fee.check_due(0));
        assert_eq!(
            fee.check_request("0x00000000000000000000000000000000000000aa"),
            Some(
                json!({"type": "maxBuilderFee", "user": "0x00000000000000000000000000000000000000aa", "builder": "0x00000000000000000000000000000000000000bb"})
            )
        );
        // Approved below 0.02% (10 tenths of a bp): still refused.
        assert!(fee.record_check(1_000, Ok(&json!(10))).is_some());
        assert!(!fee.approved());
        assert!(fee.entry_refusal().unwrap().contains("at most 10"));
        assert_eq!(fee.status()["approval"]["state"], "not_approved");
        assert_eq!(fee.status()["entries_blocked"], true);
        // Not approved: rechecked after a minute; an entry may ask for a
        // check at the next sync 15 s after the last one, once.
        assert!(!fee.check_due(60_999));
        assert!(fee.check_due(61_000));
        assert!(!fee.on_demand_due(15_999));
        assert!(fee.on_demand_due(16_000));
        fee.request_check();
        assert!(fee.check_due(16_000));
        assert!(!fee.on_demand_due(16_000));
        // Approved at exactly 20: the field goes on every order.
        assert!(fee.record_check(61_000, Ok(&json!(20))).is_some());
        assert!(fee.approved());
        assert_eq!(fee.entry_refusal(), None);
        assert_eq!(fee.builder_for_orders(), Some(&builder()));
        assert_eq!(fee.status()["charged"], true);
        assert!(fee.status().get("approve_url").is_none());
        // The same answer again: nothing to journal; next check in 5 min.
        assert_eq!(fee.record_check(62_000, Ok(&json!(20))), None);
        assert!(!fee.check_due(361_999));
        assert!(fee.check_due(362_000));
        assert!(!fee.on_demand_due(400_000));
        // An unreadable answer keeps what Guard knew.
        assert!(fee.record_check(362_000, Err("timeout".into())).is_some());
        assert!(fee.approved());
        assert!(
            fee.record_check(362_500, Ok(&json!({"weird": 1})))
                .is_some()
        );
        assert!(fee.approved());
        // The venue refuses the builder field: withdrawn after all. The
        // venue's text is carried, and the account is asked to approve.
        let text = fee
            .record_venue_refusal(363_000, "Builder fee has not been approved.")
            .unwrap();
        assert!(
            text.contains("withdrawn") && text.contains("has not been approved"),
            "{text}"
        );
        assert!(!fee.approved());
        assert_eq!(fee.builder_for_orders(), None);
        assert!(fee.entry_refusal().unwrap().contains(APPROVE_URL));
        assert_eq!(fee.status()["approval"]["state"], "refused_by_venue");
        assert_eq!(
            fee.record_venue_refusal(363_500, "Builder fee has not been approved."),
            None
        );
        // A refusal on the account's side ends with the next read: approved
        // again at the same value counts at once.
        assert!(fee.record_check(400_000, Ok(&json!(20))).is_some());
        assert!(fee.approved());
        // `null` is no approval.
        assert!(fee.record_check(500_000, Ok(&Value::Null)).is_some());
        assert_eq!(fee.approval(), &Approval::Read { max_tenths_bp: 0 });
        // A numeric string is read.
        fee.record_check(600_000, Ok(&json!("25")));
        assert!(fee.approved());
    }

    #[test]
    fn answers_out_of_order_are_ignored_and_checks_do_not_overlap() {
        let mut fee = FeeState::new(FeeMode::Builder(builder()), true);
        assert!(fee.check_due(0));
        let first = fee.begin_check(0);
        // One out: no second check, for up to twice the timeout.
        assert!(!fee.check_due(1_000));
        assert!(fee.check_due(2 * CHECK_TIMEOUT_MS));
        let second = fee.begin_check(2 * CHECK_TIMEOUT_MS);
        // The later check answers first (withdrawn), then the earlier one
        // (approved): the earlier answer is ignored.
        assert!(fee.record_answer(second, 6_000, Ok(&json!(0))).is_some());
        assert_eq!(fee.record_answer(first, 6_100, Ok(&json!(20))), None);
        assert!(!fee.approved());
        assert!(!fee.check_in_flight(6_100));
    }

    #[test]
    fn unknown_venue_texts_are_the_accounts_to_fix() {
        let mut fee = FeeState::new(FeeMode::Builder(builder()), true);
        fee.record_check(0, Ok(&json!(20)));
        fee.record_venue_refusal(1, "Builder something new.");
        assert_eq!(fee.status()["approval"]["state"], "refused_by_venue");
        assert!(fee.entry_refusal().unwrap().contains(APPROVE_URL));
    }

    #[test]
    fn a_refusal_on_the_builders_side_is_not_the_accounts_to_fix() {
        let mut fee = FeeState::new(FeeMode::Builder(builder()), true);
        fee.record_check(0, Ok(&json!(20)));
        assert!(fee.approved());
        let text = fee
            .record_venue_refusal(1_000, "Builder has insufficient balance to be approved.")
            .unwrap();
        assert!(text.contains("Orcastrate's side"), "{text}");
        assert!(text.contains("insufficient balance"), "{text}");
        let refusal = fee.entry_refusal().unwrap();
        assert!(refusal.contains("nothing for you to approve"), "{refusal}");
        assert!(!refusal.contains(APPROVE_URL), "{refusal}");
        let status = fee.status();
        assert_eq!(status["approval"]["state"], "refused_by_venue_builder");
        assert!(status.get("approve_url").is_none());
        // The same approval read again: still refused until 10 minutes
        // have passed (backoff), then the field is tried again.
        assert_eq!(fee.record_check(600_999, Ok(&json!(20))), None);
        assert!(!fee.approved());
        assert!(fee.record_check(601_000, Ok(&json!(20))).is_some());
        assert!(fee.approved());
    }

    #[test]
    fn triggers_carry_the_builder_field() {
        use crate::action::decode_action_value;
        // The tripwire: on since the testnet experiment of 6 Oct 2026;
        // switching it off is a reviewed change with a recorded decision.
        const { assert!(BUILDER_ON_TRIGGERS) };
        let mut fee = FeeState::new(FeeMode::Builder(builder()), true);
        fee.record_check(0, Ok(&json!(20)));
        let close = decode_action_value(&json!({"type": "order", "orders": [{"a": 1, "b": false,
            "p": "2900", "s": "1", "r": true, "t": {"limit": {"tif": "Ioc"}}}], "grouping": "na"}))
        .unwrap();
        let stop = decode_action_value(&json!({"type": "order", "orders": [{"a": 1, "b": false,
            "p": "2650", "s": "1", "r": true, "t": {"trigger": {"isMarket": true, "triggerPx": "2950", "tpsl": "sl"}}}],
            "grouping": "na", "builder": {"b": "0x00000000000000000000000000000000000000cc", "f": 1}}))
        .unwrap();
        let builder_of = |action: &Action| match action {
            Action::Order(order) => order.builder.clone(),
            _ => None,
        };
        // A close and a stop carry Guard's field (the stop's own is
        // replaced).
        assert_eq!(builder_of(&fee.apply(&close)), Some(builder()));
        assert_eq!(builder_of(&fee.apply(&stop)), Some(builder()));
        // Switched off (as before the experiment): the stop goes without.
        fee.set_builder_on_triggers(false);
        assert_eq!(builder_of(&fee.apply(&stop)), None);
        assert_eq!(builder_of(&fee.apply(&close)), Some(builder()));
        fee.set_builder_on_triggers(true);
        // Not approved: nothing carries it.
        fee.record_venue_refusal(1, "Builder fee has not been approved.");
        assert_eq!(builder_of(&fee.apply(&close)), None);
    }

    #[test]
    fn resting_entries_and_position_tpsl_follow_their_switch() {
        use crate::action::decode_action_value;
        let mut fee = FeeState::new(FeeMode::Builder(builder()), true);
        fee.record_check(0, Ok(&json!(20)));
        let with = |tif: &str, reduce_only: bool, grouping: &str| {
            decode_action_value(&json!({"type": "order", "orders": [
                {"a": 1, "b": true, "p": "3000", "s": "1", "r": reduce_only, "t": {"limit": {"tif": tif}}},
                {"a": 1, "b": false, "p": "2650", "s": "1", "r": true,
                 "t": {"trigger": {"isMarket": true, "triggerPx": "2940", "tpsl": "sl"}}}],
                "grouping": grouping}))
            .unwrap()
        };
        let builder_of = |action: &Action| match action {
            Action::Order(order) => order.builder.clone(),
            _ => None,
        };
        // On (the default): every shape carries it.
        const { assert!(BUILDER_ON_RESTING_AND_POSITION_TPSL) };
        for tif in ["Ioc", "Gtc", "Alo"] {
            assert_eq!(
                builder_of(&fee.apply(&with(tif, false, "normalTpsl"))),
                Some(builder()),
                "{tif}"
            );
        }
        let position = decode_action_value(&json!({"type": "order", "orders": [
            {"a": 1, "b": false, "p": "2650", "s": "1", "r": true,
             "t": {"trigger": {"isMarket": true, "triggerPx": "2940", "tpsl": "sl"}}}],
            "grouping": "positionTpsl"}))
        .unwrap();
        assert_eq!(builder_of(&fee.apply(&position)), Some(builder()));
        // Switched off: IOC entry with its stop: the field. Gtc or Alo: none.
        fee.set_builder_on_resting_and_position_tpsl(false);
        assert_eq!(
            builder_of(&fee.apply(&with("Ioc", false, "normalTpsl"))),
            Some(builder())
        );
        assert_eq!(
            builder_of(&fee.apply(&with("Gtc", false, "normalTpsl"))),
            None
        );
        assert_eq!(
            builder_of(&fee.apply(&with("Alo", false, "normalTpsl"))),
            None
        );
        // A reduce-only parent with its stop: an exit, the field.
        assert_eq!(
            builder_of(&fee.apply(&with("Gtc", true, "normalTpsl"))),
            Some(builder())
        );
        // A positionTpsl stop: none.
        assert_eq!(builder_of(&fee.apply(&position)), None);
    }

    #[test]
    fn a_retry_only_when_nothing_was_placed() {
        assert!(nothing_placed(
            &json!({"status": "err", "response": "Builder fee has not been approved."})
        ));
        assert!(nothing_placed(
            &json!({"status": "ok", "response": {"type": "order",
            "data": {"statuses": [{"error": "Builder fee has not been approved."}, {"error": "x"}]}}})
        ));
        assert!(!nothing_placed(
            &json!({"status": "ok", "response": {"type": "order",
            "data": {"statuses": [{"filled": {"totalSz": "1", "avgPx": "1", "oid": 1}}, {"error": "Builder fee has not been approved."}]}}})
        ));
        assert_eq!(
            builder_refusal_text(&json!({"status": "err", "response": "Builder fee is too high."})),
            Some("Builder fee is too high.".to_owned())
        );
    }

    #[test]
    fn paper_reports_the_fee_and_never_blocks() {
        let mut fee = FeeState::new(FeeMode::Builder(builder()), false);
        assert_eq!(fee.entry_refusal(), None);
        // Paper shows the field it would send.
        assert_eq!(fee.builder_for_orders(), Some(&builder()));
        fee.record_check(0, Ok(&json!(0)));
        assert_eq!(fee.entry_refusal(), None);
        let status = fee.status();
        assert_eq!(status["paper"], true);
        assert_eq!(status["charged"], false);
        assert_eq!(status["entries_blocked"], false);
        assert_eq!(status["rate"], "0.02%");
        // No builder (off, fee-free): nothing to check, nothing blocked.
        let off = FeeState::new(FeeMode::Off("testnet".into()), true);
        assert!(!off.check_due(0));
        assert_eq!(off.check_request("0x00"), None);
        assert_eq!(off.entry_refusal(), None);
        assert_eq!(off.status()["mode"], "off");
        let free = FeeState::new(
            FeeMode::FeeFree {
                licensee: "Desk".into(),
            },
            true,
        );
        assert_eq!(free.entry_refusal(), None);
        assert_eq!(free.builder_for_orders(), None);
    }

    #[test]
    fn builder_refusals_are_recognised() {
        assert!(is_builder_refusal(
            &json!({"status": "err", "response": "Builder fee has not been approved."})
        ));
        assert!(is_builder_refusal(
            &json!({"status": "ok", "response": {"type": "order",
            "data": {"statuses": [{"resting": {"oid": 1}}, {"error": "Builder fee has not been approved."}]}}})
        ));
        assert!(!is_builder_refusal(
            &json!({"status": "err", "response": "Order has invalid price."})
        ));
        assert!(!is_builder_refusal(
            &json!({"status": "ok", "response": {"type": "order",
            "data": {"statuses": [{"error": "Insufficient margin to place order."}]}}})
        ));
    }
}
