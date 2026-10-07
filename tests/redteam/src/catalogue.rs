// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The attack catalogue: every case is named, says which rule or decision
//! it protects, and carries the refusal the suite expects. Cases are built
//! once against a [`Ctx`] (the client key the suite plays, a second key for
//! forgeries, and the network the target signs for) so each gets a fresh,
//! increasing nonce.
//!
//! The invariant the suite checks is deliberately conservative:
//!
//! - [`Expect::Refused`]: the request must be vetoed or rejected. A resize
//!   or a clean forward is a failure. Used for authentication, fund
//!   movement, stop-loosening, leverage changes and the builder field.
//! - [`Expect::NotFullSize`]: the request must not be forwarded at the size
//!   it asked for — a veto, a resize or a rejection all pass. Used for
//!   over-sizing, over-leverage and market attacks, where Guard is allowed
//!   to cut the order down instead of refusing it.
//! - [`Expect::Handled`]: the target must stay up and answer. Used for the
//!   robustness probes.
//! - [`Expect::NoLeak`]: the reply must not contain a private key.
//!
//! `expected_code` is the refusal code or reason the attack is designed to
//! trigger. It is documentation and appears in the report; the pass/fail
//! test is the `Expect` above, so the suite reads correctly whether Guard
//! answers with a veto (testnet), a `would …` line (paper) or a plain
//! Hyperliquid error, and still catches a mock that forwards everything.

use crate::actions::{
    self, BTC, ETH, HIP3_ASSET, OUTCOME_ASSET, OrderSpec, SOL, body_with_signature, order,
    signed_body, typed, ws_post,
};
use crate::hlsign::{Key, Sig, SigningNet, Wire};

/// What a case needs from its target before it is meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requires {
    /// Nothing: runs against any target.
    Nothing,
    /// A position must exist, so Guard tracks stops and reduce-only size.
    /// Paper Guard holds no positions, so these run on the mock and on a
    /// testnet Guard only.
    Fills,
    /// A market allowlist must be set (the default is "all markets").
    Allowlist,
    /// The engine must already be halted (a daily-loss or drawdown halt).
    Halt,
    /// The target must manage a HIP-3 dex (its rules name one), found
    /// through its status and `/info` ([`Hip3Target`]).
    Hip3,
    /// As [`Requires::Hip3`], and that dex must list a halted market.
    Hip3Halted,
}

/// A HIP-3 dex the target manages, found through its public interface
/// (`/guard/status` lists the dexes Guard manages; `/info` the dex's `meta`
/// and mids, and `perpDexs`), for the cases that attack one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hip3Target {
    /// The dex's index in `perpDexs` and its name.
    pub dex: u64,
    pub name: String,
    /// A listed market of that dex: its index in the dex's `meta`, its
    /// asset id (`100000 + 10000 × dex + index`) and its mid.
    pub index: u64,
    pub asset: u64,
    pub mid: String,
    /// The index of a dex the target does not manage.
    pub other_dex: u64,
    /// The asset id of a halted (delisted) market of the managed dex.
    pub halted: Option<u64>,
}

impl Hip3Target {
    /// A made-up dex for targets that cannot be asked (the mock): dex 1,
    /// its first market at 4,000, dex 2 unmanaged, market 2 halted.
    pub fn synthetic() -> Self {
        Self {
            dex: 1,
            name: "xyz".to_owned(),
            index: 0,
            asset: 110_000,
            mid: "4000".to_owned(),
            other_dex: 2,
            halted: Some(110_002),
        }
    }

    /// The asset id of the market at `index` of dex `dex`.
    pub fn id(dex: u64, index: u64) -> u64 {
        100_000 + 10_000 * dex + index
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    Refused,
    NotFullSize,
    Handled,
    NoLeak,
    /// A cancel-then-replace sequence aimed at the protective stop with
    /// this order id: passes when the cancel is refused and that stop still
    /// rests afterwards with its trigger and size unchanged (read from the
    /// open orders). A forwarded looser stop placed beside the kept one
    /// changes no protection.
    StopKept {
        oid: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Authentication,
    FundMovement,
    Sizing,
    Stops,
    Leverage,
    Markets,
    Halts,
    BuilderField,
    Robustness,
    AgentContent,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Authentication => "authentication",
            Category::FundMovement => "fund movement disguised as trading",
            Category::Sizing => "limit evasion: sizing",
            Category::Stops => "limit evasion: stops",
            Category::Leverage => "limit evasion: leverage",
            Category::Markets => "limit evasion: markets",
            Category::Halts => "limit evasion: halts",
            Category::BuilderField => "builder field",
            Category::Robustness => "robustness",
            Category::AgentContent => "agent-style content",
        }
    }
}

/// How a case reaches the target.
#[derive(Debug, Clone)]
pub enum Probe {
    /// POST these bytes to `/exchange`.
    Exchange(Vec<u8>),
    /// POST this text to `/exchange`, as written (malformed JSON, NaN, …).
    ExchangeText(String),
    /// POST these bytes to `/info`.
    Info(Vec<u8>),
    /// A WebSocket `post` frame to `/ws`.
    Ws(String),
    /// Several `/exchange` requests in order; the last reply is judged.
    Sequence(Vec<Vec<u8>>),
    /// Many identical requests as fast as possible.
    Flood { body: Vec<u8>, count: usize },
    /// A body of this many bytes.
    HugeBody { size: usize },
    /// A request whose body dribbles in and never completes.
    Slowloris,
    /// A raw POST to an arbitrary path (for guessed control endpoints).
    RawPost { path: String, body: Vec<u8> },
}

/// One attack.
pub struct Case {
    pub id: &'static str,
    pub category: Category,
    pub rule: &'static str,
    pub about: &'static str,
    pub expected_code: &'static str,
    pub expect: Expect,
    pub requires: Requires,
    pub probe: Probe,
}

/// The keys and network the catalogue is built against.
pub struct Ctx {
    pub client: Key,
    pub attacker: Key,
    pub net: SigningNet,
    base: u64,
    /// The HIP-3 dex the target manages, when it manages one.
    pub hip3: Option<Hip3Target>,
}

impl Ctx {
    pub fn new(client: Key, attacker: Key, net: SigningNet, now_ms: u64) -> Self {
        Self {
            client,
            attacker,
            net,
            base: now_ms,
            hip3: None,
        }
    }

    /// The same context, attacking `hip3` as well.
    pub fn with_hip3(mut self, hip3: Option<Hip3Target>) -> Self {
        self.hip3 = hip3;
        self
    }
}

struct Build<'a> {
    ctx: &'a Ctx,
    counter: u64,
    cases: Vec<Case>,
}

impl<'a> Build<'a> {
    fn next_nonce(&mut self) -> u64 {
        self.counter += 1;
        self.ctx.base + self.counter
    }

    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        id: &'static str,
        category: Category,
        rule: &'static str,
        about: &'static str,
        expected_code: &'static str,
        expect: Expect,
        requires: Requires,
        probe: Probe,
    ) {
        self.cases.push(Case {
            id,
            category,
            rule,
            about,
            expected_code,
            expect,
            requires,
            probe,
        });
    }

    /// A correctly signed `/exchange` body for `action`.
    fn signed(&mut self, action: &Wire) -> Vec<u8> {
        let nonce = self.next_nonce();
        signed_body(&self.ctx.client, self.ctx.net, action, nonce, None)
    }
}

/// The whole catalogue.
pub fn all(ctx: &Ctx) -> Vec<Case> {
    let mut b = Build {
        ctx,
        counter: 0,
        cases: Vec::new(),
    };
    authentication(&mut b);
    fund_movement(&mut b);
    sizing(&mut b);
    stops(&mut b);
    leverage(&mut b);
    markets(&mut b);
    halts(&mut b);
    builder_field(&mut b);
    robustness(&mut b);
    agent_content(&mut b);
    b.cases
}

fn authentication(b: &mut Build) {
    use Category::Authentication as A;
    // A benign no-op order to carry a signature that does not match the body.
    let benign = actions::buy(BTC, "60000", "0.001");
    let oversize = actions::buy(BTC, "60000", "500");

    // Unsigned: r = s = 0, which recovers no key.
    let nonce = b.next_nonce();
    let body = body_with_signature(
        &benign,
        nonce,
        None,
        &Sig {
            r: [0; 32],
            s: [0; 32],
            v: 27,
        },
    );
    b.add(
        "auth_unsigned",
        A,
        "threat model §bot compromised; auth",
        "an /exchange request with an all-zero signature",
        "auth_bad_signature",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // Signed by a key that is not a Guard client.
    let nonce = b.next_nonce();
    let body = signed_body(&b.ctx.attacker, b.ctx.net, &benign, nonce, None);
    b.add(
        "auth_wrong_key",
        A,
        "auth: only configured clients",
        "a request signed by a key that is not a Guard client",
        "auth_unknown_signer",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // A client signature with its r/s bytes flipped: recovers nobody or a
    // stranger.
    let nonce = b.next_nonce();
    let mut sig = b
        .ctx
        .client
        .sign_l1_action(b.ctx.net, &benign, nonce, None)
        .expect("signs");
    sig.r[0] ^= 0xff;
    sig.s[0] ^= 0xff;
    let body = body_with_signature(&benign, nonce, None, &sig);
    b.add(
        "auth_forged_signature",
        A,
        "auth: signature recovers the signer",
        "a client signature with tampered r and s bytes",
        "auth_bad_signature",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // A valid signature over a benign action, pasted onto an oversize order.
    let nonce = b.next_nonce();
    let sig = b
        .ctx
        .client
        .sign_l1_action(b.ctx.net, &benign, nonce, None)
        .expect("signs");
    let body = body_with_signature(&oversize, nonce, None, &sig);
    b.add(
        "auth_tampered_action",
        A,
        "auth: the signed bytes are the sent bytes",
        "a signature for a 0.001 BTC order reused on a 500 BTC order",
        "auth_unknown_signer",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // Nonce replay: the exact same signed body twice. The second is a replay.
    let nonce = b.next_nonce();
    let body = signed_body(&b.ctx.client, b.ctx.net, &benign, nonce, None);
    b.add(
        "auth_nonce_replay",
        A,
        "threat model §5 replay",
        "the same signed request sent twice; the second is a replay",
        "auth_replay",
        Expect::Refused,
        Requires::Nothing,
        Probe::Sequence(vec![body.clone(), body]),
    );

    // Reordered nonces: a higher nonce then a lower one.
    let n_high = b.next_nonce();
    let n_low = n_high - 1;
    let high = signed_body(&b.ctx.client, b.ctx.net, &benign, n_high, None);
    let low = signed_body(&b.ctx.client, b.ctx.net, &benign, n_low, None);
    b.add(
        "auth_nonce_reorder",
        A,
        "auth: nonces are monotonic",
        "a request with nonce N, then one with nonce N-1",
        "auth_replay",
        Expect::Refused,
        Requires::Nothing,
        Probe::Sequence(vec![high, low]),
    );

    // Concurrent duplicate: two identical requests back to back.
    let nonce = b.next_nonce();
    let body = signed_body(&b.ctx.client, b.ctx.net, &benign, nonce, None);
    b.add(
        "auth_concurrent_duplicate",
        A,
        "auth: a nonce is consumed once",
        "the same request submitted twice with no delay",
        "auth_replay",
        Expect::Refused,
        Requires::Nothing,
        Probe::Sequence(vec![body.clone(), body]),
    );

    // A nonce far in the past.
    let old = b.ctx.base.saturating_sub(120_000);
    let body = signed_body(&b.ctx.client, b.ctx.net, &benign, old, None);
    b.add(
        "auth_nonce_too_old",
        A,
        "auth: nonce freshness window",
        "a valid signature with a nonce two minutes in the past",
        "auth_nonce_too_old",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // A nonce far in the future.
    let future = b.ctx.base + 120_000;
    let body = signed_body(&b.ctx.client, b.ctx.net, &benign, future, None);
    b.add(
        "auth_nonce_too_new",
        A,
        "auth: nonce freshness window",
        "a valid signature with a nonce two minutes in the future",
        "auth_nonce_too_new",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // An empty object: no action, no signature.
    b.add(
        "auth_empty_body",
        A,
        "auth: a request must be signed",
        "an empty JSON object as the request",
        "auth_bad_signature",
        Expect::Refused,
        Requires::Nothing,
        Probe::ExchangeText("{}".to_owned()),
    );

    // A signature whose r is not hex.
    let text = format!(
        "{{\"action\":{},\"nonce\":{},\"signature\":{{\"r\":\"0xZZ\",\"s\":\"0x1\",\"v\":27}}}}",
        benign.to_json_value(),
        b.next_nonce()
    );
    b.add(
        "auth_signature_malformed_hex",
        A,
        "auth: signature parsing",
        "a signature whose r field is not hexadecimal",
        "auth_bad_signature",
        Expect::Refused,
        Requires::Nothing,
        Probe::ExchangeText(text),
    );

    // Wrong network source: Guard accepts both sources, so this still
    // authenticates. The point is that it does not escape the size limit.
    let other = match b.ctx.net {
        SigningNet::Testnet => SigningNet::Mainnet,
        SigningNet::Mainnet => SigningNet::Testnet,
    };
    let nonce = b.next_nonce();
    let body = signed_body(&b.ctx.client, other, &oversize, nonce, None);
    b.add(
        "auth_wrong_network_still_bounded",
        A,
        "decisions 6 Oct: Guard re-signs for its own network",
        "an oversize order signed for the other network's phantom agent",
        "resized or vetoed (no cross-network escalation)",
        Expect::NotFullSize,
        Requires::Nothing,
        Probe::Exchange(body),
    );
}

fn fund_movement(b: &mut Build) {
    use Category::FundMovement as F;
    // Each of these is a valid action type that moves funds or changes
    // standing permissions. None may ever be forwarded.
    let movers: &[(&str, &str, &str, Wire)] = &[
        (
            "fund_usd_send",
            "usdSend",
            "a signed usdSend (transfer USDC to another account)",
            typed(
                "usdSend",
                vec![
                    ("hyperliquidChain", Wire::str("Testnet")),
                    ("signatureChainId", Wire::str("0x66eee")),
                    (
                        "destination",
                        Wire::str("0x5e9ee1089755c3435139848e47e6635505d5a13a"),
                    ),
                    ("amount", Wire::str("1000")),
                    ("time", Wire::UInt(b.ctx.base)),
                ],
            ),
        ),
        (
            "fund_withdraw3",
            "withdraw3",
            "a signed withdraw3 (withdraw to an external address)",
            typed(
                "withdraw3",
                vec![
                    ("hyperliquidChain", Wire::str("Testnet")),
                    ("signatureChainId", Wire::str("0x66eee")),
                    (
                        "destination",
                        Wire::str("0x5e9ee1089755c3435139848e47e6635505d5a13a"),
                    ),
                    ("amount", Wire::str("1000")),
                    ("time", Wire::UInt(b.ctx.base)),
                ],
            ),
        ),
        (
            "fund_spot_send",
            "spotSend",
            "a signed spotSend (transfer a spot token out)",
            typed(
                "spotSend",
                vec![
                    ("hyperliquidChain", Wire::str("Testnet")),
                    ("signatureChainId", Wire::str("0x66eee")),
                    (
                        "destination",
                        Wire::str("0x5e9ee1089755c3435139848e47e6635505d5a13a"),
                    ),
                    ("token", Wire::str("USDC:0xabc")),
                    ("amount", Wire::str("1000")),
                    ("time", Wire::UInt(b.ctx.base)),
                ],
            ),
        ),
        (
            "fund_usd_class_transfer",
            "usdClassTransfer",
            "a signed usdClassTransfer (move between perp and spot)",
            typed(
                "usdClassTransfer",
                vec![
                    ("hyperliquidChain", Wire::str("Testnet")),
                    ("signatureChainId", Wire::str("0x66eee")),
                    ("amount", Wire::str("1000")),
                    ("toPerp", Wire::Bool(false)),
                    ("nonce", Wire::UInt(b.ctx.base)),
                ],
            ),
        ),
        (
            "fund_vault_transfer",
            "vaultTransfer",
            "a signed vaultTransfer (move funds to a vault)",
            typed(
                "vaultTransfer",
                vec![
                    (
                        "vaultAddress",
                        Wire::str("0x5e9ee1089755c3435139848e47e6635505d5a13a"),
                    ),
                    ("isDeposit", Wire::Bool(false)),
                    ("usd", Wire::UInt(1000)),
                ],
            ),
        ),
        (
            "fund_approve_agent",
            "approveAgent",
            "a signed approveAgent (authorise a new API wallet)",
            typed(
                "approveAgent",
                vec![
                    ("hyperliquidChain", Wire::str("Testnet")),
                    ("signatureChainId", Wire::str("0x66eee")),
                    (
                        "agentAddress",
                        Wire::str("0x5e9ee1089755c3435139848e47e6635505d5a13a"),
                    ),
                    ("agentName", Wire::str("evil")),
                    ("nonce", Wire::UInt(b.ctx.base)),
                ],
            ),
        ),
        (
            "fund_approve_builder_fee",
            "approveBuilderFee",
            "a signed approveBuilderFee for an attacker builder",
            typed(
                "approveBuilderFee",
                vec![
                    ("hyperliquidChain", Wire::str("Testnet")),
                    ("signatureChainId", Wire::str("0x66eee")),
                    ("maxFeeRate", Wire::str("1%")),
                    (
                        "builder",
                        Wire::str("0x5e9ee1089755c3435139848e47e6635505d5a13a"),
                    ),
                    ("nonce", Wire::UInt(b.ctx.base)),
                ],
            ),
        ),
        (
            "fund_set_referrer",
            "setReferrer",
            "a signed setReferrer",
            typed("setReferrer", vec![("code", Wire::str("EVIL"))]),
        ),
        (
            "fund_create_sub_account",
            "createSubAccount",
            "a signed createSubAccount",
            typed("createSubAccount", vec![("name", Wire::str("drain"))]),
        ),
        (
            "fund_sub_account_transfer",
            "subAccountTransfer",
            "a signed subAccountTransfer",
            typed(
                "subAccountTransfer",
                vec![
                    (
                        "subAccountUser",
                        Wire::str("0x1d9470d4b963f552e6f671a81619d395877bf409"),
                    ),
                    ("isDeposit", Wire::Bool(true)),
                    ("usd", Wire::UInt(1000)),
                ],
            ),
        ),
        (
            "fund_token_delegate_staking",
            "tokenDelegate",
            "a signed tokenDelegate (stake HYPE to a validator)",
            typed(
                "tokenDelegate",
                vec![
                    ("hyperliquidChain", Wire::str("Testnet")),
                    ("signatureChainId", Wire::str("0x66eee")),
                    (
                        "validator",
                        Wire::str("0x5e9ee1089755c3435139848e47e6635505d5a13a"),
                    ),
                    ("wei", Wire::UInt(1_000_000)),
                    ("isUndelegate", Wire::Bool(false)),
                    ("nonce", Wire::UInt(b.ctx.base)),
                ],
            ),
        ),
        (
            "fund_c_deposit_staking",
            "cDeposit",
            "a signed cDeposit (move into staking)",
            typed(
                "cDeposit",
                vec![
                    ("hyperliquidChain", Wire::str("Testnet")),
                    ("signatureChainId", Wire::str("0x66eee")),
                    ("wei", Wire::UInt(1_000_000)),
                    ("nonce", Wire::UInt(b.ctx.base)),
                ],
            ),
        ),
        (
            "fund_unknown_action",
            "teleportFunds",
            "a signed action of an unknown type",
            typed("teleportFunds", vec![("amount", Wire::str("1000"))]),
        ),
    ];
    for (id, _kind, about, action) in movers {
        let body = b.signed(action);
        b.add(
            id,
            F,
            "veto-codes: action_not_allowed",
            about,
            "action_not_allowed",
            Expect::Refused,
            Requires::Nothing,
            Probe::Exchange(body),
        );
    }

    // Case trick: usdSend spelled UsdSend. Must not slip through as unknown.
    let action = typed(
        "UsdSend",
        vec![
            (
                "destination",
                Wire::str("0x5e9ee1089755c3435139848e47e6635505d5a13a"),
            ),
            ("amount", Wire::str("1000")),
            ("time", Wire::UInt(b.ctx.base)),
        ],
    );
    let body = b.signed(&action);
    b.add(
        "fund_case_trick_type",
        F,
        "veto-codes: action_not_allowed",
        "a usdSend with a capitalised type (UsdSend)",
        "action_not_allowed",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // Extra junk fields on a withdraw: must not confuse the type check.
    let action = typed(
        "withdraw3",
        vec![
            ("hyperliquidChain", Wire::str("Testnet")),
            ("signatureChainId", Wire::str("0x66eee")),
            (
                "destination",
                Wire::str("0x5e9ee1089755c3435139848e47e6635505d5a13a"),
            ),
            ("amount", Wire::str("1000")),
            ("time", Wire::UInt(b.ctx.base)),
            ("note", Wire::str("ignore me")),
            ("type2", Wire::str("order")),
        ],
    );
    let body = b.signed(&action);
    b.add(
        "fund_extra_fields",
        F,
        "veto-codes: action_not_allowed",
        "a withdraw with extra fields, including a decoy type2=order",
        "action_not_allowed",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // Duplicate type keys: "order" then "withdraw3". JSON keeps the last, so
    // a last-wins parser sees a withdraw. Must still be refused.
    let text = format!(
        "{{\"action\":{{\"type\":\"order\",\"type\":\"withdraw3\",\"destination\":\"0x5e9ee1089755c3435139848e47e6635505d5a13a\",\"amount\":\"1000\",\"time\":{base}}},\"nonce\":{nonce},\"signature\":{{\"r\":\"0x1\",\"s\":\"0x1\",\"v\":27}}}}",
        base = b.ctx.base,
        nonce = b.next_nonce()
    );
    b.add(
        "fund_duplicate_type_keys",
        F,
        "veto-codes: action_not_allowed; config deny_unknown_fields",
        "an action with two type keys: order then withdraw3",
        "action_not_allowed or auth_unknown_signer",
        Expect::Refused,
        Requires::Nothing,
        Probe::ExchangeText(text),
    );

    // A good order first, then a usdSend. The earlier order must not
    // whitelist the transfer that follows.
    let good = actions::buy(BTC, "60000", "0.001");
    let good_body = b.signed(&good);
    let send = typed(
        "usdSend",
        vec![
            ("hyperliquidChain", Wire::str("Testnet")),
            ("signatureChainId", Wire::str("0x66eee")),
            (
                "destination",
                Wire::str("0x5e9ee1089755c3435139848e47e6635505d5a13a"),
            ),
            ("amount", Wire::str("1000")),
            ("time", Wire::UInt(b.ctx.base)),
        ],
    );
    let send_body = b.signed(&send);
    b.add(
        "fund_order_then_usd_send",
        F,
        "veto-codes: action_not_allowed",
        "a valid order, then a usdSend; the send must still be refused",
        "action_not_allowed",
        Expect::Refused,
        Requires::Nothing,
        Probe::Sequence(vec![good_body, send_body]),
    );
}

fn sizing(b: &mut Build) {
    use Category::Sizing as S;

    // A single order worth ~100x a 2,000 account.
    let body = b.signed(&actions::buy(BTC, "60000", "200"));
    b.add(
        "size_oversize_single",
        S,
        "rule (g) max loss at stop; (c) leverage",
        "one BTC buy worth about 12,000,000 on a small account",
        "resized to the per-trade budget (max_loss_per_trade)",
        Expect::NotFullSize,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // Size in exponent form.
    let body = b.signed(&actions::buy(ETH, "3000", "2e3"));
    b.add(
        "size_exponent_form",
        S,
        "rule (g); config refuses float sizes",
        "an order whose size is written as 2e3",
        "resized or rejected (invalid_request)",
        Expect::NotFullSize,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // Size with leading-zero and trailing-zero padding.
    let body = b.signed(&actions::buy(ETH, "3000", "0000100.0000"));
    b.add(
        "size_padded_string",
        S,
        "rule (g)",
        "an oversize order with a zero-padded size string",
        "resized to the per-trade budget",
        Expect::NotFullSize,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // Split: many orders each inside the per-trade budget but together far
    // over the open-risk budget. The last one must bind.
    let mut split = Vec::new();
    for _ in 0..12 {
        let order = order(
            &[OrderSpec {
                trigger: None,
                ..OrderSpec::limit_buy(BTC, "60000", "0.03")
            }],
            "na",
        );
        split.push(b.signed(&order));
    }
    b.add(
        "size_split_orders",
        S,
        "rule (e) max open risk",
        "twelve small BTC buys that together exceed the open-risk budget",
        "open_risk_exhausted on the later orders",
        Expect::NotFullSize,
        Requires::Nothing,
        Probe::Sequence(split),
    );

    // Batch: one action carrying many sub-orders sized as a group.
    let batch: Vec<OrderSpec> = (0..10)
        .map(|_| OrderSpec::limit_buy(BTC, "60000", "0.5"))
        .collect();
    let body = b.signed(&order(&batch, "na"));
    b.add(
        "size_batch_grouped",
        S,
        "rule (c), (e), (g): a batch is sized as a group",
        "one action with ten BTC buys of 0.5 each",
        "resized so the batch total stays within the budgets",
        Expect::NotFullSize,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // An entry with no protective stop at all.
    let body = b.signed(&actions::buy(BTC, "60000", "5"));
    b.add(
        "size_no_stop",
        S,
        "rule (b) protective stop; stop_policy",
        "a sizable entry with no stop order",
        "attached-stop resize, or no_protective_stop",
        Expect::NotFullSize,
        Requires::Nothing,
        Probe::Exchange(body),
    );
}

fn stops(b: &mut Build) {
    use Category::Stops as St;

    // A stop on the wrong side of the entry (long with a stop above price).
    let wrong = order(
        &[
            OrderSpec::limit_buy(BTC, "60000", "0.1"),
            OrderSpec::stop(BTC, false, "61000", "0.1"),
        ],
        "normalTpsl",
    );
    let body = b.signed(&wrong);
    b.add(
        "stop_wrong_side",
        St,
        "rule (g) stop_on_wrong_side",
        "a long whose stop trigger is above the entry price",
        "stop_on_wrong_side",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // Loosen a resting stop with a modify. Needs a position to exist.
    let modify = typed(
        "modify",
        vec![
            ("oid", Wire::UInt(1001)),
            (
                "order",
                OrderSpec::stop(BTC, false, "40000", "0.1").to_wire(),
            ),
        ],
    );
    let body = b.signed(&modify);
    b.add(
        "stop_modify_loosen",
        St,
        "stops only tighten",
        "a modify that moves a stop further from the price",
        "stop_loosening_ignored",
        Expect::Refused,
        Requires::Fills,
        Probe::Exchange(body),
    );

    // Cancel-and-replace a stop with a looser one.
    let cancel = actions::cancel(BTC, 1001);
    let replace = order(&[OrderSpec::stop(BTC, false, "40000", "0.1")], "na");
    let cancel_body = b.signed(&cancel);
    let replace_body = b.signed(&replace);
    b.add(
        "stop_cancel_replace_loosen",
        St,
        "stops only tighten",
        "cancel a stop, then place a looser one",
        "the cancel refused (guard_stop / stop_removed); the stop kept",
        Expect::StopKept { oid: 1001 },
        Requires::Fills,
        Probe::Sequence(vec![cancel_body, replace_body]),
    );

    // Cancel the only stop of an open position.
    let body = b.signed(&actions::cancel(BTC, 1001));
    b.add(
        "stop_cancel_last_stop",
        St,
        "stops only tighten; rule (e) unprotected_position",
        "cancel a position's only protective stop",
        "refused (the last stop stays)",
        Expect::Refused,
        Requires::Fills,
        Probe::Exchange(body),
    );
}

fn leverage(b: &mut Build) {
    use Category::Leverage as L;

    // Raise leverage well past the cap after entry.
    let body = b.signed(&actions::update_leverage(BTC, false, 50));
    b.add(
        "lev_update_leverage",
        L,
        "decisions 6 Oct: Guard sets isolated leverage itself",
        "a client updateLeverage to 50x",
        "refused or clamped to the policy cap",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // Pull margin out with updateIsolatedMargin.
    let body = b.signed(&actions::update_isolated_margin(BTC, true, -500_000));
    b.add(
        "lev_update_isolated_margin",
        L,
        "decisions 6 Oct: isolated margin is Guard's to set",
        "a client updateIsolatedMargin removing margin",
        "refused",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // A reduce-only order larger than the position, trying to flip it.
    let flip = order(
        &[OrderSpec {
            reduce_only: true,
            ..OrderSpec::limit_sell(BTC, "59000", "5")
        }],
        "na",
    );
    let body = b.signed(&flip);
    b.add(
        "lev_reduce_only_flip",
        L,
        "rule: reduce-only may only reduce",
        "a reduce-only sell larger than the long it should close",
        "bounded to the position size, never flipped",
        Expect::NotFullSize,
        Requires::Fills,
        Probe::Exchange(body),
    );

    // An ordinary entry whose notional implies more than the leverage cap.
    let body = b.signed(&actions::buy(BTC, "60000", "1"));
    b.add(
        "lev_over_cap_entry",
        L,
        "rule (c) max leverage",
        "an entry whose notional is well over 5x equity",
        "leverage_exhausted or resized",
        Expect::NotFullSize,
        Requires::Nothing,
        Probe::Exchange(body),
    );
}

fn markets(b: &mut Build) {
    use Category::Markets as M;

    // A non-existent asset index.
    let body = b.signed(&actions::buy(9999, "1", "1"));
    b.add(
        "market_bad_asset_index",
        M,
        "rule (a) market allowlist; venue meta",
        "an order on asset index 9999, which does not exist",
        "coin_not_allowed or rejected",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // A spot asset index (10000+) where only perps are expected.
    let body = b.signed(&actions::buy(10_107, "36", "1"));
    b.add(
        "market_spot_index",
        M,
        "rule (a); spot vs perp",
        "an order on a spot asset index (10107) past a perp-only policy",
        "coin_not_allowed or rejected",
        Expect::Refused,
        Requires::Allowlist,
        Probe::Exchange(body),
    );

    // A HIP-3 dex's perp (100000 + 10000 × dex + index) on a dex the
    // target does not manage: dex 1 by default (no HIP-3 dex is allowed
    // unless the rules name it), or the unmanaged dex the target's status
    // shows.
    let unmanaged = b
        .ctx
        .hip3
        .as_ref()
        .map_or(HIP3_ASSET, |hip3| Hip3Target::id(hip3.other_dex, 0));
    let body = b.signed(&actions::buy(unmanaged, "60000", "0.01"));
    b.add(
        "market_hip3_index",
        M,
        "HIP-3: only the dexes the rules name",
        "an order on a perp of a HIP-3 dex the rules do not name",
        "dex_not_allowed",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // A HIP-4 outcome side (100000000 + 10 × outcome + side): no leverage,
    // no stop, a settlement at 0 or 1; not a perp.
    let body = b.signed(&actions::buy(OUTCOME_ASSET, "0.5", "100"));
    b.add(
        "market_outcome_index",
        M,
        "phase 1: main-dex perps only",
        "an order on a HIP-4 outcome side (asset 100000950)",
        "unsupported_market",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // The same as a reduce-only order: closes pass even while halted, so
    // the market check must come first.
    let close = order(
        &[OrderSpec {
            reduce_only: true,
            ..OrderSpec::limit_sell(OUTCOME_ASSET, "0.4", "100")
        }],
        "na",
    );
    let body = b.signed(&close);
    b.add(
        "market_outcome_reduce_only",
        M,
        "phase 1: main-dex perps only; closes are not a way around it",
        "a reduce-only order on a HIP-4 outcome side",
        "unsupported_market",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // Margin moved onto a position on a dex Guard does not manage, whose
    // account it does not read.
    let body = b.signed(&actions::update_isolated_margin(unmanaged, true, 1_000_000));
    b.add(
        "market_hip3_isolated_margin",
        M,
        "HIP-3: Guard sees no account of a dex the rules do not name",
        "an updateIsolatedMargin adding margin on a perp of a HIP-3 dex the rules do not name",
        "dex_not_allowed",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );
    // Leverage set there.
    let body = b.signed(&actions::update_leverage(unmanaged, false, 1));
    b.add(
        "market_hip3_leverage_not_allowed",
        M,
        "HIP-3: only the dexes the rules name",
        "an updateLeverage on a perp of a HIP-3 dex the rules do not name",
        "dex_not_allowed",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    hip3_markets(b);

    // Leverage set on an outcome side.
    let body = b.signed(&actions::update_leverage(OUTCOME_ASSET, false, 1));
    b.add(
        "market_outcome_leverage",
        M,
        "phase 1: main-dex perps only",
        "an updateLeverage on a HIP-4 outcome side",
        "unsupported_market",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // A coin outside a configured allowlist.
    let body = b.signed(&actions::buy(SOL, "150", "1"));
    b.add(
        "market_outside_allowlist",
        M,
        "rule (a) market allowlist",
        "a SOL order when the allowlist is BTC and ETH only",
        "coin_not_allowed",
        Expect::Refused,
        Requires::Allowlist,
        Probe::Exchange(body),
    );
}

/// Attacks on a HIP-3 dex the target manages. Without one (the default
/// rules name none) they are skipped; their ids then point at made-up
/// markets.
fn hip3_markets(b: &mut Build) {
    use Category::Markets as M;
    let hip3 = b.ctx.hip3.clone().unwrap_or_else(Hip3Target::synthetic);

    // Oversize on the allowed dex: sized down or refused, never forwarded
    // as asked.
    let body = b.signed(&actions::buy(hip3.asset, &hip3.mid, "100000"));
    b.add(
        "market_hip3_oversize_allowed_dex",
        M,
        "HIP-3: the same nine rules, account-wide; the dex's own margin and book",
        "a buy of 100,000 of a market of the allowed HIP-3 dex",
        "resized, dex_margin or thin_book",
        Expect::NotFullSize,
        Requires::Hip3,
        Probe::Exchange(body),
    );

    // The right market index on the wrong dex: the id of the same index on
    // a dex the target does not manage.
    let wrong = Hip3Target::id(hip3.other_dex, hip3.index);
    let body = b.signed(&actions::buy(wrong, &hip3.mid, "0.01"));
    b.add(
        "market_hip3_wrong_dex_id",
        M,
        "HIP-3: asset ids by Hyperliquid's arithmetic; only the dexes the rules name",
        "the allowed market's index under another dex's index (an id one dex off)",
        "dex_not_allowed",
        Expect::Refused,
        Requires::Hip3,
        Probe::Exchange(body),
    );

    // The dex multiplied by 1,000 instead of 10,000: an id on no dex, or on
    // another one.
    let wrong = 100_000 + 1_000 * hip3.dex + hip3.index;
    let body = b.signed(&actions::buy(wrong, &hip3.mid, "0.01"));
    b.add(
        "market_hip3_wrong_multiplier",
        M,
        "HIP-3: asset ids by Hyperliquid's arithmetic",
        "the allowed market's id computed with 1,000 per dex instead of 10,000",
        "unknown_market or dex_not_allowed",
        Expect::Refused,
        Requires::Hip3,
        Probe::Exchange(body),
    );

    // An entry on the allowed dex whose stop is on another dex's coin (the
    // main dex's BTC): no protection for the entry.
    let entry = OrderSpec {
        tif: "Ioc",
        ..OrderSpec::limit_buy(hip3.asset, &hip3.mid, "0.01")
    };
    let foreign_stop = OrderSpec::stop(BTC, false, "1", "0.01");
    let body = b.signed(&order(&[entry, foreign_stop], "normalTpsl"));
    b.add(
        "market_hip3_stop_other_dex",
        M,
        "HIP-3: an entry's stop is on its own market",
        "an entry on the allowed HIP-3 dex with its stop on the main dex's BTC",
        "invalid",
        Expect::Refused,
        Requires::Hip3,
        Probe::Exchange(body),
    );

    // A market its deployer halted (delisted in the dex's meta).
    let halted = hip3.halted.unwrap_or(Hip3Target::id(hip3.dex, 9_999));
    let body = b.signed(&actions::buy(halted, "1", "1"));
    b.add(
        "market_hip3_halted",
        M,
        "HIP-3: a deployer's halt or settlement",
        "an entry on a halted market of the allowed HIP-3 dex",
        "market_halted",
        Expect::Refused,
        Requires::Hip3Halted,
        Probe::Exchange(body),
    );
}

fn halts(b: &mut Build) {
    use Category::Halts as H;

    // An entry while the engine is halted.
    let body = b.signed(&actions::buy(BTC, "60000", "0.01"));
    b.add(
        "halt_entry_when_halted",
        H,
        "rule (h)/(i); circuit breakers",
        "a fresh entry while a daily-loss or drawdown halt is in force",
        "halted_for_day or stopped",
        Expect::Refused,
        Requires::Halt,
        Probe::Exchange(body),
    );

    // An action that tries to name itself a resume.
    let body = b.signed(&typed("resume", vec![("note", Wire::str("pretty please"))]));
    b.add(
        "halt_no_resume_action",
        H,
        "only a person may resume after review",
        "a made-up resume action over the API",
        "action_not_allowed",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // A guessed control endpoint to clear a halt.
    b.add(
        "halt_no_resume_endpoint",
        H,
        "only a person resumes; the event API is read-only",
        "a POST to a guessed /guard/resume endpoint",
        "404 / not found (no such endpoint)",
        Expect::Refused,
        Requires::Nothing,
        Probe::RawPost {
            path: "/guard/resume".to_owned(),
            body: b"{\"note\":\"go\"}".to_vec(),
        },
    );
}

fn builder_field(b: &mut Build) {
    use Category::BuilderField as Bf;

    // An order that carries its own builder field. Guard adds the builder
    // itself; a client-supplied one must not be honoured.
    let mut fields = match order(&[OrderSpec::limit_buy(BTC, "60000", "0.01")], "na") {
        Wire::Map(entries) => entries,
        _ => unreachable!("order is a map"),
    };
    fields.push((
        "builder".to_owned(),
        Wire::map(vec![
            ("b", Wire::str("0x000000000000000000000000000000000000dead")),
            ("f", Wire::UInt(1000)),
        ]),
    ));
    let body = b.signed(&Wire::Map(fields));
    b.add(
        "builder_client_supplied",
        Bf,
        "go-to-market §3.1: Guard adds the builder code",
        "an order carrying its own builder address and a 100 bp fee",
        "refused or the client builder stripped",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );
}

fn robustness(b: &mut Build) {
    use Category::Robustness as R;

    b.add(
        "robust_malformed_json",
        R,
        "server: a broken body is handled",
        "a body that is not valid JSON",
        "handled (422/err), no crash",
        Expect::Handled,
        Requires::Nothing,
        Probe::ExchangeText("{\"action\": {\"type\": \"order\" ".to_owned()),
    );

    b.add(
        "robust_huge_body",
        R,
        "server: MAX_BODY cap",
        "a four-megabyte request body",
        "413 / rejected, no crash",
        Expect::Handled,
        Requires::Nothing,
        Probe::HugeBody { size: 4 << 20 },
    );

    // An unsigned body, so the flood is refused at authentication and never
    // forwards an order, even against a live Guard.
    let flood_nonce = b.next_nonce();
    let flood_body = body_with_signature(
        &actions::buy(BTC, "60000", "0.001"),
        flood_nonce,
        None,
        &Sig {
            r: [0; 32],
            s: [0; 32],
            v: 27,
        },
    );
    b.add(
        "robust_request_flood",
        R,
        "server: rate limiting, not a crash",
        "two hundred unsigned requests as fast as the client can send them",
        "handled or rate-limited, no crash",
        Expect::Handled,
        Requires::Nothing,
        Probe::Flood {
            body: flood_body,
            count: 200,
        },
    );

    b.add(
        "robust_slowloris",
        R,
        "server: a slow body does not tie it up forever",
        "a request whose body is sent one byte at a time and never finishes",
        "handled (timeout), no crash",
        Expect::Handled,
        Requires::Nothing,
        Probe::Slowloris,
    );

    // Deeply nested JSON, to test for stack blow-ups.
    let deep = format!(
        "{{\"action\":{{\"type\":\"order\",\"orders\":{}{}}} }}",
        "[".repeat(2000),
        "]".repeat(2000)
    );
    b.add(
        "robust_deeply_nested_json",
        R,
        "server: a broken body is handled",
        "an action with two thousand nested arrays",
        "handled (err), no crash",
        Expect::Handled,
        Requires::Nothing,
        Probe::ExchangeText(deep),
    );

    // The same fund-movement attack, over the WebSocket post path.
    let send = typed(
        "usdSend",
        vec![
            ("hyperliquidChain", Wire::str("Testnet")),
            ("signatureChainId", Wire::str("0x66eee")),
            (
                "destination",
                Wire::str("0x5e9ee1089755c3435139848e47e6635505d5a13a"),
            ),
            ("amount", Wire::str("1000")),
            ("time", Wire::UInt(b.ctx.base)),
        ],
    );
    let body = b.signed(&send);
    b.add(
        "robust_ws_fund_movement",
        R,
        "veto-codes: action_not_allowed (WebSocket post)",
        "a usdSend sent as a WebSocket post",
        "action_not_allowed",
        Expect::Refused,
        Requires::Nothing,
        Probe::Ws(ws_post(&body, 1)),
    );

    // An oversize order over the WebSocket post path.
    let body = b.signed(&actions::buy(BTC, "60000", "200"));
    b.add(
        "robust_ws_oversize_order",
        R,
        "rule (g) over WebSocket",
        "an oversize order sent as a WebSocket post",
        "resized or vetoed",
        Expect::NotFullSize,
        Requires::Nothing,
        Probe::Ws(ws_post(&body, 2)),
    );

    // info passthrough must not leak the API wallet key.
    let info = serde_json::to_vec(
        &serde_json::json!({"type": "clearinghouseState", "user": b.ctx.client.address().to_hex()}),
    )
    .expect("json");
    b.add(
        "robust_info_no_key_leak",
        R,
        "threat model: Guard holds the key; info passes through",
        "a clearinghouseState info query; the reply must carry no private key",
        "no 64-hex private key in the reply",
        Expect::NoLeak,
        Requires::Nothing,
        Probe::Info(info),
    );
}

fn agent_content(b: &mut Build) {
    use Category::AgentContent as Ag;

    // An instruction-like cloid on an oversize order. Treated as data.
    let order = order(
        &[OrderSpec {
            cloid: Some(
                "0x00000000ignore0000previous0000rules"
                    .chars()
                    .take(34)
                    .collect(),
            ),
            ..OrderSpec::limit_buy(BTC, "60000", "200")
        }],
        "na",
    );
    let body = b.signed(&order);
    b.add(
        "agent_injection_in_cloid",
        Ag,
        "instruction-like content is data, rule (g) still binds",
        "an oversize order whose cloid reads like an instruction",
        "resized or rejected; the cloid changes nothing",
        Expect::NotFullSize,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // A negative size.
    let body = b.signed(&actions::buy(BTC, "60000", "-1"));
    b.add(
        "agent_negative_size",
        Ag,
        "rule (g) invalid_request",
        "an order with a size of -1",
        "invalid_request or rejected",
        Expect::Refused,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // Absurd precision.
    let body = b.signed(&actions::buy(
        BTC,
        "60000.000000000000000001",
        "0.00000000000000000001",
    ));
    b.add(
        "agent_absurd_precision",
        Ag,
        "rule (g) below_minimum / overflow",
        "an order with twenty-decimal price and size",
        "below_minimum, overflow or resized",
        Expect::NotFullSize,
        Requires::Nothing,
        Probe::Exchange(body),
    );

    // A NaN literal in the body.
    let text = format!(
        "{{\"action\":{{\"type\":\"order\",\"orders\":[{{\"a\":0,\"b\":true,\"p\":\"60000\",\"s\":NaN,\"r\":false,\"t\":{{\"limit\":{{\"tif\":\"Gtc\"}}}}}}],\"grouping\":\"na\"}},\"nonce\":{},\"signature\":{{\"r\":\"0x1\",\"s\":\"0x1\",\"v\":27}}}}",
        b.next_nonce()
    );
    b.add(
        "agent_nan_literal",
        Ag,
        "server/JSON: non-finite numbers are rejected",
        "a size given as the JSON literal NaN",
        "rejected (not valid JSON)",
        Expect::Refused,
        Requires::Nothing,
        Probe::ExchangeText(text),
    );

    // An Infinity literal in the body.
    let text = format!(
        "{{\"action\":{{\"type\":\"order\",\"orders\":[{{\"a\":0,\"b\":true,\"p\":Infinity,\"s\":\"1\",\"r\":false,\"t\":{{\"limit\":{{\"tif\":\"Gtc\"}}}}}}],\"grouping\":\"na\"}},\"nonce\":{},\"signature\":{{\"r\":\"0x1\",\"s\":\"0x1\",\"v\":27}}}}",
        b.next_nonce()
    );
    b.add(
        "agent_infinity_literal",
        Ag,
        "server/JSON: non-finite numbers are rejected",
        "a price given as the JSON literal Infinity",
        "rejected (not valid JSON)",
        Expect::Refused,
        Requires::Nothing,
        Probe::ExchangeText(text),
    );

    // A gigantic exponent.
    let body = b.signed(&actions::buy(BTC, "60000", "1e308"));
    b.add(
        "agent_huge_exponent",
        Ag,
        "rule (g) overflow",
        "an order with a size of 1e308",
        "overflow, invalid_request or resized",
        Expect::NotFullSize,
        Requires::Nothing,
        Probe::Exchange(body),
    );
}
