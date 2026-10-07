# The Zunder Guard red-team suite

An automated adversary that attacks Zunder Guard through its public interface
and tries to make it break one of its own limits. **Every attack must be
refused.** It is our free stand-in for a paid security audit (go-to-market
§5a) and the basis for a marketing claim we can back up: *N attacks, all
refused, rerun them yourself.*

The suite lives in `tests/redteam/` (crate `zunder-redteam`).

## Why a runner binary, not `#[test]`s against Guard

The suite is **black-box**: it speaks only Hyperliquid's own HTTP and
WebSocket API plus Guard's read-only `/guard/*` endpoints, exactly as a
third-party bot would. A small runner binary is the clearer shape for that:

- it points at *any* Guard by URL and client key, including one on another
  host, without linking Guard's code;
- it shares **no code** with `zunder-guard` / `zunder-guard-core`. The
  Hyperliquid signing in `src/hlsign.rs` is an independent second
  implementation, pinned against the official Python SDK's signing vectors
  (`connection_id`, the dummy-action signature). A bug in Guard's own signer
  therefore cannot be masked by a matching bug in the attacker;
- it emits JSON and a human report for the website and for release notes.

A thin `#[test]` layer (`tests/mock_suite.rs`) still runs the whole catalogue
against the naive mock under `cargo test`, so the gate proves the suite keeps
biting. The signer's SDK vectors are unit tests in `src/hlsign.rs`.

## What it attacks

Two targets implement the same `Target` trait:

- **(a) A running Guard**, over HTTP and WebSocket, configured with `--url`
  and `--client-key`.
- **(b) A deliberately naive mock proxy** (`src/mock.rs`): no authentication,
  no nonce check, no risk rules; it forwards every action. The mock exists to
  **fail**, which proves the suite catches real problems. It keeps only the
  protections any JSON endpoint has for free (a 1 MiB body cap, JSON
  parsing), so a handful of JSON-level and robustness cases pass even against
  it.

## How a case is judged

Guard answers differently depending on mode — a veto on testnet
(`{"status":"err","response":"Zunder Guard veto [code]: …"}`), a `would …`
line in paper mode, a plain Hyperliquid error for a bad signature or reused
nonce. The suite reads all three, plus transport errors, into one verdict
(`allowed` / `resized` / `vetoed` / `rejected`), and checks a conservative
invariant per case:

| Expectation | Passes when | Used for |
|---|---|---|
| `refused` | vetoed or rejected (never allowed or resized) | auth, fund movement, stop loosening, leverage changes, builder field |
| `not_forwarded_at_full_size` | anything but a clean full-size forward | over-sizing, over-leverage, market attacks (Guard may resize) |
| `cancel_refused_stop_kept` | the cancel in a cancel-then-replace sequence is refused, and the stop it aimed at still rests afterwards with its trigger and size unchanged (read from the open orders through `/info`); a target that cannot show its open orders passes only if every request is refused | `stop_cancel_replace_loosen` |
| `handled_no_crash` | the target still answers its status endpoint | robustness probes |
| `no_key_leak` | the reply contains no 64-hex private key | info passthrough |

The documented `expected_code` for each case (for example `auth_replay`,
`action_not_allowed`) is reported but is **advisory**: the pass/fail test is
the invariant above, so the suite reads correctly on paper, on testnet and
against the mock without being brittle about exact wording.

## Running it

Run these commands on a build host with the pinned Rust toolchain:

```sh
# Against the naive mock: proves the suite bites. Places no orders anywhere.
cargo run -p zunder-redteam -- --mock

# The gate's copy of the same thing (part of `cargo test --workspace`):
cargo test -p zunder-redteam
```

### Against a running Guard (operator-controlled test)

Run Guard in **paper mode** first. In paper mode Guard authenticates, judges
every rule and journals, but **sends nothing**, so no order ever reaches a
venue — the safe default for the whole suite.

```sh
# On the machine running Guard, in paper mode on testnet data:
zunder-guard run --config guard.toml           # mode = "paper"

# From a checkout, pointing at it with the client key `zunder-guard init` issued:
cargo run -p zunder-redteam -- \
    --url http://127.0.0.1:8547 \
    --client-key 0x<client-key> \
    --json reports/redteam.json \
    --report reports/redteam.txt
```

The runner exits non-zero if any applicable attack was **not** refused.

**Safety rails built into the runner:**

- It reads `/guard/status` first. It **refuses outright** to run against a
  Guard in **mainnet** mode.
- It refuses a **testnet** Guard unless you pass `--testnet-ok`, because on
  testnet a resized order actually reaches the venue. Paper mode has no such
  risk and is the recommended target.
- The request-flood case uses **unsigned** bodies, so even a live run never
  forwards an order while flooding.

Order-forwarding cases (sizing, leverage, reduce-only, the WebSocket order)
would place *resized testnet orders* on a testnet Guard. Run the full suite
in paper mode; use testnet only deliberately, with `--testnet-ok`, when you
want to exercise the real order path on testnet funds within the sleeve.

### Cases that need a scenario

Some cases need state the suite cannot set from outside, and are skipped with
a reason unless the target provides it (the runner infers this from
`/guard/status`, and `--allowlist` / `--halted` force them on):

- **`needs: fills`** (stop lifecycle, reduce-only flip): need an open
  position. Paper Guard holds none, so these run against the mock and against
  a testnet Guard that already has a position.
- **`needs: allowlist`** (market cases): need a market allowlist configured;
  the default policy allows all markets.
- **`needs: halt`** (trading while halted): need the engine already halted.
- **`needs: hip3`** (the HIP-3 cases on an allowed dex): need a HIP-3 dex the rules name. The runner finds it through Guard's public interface only: the first HIP-3 dex in `/guard/status` `dexes`, a market of it with a mid and a halted one (`needs: hip3 halted`) from `/info` `meta` and `allMids` with its `dex`, and from `perpDexs` a dex Guard does not manage. Without one these cases are skipped.

In paper mode the suite's burst meets Guard's request-read budget, and many order cases are refused `rate_limited` (still a refusal, but not on their merits). `--only <prefix> --pace-ms <ms>` runs a subset spaced out, each case built just before it runs so its nonce is fresh: `--only market_hip3 --pace-ms 7500` judges the HIP-3 cases on their merits. `deploy/guard/test/redteam-paper.sh` does the whole paper run on a Linux build host (`REDTEAM_ARGS` passes such options).

## The catalogue (75 cases)

Grouped by category. IDs match the report.

- **Authentication (12):** `auth_unsigned`, `auth_wrong_key`,
  `auth_forged_signature`, `auth_tampered_action`, `auth_nonce_replay`,
  `auth_nonce_reorder`, `auth_concurrent_duplicate`, `auth_nonce_too_old`,
  `auth_nonce_too_new`, `auth_empty_body`, `auth_signature_malformed_hex`,
  `auth_wrong_network_still_bounded` (Guard accepts both phantom-agent
  sources by design, so this checks that the wrong network does **not** let
  an oversize order escape the size limit).
- **Fund movement disguised as trading (17):** `fund_usd_send`,
  `fund_withdraw3`, `fund_spot_send`, `fund_usd_class_transfer`,
  `fund_vault_transfer`, `fund_approve_agent`, `fund_approve_builder_fee`,
  `fund_set_referrer`, `fund_create_sub_account`, `fund_sub_account_transfer`,
  `fund_token_delegate_staking`, `fund_c_deposit_staking`,
  `fund_unknown_action`, `fund_case_trick_type`, `fund_extra_fields`,
  `fund_duplicate_type_keys`, `fund_order_then_usd_send`.
- **Limit evasion — sizing (6):** `size_oversize_single`,
  `size_exponent_form`, `size_padded_string`, `size_split_orders`,
  `size_batch_grouped`, `size_no_stop`.
- **Limit evasion — stops (4):** `stop_wrong_side`, `stop_modify_loosen`
  (needs fills), `stop_cancel_replace_loosen` (needs fills),
  `stop_cancel_last_stop` (needs fills).
- **Limit evasion — leverage (4):** `lev_update_leverage`,
  `lev_update_isolated_margin`, `lev_reduce_only_flip` (needs fills),
  `lev_over_cap_entry`.
- **Limit evasion — markets (14):** `market_bad_asset_index`,
  `market_spot_index` (needs allowlist), `market_hip3_index`,
  `market_outcome_index`, `market_outcome_reduce_only`,
  `market_hip3_isolated_margin`, `market_hip3_leverage_not_allowed`,
  `market_outcome_leverage` (spot `10000 + index` and HIP-4 outcome
  `100000000 + 10 × outcome + side` asset ids, and HIP-3 ids `100000 + 10000
  × dex + index` on a dex the rules do not name, are refused for every
  action but a cancel), `market_outside_allowlist` (needs allowlist); on a
  HIP-3 dex the rules name (needs hip3): `market_hip3_oversize_allowed_dex`,
  `market_hip3_wrong_dex_id` (the right index under another dex's index),
  `market_hip3_wrong_multiplier` (1,000 per dex instead of 10,000),
  `market_hip3_stop_other_dex` (the entry's stop on the main dex's BTC),
  `market_hip3_halted` (needs a halted market there).
- **Limit evasion — halts (3):** `halt_entry_when_halted` (needs halt),
  `halt_no_resume_action`, `halt_no_resume_endpoint`.
- **Builder field (1):** `builder_client_supplied`.
- **Robustness (8):** `robust_malformed_json`, `robust_huge_body`,
  `robust_request_flood`, `robust_slowloris`, `robust_deeply_nested_json`,
  `robust_ws_fund_movement`, `robust_ws_oversize_order`,
  `robust_info_no_key_leak`.
- **Agent-style content (6):** `agent_injection_in_cloid`,
  `agent_negative_size`, `agent_absurd_precision`, `agent_nan_literal`,
  `agent_infinity_literal`, `agent_huge_exponent`.

## Current results against the naive mock

Run on a Linux build host (`cargo run -p zunder-redteam -- --mock`):

```
75 cases: 10 refused (pass), 65 got through (FAIL), 0 skipped
```

The **65 failures are the point**: the naive mock has no auth, no nonce
tracking and no risk rules, so it forwards every authentication forgery,
every fund-movement action, every oversize or unstopped order, every leverage
change and every builder-field order. A real Guard must refuse all 65.

The **10 that pass against the mock** are the ones a bare JSON endpoint stops
on its own, and so are not evidence about Guard's logic: `auth_empty_body`
and `halt_no_resume_endpoint` (no such action/endpoint), `agent_nan_literal`
and `agent_infinity_literal` (not valid JSON), and the robustness cases
`robust_malformed_json`, `robust_huge_body`, `robust_request_flood`,
`robust_slowloris`, `robust_deeply_nested_json`, `robust_info_no_key_leak`
(the mock keeps a body-size cap and stays up).

If a future change makes the mock "pass" everything, `tests/mock_suite.rs`
fails — that test asserts the mock is still caught.

## Adding a case

1. Add a builder in the right category in `src/catalogue.rs`. Call `b.add(…)`
   with a unique `id`, the `Category`, the `rule` or decision it protects, a
   one-line `about`, the `expected_code` (advisory), the `Expect` invariant,
   the `Requires` precondition, and a `Probe`.
2. Build the request with the helpers in `src/actions.rs` (`buy`, `order`,
   `cancel`, `update_leverage`, `typed`, …) and sign it with `b.signed(...)`
   for a valid client signature, or `body_with_signature(...)` to forge one.
3. If the attack should be fully refused, use `Expect::Refused`. If Guard may
   resize it instead, use `Expect::NotFullSize`.
4. Run `cargo test -p zunder-redteam`. If the new
   case is JSON-level or robustness, add its id to the matching assertion in
   `tests/mock_suite.rs`.

## Scenario cases outside the runner

Some attacks happen before Guard serves anything, so the HTTP suite cannot
make them. They are Guard's own tests:

- **A licence key for another account** (`crates/zunder-guard/tests/fee.rs`,
  `redteam_a_licence_for_another_account_buys_nothing`): a valid, fee-free
  key that names other accounts, given to a Guard for this one, buys
  nothing: Guard runs with the builder fee and journals why. A key that
  names no account (as every key issued before 7 Oct 2026) is good for none.
  Not covered: the test computes the fee mode itself, so that `main.rs`
  passes Guard's own configured account is checked by reading only (in
  send mode `venue_checks` ties that account to the API wallet's master,
  and `vaultAddress` is refused).

## Relationship to Guard's own tests

Guard (built separately in `crates/zunder-guard*`) has its own white-box unit
and end-to-end tests. This suite is independent and adversarial: it does not
import Guard, and it should keep finding nothing on a correct Guard while
continuing to catch the naive mock. The two are complementary — Guard's tests
check that each rule is implemented; the red-team suite checks that no bot can
get past them from outside.
