# Zunder Guard agent kit (MCP server)

`zunder-guard mcp` (the crate `crates/zunder-guard-mcp`) is an MCP server that gives AI agents guarded trading tools on Hyperliquid through a local Zunder Guard: the OpenAI Agents SDK, Cursor, LangGraph, and other MCP clients that start local servers. The server uses Guard's documented HTTP interface; contract assumptions are isolated in `src/contract.rs` and listed under "Open questions" below.

The server holds no API wallet key and never talks to Hyperliquid itself. Its only peer is a Guard on the same machine, reached through Guard's public contract:

- Hyperliquid's own `/info` and `/exchange` formats, with each request signed by a Guard-issued **client key**, exactly as the official SDK signs an L1 action (pinned against the Python SDK's test vectors);
- Guard's read-only `GET /guard/status` and `GET /guard/events?since=N`;
- Guard's signed, loopback-only `POST /guard/kill` (the kill file, `state_dir/kill`, only for an older Guard without that endpoint).

Guard checks every request against its rules, sizes or refuses it, re-signs it with the real API wallet key and sends it. Nothing the agent does through this server can get past that.

## Choices

- **Shipped as `zunder-guard mcp`**, a subcommand of the one binary users install (releases, the image, Homebrew and the installer carry only `zunder-guard`). The crate is a library (`cli::build` and `protocol::serve`) that the subcommand calls, with the same flags; it also builds a standalone `zunder-guard-mcp` binary from source, which no release ships. The configs below run `zunder-guard mcp`.
- **The MCP protocol by hand**, not an SDK. The official Rust SDK (`rmcp`) is Apache-2.0 and would pass `cargo deny`, but a tools-only server needs five methods (`initialize`, `ping`, `tools/list`, `tools/call`, notifications ignored), and writing them keeps every byte the model sees under this crate's control: no async runtime, no generated schemas, no unused transports. Newline-delimited JSON-RPC 2.0 on standard input and output; logs on standard error; messages over 1 MiB and batches refused. Protocol versions 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05.
- **`preview_order` is an estimate**, made here with the real risk engine (`zunder-risk`'s `combined_exposure` and `size_entry`) and Guard's published rules, in Guard's documented order (`src/preview.rs`). Every estimate says what it did not judge. Guard's own preview endpoint is not called from here yet; once it is, that module is replaced by a call to it.

## Setup

1. **Run Guard** (`zunder-guard run`, paper by default; `--network testnet` after a testnet `init`; see Guard's own docs). Guard listens on `127.0.0.1:8547`.
2. **A client key for the agent**, its own, not the bot's (the one `init` or `pair` showed). `zunder-guard client add --out FILE` writes a new client key into a new file of mode 0600 and adds its address to `[auth] clients`; Guard keeps only the address and accepts it after a restart:

   ```sh
   mkdir -p ~/.config/zunder-guard
   zunder-guard client add --out ~/.config/zunder-guard/mcp-client.key
   ```

   The server refuses a key file that the group or others can read, a symbolic link, or a file with anything but one key in it (checked on the opened file, so the path cannot be swapped in between). It never takes the key as an argument or from the environment, on any network. To keep the key in a password manager instead, pipe it in as the first line of standard input with `--key-stdin`; the key then also passes through the standard library's input buffer, which is not wiped, so a key file is the better choice. Without a key the server is read-only: the reading tools and the kill switch work, every order tool refuses.

   **A client key must be a fresh key the venue has never seen.** Its signatures use Hyperliquid's own L1 format (that is how Guard authenticates bots unchanged), so if the same key were also an API wallet of an account, anything that intercepted a request could send it to the venue without Guard. Before the first order request the server asks Hyperliquid, through Guard, for the key's role (`userRole`) and refuses unless it is unknown there (`missing`). Never approve a client key as an API wallet.
3. **The kill switch** needs nothing more: with a client key, `kill_switch` signs Guard's kill request (`POST /guard/kill`). The `--kill-file` flag exists only for an older Guard without that endpoint and is left out below.
4. **Add the server to your client** (below). JSON configs start the program without a shell, so `~` is not expanded: write absolute paths. The binary is `/usr/local/bin/zunder-guard` after the installer as root; `~/.local/bin/zunder-guard` without root; `$(brew --prefix)/bin/zunder-guard` with Homebrew.

| Flag | Default | Meaning |
|---|---|---|
| `--guard-url` | `http://127.0.0.1:8547` | Guard's address. Plain `http` on `127.0.0.1`, `localhost` or `[::1]` only; anything else (the venue's own API among it) is refused at start. |
| `--network` | `paper` | The network Guard must be running: `paper`, `testnet` or `mainnet`. Every order tool refuses when Guard's status reports another one. `mainnet` works only through a Guard that runs mainnet, and needs a key. |
| `--key-file PATH` | none | The client key, in a file of mode 0600 or 0400. |
| `--key-stdin` | off | The client key on the first line of standard input; the MCP messages follow. |
| `--kill-file PATH` | none | Guard's `state_dir/kill`, only for an older Guard without `POST /guard/kill`. |
| `--confirm-account 0x…` | none | Mainnet only, and required there: the account Guard trades, named by you. Every order request is refused unless Guard reports this account. Refused on paper and testnet. |

### Cursor

`~/.cursor/mcp.json` for all projects, or `.cursor/mcp.json` in one:

```json
{
  "mcpServers": {
    "zunder-guard": {
      "command": "/usr/local/bin/zunder-guard",
      "args": ["mcp", "--network", "testnet", "--key-file", "/Users/you/.config/zunder-guard/mcp-client.key"]
    }
  }
}
```

### OpenAI Agents SDK (Python)

```python
import asyncio
from agents import Agent, Runner
from agents.mcp import MCPServerStdio

async def main():
    async with MCPServerStdio(
        name="zunder-guard",
        params={
            "command": "/usr/local/bin/zunder-guard",
            "args": [
                "mcp",
                "--network", "testnet",
                "--key-file", "/Users/you/.config/zunder-guard/mcp-client.key",
            ],
        },
        cache_tools_list=True,
    ) as guard:
        agent = Agent(
            name="Trader",
            instructions="Trade only through the zunder-guard tools. Preview before placing.",
            mcp_servers=[guard],
        )
        result = await Runner.run(agent, "What would Guard allow for a BTC long with a stop at 58800?")
        print(result.final_output)

asyncio.run(main())
```

### LangGraph

With `langchain-mcp-adapters`:

```python
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({
    "zunder-guard": {
        "transport": "stdio",
        "command": "/usr/local/bin/zunder-guard",
        "args": ["mcp", "--network", "testnet", "--key-file", "/Users/you/.config/zunder-guard/mcp-client.key"],
    }
})
tools = await client.get_tools()   # hand these to create_react_agent or a ToolNode
```

### ChatGPT

ChatGPT's connectors reach MCP servers over the internet (streamable HTTP or SSE); a server started from a command on your machine does not work there, and this one only speaks stdio and only talks to a Guard on loopback. Not supported; exposing Guard through a tunnel is not recommended.

## The tools

Every description ends with: "Zunder Guard enforces the account's limits on every order; this tool cannot change, loosen or bypass them, and no tool of this server can." Every input schema is `type: object` with `additionalProperties: false`; every string has a pattern or an enum; money is a decimal **string** (JSON numbers are refused). The schemas are checked again on the server, field by field, before anything else happens.

| Tool | Arguments (required in bold) | What it does |
|---|---|---|
| `account_overview` | none | Equity, positions with the stops that protect them (which cover the whole position, which Guard placed), open orders, Guard's state. Read-only. |
| `limits` | none | Guard's nine rules decoded from its `zr1_` rules code, each with its value, unit and who enforces it (`risk_engine` or `guard_policy`), and Guard's state. Read-only. |
| `preview_order` | **`coin`**, **`side`**, **`stop`**, `size`, `limit_price` | The estimate: verdict (`allow`, `resize`, `veto`), code and reason, allowed and maximum size, the rule that bound a resize, order price, stop price, notional, risk at the stop in USD and % of equity, every check in order, and what was not judged. Sends nothing. |
| `place_order` | **`coin`**, **`side`**, **`stop`**, **`size`**, `limit_price` | An entry with its stop: an IOC limit at Guard's 0.5% bound (or a GTC limit at `limit_price`) and, with a stop price, a reduce-only stop-market in the same `normalTpsl` request. Returns Guard's verdict (from its events, matched by nonce) and the venue's statuses. |
| `move_stop` | **`coin`**, **`new_stop`**, `stop_order_id` | Tightens a position's stop (a `modify` of it, or a new stop if it has none). Looser, unchanged, or at or through the price: refused here before anything is sent; Guard refuses looser too. |
| `close_position` | **`coin`**, `fraction` | A reduce-only IOC 5% beyond the mid (Guard's exit band), for all (default) or a fraction of the position. Guard never blocks it, and neither do this server's order-rate limit or an unknown earlier outcome. |
| `cancel_order` | **`coin`**, **`order_id`** | Cancels one open order of that coin. Refused here when it would leave a position without a stop that covers it (Guard refuses that too); says whether it was a protective stop. |
| `recent_decisions` | `limit` (1–50, default 20), `since` | Guard's events, summarised: verdicts with codes and this server's reasons, what reached the venue, risk states, flattens, the kill switch. |
| `kill_switch` | **`confirm`** (must be `true`), `reason` | Sends Guard's signed kill request (`POST /guard/kill`; with no client key, or an older Guard without the endpoint, it writes the kill file given by `--kill-file`), then waits up to 15 s (longer if Guard does not answer its status) for Guard's status to report the switch latched, during which the server handles no other call; if it does not (a wrong path, a stopped Guard), the result is an error that says so and asks for `zunder-guard kill` at the machine. Pull only: an existing file is left as it is, and nothing can remove it. Never rate-limited, needs no key. |

Field patterns:

| Field | Schema |
|---|---|
| `coin` | string `^[A-Za-z0-9]{1,16}$`, and a listed, not delisted perp of the main dex |
| `side` | `"buy"` or `"sell"` |
| `stop` | string `^(guard_policy|[0-9]{1,12}(\.[0-9]{1,8})?)$`, above 0. `guard_policy` lets Guard attach its default stop; refused when Guard's stop policy is `refuse` |
| `size` | string `^(max|[0-9]{1,12}(\.[0-9]{1,8})?)$`, above 0. `max` is the estimate's allowed size |
| `limit_price`, `new_stop` | string `^[0-9]{1,12}(\.[0-9]{1,8})?$`, above 0 |
| `fraction` | string `^(1(\.0{1,8})?|0\.[0-9]{1,8})$`, above 0 |
| `order_id`, `stop_order_id` | integer 1 to 2^53 − 1 |
| `confirm` | boolean, `const: true` |
| `reason` | string, at most 120 of `A–Z a–z 0–9 space . , : ; ' ( ) _ -` |
| `limit` | integer 1 to 50 |
| `since` | integer ≥ 0 |

Results come back as `structuredContent` and the same JSON as text. A refusal or failure has `isError: true` and `{"ok": false, "error": {"code", "reason"}}`, and says whether anything was sent (`sent`: `true`, `false`, or `null` when unknown). An unknown tool is a JSON-RPC error that does not repeat the name.

- **What `place_order` sends.** It first makes the same estimate as `preview_order`. Every veto of the estimate is final here, nothing sent: Guard's halts and kill switch, a stop on the wrong side (after rounding onto the price grid, towards the price), `guard_policy` under `refuse`, a market off the list, a flip, cross margin, the position cap, absurd numbers. Only the risk engine's budget vetoes (`open_risk`, `leverage`, `below_minimum`, `unprotected_position`, where the estimate counts open risk more conservatively than Guard) with an explicit size go to Guard, whose own verdict counts there; `max` with no allowed size is never sent.
- **Unknown outcomes.** Only a connection that never opened proves nothing was sent. A timeout, an HTTP error or an unreadable answer after a request to `/exchange` is `outcome_unknown` with `sent: null`; so are an error reply that is not Guard's veto (the venue may have refused what Guard forwarded: `refused`) and a venue reply whose statuses cannot be read or are missing (`venue_reply_unreadable`). `place_order` then refuses (`check_first`) until the agent has called `account_overview` or `recent_decisions`, so a retry does not open a second position. Closing, tightening and cancelling stay available. What remains: after a timeout, Guard may still be waiting for the venue when the agent looks, so the look can miss an entry that fills a moment later; each retry has a fresh client order id, and Guard's open-risk budget is what bounds a duplicate then.
- **Partial results.** When the venue refuses part of a request (an entry filled but its stop refused, or an IOC entry that did not match while its stop waits), the result is an error, `partly_refused`, telling the agent to check the account now.

## What no tool can do

Change a limit or the stop policy; clear a halt or resume after one; release the kill switch; move funds (transfer, withdraw, approve an agent or a builder fee); change leverage or isolated margin; set a scheduled cancel; trade for a vault; send a raw action or call an arbitrary endpoint. There is no tool for any of these, no argument that reaches them, and no code that could build them: `sign::Action` has exactly three variants (`order`, `cancel`, `modify`), each built from checked arguments, and the vault address is always null. Guard refuses all of them independently, by name.

## What is enforced where

| Guarantee | Where |
|---|---|
| The nine rules, sizing from the stop, isolated leverage, halts, the kill switch, stops only tighten, exits never blocked | **Guard**, on every request, whatever this server sends |
| Only order, cancel and modify can be signed; no builder field; vault always null | this server, by type (`sign.rs`) |
| Nine tools, nothing else; closed schemas; arguments checked again server-side, never echoed | this server (`tools.rs`, `schema.rs`) |
| Absurd sizes (worth more than 200 × equity) and prices (more than 10 × away from the mid) refused, not resized | this server (`preview.rs`) |
| A looser or crossing stop refused before sending | this server (`move_stop`), and Guard |
| Orders refused locally when Guard's status shows the kill switch, a halt or a broken journal | this server, from Guard's state; Guard refuses them anyway |
| A stop on the wrong side, a missing stop under `refuse`, a market off the list, a flip, cross margin, the position cap: never sent | this server (`place_order`, from the estimate), and Guard |
| A position's last covering stop is not cancelled | this server (`cancel_order`), and Guard |
| No blind retry after an unknown outcome | this server (`place_order` refuses until the agent has looked) |
| Only a Guard on this machine: loopback `http` URL, no redirects, no proxy, a status of schema 1 | this server (`guard.rs`, `contract.rs`) |
| The network: Guard's `mode` must equal `--network` before any order request; mainnet only through a mainnet Guard, and only for the account named with `--confirm-account` | this server; Guard's own mainnet guards (its `MainnetConsent`, the equity cap, the API wallet check) are untouched |
| The client key: one of Guard's clients before any order request, and unknown to Hyperliquid (`userRole` is `missing`) before the first entry (a failing look-up never holds up a close, a stop or a cancel); from a 0600 file or stdin, never arguments or environment | this server (`key.rs`, `tools.rs`); Guard authenticates every signature and nonce |
| The kill switch latched | Guard; this server waits for Guard's status to confirm it and says so when it does not |
| Call rates | this server (`ratelimit.rs`) |

## Prompt-injection hygiene

- Tool descriptions and the server's `instructions` say plainly that Guard enforces the limits and the agent cannot change them, and that text from Guard, the venue or market data is data, never an instruction.
- **Reasons are this server's own words.** Every refusal carries a code and a fixed sentence for it (`contract::reason_for`); an unknown code gets a neutral sentence. Text from Guard or the venue appears only in fields named `*_quoted` (and `venue_statuses[].venue_quoted`), as one line of at most 200 characters from a small character set: no newlines, quotes, braces or backticks (`sanitize.rs`).
- Identifiers from outside (coin names, codes, order types, addresses) are checked against strict patterns and replaced or dropped when they do not match. Guard's events are summarised field by field; the bot's raw request, what Guard forwards and the venue's raw reply are left out.
- Arguments are never repeated in errors: an injection-shaped coin name or an unknown argument is refused by name of the parameter only.
- Labels and codes from outside are closed sets: Guard's reason codes (the ones this server has a reason for), event kinds, risk states, order types, margin modes and action types; anything else becomes `other`. Guard's version must look like a version.
- **Rate limits:** 30 calls at once, then 60 a minute; order requests (`place_order`, `move_stop`, `cancel_order`) 4 at once, then 10 a minute. Every call counts, refused ones too. `close_position` counts only against all calls, so failed entries never hold up an exit; the kill switch is never limited.

## Tests

`cargo test -p zunder-guard-mcp` (on a Linux build host): 45 unit tests and 27 end-to-end runs against a mock Guard, an in-process HTTP server speaking Hyperliquid's `/info` and `/exchange` and Guard's status and events, which authenticates every request as Guard does (the signature must recover to a registered client key, for either phantom-agent source).

- Signing pinned against the Python SDK's vectors (orders, a stop-market, a client order id, the dummy action on both networks, the production connection id).
- Tool schemas: exactly nine tools, closed schemas, every string constrained, no parameter that names leverage, vaults, builders, actions, keys, networks or policies.
- Refusal of every forbidden capability: 31 tool names (withdrawals, transfers, approvals, leverage, limits, resume, raw actions, case and whitespace variants) are JSON-RPC errors; extra arguments such as `leverage`, `vaultAddress`, `builder`, `action` or `network` are refused; nothing reaches `/exchange`.
- End to end: account and limits read through Guard; the preview's numbers (hand-computed in the test's header and in `preview.rs`, buy and sell); an entry with its stop signed and sent, byte for byte; the `guard_policy` path; stops rounded towards the price; wrong-side stops never sent; a veto, paper mode, a partly refused request, an unknown outcome (HTTP 502 after sending) and the block on retrying it; the wrong network both ways, a mainnet account that was not confirmed, the signing source per network, an unknown key, a key the venue knows, something that is not a Guard, no key; stops only tighten, for a long and a short; close (sell and buy) and cancel, and the last stop kept; the kill switch (confirmation, pull only, never rate-limited, confirmed by Guard, and reported when Guard does not see it); rate limits and strictly increasing nonces; an unreachable Guard; a rules code Guard could not have written (`requireStop: false` among them); an account value near the largest `Decimal`.
- Prompt-injection-shaped inputs: a coin name carrying instructions, a well-formed unknown coin, sizes such as `1e30`, `-5`, `NaN` and 1,000,000 BTC, numbers for strings, a stop given as prose; a veto and an event whose text tries to give instructions (it stays quoted and stripped; the bot's request with an attacker's address is left out).

No test touches a network, a key or a venue.

## Guard's contract: what was open, and how it is settled

All of it lives in `src/contract.rs`. Guard (`docs/guard.md`, "The public contract") settled the open questions on 6 Oct 2026:

1. **Preview.** Guard has `POST /guard/preview`: its real judgement on an unsigned action, read-only, with the requested and the forwarded size (`entry.requested_size`, `entry.size`). `preview_order` here is still the estimate; calling Guard's preview from it is the next step for this server (the place_order path already gets Guard's own verdict).
2. **Kill switch.** Guard has `POST /guard/kill`, authenticated by a client signature (`sign::signed_kill_request`), from this machine only, pull only. `kill_switch` uses it whenever the server has a client key; `--kill-file` remains only for an older Guard without the endpoint (a 404) or a server without a key.
3. **Client keys for agents.** `zunder-guard client add --out FILE` writes a new client key into a new 0600 file and adds its address to `[auth] clients` (`init --client-key-out FILE` for the first one). A running Guard accepts it after a restart.
4. **The status schema.** Schema 1 as assumed: `risk.state` is a plain string (`active`, `halted_for_day`, `stopped`; the details under `risk.detail`), `rules` is the rules schema v1 code (no `requireStop`), and the status adds `equity_cap`, `assumptions` (fees, slippage, the entry price bound, stop and exit slippage, the default stop distance, the minimum order value), `alerts` and `kill_file`.
5. **Reply text.** Veto and paper replies carry `code` (and paper replies `verdict`) as fields beside the text; forwarded replies carry Guard's `code` and `verdict` too, so a resize is visible without reading fill sizes. SDKs ignore fields they do not know.
6. **Decisions by nonce.** `GET /guard/decision?nonce=N&client=0x…` reads the decision journal on disk, so a verdict no longer scrolls out of the 1,000-event buffer.
7. **`zunder-guard mcp`.** The Guard binary runs this server as a subcommand (`zunder-guard mcp …`, the same flags), so users install one program. Releases ship only `zunder-guard`; `zunder-guard-mcp` builds from source for those who want it alone.
8. **The event schema.** Guard's code is the schema (`schema: 1`, `seq`, `at_ms`, `kind`); `docs/guard.md`, "Events", documents that form.
