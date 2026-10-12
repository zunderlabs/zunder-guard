# Zunder Guard agent kit (MCP server)

`zunder-guard mcp` (the crate `crates/zunder-guard-mcp`) is an MCP server that gives AI agents guarded trading tools on Hyperliquid through a local Zunder Guard: the OpenAI Agents SDK, Cursor, LangGraph, and other MCP clients that start local servers. The server uses Guard's documented HTTP interface; contract assumptions are isolated in `src/contract.rs` and listed under "Guard's contract" below.

The server holds no API wallet key and never talks to Hyperliquid itself. Its only peer is a Guard on the same machine, reached through Guard's public contract:

- Hyperliquid's own `/info` and `/exchange` formats, with each request signed by a Guard-issued **client key**, exactly as the official SDK signs an L1 action (pinned against the Python SDK's test vectors);
- Guard's read-only `GET /guard/status` and `GET /guard/events?since=N`;
- Guard's read-only `POST /guard/preview` (its own judgement of an unsigned action, nothing journaled or sent);
- Guard's signed, loopback-only `POST /guard/kill` (the kill file, `state_dir/kill`, only for an older Guard without that endpoint).

Guard checks every request against its rules, sizes or refuses it, re-signs it with the real API wallet key and sends it. Nothing the agent does through this server can get past that.

## Choices

- **Shipped as `zunder-guard mcp`**, a subcommand of the one binary users install (releases, the image, Homebrew and the installer carry only `zunder-guard`). The crate is a library (`cli::build` and `protocol::serve`) that the subcommand calls, with the same flags; it also builds a standalone `zunder-guard-mcp` binary from source, which no release ships. The configs below run `zunder-guard mcp`.
- **The MCP protocol by hand**, not an SDK. The official Rust SDK (`rmcp`) is Apache-2.0 and would pass `cargo deny`, but a tools-only server needs five methods (`initialize`, `ping`, `tools/list`, `tools/call`, notifications ignored), and writing them keeps every byte the model sees under this crate's control: no async runtime, no generated schemas, no unused transports. Newline-delimited JSON-RPC 2.0 on standard input and output; logs on standard error; messages over 1 MiB and batches refused. Protocol versions 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05.
- **`preview_order` is Guard's own answer**, not an estimate: the server builds the entry `place_order` would send (the same prices, size and stop; only the client order id is left out) and asks Guard's `POST /guard/preview` (`src/preview.rs`). Guard's preview runs `zunder_guard_core::judge`, the judgement its `/exchange` runs: an entry goes through the nine steps of `docs/guard.md`, "An entry", in that order and one function each (halts, market, account, worst fill, stop, the risk engine's size, position cap, liquidation and isolated leverage, quantity), and the first refusal wins. The server does no rule arithmetic of its own; it keeps only its sanity bound on absurd prices and sizes, stops rounded onto the price grid towards the price, and the price an entry is sent at (Guard's 0.5% bound from the mid).
- **No preview, no estimate.** When Guard gives no preview (an older Guard without the endpoint, its one-a-second budget spent, no account view from the last 60 s, an answer that cannot be read), `preview_order` and `place_order` refuse with a code of their own and send nothing; there is no fallback estimate. A Guard old enough to lack `/guard/preview` also lacks `capabilities.exchange_expected_mode`, so this server sends it no order anyway; a second, non-binding implementation of the rules would only be a second answer that can disagree with Guard's.

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
| `--network` | `paper` | The network Guard must be running: `paper`, `testnet` or `mainnet`. Every order tool refuses when Guard's status reports another one, and every `/exchange` request and kill request names this mode to Guard (`expectedMode`, below; the kill unless Guard's status shows an older Guard), which refuses it when it runs another. `mainnet` works only through a Guard that runs mainnet, and needs a key. |
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
| `account_overview` | none | Equity, positions with the stops that protect them (which cover the whole position, which Guard placed), open orders, Guard's state. Read-only. A stop protects by Guard core's own rule (`OpenOrderView`, the covering stop): a reduce-only market stop on the closing side whose limit leaves room to fill; a stop-limit protects nothing. An order Guard core cannot read is still listed, counts as no stop, and is named in `warnings`; it never fails the read, so closing and cancelling do not depend on it. |
| `limits` | none | Guard's nine rules decoded from its `zr1_` rules code, each with its value, unit and who enforces it (`risk_engine` or `guard_policy`), and Guard's state. Read-only. |
| `preview_order` | **`coin`**, **`side`**, **`stop`**, `size`, `limit_price`, `time_in_force` | Guard's own preview of the entry (`source: "guard"`): verdict (`allow`, `resize`, `veto`), code and this server's reason, Guard's text and changes (quoted), the size asked and the size Guard would send (`allowed_size`, and `size_cut`), the order price, Guard's worst fill and stop, the isolated leverage Guard would set, notional and risk at the stop in USD and % of equity (computed from Guard's size, worst fill and stop, with Guard's default costs), the age of the account view Guard judged from (`view_age_ms`), and its caveats. Sends nothing; journals nothing at Guard. |
| `place_order` | **`coin`**, **`side`**, **`stop`**, **`size`**, `limit_price`, `time_in_force` | An entry with its stop: an IOC limit at Guard's 0.5% bound (or a GTC limit at `limit_price`, unless `time_in_force: "ioc"` selects IOC at that limit) and, with a stop price, a reduce-only stop-market in the same `normalTpsl` request. Guard previews exactly that request first; nothing its preview vetoes is sent. Returns Guard's verdict on the send (from its events, matched by nonce), the venue's statuses and the preview it was sent after. |
| `move_stop` | **`coin`**, **`new_stop`**, `stop_order_id` | Tightens a position's stop (a `modify` of it, or a new stop if it has none). Looser, unchanged, or at or through the price: refused here before anything is sent; Guard refuses looser too. |
| `close_position` | **`coin`**, `fraction`, `expected_size` | A reduce-only IOC 5% beyond the mid (Guard's exit band), for all (default) or a fraction of the position. With `expected_size` (not together with `fraction`): sent only when the open position's size (long or short) is exactly `expected_size`, compared as numbers (`"0.10"` is `0.1`), and then for exactly that quantity, never a fraction of it or more; otherwise (also for a position off the venue's size grid) `position_size_mismatch` with `expected_size`, `position_size` (`"0"` when there is none) and `sent: false`, nothing sent. An explicit `null` is refused (`invalid_arguments`), never read as absent. A position that changes after the read is still closed by at most `expected_size`: the order is reduce-only, Guard cuts a reduce-only order to the position it sees, and the venue never lets one open or flip a position. The bound is per call: a close with an unknown outcome (`sent: null`) retried with the same `expected_size` can fill twice, so read the position again first. Sizes are compared without their side: a short of exactly `expected_size` is closed too. Guard never blocks it, and neither do this server's order-rate limit or an unknown earlier outcome. |
| `cancel_order` | **`coin`**, **`order_id`** | Cancels one open order of that coin. Refused here when it would leave a position without stops that cover it together, by Guard core's covering-stop rule (Guard refuses that too); says whether it was a protective stop. |
| `recent_decisions` | `limit` (1–50, default 20), `since` | Guard's events, summarised: verdicts with codes and this server's reasons, what reached the venue, risk states, flattens, the kill switch. |
| `kill_switch` | **`confirm`** (must be `true`), `reason` | Sends Guard's signed kill request (`POST /guard/kill`; with no client key, or an older Guard without the endpoint, it writes the kill file given by `--kill-file`), then waits up to 15 s (longer if Guard does not answer its status) for Guard's status to report the switch latched, during which the server handles no other call; if it does not (a wrong path, a stopped Guard), the result is an error that says so and asks for `zunder-guard kill` at the machine. Pull only: an existing file is left as it is, and nothing can remove it. Never rate-limited, needs no key. Looks at Guard's status first (at most 2 s): refused (`network_mismatch`, nothing pulled, the kill file not written either, also without a client key) when it names another mode than `--network`, which also stops a server started with the default `--network paper` from pulling a testnet or mainnet Guard's switch. The kill request names `--network` (`expectedMode`) unless the status was read and lacks `kill_expected_mode` (an older Guard); a Guard of another mode answering it pulls nothing (`mode_mismatch`, `sent: false`), and the kill file is left alone. A slow or unreadable status holds the kill up by at most 2 s: it goes ahead with the field, and an older Guard that refuses the field as `malformed` gets the kill file instead. |

Field patterns:

| Field | Schema |
|---|---|
| `coin` | string `^[A-Za-z0-9]{1,16}$`, and a listed, not delisted perp of the main dex |
| `side` | `"buy"` or `"sell"` |
| `stop` | string `^(guard_policy|[0-9]{1,12}(\.[0-9]{1,8})?)$`, above 0. `guard_policy` lets Guard attach its default stop; refused when Guard's stop policy is `refuse` |
| `size` | string `^(max|[0-9]{1,12}(\.[0-9]{1,8})?)$`, above 0. `max` is the size Guard's preview allows: the server asks for its sanity bound (200 × equity at the order price, on the grid), which no rules code lets Guard allow, so Guard cuts it to the most its rules allow (its verdict for `max` is normally `resize`); what is sent is that size on the grid, never more than was asked |
| `limit_price`, `new_stop` | string `^[0-9]{1,12}(\.[0-9]{1,8})?$`, above 0 |
| `time_in_force` | only the string `"ioc"`, with explicit `limit_price`; omitted keeps GTC with an explicit limit and IOC without one |
| `fraction` | string `^(1(\.0{1,8})?|0\.[0-9]{1,8})$`, above 0 |
| `expected_size` | string `^[0-9]{1,12}(\.[0-9]{1,8})?$`, above 0 |
| `order_id`, `stop_order_id` | integer 1 to 2^53 − 1 |
| `confirm` | boolean, `const: true` |
| `reason` | string, at most 120 of `A–Z a–z 0–9 space . , : ; ' ( ) _ -` |
| `limit` | integer 1 to 50 |
| `since` | integer ≥ 0 |

**Explicit-price IOC.** Before using `time_in_force: "ioc"`, require `initialize`'s `result.capabilities.experimental.limit_price_ioc.enabled` to be the literal `true`. Missing or malformed capability means send no preview or order: an older server could ignore this option and place GTC. Both entry tools use the same checked request and action builder, including this option; `preview.time_in_force` and `order.time_in_force` report the selected value. A missing `limit_price`, unsupported TIF value, explicit null or unknown argument is `invalid_arguments`, `sent: false`, before any Guard request. The explicit limit still obeys Guard's 0.5% price bound, risk rules and protective stop.

**Leave an argument out; never send `null` for it.** On the tools that build an order (`preview_order`, `place_order`, `move_stop`, `close_position`, `cancel_order`), an optional argument given as JSON `null` is refused (`invalid_arguments`, `sent: false`), because leaving one out selects a default that can do more: `fraction` left out closes all of the position, `limit_price` left out sends an immediate order instead of a resting one, `size` left out previews Guard's maximum, `stop_order_id` left out lets the server pick the stop, and `expected_size` left out drops the size check. A client that fills unset fields with `null` must omit them instead. The read tools and the kill switch's `reason` take `null` as left out.

Results come back as `structuredContent` and the same JSON as text. A refusal or failure has `isError: true` and `{"ok": false, "error": {"code", "reason"}}`, and says whether anything was sent (`sent`: `true`, `false`, or `null` when unknown). An unknown tool is a JSON-RPC error that does not repeat the name.

- **What `place_order` sends.** It refuses first, nothing sent, when Guard's status shows the kill switch, a halt or a broken decision journal, and for absurd numbers. Then Guard previews exactly the request it would send (the same client order id, size, prices and stop), and every veto of that preview is final, nothing sent: Guard's halts, a stop on the wrong side (after rounding onto the price grid, towards the price), `guard_policy` under `refuse`, a market off the list, a flip, cross margin, the position cap, the open-risk and leverage budgets, an unprotected position. An explicit size goes as asked, and Guard cuts it when it sends; `max` goes at the size Guard's preview named. Guard judges the send again from a fresh read of the account, and that verdict is the one reported; the preview's verdict, code, size and view age come back beside it (`order.guard_preview_before_sending`). A preview judges from a view up to 60 s older than the send's, so when the account changed in between (a fill, another bot's entry) the two verdicts can differ, and the send's counts; a preview cannot show the venue's own refusals (`venue_refused_leverage`, `venue_unreachable`).
- **When Guard gives no preview**, both `preview_order` and `place_order` refuse and send nothing: `preview_unsupported` (HTTP 404: a Guard older than its preview; update `zunder-guard`), `preview_rate_limited` (Guard answers one preview a second for all its clients together; this server spaces its own a second apart, tries once more a second later, then refuses with `retry_after_ms`), `preview_view_stale` (Guard has no view of the account from the last 60 s: it has just started or cannot read the venue), `preview_refused` (any other refusal, `malformed` or a code this server does not know, Guard's words in `guard_quoted`), `preview_unreadable` (an answer that is not a preview, names another coin, side or requested size than was asked, or forwards more than asked; a view older than 60 s is `preview_view_stale`), `not_an_entry` (Guard judged the order as reducing a position held, opposite it and no larger: use `close_position`), `network_mismatch` (the preview names another mode than `--network`), `guard_unreachable`, `preview_unavailable` (any other failure). A read before any request to `/exchange` that gets no answer in time (the status, the account, a preview) is `guard_timeout`, nothing sent; `outcome_unknown` is only ever an `/exchange` request's. Guard's refusals are told apart by their stable `code` (`preview_rate_limited`, `preview_view_stale`, `malformed`), never by the text, which is only quoted; only a Guard from before the code, answering `{"error": text}` alone, has its words matched instead (a fallback, `contract::parse_preview`). While Guard's recovery after a restart runs or its decision journal cannot be written, its preview is a veto with the code `journal` (`view_age_ms` null when Guard refused before looking at the view, so `preview_order`'s `view_age_ms` can be null on a veto): `preview_order` shows that veto, and `place_order` sends nothing.
- **Unknown outcomes.** Only a connection that never opened proves nothing was sent. A timeout, an HTTP error or an unreadable answer after a request to `/exchange` is `outcome_unknown` with `sent: null`; so are an error reply that is not Guard's veto (the venue may have refused what Guard forwarded: `refused`) and a venue reply whose statuses cannot be read or are missing (`venue_reply_unreadable`). `place_order` then refuses (`check_first`) until the agent has called `account_overview` or `recent_decisions`, so a retry does not open a second position. Closing, tightening and cancelling stay available. What remains: after a timeout, Guard may still be waiting for the venue when the agent looks, so the look can miss an entry that fills a moment later; each retry has a fresh client order id, and Guard's open-risk budget is what bounds a duplicate then.
- **The expected mode.** Every request to Guard's `/exchange` carries `"expectedMode"` set to `--network` (`paper`, `testnet` or `mainnet`), beside the signed fields: the signed action, nonce, expiry and signature are exactly what they would be without it. Guard refuses a request expecting another mode than its own before it checks the signature, judges or sends anything (`mode_mismatch`: `isError: true`, `outcome: "vetoed_by_guard"`, `sent: false`). Reading Guard's status first is not enough on its own: another Guard (a mainnet one, say) could take over the address between that read and the request, and Guard accepts a client's signature made for either network. The server sends no `/exchange` request to a Guard whose status lacks `capabilities.exchange_expected_mode: true` (an older Guard would refuse the field anyway): `place_order`, `move_stop`, `cancel_order` and `close_position` refuse with `expected_mode_unsupported`, `sent: false`; update `zunder-guard`. Reading still works. `account_overview` shows it as `guard.enforces_expected_mode`. If an older Guard takes over the address between the status read and the request, it refuses the unknown field: `malformed` ("Guard could not read the request"), `sent: false`. The kill switch refuses (`network_mismatch`, nothing pulled) when Guard's status reports another mode than `--network`, and its request carries `expectedMode` whenever Guard's status lists `capabilities.kill_expected_mode: true`, so a Guard of another mode taking over in between pulls nothing (`mode_mismatch`). The field is left out only when the status was read, names `--network` and lacks `kill_expected_mode` (an older Guard, which would refuse it); only then could a Guard of another mode taking over in that moment still be pulled. A slow or unreadable status does not leave it out: the kill goes ahead with the field (an older Guard answering `malformed` gets the kill file instead). `initialize` advertises the `/exchange` guarantee as `capabilities.experimental.exchange_expected_mode: {"enabled": true}` (an object, as MCP requires of every experimental capability), so an MCP client can require it before it places, closes or cancels anything.
- **The expected size of a close.** `initialize` also advertises `capabilities.experimental.close_expected_size: {"enabled": true}`: `close_position` takes `expected_size`, closes exactly that quantity, and sends nothing unless the open position is exactly that size. A client that closes a position it has observed (a cleanup after a test, say) can require it, so that a position that grew since its look is never closed in full by mistake. The close still carries `expectedMode` like every other request.
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
| What `preview_order` shows: Guard's own judgement of the exact request `place_order` would send | **Guard** (`POST /guard/preview`); this server builds the request and reads the answer field by field |
| A looser or crossing stop refused before sending | this server (`move_stop`), and Guard |
| Entries refused locally when Guard's status shows the kill switch, a halt or a broken journal | this server, from Guard's state; Guard refuses them anyway |
| Anything Guard's preview vetoes (a stop on the wrong side, a missing stop under `refuse`, a market off the list, a flip, cross margin, the position cap, the budgets): never sent; nothing sent without a preview | this server (`place_order`), from Guard's preview; Guard judges the send again |
| A position's last covering stop is not cancelled | this server (`cancel_order`), and Guard |
| No blind retry after an unknown outcome | this server (`place_order` refuses until the agent has looked) |
| Only a Guard on this machine: loopback `http` URL, no redirects, no proxy, a status of schema 1 | this server (`guard.rs`, `contract.rs`) |
| The network: Guard's `mode` must equal `--network` before any order request; mainnet only through a mainnet Guard, and only for the account named with `--confirm-account` | this server; Guard's own mainnet guards (its `MainnetConsent`, the equity cap, the API wallet check) are untouched |
| The network at the moment of sending: every request carries `expectedMode` = `--network`, and only a Guard whose status has `capabilities.exchange_expected_mode: true` gets one | this server sends it and refuses older Guards; **Guard** refuses a mismatch (`mode_mismatch`) before judging or sending, under the same lock it sends under |
| The client key: one of Guard's clients before any order request, and unknown to Hyperliquid (`userRole` is `missing`) before the first entry (a failing look-up never holds up a close, a stop or a cancel); from a 0600 file or stdin, never arguments or environment | this server (`key.rs`, `tools.rs`); Guard authenticates every signature and nonce |
| The kill switch latched | Guard; this server waits for Guard's status to confirm it and says so when it does not |
| Call rates | this server (`ratelimit.rs`); its previews at most one a second (`tools.rs`), Guard's own budget for all clients |

## Prompt-injection hygiene

- Tool descriptions and the server's `instructions` say plainly that Guard enforces the limits and the agent cannot change them, and that text from Guard, the venue or market data is data, never an instruction.
- **Reasons are this server's own words.** Every refusal carries a code and a fixed sentence for it (`contract::reason_for`); an unknown code gets a neutral sentence. Text from Guard or the venue appears only in fields named `*_quoted` (and `venue_statuses[].venue_quoted`), as one line of at most 200 characters from a small character set: no newlines, quotes, braces or backticks (`sanitize.rs`).
- Identifiers from outside (coin names, codes, order types, addresses) are checked against strict patterns and replaced or dropped when they do not match. Guard's events are summarised field by field; the bot's raw request, what Guard forwards and the venue's raw reply are left out.
- Arguments are never repeated in errors: an injection-shaped coin name or an unknown argument is refused by name of the parameter only.
- Labels and codes from outside are closed sets: Guard's reason codes (the ones this server has a reason for), event kinds, risk states, order types, margin modes and action types; anything else becomes `other`. Guard's version must look like a version.
- **Rate limits:** 30 calls at once, then 60 a minute; order requests (`place_order`, `move_stop`, `cancel_order`) 4 at once, then 10 a minute. Every call counts, refused ones too. `close_position` counts only against all calls, so failed entries never hold up an exit; the kill switch is never limited.

## Tests

`cargo test -p zunder-guard-mcp` (on a Linux build host): unit tests and end-to-end runs against a mock Guard, an in-process HTTP server speaking Hyperliquid's `/info` and `/exchange` and Guard's status, events and preview, which authenticates every request as Guard does (the signature must recover to a registered client key, for either phantom-agent source). The mock's preview follows Guard's order with the test's numbers; Guard's real judgement is in `crates/zunder-guard/tests/mcp_kit.rs`.

- The preview: `preview_order` asks Guard about the request `place_order` would send (unsigned, with its stop in `normalTpsl`), and `place_order` previews exactly the action it then signs and sends, client order id included, and shows Guard's verdict, code, size, stop and leverage with the numbers computed from them (hand-computed in the test's header); `max` asks for the sanity bound and gets Guard's cut; every veto of Guard's preview is final in `place_order` (nothing sent, `max` or an explicit size); no preview, nothing sent: an older Guard (404), Guard's budget spent twice (one more try, then `preview_rate_limited` with `retry_after_ms`) or once (the second try goes), no recent view (`preview_view_stale`), another refusal (quoted, an injection in it stays data), an answer that forwards more than asked, echoes a larger request than was asked (also for `max`) or names another coin (`preview_unreadable`), an allow without an entry (`not_an_entry`), a preview from a Guard in another mode (`network_mismatch`), a `journal` veto with no view age (shown, nothing sent); the preview parsed field by field, Guard's refusals told apart by their code even when the words say otherwise, an unknown or `malformed` code quoted as `preview_refused`, and, for a Guard from before the code only, by its words.

- Signing pinned against the Python SDK's vectors (orders, a stop-market, a client order id, the dummy action on both networks, the production connection id).
- An explicit `null` on an order tool: `fraction`, `expected_size`, `limit_price` (entry and preview), the preview's `size` and `stop_order_id` refuse as `invalid_arguments` with `sent: false`, nothing sent, naming the argument; left out, the default still applies (the whole position is closed), and a read still takes `null` as left out.
- Tool schemas: exactly nine tools, closed schemas, every string constrained, no parameter that names leverage, vaults, builders, actions, keys, networks or policies.
- Refusal of every forbidden capability: 31 tool names (withdrawals, transfers, approvals, leverage, limits, resume, raw actions, case and whitespace variants) are JSON-RPC errors; extra arguments such as `leverage`, `vaultAddress`, `builder`, `action` or `network` are refused; nothing reaches `/exchange`.
- End to end: account and limits read through Guard; an entry with its stop signed and sent, byte for byte; the `guard_policy` path; stops rounded towards the price; wrong-side stops never sent; a veto, paper mode, a partly refused request, an unknown outcome (HTTP 502 after sending) and the block on retrying it; the wrong network both ways, a mainnet account that was not confirmed, the signing source per network, an unknown key, a key the venue knows, something that is not a Guard, no key; stops only tighten, for a long and a short; close (sell and buy) and cancel, and the last stop kept; the kill switch (confirmation, pull only, never rate-limited, confirmed by Guard, and reported when Guard does not see it); rate limits and strictly increasing nonces; an unreachable Guard; a rules code Guard could not have written (`requireStop: false` among them); an account value near the largest `Decimal`.
- The expected size of a close: `initialize` advertises `experimental.close_expected_size: {"enabled": true}`; a position of exactly `expected_size` (also written with trailing zeros, long and short) gets one reduce-only IOC of exactly that size with the pinned mode; larger and smaller positions (long and short) and no position refuse with `position_size_mismatch`, `sent: false`, nothing sent; a position off the size grid refuses with both sizes; zero, negative, signed, exponent, over-precise, non-string, `null` or `max` sizes, and `expected_size` with `fraction`, refuse as `invalid_arguments`, `sent: false`; a rate-limited close says `sent: false`. `crates/zunder-guard/tests/mcp_kit.rs` runs it against the real testnet Guard on the in-memory venue: a position that already differs when the kit reads it (larger, smaller, a short) is refused with no request to `/exchange`; and with the position changing between the kit's read and its send, the reduce-only order bounds the close: grown from 0.0002 to 0.0003, exactly 0.0002 is sold and 0.0001 stays open; shrunk from 0.0003 to 0.0002, the account ends flat, never short.
- The expected mode: `initialize` advertises `experimental.exchange_expected_mode: {"enabled": true}`, and its capabilities follow MCP's schema (every experimental value an object) in every protocol version; every order, modify, cancel and close carries the pinned mode in all three modes, last in the envelope, with the signature unchanged; a Guard replaced between the preview and the send of an entry, or between the status read and the send of a close (testnet by mainnet, paper by testnet), refuses with `mode_mismatch` and nothing reaches the venue; replaced between the status read and an entry's preview, its preview names its mode and nothing is sent (`network_mismatch`); an older Guard taking over refuses it as `malformed`, nothing sent; the kill switch of a Guard in another mode is not pulled, the kill request names the pinned mode when Guard lists `kill_expected_mode` (and not otherwise), a Guard replaced between the status read and the kill pulls nothing, a status that cannot be read or is slow does not stop the kill (at most 2 s) but still names the mode, so a mainnet Guard with an unreadable status is not pulled, an older Guard refusing the field gets the kill file, and a status naming another mode refuses even when it cannot otherwise be parsed; a status without the capability, or with anything but a literal `true`, gets nothing from any order tool. `crates/zunder-guard/tests/mcp_kit.rs` repeats the replacement against the real Guard: a paper-pinned server reads a paper Guard's status and preview, a testnet Guard on the in-memory venue answers the order and refuses it, and the venue receives nothing; taken over right after the status read, the testnet Guard's preview names its mode and nothing is sent or journaled; the same for the kill switch, which leaves the testnet Guard's switch unlatched and its position open.
- Against the real Guard (`crates/zunder-guard/tests/mcp_kit.rs`, paper mode on the in-memory venue): `preview_order` equals Guard's decision on the same request sent to `/exchange` (verdict, code and size) for an allow, a resize, `max` and a veto, and `place_order` sends nothing Guard's preview vetoes (nothing journaled); on a clock the test moves, a second preview in Guard's second is refused (`preview_rate_limited`, also for `place_order`, nothing sent), a second later it answers, after 61 s without a sync it refuses (`preview_view_stale`, nothing sent), and after a sync it answers again; no decision is journaled by any preview.
- Prompt-injection-shaped inputs: a coin name carrying instructions, a well-formed unknown coin, sizes such as `1e30`, `-5`, `NaN` and 1,000,000 BTC, numbers for strings, a stop given as prose; a veto and an event whose text tries to give instructions (it stays quoted and stripped; the bot's request with an attacker's address is left out).

No test touches a network, a key or a venue.

## Guard's contract: what was open, and how it is settled

All of it lives in `src/contract.rs`. Guard (`docs/guard.md`, "The public contract") settled the open questions on 6 Oct 2026:

1. **Preview.** Guard has `POST /guard/preview`: its real judgement (the same `judge` as `/exchange`) on an unsigned action, read-only, answering `verdict`, `code`, `text`, `changes`, `entry`, `pre`, `forward`, `post`, `mode` and `view_age_ms`; `entry` carries the requested and the forwarded size (`requested_size`, `size`), the worst price, the stop and the isolated leverage Guard would set. It judges from the background sync's last view of the account (at most 60 s old), at most once a second for all clients together, and journals, sends and consumes nothing; otherwise it answers `{"code", "error"}` (HTTP 200) with a stable code (`preview_rate_limited`, `preview_view_stale`, `malformed`), and a Guard without it HTTP 404. While recovery runs or the decision journal is broken, the preview is a veto with the code `journal` (`view_age_ms` null when refused before the view is looked at), as `/exchange` refuses then. `preview_order` shows that answer and `place_order` asks it before every entry (`contract::parse_preview`); this server no longer estimates. Kept for Guards from before the code only, and marked as a fallback in the code: their words for the two expected refusals ("previews a second", "no recent view of the account"), matched only when the answer has no `code`. This server still refuses an entry itself when Guard's status shows a broken decision journal, for a Guard from before the preview's `journal` veto.
2. **Kill switch.** Guard has `POST /guard/kill`, authenticated by a client signature (`sign::signed_kill_request`), from this machine only, pull only. `kill_switch` uses it whenever the server has a client key; `--kill-file` remains only for an older Guard without the endpoint (a 404) or a server without a key.
3. **Client keys for agents.** `zunder-guard client add --out FILE` writes a new client key into a new 0600 file and adds its address to `[auth] clients` (`init --client-key-out FILE` for the first one). A running Guard accepts it after a restart.
4. **The status schema.** Schema 1 as assumed: `risk.state` is a plain string (`active`, `halted_for_day`, `stopped`; the details under `risk.detail`), `rules` is the rules schema v1 code (no `requireStop`), and the status adds `equity_cap`, `assumptions` (fees, slippage, the entry price bound, stop and exit slippage, the default stop distance, the minimum order value), `alerts` and `kill_file`.
5. **Reply text.** Veto and paper replies carry `code` (and paper replies `verdict`) as fields beside the text; forwarded replies carry Guard's `code` and `verdict` too, so a resize is visible without reading fill sizes. SDKs ignore fields they do not know.
6. **Decisions by nonce.** `GET /guard/decision?nonce=N&client=0x…` reads the decision journal on disk, so a verdict no longer scrolls out of the 1,000-event buffer.
7. **`zunder-guard mcp`.** The Guard binary runs this server as a subcommand (`zunder-guard mcp …`, the same flags), so users install one program. Releases ship only `zunder-guard`; `zunder-guard-mcp` builds from source for those who want it alone.
8. **The event schema.** Guard's code is the schema (`schema: 1`, `seq`, `at_ms`, `kind`); `docs/guard.md`, "Events", documents that form.
9. **The expected mode.** Guard's `/exchange` takes `expectedMode` beside the signed fields and refuses another mode than its own (`mode_mismatch`) before anything else; its status lists `capabilities.exchange_expected_mode: true` (`docs/guard.md`, "The expected mode"). This server sends it on every request and sends no `/exchange` request to a Guard without the capability. `/guard/kill` takes it too (`capabilities.kill_expected_mode: true`); this server puts it on its kill request when Guard lists that.
