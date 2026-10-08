# Zunder Guard

A self-hosted risk firewall between trading bots or AI agents and Hyperliquid. Your bot keeps
its code and points its Hyperliquid client at Guard instead of the venue. Guard speaks
Hyperliquid's own API, sizes or refuses every order against the limits you set (risk per
trade, open risk, daily loss stop, drawdown halt, leverage, distance to liquidation, markets, a
stop on every entry), re-signs what it allows with your API wallet key and sends it on.

- Guided installation offers mainnet setup with explicit local consent, or paper rehearsal
  (real prices, no orders). Guard listens on **127.0.0.1:8547** only.
- Market and order traffic goes directly to Hyperliquid. Optional licence renewal contacts
  zunderlabs.com; no telemetry.
- Your key stays on your machine; use an API wallet that can trade but cannot withdraw.

Documentation: <https://zunderlabs.com/docs>.

## Install

Binary installation requires a published, signed release. Check the
[releases page](https://github.com/zunderlabs/zunder-guard/releases) for availability.

Configure rules and choose an installation path at
[Connect](https://zunderlabs.com/connect#guard). The AWS template starts in paper mode,
defaults to Tokyo (`ap-northeast-1`), and supports changing the region. Cloud deployment
in v1.0 supports AWS; Docker Compose is also included.

On a Linux server, guided (rules from <https://zunderlabs.com>, then account, mode and key with
hidden input):

```sh
ssh -t you@server "curl -fsSL https://zunderlabs.com/i | sh -s -- --network mainnet --rules zr1_…"
```

The loader checks the release's Sigstore signature and checksums before it runs anything.
Read it first if you prefer: `curl -fsSLO https://zunderlabs.com/i && less i && sh i --rules zr1_…`.

Docker paper rehearsal (`linux/amd64`, `linux/arm64`):

```sh
docker run -it --rm --log-driver=none -v zunder-guard:/data ghcr.io/zunderlabs/zunder-guard:v1.0.1 init --interactive --network paper --rules zr1_…
docker run -d --name zunder-guard --init --restart unless-stopped -v zunder-guard:/data \
  -e ZUNDER_GUARD_LISTEN=0.0.0.0:8547 -p 127.0.0.1:8547:8547 ghcr.io/zunderlabs/zunder-guard:v1.0.1
```

After a testnet setup add `-e ZUNDER_GUARD_NETWORK=testnet`: Guard sends only where it is told
to, and only when that is the mode `init` recorded.

For mainnet containers on native Linux with systemd 250+, Python 3.11+ and a local rootful Docker Engine:

```sh
curl -fsSL https://zunderlabs.com/i | sh -s -- --container --network mainnet
```

Homebrew (macOS, Linux): `brew install zunderlabs/tap/zunder-guard`. Archives for Linux and
macOS (x86_64 and arm64), plus Windows x86_64, are on the
[releases page](https://github.com/zunderlabs/zunder-guard/releases).
Mainnet on Linux and macOS uses the separately verified protected service installer:
`curl -fsSL https://zunderlabs.com/i | sh -s -- --network mainnet`, including after Homebrew
installation. Homebrew's own service is for paper rehearsal.
macOS release rehearsals use Apple Silicon. Intel builds retain native CI tests and signed
installer smoke checks; a separate Intel service/reboot rehearsal is not part of release qualification.

On native x64 Windows, open an elevated interactive PowerShell terminal:

```powershell
& ([scriptblock]::Create((irm https://zunderlabs.com/i.ps1))) -Network mainnet
```

Mainnet installers verify the signed service helper, ask for separate account confirmation,
cap and hidden API wallet key, and leave the service stopped for explicit activation.
See the [Windows](https://zunderlabs.com/docs/deploy/windows/),
[macOS](https://zunderlabs.com/docs/deploy/macos/) and
[mainnet activation](https://zunderlabs.com/docs/start/go-live/) guides.
For a separate per-user paper/testnet installation, select that network without elevation.

AI agents: `zunder-guard mcp` is an MCP server with guarded trading tools (`docs/guard-mcp.md`).

## Verify a release

```sh
V=v1.0.1; R=https://github.com/zunderlabs/zunder-guard/releases/download/$V
curl -fsSLO "$R/SHA256SUMS" -O "$R/SHA256SUMS.sigstore.json" -O "$R/zunder-guard-$V-linux-amd64.tar.gz"
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/$V" \
  SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

Every release also carries SBOMs (SPDX and CycloneDX) and SLSA provenance; the image is signed
the same way. The Linux binaries are reproducible:

```sh
git checkout v1.0.1
docker buildx build -f deploy/guard/Dockerfile --target bin-build --platform linux/amd64 -o out .
sha256sum out/zunder-guard   # equals the binary in zunder-guard-v1.0.1-linux-amd64.tar.gz
```

## Build and test from source

```sh
cargo build --release --locked -p zunder-guard
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
```

The toolchain is pinned in `rust-toolchain.toml`.

| Path | What it is |
|---|---|
| `crates/zunder-guard` | The `zunder-guard` binary: setup, the local server, the risk journal |
| `crates/zunder-guard-core` | Decoding, authentication, the policy and judging of a bot's requests; no I/O |
| `crates/zunder-guard-mcp` | The MCP server behind `zunder-guard mcp` |
| `crates/zunder-risk` | The risk engine that sizes every entry and can veto anything |
| `crates/zunder-core`, `crates/zunder-venue` | Shared types; Hyperliquid addresses, networks, mainnet consent and transport, instrument rules, and the risk journal that Guard builds on |
| `deploy/guard/rules` | The `zr1_` rules code (Rust and TypeScript, shared test vectors) |
| `deploy/guard` | Loader, installer, image, systemd unit, deployment templates, release tooling |
| `tests/redteam` | A black-box red-team suite that attacks a running Guard |
| `docs/` | Guard's design (`guard.md`), the agent kit (`guard-mcp.md`), the red team (`redteam.md`) |

## Licence

Zunder Guard is **source-available** under the [Elastic License 2.0](LICENSE) (SPDX
`Elastic-2.0`). It is not open source. In short, and the licence text governs: you may use,
copy, modify and run it, but you may not offer it to others as a hosted or managed service, and
you may not move, change, disable or circumvent its licence key functionality.

On mainnet, official builds attach Orcastrate's Hyperliquid builder fee of 0.02% to the orders
Guard sends. You approve it once, in your own wallet, and can revoke it there at any time.
Without the required approval, new entries are refused; protective and reduce-only handling
continues as documented. Running without the fee needs a paid licence key, checked offline;
the fee and that check are licence key functionality (`NOTICE`). See
[licences](https://zunderlabs.com/licence) and the
[fee and licence documentation](https://zunderlabs.com/docs/concepts/builder-fees/).

Copyright 2026 Orcastrate UG (haftungsbeschränkt). Third-party components and their licences:
`THIRD_PARTY_LICENSES.md`.

## Security

Please report vulnerabilities privately; see `SECURITY.md`.
