# Zunder Guard: distribution

How a user gets Guard onto their own machine in one step, how they can check that what they run
is what we built, and what it talks to.

| Path | What it is |
|---|---|
| `loader/i.sh` | The loader served at `zunderlabs.com/i` (37 lines, POSIX sh) |
| `loader/i.ps1` | The Windows installer served at `zunderlabs.com/i.ps1` (PowerShell 5.1 and 7) |
| `install.sh` | The guided installer the loader runs |
| `Dockerfile`, `Dockerfile.dockerignore`, `compose.yaml` | Image (static, distroless, non-root, two architectures) and Compose |
| `systemd/zunder-guard.service` | The hardened unit for servers |
| `templates/` | AWS (`cloudformation.yaml`); other provider templates are deferred |
| `github/workflows/` | `release.yml`, `publish.yml`, `ci.yml` for `github.com/zunderlabs/zunder-guard` (kept outside `.github/`, so nothing runs here) |
| `github/build-release.sh`, `packaging/` | Reproducible builds and archives; the Homebrew formula's template |
| `rules/` | Rules schema v1: Rust crate `zunder-guard-rules`, `zr1.ts`, `schema-v1.json`, `vectors.json` |
| `test/` | Every test, run on the Linux build host |

## Install paths

The website preselects **mainnet setup**, with paper and testnet available. Mainnet setup
requires local account confirmation, an equity cap, a protected credential and an explicit
journal/start decision; installing does not start trading. AWS bootstraps in paper mode.
All paths bind to **127.0.0.1:8547** and keep API wallet keys out of URLs, templates,
command arguments and environment variables.

### 1. One SSH command (the default)

The website generates, with the user's rules filled in:

```sh
ssh -t you@server "curl -fsSL https://zunderlabs.com/i | sh -s -- --network mainnet --rules zr1_…"
```

`-t` gives the setup a terminal. On the server the loader checks the installer's signature,
then the installer checks the release and walks through the setup:

1. shows the rules decoded from `--rules` and asks "Keep these? [Y/edit]"; "edit" asks for each
   value with its bounds and refuses anything outside them;
2. asks for the Hyperliquid account address;
3. asks for the mode when no `--network` is supplied (paper is the CLI default). Mainnet
   always requires the account address again as a separate confirmation;
4. for testnet or mainnet, asks for the API wallet key with hidden input (`stty -echo`). It is
   never echoed, never in shell history (it is read, not typed into a command), never on a
   command line (`printf` is a shell builtin, so not in `ps`), never in the environment;
5. pipes the key on standard input to `zunder-guard key check` and then to `systemd-creds`;
6. installs the hardened systemd unit; a fresh mainnet setup without a journal stays stopped
   and prints journal/start commands. Reconfiguration with an existing mainnet journal can
   restart the service; keep bots stopped. Paper/testnet starts after setup;
7. prints the client key for the bot (once), the pairing code and the next step.

Steps 1 to 3 are the binary's own prompts (`zunder-guard init --interactive`): the binary owns
the questions, so the same flow runs in Docker and Homebrew. The shell only gathers the
key itself, because it stores the key with `systemd-creds`, and pipes it.

Without a terminal (`ssh` without `-t`, cloud-init, CI) the installer refuses, unless
`--non-interactive` is given with every value: `--rules`, `--network`, and for testnet or mainnet
`--account` and `--key-file` (a file the installer reads; mainnet also `--confirm-mainnet` with
the same account and `--equity-cap`). Other options: `--listen` (warns unless loopback), `--ip-share S` (this
Guard's part of the IP address's request weight: `1/N` for N Guards on one machine), `--prefix`,
`--no-service`,
`--force` (replace a configuration; the journal is kept). Running the one-liner again
reconfigures: Guard asks before replacing its configuration.

### Upgrade without reconfiguring

Stop your bot and Guard first. Run the new release's verified loader with
`--install-only`, retaining the existing binary directory (`--prefix DIR` if customized):

```sh
curl -fsSL https://zunderlabs.com/i | sh -s -- --install-only
```

This verifies the signed archive and replaces only the binary and distribution notices. It
needs no setup terminal, key or setup values (sudo may still require authentication); setup flags including `--force` are refused. It does
not run `init`, change the systemd unit or credentials, reset journals, or restart Guard.
Keep the existing config, licence, renewal settings and client pairings. Restart Guard
explicitly using the same service or foreground command, check its version, health, network,
account and fee mode before restarting your bot. Review release notes for any required unit
or configuration migration: this option deliberately does not apply those changes. Use
Homebrew's upgrade command for a Homebrew installation, not this installer.

Without root the installer uses `sudo` for the service; without either it installs to
`~/.local/bin`, lets the binary ask for the key and store it its own way, and prints how to
start Guard for paper/testnet. Mainnet requires its protected service path. macOS mainnet
uses the separately signed service installer, System Keychain and a system LaunchDaemon;
see [macOS setup](https://zunderlabs.com/docs/deploy/macos/).

**Read it first.** Anyone who prefers not to pipe a script into a shell:

```sh
curl -fsSLO https://zunderlabs.com/i     # the loader: 37 lines
less i                                   # read it
sh i --rules zr1_…                       # run it
```

Or skip the loader and verify by hand (needs cosign), which is what the loader does:

```sh
V=v1.0.2; R=https://github.com/zunderlabs/zunder-guard/releases/download/$V
curl -fsSLO "$R/install.sh" -O "$R/SHA256SUMS" -O "$R/SHA256SUMS.sigstore.json"
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/$V" \
  SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS && sh install.sh --rules zr1_…
```

#### The trust chain, honestly

- **The loader comes over TLS from `zunderlabs.com`.** Whoever controls that site (or its
  Cloudflare account) controls the 37 lines that run first. The loader is short so it can be
  read; it is published inside every signed release as the asset `i`, so anyone can compare the
  served copy with the signed one; and the manual path above skips it entirely.
- **The loader pins the release, the signer and cosign.** It holds the version, the signing
  identity (`release.yml` of `zunderlabs/zunder-guard` at exactly that tag, issued by GitHub's
  OIDC provider) and, for machines without cosign, cosign v3.1.3's download URL and SHA-256 per
  platform. It downloads `install.sh`, `SHA256SUMS` and the Sigstore bundle, verifies the
  bundle, checks `install.sh` against the signed checksums, and only then runs it. A mismatch
  stops it before anything else runs.
- **install.sh checks everything again**: the signature (same identity, its own version), the
  archive against the signed checksums, and only then extracts. It is safe to run on its own.
- **What a valid signature means**: the file was produced by our release workflow, at that tag,
  in our GitHub organisation, and recorded in Sigstore's public transparency log. It does not
  mean the code is free of bugs; that is what the readable source, the reproducible build and
  the provenance are for (below).
- **Residual trust**: GitHub (runs the workflow, hosts releases), Sigstore (Fulcio, Rekor and
  its TUF root), the TLS certificate of `zunderlabs.com`, and the pinned cosign binary.

### 2. Docker and Compose

```sh
docker run -it --rm --log-driver=none -v zunder-guard:/data ghcr.io/zunderlabs/zunder-guard:v1.0.2 init --interactive --rules zr1_…
docker run -it --rm --log-driver=none -v zunder-guard:/data ghcr.io/zunderlabs/zunder-guard:v1.0.2 pair
docker run -d --name zunder-guard --init --restart unless-stopped -v zunder-guard:/data \
  -e ZUNDER_GUARD_LISTEN=0.0.0.0:8547 -p 127.0.0.1:8547:8547 ghcr.io/zunderlabs/zunder-guard:v1.0.2
```

After a testnet `init`, add `-e ZUNDER_GUARD_NETWORK=testnet` to the last command: `run` sends
only where it is told to, and only when that is the mode `init` recorded, so a testnet setup
started without it refuses to start instead of running as paper. These Docker/Compose
commands are for paper/testnet. For mainnet on a native Linux host with systemd 250+, Python 3.11+ and a
local rootful Docker Engine, use the verified supervised installer:

```sh
curl -fsSL https://zunderlabs.com/i | sh -s -- --container --network mainnet
```

It supplies an encrypted systemd credential over stdin to an owned container, binds only
loopback, and leaves boot activation inhibited until explicit local activation and readiness
checks pass. Follow [Docker setup](https://zunderlabs.com/docs/deploy/docker/).

Or `compose.yaml` (`docker compose run --rm guard init --interactive --rules zr1_…`, then
`docker compose up -d`; after a testnet init, uncomment `ZUNDER_GUARD_NETWORK: testnet` first).
The image:

- static musl binary on `gcr.io/distroless/static-debian12:nonroot` (pinned by digest): no shell,
  no package manager, uid 65532, read-only root in Compose, all capabilities dropped;
- `linux/amd64` and `linux/arm64` from one Dockerfile (buildx);
- a healthcheck that runs the binary's own `health` (there is no curl in the image);
- **listens on 127.0.0.1 inside the container by default**, so even a careless
  `-p 8547:8547` reaches nothing. To reach it from the host, set
  `ZUNDER_GUARD_LISTEN=0.0.0.0:8547` and publish on `127.0.0.1:` as above and in Compose.
  Never publish without `127.0.0.1:`: Docker writes its own firewall rules and bypasses ufw;
- for testnet, `init --interactive` asks for the key with hidden input and stores it in the volume (0600,
  with a warning), or the Compose secret holds it in a 0600 file owned by uid 65532.

### 3. Homebrew, a plain archive

```sh
brew install zunderlabs/tap/zunder-guard     # macOS, Linux; then the caveats: init --interactive, brew services start
```

Homebrew checks the SHA-256 the release workflow wrote into the formula from the signed
release. The archives (`zunder-guard-<version>-<os>-<arch>.tar.gz`, Linux and macOS, amd64 and
arm64) verify by hand as in path 1. `brew services` runs paper mode; a testnet setup runs with
`zunder-guard run --network testnet` (the caveats say so).

### 3a. Windows

On native x64 Windows, open an elevated interactive Windows PowerShell 5.1 or PowerShell 7:

```powershell
& ([scriptblock]::Create((irm https://zunderlabs.com/i.ps1))) -Network mainnet
```

The loader verifies the signed archive and machine-service helper before installation.
The managed service uses a virtual service account, machine-protected credential with
restricted ACLs, and a broker that passes the key to Guard over stdin. Setup leaves the
service stopped; use its printed commands for licence or builder approval, explicit journal
initialization when needed, and activation. Interrupted setup and upgrades remain disabled
until explicitly recovered. Existing journals and halts are preserved.

For a separate per-user paper/testnet installation, run without administrator rights and
select `-Network paper` or `-Network testnet`. The binary goes to
`%LOCALAPPDATA%\Programs\zunder-guard`; testnet credentials use Windows Credential Manager.
`-InstallOnly` remains the per-user binary-only path, not a mainnet service upgrade.
See [Windows setup](https://zunderlabs.com/docs/deploy/windows/) for activation and management.
Winget publication remains deferred beyond 1.0.

### 4. AWS launch (the user's own account)

AWS is the only cloud template published for this release. Docker, SSH, and downloadable
binaries remain available. Other provider templates are deferred.

The website launch link opens AWS CloudFormation's quick-create review with Tokyo
(`ap-northeast-1`) selected and `param_Rules` / `param_Account` prefilled. Tokyo is a default,
not a restriction: the customer may change regions. AWS still requires sign-in, review of
costs and IAM resources, and its final Create stack confirmation.

`templates/cloudformation.yaml` creates one ARM instance in its own VPC and subnet, with
no inbound access by default and Session Manager access through `ConsoleShell`. Installation
starts in paper mode using only a public account address and rules; no trading key or licence
belongs in the launch URL or template. The release renderer pins the loader URL and checksum.
CloudFormation reports success only after installation, service and local health checks pass.
Optional public access is restricted to one valid IPv4 /32 address. Installer output is
captured in a root-only temporary file, removed on success, so client keys and pairing codes
never enter cloud-init logs. On failure the console reports only the diagnostic file path.
Use `PairPaper` to pair the running paper setup. `NextStep` points to
[separate native activation](systemd/ACTIVATION.md). Stop the paper service and its bot,
then explicitly select Testnet or Mainnet in a fresh service instance. The paper binary,
configuration, client identities and journals are preserved; the sending instance gets
its own identity, state and encrypted credential. There is no automatic Mainnet activation.

The encrypted, tagged state volume is retained when the instance terminates. Stack deletion
therefore needs an explicit follow-up volume deletion after any required backup to stop all
storage charges. Replacement does not automatically reattach that volume.

See [AWS publication setup](github/AWS-PUBLISH.md) for the restricted OIDC publisher and
signed, versioned S3 URL. The website launch control stays gated until the actual installer,
AWS deployment, and customer licence journey have been verified.

### 5. systemd on a server

`systemd/zunder-guard.service`, installed by `install.sh`: a dedicated `zunder-guard` user,
`StateDirectory=/var/lib/zunder-guard` (0700), no capabilities, `ProtectSystem=strict`,
`PrivateUsers`, `MemoryDenyWriteExecute`, a system-call filter, only AF_INET/AF_INET6/AF_UNIX,
no core dumps (`LimitCORE=0`, as the testnet runner). `systemd-analyze security` rates it 1.1
("OK"; the testnet runner's unit has no `SystemCallFilter`, `PrivateUsers` or
`RestrictAddressFamilies`). The installer adds a drop-in, `zunder-guard.service.d/10-install.conf`,
which names the network and, for testnet or mainnet, loads the key as a credential and hands it
to the binary on standard input:

```ini
[Service]
Environment=ZUNDER_GUARD_NETWORK=testnet
LoadCredentialEncrypted=hl-api-wallet-key:/etc/credstore.encrypted/zunder-guard.hl-api-wallet-key
ExecStart=
ExecStart=/bin/sh -c 'exec /usr/local/bin/zunder-guard run --network testnet --key-stdin < "$$CREDENTIALS_DIRECTORY/hl-api-wallet-key"'
```

For mainnet it also loads `/etc/zunder-guard/mainnet-confirm.env` (`ZUNDER_MAINNET_CONFIRM`, the
account, which the user typed twice). Without that file Guard refuses to start on mainnet;
deleting it is how a person stops mainnet.

#### Mainnet under systemd: the key on standard input from an encrypted credential

Guard takes a mainnet key on standard input only: `run --network mainnet` refuses `--key-file`,
`ZUNDER_GUARD_KEY_FILE` and any key in the environment. Three ways a service could provide
standard input were weighed:

| Option | Key at rest | Restarts on its own | Verdict |
|---|---|---|---|
| **systemd-creds credential piped to standard input** (the drop-in above) | encrypted with the host key and TPM2; decrypted only into the unit's private in-memory credentials directory while it runs | yes | **chosen** |
| A one-shot unit a person starts with the key piped in (`systemd-run --pipe`, or `systemd-ask-password`) | nowhere | no: after a crash, a reboot or a venue outage at start-up, positions stay without Guard until a person types the key again | refused: an unattended Guard is the larger risk |
| A 0600 plain file read by `LoadCredential=` | in plain text on disk | yes | testnet only (with a warning); refused for mainnet |

For native Linux mainnet the installer **requires `systemd-creds`** (systemd 250 or newer) and refuses
before it asks for the key when it is missing (run Guard by hand with the key piped in, or
upgrade). The binary itself still sees only standard input: `sh -c 'exec … run --key-stdin <
"$CREDENTIALS_DIRECTORY/…"'` opens the decrypted credential as file descriptor 0 and replaces
itself with Guard, so the key is never in an argument, the environment or a log.

The mainnet risk journal is a person's start, as everywhere in Zunder: the installer sets
everything up and, when no mainnet journal exists, enables the unit without starting it.
Reconfiguring an existing mainnet installation with its journal can restart the service;
use `--install-only` for an upgrade that must not run setup or restart. A fresh setup prints
the two commands for when
the user is ready: `journal-init --mode mainnet` (with `ZUNDER_MAINNET_CONFIRM` naming the account,
as the `zunder-guard` user), then `systemctl start zunder-guard`. Non-interactive mainnet installs
need `--confirm-mainnet` and `--equity-cap` as well.

What the box tests cover (`test/installer_test.py`, `systemd`): paper running under the unit; a
key the venue does not know refused at the check with nothing stored; an encrypted credential
handed to the binary on standard input (the service reads it and the venue check refuses the fake
key, which proves the plumbing; the key in no log and nowhere on disk); mainnet refused without
`systemd-creds` before any key is read. A keyed install that succeeds needs a real API wallet key
and is checked by hand.

#### Where the key is stored on a server, and why

1. **`systemd-creds encrypt`** (systemd 250 or newer: Ubuntu 24.04, Debian 12 and later). The
   key is encrypted with the host key in `/var/lib/systemd/credential.secret` and, where the
   machine has one, the TPM2. systemd decrypts it only when starting the unit, into a private
   in-memory directory only the service can read. A copy of the disk or of
   `/etc/credstore.encrypted` without that host key (or without the TPM) is useless. Root on the
   running machine can still decrypt it, as root can read any process's memory.
2. **Fallback, older systemd (Ubuntu 22.04 has 249), testnet only**: a file
   `/etc/zunder-guard/hl-api-wallet-key`, mode 0600, owned by the `zunder-guard` user, loaded with
   `LoadCredential=`. The installer says so with a warning. Root, and anyone with a copy of the
   disk, can read it. Mainnet refuses this fallback (above).

Either way the key is an API wallet that can trade but cannot withdraw, on an account holding
only what the user is willing to risk (go-to-market plan, 5a).

## How verification works

Every release (`github/workflows/release.yml`, on a tag `vX.Y.Z`):

- **Reproducible builds.** The toolchain is pinned (`rust-toolchain.toml`, and the builder image
  by digest), dependencies by `Cargo.lock` (`--locked`), build paths are remapped, symbols
  stripped. Linux binaries are built in the Dockerfile's pinned build stage; a second job
  rebuilds them on fresh runners and the release stops if one byte differs. Archives are packed
  deterministically (`packaging/package.sh`: fixed order, owners and times, `gzip -n`).
- **Checksums**: `SHA256SUMS` lists every asset: archives (each with `LICENSE`, `NOTICE` and
  `THIRD_PARTY_LICENSES.md`), `install.sh`, the loaders `i` and `i.ps1`, SBOMs, the signed
  immutable image reference `zunder-guard-<version>.image.txt`, the Homebrew formula, and the
  deployment payloads (`compose.yaml`, `cloudformation.yaml`) with the image pinned to its
  immutable release digest and the AWS loader pinned to its release URL and checksum.
- **Sigstore keyless signing**: `SHA256SUMS.sigstore.json` is the cosign bundle for
  `SHA256SUMS`, signed with the workflow's own GitHub identity; no key exists that could leak.
  The workflow verifies its own signature the way the installer will before releasing.
- **SLSA provenance** (`slsa-github-generator`, level 3): `zunder-guard-<version>.intoto.jsonl`
  for every file in `SHA256SUMS`, and attached to the image.
- **SBOMs** (syft): SPDX and CycloneDX from `Cargo.lock`, and an SPDX attestation on the image.
- **Image**: pushed by digest to `ghcr.io/zunderlabs/zunder-guard`, signed with cosign, with the
  very Linux binaries of the release inside (`GUARD_SOURCE=prebuilt`; the box test checks the
  bytes are identical).
- **A draft, not a release.** The workflow stops at a draft; a person publishes it.

What a user can check:

```sh
# The release (as above)
cosign verify-blob --bundle SHA256SUMS.sigstore.json --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/v1.0.2 SHA256SUMS
# Provenance: built from this repository at this tag
slsa-verifier verify-artifact zunder-guard-v1.0.2-linux-amd64.tar.gz \
  --provenance-path zunder-guard-v1.0.2.intoto.jsonl --source-uri github.com/zunderlabs/zunder-guard --source-tag v1.0.2
# The image
cosign verify ghcr.io/zunderlabs/zunder-guard@sha256:<digest> --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/v1.0.2
slsa-verifier verify-image ghcr.io/zunderlabs/zunder-guard@sha256:<digest> \
  --source-uri github.com/zunderlabs/zunder-guard --source-tag v1.0.2
```

### Reproducing a release

```sh
git clone https://github.com/zunderlabs/zunder-guard && cd zunder-guard && git checkout v1.0.2
docker buildx build -f deploy/guard/Dockerfile --target bin-build --platform linux/amd64 -o out .
sha256sum out/zunder-guard     # equals zunder-guard inside zunder-guard-v1.0.2-linux-amd64.tar.gz
```

## Network footprint

**While installing**: `zunderlabs.com` (the loader), `github.com` and
`objects.githubusercontent.com` (release assets; cosign from `github.com/sigstore` if none is
installed), and cosign's trust root from `tuf-repo-cdn.sigstore.dev`. The Docker image comes
from `ghcr.io`. Nothing is sent about the user.

**While running**, Guard's market and order traffic connects to Hyperliquid:
`api.hyperliquid.xyz` (mainnet, and paper mode's prices) or `api.hyperliquid-testnet.xyz`, HTTPS
and WebSocket on port 443. It listens on 127.0.0.1:8547. No telemetry or relay is built.
Optional licence renewal is off by default:
`licence_auto_update = true` with a renewal token also contacts
`zunderlabs.com/api/licence/renewal` over HTTPS, from 14 days before expiry, at most every
6 hours. Licence verification itself stays offline. To see the connections for yourself:

```sh
sudo ss -tnp | grep zunder-guard     # every open connection of the process
```

To enforce it, allow the service user DNS and HTTPS and nothing else (nftables; on ufw hosts
put the same rules in `/etc/ufw/before.rules`):

```sh
sudo nft add table inet guard
sudo nft add chain inet guard out '{ type filter hook output priority 0; }'
sudo nft add rule inet guard out meta skuid zunder-guard udp dport 53 accept
sudo nft add rule inet guard out meta skuid zunder-guard tcp dport '{ 53, 443 }' accept
sudo nft add rule inet guard out meta skuid zunder-guard oif lo accept
sudo nft add rule inet guard out meta skuid zunder-guard counter drop
```

This restricts ports, not names: Hyperliquid sits behind a CDN whose addresses change, so a
rule by address would need refreshing. Who it talks to on 443 is what `ss` shows.

## The CLI contract the packaging relies on

What the real binary implements (`docs/guard.md`, "The command line", is the reference; each
item is used by a file here). The flags the packaging needs have environment variables, so a
container without a shell can be configured.

| Command | Does | Used by |
|---|---|---|
| `zunder-guard --version` | Prints `zunder-guard <version>` | everything (the release still refuses the old stub's marker) |
| `init --interactive [--rules R] [--account A] [--no-key] [--force]` | Prompts on the terminal: rules (keep or edit, bounds-checked), account, mode (paper default), then the key with hidden input unless `--no-key` or paper. Testnet stores it through systemd-creds or a 0600 file on Unix, or Windows Credential Manager on Windows. Mainnet validates the API wallet without storing a plaintext key. Managed services use protected Linux systemd credentials, macOS System Keychain or the Windows machine broker; each start retains account consent and credential handoff. Direct Unix foreground starts require the key on stdin. | install.sh, i.ps1, Docker, Homebrew |
| `init --non-interactive --rules R --network N [--account A] [--account-network testnet\|mainnet] [--confirm-mainnet A] [--equity-cap USDC] [--key-stdin \| --no-key] [--listen L] [--ip-share S] [--key-store auto\|file\|systemd-creds] [--client-key-out F] [--force]` | The same without prompts; refuses anything missing. Paper reads the account of `--account-network` (default mainnet). Writes the config with `mode`, starts the risk journal for paper and testnet (mainnet: `journal-init --mode mainnet` by a person) | install.sh, AWS |
| `config get network\|account\|listen\|rules` | Prints one configured value | install.sh |
| `key check --key-stdin` | Reads the key from standard input, checks it is an API wallet approved by the configured account on the configured network; prints the wallet address, never the key | install.sh |
| `pair` | Creates a client key for a bot, prints it once with a pairing code; safe while `run` runs (the running Guard accepts it after a restart) | install.sh, Compose, Homebrew |
| `client add --out F` | A new client key written to a new 0600 file, never printed (for bots and the agent kit) | Compose, the agent kit |
| `client list [--listen L \| --url U]` | The config's client addresses, each marked when the running Guard does not accept it yet, and the ones it still accepts although revoked | docs |
| `client revoke ADDRESS [--listen L \| --url U]` | Removes a client address from the config; refuses an unknown address and the last client; always says to restart Guard (a running Guard accepts the client until then) | docs |
| `kill --reason R` | Writes the kill file; a running Guard opens nothing and flattens until a person removes it and restarts; warns when the running Guard watches another file | docs |
| `journal-init`, `journal-resume`, `journal-show --mode M` | The risk journal: start (a person's decision), resume after a drawdown review, print | docs |
| `mcp …` | The agent kit's MCP server over stdio (`docs/guard-mcp.md`), the same code as `zunder-guard-mcp` | agents |
| `run [--network N] [--listen L] [--ip-share S] [--key-stdin \| --key-file F] [--container]` | Runs Guard. `--network` must equal the configuration's mode (a testnet config never runs as paper by accident). On an empty home with `ZUNDER_GUARD_RULES` and `ZUNDER_GUARD_ACCOUNT` set it sets up paper mode non-interactively (sending modes need `init`). Mainnet needs `ZUNDER_MAINNET_CONFIRM` (the variable Zunder's runner uses; not `ZUNDER_GUARD_MAINNET_CONFIRM`) naming the account at every start, a risk journal started for mainnet, and the key on standard input only (no key file or key environment variable; the managed container supervisor supplies stdin). A key file group or others can write is refused; on bare metal one they can read too; in a container (`--container`, `ZUNDER_GUARD_CONTAINER`, or Docker's `/.dockerenv`) a read-only mount readable by others is accepted with a warning. Warns when not listening on loopback. Handles SIGTERM and SIGINT (also as PID 1) | systemd unit, image, templates |
| `health [--listen L \| --url U]` | Exit 0 if `GET /healthz` on the listen address answers 200 (`0.0.0.0` and `[::]` mean loopback) | image healthcheck, install.sh |
| `status [--listen L \| --url U] [--json]` | `GET /guard/status` for a person, one fact a line (mode, kill switch, risk state, equity, the fee and its approval, alerts), or the JSON as Guard answers it; exit 2 when no Guard answers | docs, quickstart |

Environment: `ZUNDER_GUARD_HOME` (default `~/.zunder-guard`; `/data` in the image,
`/var/lib/zunder-guard` under systemd), `ZUNDER_GUARD_RULES`, `ZUNDER_GUARD_NETWORK`,
`ZUNDER_GUARD_ACCOUNT`, `ZUNDER_GUARD_LISTEN` (default `127.0.0.1:8547`), `ZUNDER_GUARD_IP_SHARE`, `ZUNDER_GUARD_KEY_FILE`,
`ZUNDER_GUARD_CONTAINER`, and `ZUNDER_MAINNET_CONFIRM` for mainnet. Exit status 2 for a refusal,
with the reason on standard error.

## Rules schema v1

The same in the website, the docs and the CLI; this is the reconciled v1 (6 Oct 2026), which
supersedes earlier drafts. A rules string is `zr1_` followed by base64url (RFC 4648 §5, no
padding, canonical: no stray bits) of a JSON object, at most 4,096 characters in all.
`schema-v1.json` is the JSON Schema; `rules/src/lib.rs` (Rust, crate `zunder-guard-rules`) and
`rules/zr1.ts` (TypeScript, no dependencies) are the reference encoders and decoders;
`vectors.json` holds 11 valid and 53 invalid cases that both pass (the canonical strings were
computed by a third, independent Python implementation).

| Field | Default | Allowed (provisional) |
|---|---|---|
| `v` | (required) | 1 |
| `maxLeverage` | 5 | above 0, at most 10 |
| `maxLossAtStopPct` | 2 | above 0, at most 5 |
| `stopPolicy` | `"attach"` | `"attach"` (Guard attaches a stop and sizes from it), `"refuse"` |
| `defaultStopDistancePct` (optional) | 2 | above 0, at most 50: where the attached stop goes |
| `minLiqDistancePct` | 10 | 1 to 50 |
| `maxPositionPct` | 200 | above 0, at most 1000, and at most `maxLeverage` × 100 |
| `maxOpenRiskPct` | 6 | above 0, at most 20, and at least `maxLossAtStopPct` |
| `dailyLossStopPct` | 6 | above 0, at most 15 |
| `drawdownHaltPct` | 25 | above 0, at most 50 |
| `markets` | `["*"]` (every market of the main dex) | 1 to 32 unique entries: names `^[A-Za-z0-9@][A-Za-z0-9:/@._-]{0,31}$`, `dex:*` (`^[A-Za-z0-9]{1,30}:\*$`, every market of that HIP-3 dex) and `*`, which stands alone among main-dex names but may stand beside HIP-3 entries; no market beside its own dex's `dex:*`. A HIP-3 market (`dex:COIN`) is never covered by `*`. The two HIP-3 forms were refused by earlier v1 decoders, so codes written before decode unchanged. Guard itself reads at most two HIP-3 dexes. |

`requireStop` is gone: with either stop policy no entry is ever without a stop (the risk engine
sizes every entry from it), and a string that still carries `requireStop` is refused as an
unknown field. `…Pct` values are percent (2 means 2%), unlike Zunder's fractions;
`Rules::risk_limits()` converts. Numbers have at most four decimal places. Missing fields take
the default; unknown fields and out-of-bounds values are refused. The encoder always writes
every field, `defaultStopDistancePct` included, in the order above, numbers without trailing
zeros.

**The bounds are provisional.** Their source of truth is the Guard core's policy configuration
(`crates/zunder-guard-core`, being built); align `number_bounds()` in `lib.rs`, `NUMBER_BOUNDS`
in `zr1.ts`, `schema-v1.json` and the vectors to it once it lands (the tests keep the four
equal). Until then the risk-engine values are capped at `RiskLimits::aggressive()`, so no rules
string goes beyond what `zunder-risk` allows. Their defaults are Guard core's own preset
(`Policy::guard_defaults()`), not read from `RiskLimits::default()`; tests pin both.

Checks, in order (the first failure is reported; codes are shared): length (`too_long`),
prefix (`prefix`), base64url (`base64`), UTF-8 and JSON (`json`), an object (`not_object`),
unknown fields (`unknown_field`), `v` equal to 1 (`version`); then each field in the order
above: its type (`type`), for `stopPolicy` its value (`stop_policy`), for numbers the range
(`out_of_range`, compared as IEEE doubles as browsers do) and then four decimals (`precision`);
then `markets` (`markets`) and the two cross-field rules (`open_risk_below_trade_risk`,
`position_above_leverage`).

## Release pipeline and publishing

`github/workflows/release.yml` (tag → draft release, image, provenance), `publish.yml` (a person
promotes the verified draft → Homebrew pull request, image `latest`), `ci.yml` (checks on every push). Actions are pinned by commit; `slsa-github-generator` by tag, as it
requires. Permissions are per job; nothing runs on `pull_request_target`. Linux and both macOS
architectures build and install natively; Windows uses MSVC. Publishing requires successful
completed CI and release runs for the tag commit, every signed asset, and a verified immutable
image digest covered by `SHA256SUMS`, and complete identified maintainer-attested native
observations bound to those exact assets. Use `github/promote-release.sh` before a draft
becomes public; downstream publishing repeats the same full gate. Draft rehearsal uses
`github/verify-release-assets.sh`, which does not authorize publication. See
[Native readiness and promotion](github/NATIVE-READINESS.md). Prereleases do not promote
packages or `latest`. Homebrew and AWS additionally require their own exact public-entrypoint
attestations before their publisher jobs acquire write credentials; native service evidence
alone does not establish those channels.

## Testing

The tests run on a Linux machine with Docker: `test/box-setup.sh` installs what they need once
(Docker, buildx, QEMU, shellcheck, Ruby, pexpect, on Ubuntu), `test/all.sh` runs them.

- `release-policy.py`: publication gate regressions with fake GitHub/cosign and real checksum
  checks; incomplete runs, wrong sources, unsigned or mutable image references, missing assets
  and bad signatures must refuse. Real OIDC/signature/native gates run on the first tag.
- `rules.sh`: the rules crate and Guard (fmt, clippy, tests); `zr1.ts` under `tsc --strict`
  and `node --test` in a pinned Node image.
- `lint.sh`: shellcheck (scripts, the one-liner and the read-first form), actionlint,
  hadolint, `systemd-analyze verify`, three-region CloudFormation validation, winget schemas,
  Ruby's syntax check of the formula and Compose. Deferred provider files are checked only
  when their source files are present;
  `i.ps1` and its Windows test parsed by PowerShell, ASCII only, PSScriptAnalyzer clean, and
  refusing on Linux without closing the shell.
- `windows-cross.sh`: Guard's crates cross-compiled for `x86_64-pc-windows-gnu` (MinGW-w64):
  clippy `-D warnings` on the Windows code paths and a release build of `zunder-guard.exe`.
  Windows binaries cannot run on the box; the public repository's CI runs the tests and
  `test/installer-windows.ps1` (per-user installs, tampering, invalid mainnet invocations refused) on `windows-2025`
  under Windows PowerShell 5.1 and PowerShell 7, and `release.yml`'s `install-smoke` runs
  `i.ps1` against every signed draft.
- `image.sh`: native and two-architecture builds, the smoke test (non-root, no shell,
  healthcheck, refusals, the 127.0.0.1 default), two builds without cache byte-identical (binary
  and every image blob), the prebuilt path holding the exact release binary, Compose on
  127.0.0.1 only.
- `installer.sh`: a fake release from the real binary through `package.sh` and `render.sh`;
  the loader and installer driven through a terminal in Ubuntu (dash) and Alpine (busybox) as a
  non-root user (guided paper; edit with bounds; testnet and mainnet with a hidden key that
  never appears on the terminal and that the venue check refuses, nothing written; mainnet
  confirmation and equity cap; no-terminal refusal; non-interactive; invalid rules; a changed
  archive, `SHA256SUMS`, `install.sh` or signer each refused before anything is installed); the
  real cosign download with its pinned hash; on the box itself the systemd path (paper running,
  listening on 127.0.0.1 only as `zunder-guard`; a refused key storing nothing; an encrypted
  credential reaching the binary on standard input; mainnet refused without `systemd-creds`;
  then removed); `docker run -it … init --interactive`. The binary reads public data of two
  public accounts in standard mode (one on mainnet, one on testnet) and sends nothing; a keyed
  install that succeeds needs a real API wallet key and is checked by hand.

A real Sigstore signature cannot be made without publishing to the public transparency log, so
the tests use `test/fake-cosign`, which accepts the test bundle only for the right identity and
the right file hash. The real cosign is exercised by the download test (it rejects the fake
bundle, as it must).

### Pins

Image digests (`rust:1.97.0-alpine3.22`, `distroless/static-debian12:nonroot`,
`node:24-alpine`), action commits, and cosign v3.1.3 with its SHA-256 per platform (in
`loader/i.sh`, `install.sh` and, for Windows, `loader/i.ps1`). `test/resolve-pins.sh` prints the current ones; bump them
deliberately, together with `rust-toolchain.toml` for the builder image (the Dockerfile refuses
a mismatch).

## Open questions

1. **The CLI contract**: `pair` prints the client key as `0x` followed by 64 hex digits.
   Mainnet uses `ZUNDER_MAINNET_CONFIRM` naming the account at every start. Native macOS and
   Windows MSVC builds and installer checks, native amd64 reproduction, and real keyless
   signing and provenance verification remain release gates.
2. **Rules bounds** are the Guard core's policy bounds (`crates/zunder-guard-core/src/policy.rs`,
   the `…_BOUNDS` constants), which the rules crate reads; `minLiqDistancePct` must exceed
   `defaultStopDistancePct` (`liq_not_beyond_stop`), so an attached stop always fires before
   liquidation. The `…Pct` names mean percent, against Zunder's fractions convention, because
   the schema's names were given.
3. **Platform secret files**: read-only mounts readable by others are accepted in a container
   with a warning; a key file others can write is refused everywhere (decided 6 Oct 2026).
4. **Keys from environment variables**: not offered. Allowing it means a
   key in a process environment, against the decision of 6 Oct 2026 for Zunder's own keys.
5. **macOS signing and notarisation**: binaries from `install.sh` are not quarantined (curl) and
   Homebrew's are fine, but a downloaded archive opened in Finder is blocked by Gatekeeper.
   Notarisation needs an Apple Developer account (99 USD a year).
6. **Architecture**: the Windows managed mainnet service requires native x64. Linux and macOS
   provide amd64 and arm64 builds; Linux on 32-bit ARM is not built.
7. **Licence**: Elastic License 2.0 (SPDX `Elastic-2.0`, decided 6 Oct 2026). The formula and the
   image label carry it; the public repository has the text verbatim in `LICENSE`.

### Private candidate image preparation

A private release candidate can use a separate root-only registry preparation phase. The normal public image route retains its signature verification and pull. The private route is explicit Testnet only, and requires the release controller to independently verify the exact signed manifest and SLSA source before invoking it.

Stage a canonical root-owned mode0700 directory containing only a mode0600 `config.json`: the sole permitted Docker field is `auths`, with only `ghcr.io` basic `auth`. Credential helpers, credential stores, other registries, linked files and shared writes are refused. The registry token is never a command argument or environment value.

```sh
sudo sh i --container --network testnet --prepare-image \
  --registry-auth-dir /root/private-candidate-registry \
  --source-commit VERIFIED_RELEASE_COMMIT
```

This phase reads no wallet key, verifies the OCI signature against the exact release tag, pulls the immutable signed image and records its local image ID and RepoDigest. It removes the admitted registry config and directory on success or artifact failure. Independently confirm that absence before retrieving any API-wallet frame. An authentication validation or scrub failure blocks wallet setup and requires inspection.

A successful phase leaves `/etc/zunder-guard-container-image-prepared/receipt.json`, root-owned mode0600 in a mode0700 directory. It is a preparation receipt, not release acceptance evidence. The following protected setup adds `--prepared-image --source-commit VERIFIED_RELEASE_COMMIT` to its existing explicit Testnet/account/rules/cap/share/stdin options. Both the signed installer and installed supervisor require the same manifest, source, exact image digest and immutable local image ID. They reject cache changes and never fall back to ambient registry credentials. Runtime Docker configuration remains empty.

Prepared receipts are retained for signed reinstalls/recovery of that exact candidate. A different source, manifest, image or pre-existing preparation requires separate inspection; no preparation receipt is silently replaced. The release controller disposes of its owned preparation receipt after native cleanup.
