# Activate a separate native Linux service

The AWS template bootstraps paper in `/var/lib/zunder-guard`. Preserve that home and
its client identities and journals. Sending modes use a fresh service instance;
there is no in-place conversion or automatic risk-halt reset.

Use this guide only with a published signed release that includes
`--service-instance`. Requirements: native Linux systemd 250+, `systemd-creds`,
`ss` from iproute2, root or sudo, and an interactive terminal (SSH with `-t` or
a Session Manager shell). Docker is not required.

## Before setup

Stop the paper bot, then stop its service:

```sh
sudo systemctl stop zunder-guard
```

Paper remains recoverable with `sudo systemctl start zunder-guard`. Leave its
config and journals intact. Do not resume any halted journal automatically.
The following commands use the release's pinned loader; it verifies the signed
installer and archives. Use the actual published release version, never a draft
asset URL or an old website loader. Run the command in the private terminal;
never put the API wallet key in an argument, template, URL or environment.

## Testnet

Use a Testnet account and a trade-only API wallet approved by that account.
Replace `zr1_…` and `0x…` with your explicit rules and account. The example cap
is 40 Testnet USDC; select a cap appropriate to that account. A licence is optional
for Testnet; an explicitly supplied `--licence zgl1_…` is validated normally.

```sh
curl -fsSL https://github.com/zunderlabs/zunder-guard/releases/download/v1.0.2/i |
  sh -s -- --service-instance testnet --network testnet \
    --rules zr1_… --account 0x… --equity-cap 40 \
    --listen 127.0.0.1:8548 --ip-share 1
```

The binary shows the rules. The installer checks hidden key input with the venue
before encrypting it with the host's systemd credential store. Testnet starts
only after setup succeeds. Check the printed service and health output, then
pair the bot with this instance's **new** client identity and endpoint:

```sh
/opt/zunder-guard-testnet/bin/zunder-guard health --listen 127.0.0.1:8548
sudo systemctl status zunder-guard-testnet
```

Paper's client identity never authorizes the sending instance. Stop it with
`sudo systemctl stop zunder-guard-testnet` before returning to paper.

## Mainnet

Use a Mainnet account and its own trade-only API wallet. The cap, rules and real
licence must describe that account. Replace the example cap deliberately. The
binary retains its explicit Mainnet account confirmation; this command grants
no consent by itself.

```sh
curl -fsSL https://github.com/zunderlabs/zunder-guard/releases/download/v1.0.2/i |
  sh -s -- --service-instance mainnet --network mainnet \
    --rules zr1_… --account 0x… --equity-cap 100 \
    --listen 127.0.0.1:8549 --ip-share 1 --licence zgl1_…
```

Setup preserves the encrypted credential and account confirmation in separate
paths and leaves a fresh Mainnet service **stopped**. Complete any licence or
builder approval using the instance's binary and home; read its actual status.
Only when ready to trade, use the installer's printed `journal-init --mode mainnet`
command with a meaningful operator note and then its `systemctl start` command.
Do not initialize a journal to clear a prior halt or reuse a paper/Testnet journal.

## Instance boundaries and retries

| Instance | User and unit | Home | Binary prefix | Encrypted credential |
|---|---|---|---|---|
| Paper bootstrap | `zunder-guard` | `/var/lib/zunder-guard` | `/usr/local/bin` | None |
| Testnet | `zunder-guard-testnet` | `/var/lib/zunder-guard-testnet` | `/opt/zunder-guard-testnet/bin` | `/etc/credstore.encrypted/zunder-guard-testnet.hl-api-wallet-key` |
| Mainnet | `zunder-guard-mainnet` | `/var/lib/zunder-guard-mainnet` | `/opt/zunder-guard-mainnet/bin` | `/etc/credstore.encrypted/zunder-guard-mainnet.hl-api-wallet-key` |

The named installer refuses an existing target home, unit, user, credential or
prefix. After a failed setup, inspect those paths and the diagnostic output;
do not retry with `--force`, delete state, or rerun journal initialization.
This is a first-install command, not an upgrade or cleanup command.

Each instance requires a distinct unused IPv4 loopback port other than 8547.
The examples assume only one Guard is running on this public IP. If multiple
Guards or other API consumers share it, allocate their IP shares explicitly
within the venue budget before starting them; for two equivalent Guards use
0.5 for each, including the existing paper configuration. Never start paper and
a sending instance both configured with the full share of 1.

The installer has focused offline refusal/path tests. These are not signed
native lifecycle or real customer activation evidence; the release gates must
exercise the actual official artifact and encrypted credential handoff.
