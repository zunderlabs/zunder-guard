# Mainnet container supervised by Linux systemd

Install the verified release and immutable Guard image with the guided installer:

```sh
curl -fsSL https://zunderlabs.com/i | sh -s -- --container --network mainnet
```

Use native Linux with systemd 250+, Python 3.11+, administrator access and a local rootful
Docker Engine. Docker Desktop, remote Docker daemons and Docker contexts are not supported.
The installer does not install Docker or open a public port. Guard is exposed only at
`http://127.0.0.1:8547` on the host.

The installer verifies its signed helper assets and image, prepares a fresh named volume
with your explicit consent, or preserves the existing managed installation. It asks for the
mainnet account, separate confirmation, equity cap and API wallet key through hidden input.
The initial Guard setup prints the first bot client key and pairing code once. Save those in
your bot's secret storage; setup containers use `--log-driver=none`.

Before activation, setup asks you to type `START` with the exact account, provide an
attributable note for a genuinely new mainnet risk journal, and type `ACTIVATE` to commit the
start and boot choice. These are prompts within the installer. Cancelling leaves the service
stopped and boot activation inhibited; rerun the verified installer to continue. A missing
journal on an adopted or interrupted installation requires explicit recovery, not automatic
initialization. Setup never connects a bot, clears a halt or submits an order.

See [the complete guided installation and recovery contract](INSTALL-CONTAINER.md) for
supported options, account and volume ownership checks, interrupted setup, approval status
and the native verification procedure. Do not install individual helper files manually:
the installer admits and installs the complete signed helper set together.

## Credentials and restarts

The API wallet credential is encrypted by `systemd-creds` on the host. After each
`ExecStart`, the fixed supervisor opens the protected systemd credential and supplies its
file descriptor as standard input to Docker and Guard. No private key is placed in an
argument, environment variable, volume or plaintext credential file. Host and container
core dumps are disabled.

Systemd owns the long-running container and retries failures at ten-second intervals until
an explicit stop. Docker's own restart policy is disabled. Cleanup admits only a container's
immutable ID with matching ownership, image and volume. An unrelated container blocks
startup instead of being removed. The independent setup guardian also reconciles delayed
container creation after client failure; leave it installed while setup cleanup is pending.

## Upgrade, verify and remove

Stop your bot before upgrading. Rerun the verified installer without new rules, limits or
licence options, retaining the same account and volume. It requests confirmation before
stopping the service and asks for the configured API wallet again. Activation remains
inhibited through staging, failures and reboot until the explicit start choice succeeds.
It preserves configuration, client identities, licence and journals; never use `init --force`
or replace the volume as an upgrade.

After starting, verify health and status before reconnecting the bot:

```sh
curl -fsS http://127.0.0.1:8547/healthz
curl -fsS http://127.0.0.1:8547/guard/status
```

Confirm the expected mainnet account, risk state, journal readiness and fee mode. A flat
licence must report `fee.mode` as `fee_free`. Pay-per-order entries require
`fee.approval.state` to be `approved`; if not, follow the installer link to
<https://zunderlabs.com/approve> using that account's main wallet on Hyperliquid Mainnet.
A running service alone is not proof that entries are ready.

To stop and retire the runtime supervisor:

```sh
sudo systemctl stop zunder-guard-container.service
sudo systemctl disable zunder-guard-container.service
```

Keep the named volume and journals for recovery. Credential and volume deletion are separate
explicit decisions; never start two Guards against the same journal. Do not remove the setup
guardian while an installation or cleanup operation remains unresolved.

## Development verification

The guided protected installer accepts explicit Testnet as well as Mainnet.
Interactive Testnet setup uses Guard's hidden key check with no user-store write;
the service supervisor separately encrypts the credential with systemd-creds.
An explicit equity cap is required and is prompted when absent. Unattended Testnet
keeps the paired private stdin flags; Mainnet keeps interactive consent.
Testnet needs no paid licence. An explicitly supplied licence is validated and
preserved, and an invalid licence refuses setup. Disposable staging checkout keys
cannot activate the official signed Guard; genuine paid activation has its own
release evidence lane.

```sh
python3 -B deploy/guard/test/container-installer.py
python3 -B deploy/guard/test/container-supervisor.py
```

Synthetic tests are not native lifecycle evidence. The disposable Linux systemd/Docker
harness must separately demonstrate encrypted credential delivery, client/process failure,
daemon recovery and actual host reboot. Record verified release artifact and native results
before declaring the release ready; retain pending checks honestly. See
[INSTALL-CONTAINER.md](INSTALL-CONTAINER.md) for the synthetic subset's scope and limitations.
