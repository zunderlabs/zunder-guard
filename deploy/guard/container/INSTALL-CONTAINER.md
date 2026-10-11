# Guided mainnet Docker installation

The released installer accepts:

```sh
curl -fsSL https://zunderlabs.com/i | sh -s -- --container --network mainnet
```

Run on Linux with systemd 250+, Python 3.11+, and local root Docker. The installer verifies
its signed release helpers and immutable image, handles the named volume and encryption,
and asks before mainnet activation. It does not install Docker or open a public port.
The website can append `--rules zr1_…` and `--account 0x…`; `--volume NAME` selects the home.
Do not add a private key to the command. Initial setup and encrypted service provisioning
ask for it with hidden terminal input. Initial setup displays the first client/pairing code
once. Temporary containers have Docker logging disabled so that code is not copied to logs.

Mainnet setup validates the configured API wallet and never saves its plaintext private key.
The Linux credential manager encrypts it for the service; systemd supplies it on stdin after
restart. The installer shows the account and equity cap and asks separately before creating
the first mainnet risk journal and starting. Guard remains at `http://127.0.0.1:8547`.
No bot is connected automatically.

An existing installation keeps its named volume, journals, client keys, configuration,
licence and supervisor identity. Rerun the command without rules/limit/licence options to
install a new verified version. Stop the bot when asked. The wrapper stops the service only
with your confirmation and asks for the configured API wallet again. It never uses `init
--force`, clears a halt or initializes a journal during an upgrade. Configuration or licence
changes use Guard's existing separate commands against the same home.

A durable systemd condition blocks activation during installation, including across a reboot
or the helper's intermediate service-enable step. Cancelling or failing leaves this condition
in place and preserves the data. Rerun the verified installer to continue the recorded
transaction. Do not delete its marker to bypass a failed check. An interrupted or adopted
home without a journal requires explicit journal recovery; its missing file is not treated
as permission to initialize one. The installer never automatically deletes a volume.

The independent setup guardian owns temporary containers by immutable ID and unique labels.
If the installer or Docker client dies, it stops/removes only that exact owned container.
If Docker is unreachable, cleanup stays pending and activation stays blocked until the daemon
returns and cleanup completes. Never remove the guardian while an installation is pending.

For an originally disabled service, activation starts it once while preserving disabled boot
state. Existing enabled installations retain boot recovery only after explicit successful
activation; a fresh install asks before enabling boot recovery. Check status, risk and expected
licence/fee mode before reconnecting the bot.

## Development verification

```sh
python3 -B deploy/guard/test/container-installer.py
python3 -B deploy/guard/test/container-supervisor.py
```

These tests use synthetic boundaries; they do not prove real released-image installation.
The additive `test/container-native/installer.py` fixture runs only in the marked disposable
QEMU guest. It checks nonroot fresh-volume writes, secret stdin, Docker log suppression,
wrapper/client SIGKILL cleanup and an actual reboot after enable while installation remains
inhibited. Its receipt explicitly labels this a synthetic subset, with official artifact,
venue role/licence and daemon-live-restore proofs still separate. It must be reviewed and run
before claiming this route is release-ready.

## Ownership, interrupted creates and approval state

The installer changes an existing reserved service only when its root-only managed-install
receipt matches the loaded systemd fragment, installed unit/helper hashes and configured
account/volume/image. An unrelated service using either reserved name is refused unchanged.
An older manual installation without this receipt needs a separately reviewed migration;
root ownership or the filename alone is not enough to adopt it.

A Docker create timeout can leave the daemon processing the original request. Such an
operation remains a durable unresolved-create record even when an inspection currently finds
nothing. The guardian continues reconciling it and removes a later exact-owned result. It
never treats an empty observation as permanent cleanup proof. If no result ever arrives,
setup stays blocked for explicit diagnostic recovery rather than discarding ownership.

A healthy running process is not necessarily ready for entries. Pay-per-order mode additionally
requires `fee.approval.state` to be `approved`. Otherwise the installer reports installed and
running with entries blocked, and directs the owner to https://zunderlabs.com/approve with the
main wallet on Hyperliquid Mainnet. Fee-free mode is reported only when Guard confirms it;
an explicitly expected licence never silently falls back to builder fees.

## Protected Testnet automation candidate

The additive Testnet path requires a newly signed release containing these helpers. Signed
v1.0.1 draft assets remain immutable. Offline tests below do not establish native release
readiness; signed-image installation, restart, reboot and venue journey evidence remain gates.

Download and verify the exact release loader as usual, then invoke the saved loader from an
unattended controller with these public arguments:

```sh
sh i --container --network testnet --non-interactive --key-stdin \
  --account 0xYOUR_TESTNET_ACCOUNT --rules zr1_YOUR_RULES --equity-cap 100
```

The controller supplies two LF-terminated API wallet key frames on a private stdin pipe for a
fresh installation. The first validates the Testnet API-wallet role and records only its public
address; the second provisions the encrypted systemd credential. No private key belongs in
arguments, environment variables, files or logs. A reinstall consumes only the provisioning
frame; inspect the owned transaction before choosing the frame count. Pairing output is private
controller output and must not be uploaded as public CI logs.

Testnet defaults to the distinct `zunder-guard-testnet-data` volume. The supervisor and managed
installation receipts bind the sending network; a Mainnet installation, pending transaction or
unowned existing volume cannot be adopted by this route. This host supervisor supports one
managed network at a time. Mainnet retains its existing interactive confirmations.

Fresh Testnet init creates its risk journal once. Unattended activation checks matching network,
account, active risk, a ready journal, no kill state and fee mode `off`; an explicitly supplied
licence must also be active. Reinstallation preserves configuration, pairings, journals and
risk stops. Missing or halted state is refused; no automatic journal reset or risk resume exists.
The same durable activation gate, encrypted credentials, root ownership checks and independent
owned-container guardian apply to Testnet. Failure leaves activation inhibited.
