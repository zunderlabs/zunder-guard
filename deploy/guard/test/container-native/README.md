# Native synthetic container lifecycle gate

This is a real Linux kernel, systemd, systemd-creds and Docker lifecycle test, using a
synthetic process image with **no venue or order implementation**. The harness is prepared;
no native passing result is claimed until CI produces `evidence.json` with
`passed-native-synthetic-lifecycle` and distinct pre/post kernel boot IDs.

The `container-native` CI job installs VM tooling on an ephemeral Ubuntu runner and runs:

```sh
python3 -B deploy/guard/test/container-native/vm.py --output /path/to/redacted-evidence
```

It downloads a dated Ubuntu cloud image, validates Canonical's checksum signature with the
Ubuntu cloud-image keyring, and checks its pinned SHA-256. It boots that image with QEMU;
KVM is used when accessible, otherwise evidence identifies TCG emulation. Both paths use an
actual guest kernel, systemd and Docker. Only the guest's daemon is restarted; only the guest
is rebooted. The wrapper never invokes host Docker or reboots its host, and uses no paid
cloud resources or repository secrets. Temporary SSH credentials stay outside the output
artifact and are removed with the VM directory.

The guest requires a root-owned per-run marker plus QEMU/KVM identity before destructive
checks. **Do not run guest.py directly on any real/shared host.** A source archive containing
only this harness and supervisor is copied into the VM; no environment credentials follow.

The fixture image is pinned to a Python base digest. It accepts only a public synthetic
stdin key, reads fixed dummy account/config/journal/licence data, runs as UID 65532, records
only hashes and a start counter, and offers a local HTTP health endpoint. There is no API
wallet, mainnet request or trading path. Never interpret fixture `mainnet` or licence fields
as evidence of real Guard validation or a paid licence.

`driver.py` imports the **exact production supervisor source**. It changes only fixture
paths/names and image metadata admission for the locally built immutable image ID. Actual
runtime argv construction, fixed local Docker connection, stdin forwarding, cleanup checks,
locking and ExecStop/StopPost are unchanged. The installed fixture unit differs only in
names/paths from the production unit. No production skip-signature flag is added.

Checks include encrypted credential delivery, first start, child crash, Docker-client-only
SIGKILL, guest daemon restart, missing/stale/foreign cidfiles, foreign/reused name and wrong
volume refusal, a >75-second failure lasting beyond the former start-budget window,
recovery without reset-failed, same-version service reinstall/state preservation and an
**actual guest kernel reboot**. A restart or erased `/run` directory cannot pass the reboot
check. Indefinite retries remain rate-bounded by the production ten-second delay.

Outputs contain artifact hashes, synthetic public metadata, boot IDs and redacted status.
The harness checks the synthetic key is absent from service logs, Docker metadata, process
argv/environment and persisted supervisor state. It does not export raw credentials,
private SSH material, all guest files or a plaintext key.

Remaining separate gates: production signed-image/signature/provenance checks, actual Guard
first initialization and mainnet API-wallet admission, real licence activation/preservation,
and a real prior-version upgrade once such a release exists. The fake image gate does not
replace those checks.

Ubuntu verification reference:
https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/
