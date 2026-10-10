# Hosted Linux Paper guest lifecycle

This workflow runs the signed Linux AMD64 release inside one disposable Ubuntu
guest on a free public GitHub Ubuntu runner. The original host job survives the
guest's actual kernel reboot. It never reboots the GitHub host or a working Mac.

## Acceptance

The candidate is v1.0.4, source `ddb3ce0b86cdfd094cfffd60dd8ea8073f20d844`,
original successful release run `38006057745`, attempt 1. Immutable Actions
artifact IDs `11651844192` and `11651714491` supply all 27 pinned inputs. The
workflow verifies the Sigstore signature of SHA256SUMS and SLSA provenance of
all 24 subjects, including both loader and installer, before either executes.
There is no draft-release download, floating candidate or stale-byte fallback.

The fixed observer then runs the unchanged shipped `i` and `install.sh`:

1. Fresh Paper setup; actual account, version, two clients, loopback health,
   installed binary hash, service UID and shipped systemd protections.
2. Systemd restart and actual main-process SIGKILL recovery, with new process
   identities. The service's own restart policy handles recovery.
3. A fresh operator halt, followed by stop and same-version signed reinstall.
   Configuration, Paper journal prefix and halt bytes must remain unchanged.
   The halt is never cleared, and risk review/resume is never called.
4. Actual guest kernel reboot. The same original QEMU PID, kernel birth and
   cgroup survive; the guest boot ID changes. The enabled shipped service must
   answer with its original halted Paper state and preserved journal prefix.
5. Stop and listener absence; removal of the installed binary with state first
   retained; then removal of only the fresh owned guest unit/drop-in, state,
   notices, config directory and service user. The original host confirms its
   QEMU process and descendants are gone before removing its owned disk stage.

The source observer autostarts after cloud-init. No interactive login or SSH is
used. This does not prove a first-login credential branch: Paper has no external
API-wallet encrypted credential, owner/merchant material or licence acceptance.
The shipped installer creates only disposable Paper client-pairing material;
no pairing bytes, raw logs, status-client contents or command output are uploaded.
The receipt explicitly leaves `privateNativeAcceptance` and `releaseReady` false.
Testnet whole-journey, native private-key protection and other-platform acceptance
remain separate. A new signed v1.0.5 requires a reviewed inventory successor;
v1.0.4 success cannot stand in for changed v1.0.5 bytes.

## Authentication and control

Canonical's dated Noble `release-20260911` cloud image, external kernel and
initrd have fixed SHA256 values. Both checksum files and detached signatures
are pinned; GPG verifies the official image signing fingerprint before the
corresponding downloads are admitted. No guest package update/install occurs.
Cloud-init mounts a read-only source/candidate ISO and starts the fixed observer.
The observer checks root, AMD64, systemd PID 1, virtualization, exact source,
original kernel command-line challenge and root-owned original marker.

The public channel is a virtio-serial port on an owned QEMU Unix socket. The host
checks `SO_PEERCRED` against its actual QEMU PID/root UID, plus exact executable,
argv, kernel birth, unit and cgroup. One fresh challenge and original source/run/
attempt bind every phase. Only `exercise`, `reboot`, `after-reboot`, and `remove`
exist. No generic command server, SSH identity, TOFU, saved-receipt adoption,
guest reboot retry or automatic resume is present. Guest sequence starts at zero
on each observed kernel boot; the original host authority/challenge never renews.
QMP's ordinary vendor JSON is parsed separately from the strict canonical public
guest frames. QMP must report KVM present and enabled; TCG fallback is absent.

## Public vendor runtime and bounds

The hosted image does not currently contain QEMU. A separate fixed preparation
step uses only the official Ubuntu snapshot `20260911T000000Z`, exact three
signed InRelease byte pins, Ubuntu archive keyring and isolated APT source/list/
cache paths. The shared fixed archive keyring is read with O_NOFOLLOW, root
ownership, one link, exact length and stable descriptor/path identity. Only the
independently obtained 3,607-byte vendor SHA256 is admitted, even if the hosted
file has writable mode bits. Verified bytes are copied once into the owned root
0700 stage as a create-only 0600 file; Signed-By names only that copy. The shared
file is never chmodded. A mismatch, race or short write refuses without fetching
a replacement or retrying. Package provenance pins document the source of the
public key bytes; package scripts are not used to obtain the key. APT authenticates Release → Packages → package bytes. The fixed six
package names include QEMU, cloud-image-utils, genisoimage, gpgv and image keyring.
Default repositories/config hooks, unsigned/insecure fallback, forced downgrade,
guest apt, PPAs and unrelated daemons are absent. Packages and their OS dependency
closure are the explicit Ubuntu vendor trust boundary; no invented upstream
binary or dyld hash is claimed. The host separately checks root-owned selected
tool paths and hashes their actual bytes in the receipt. The preexisting GitHub
kernel, Python, systemd, OpenSSL, libc, firmware and network are platform/vendor
TCB. This source packet has not admitted or executed that actual selected runtime.

Preparation has an outer 10-minute timeout; guest control has an original
2,320-second UTC/monotonic limit beginning before image downloads, plus bounded
cleanup inside an outer 40-minute timeout. No clock is extended on reboot. The
QEMU unit's kernel-enforced memory/CPU/task limits are read back: 5 GiB / at most
two CPUs / 64 tasks. The guest has two vCPUs, 4 GiB RAM and a fresh 14 GiB overlay.
A remaining-time `RuntimeMaxSec` with a conservative 30-second startup margin,
control-group kill, no new privileges
and zero core dumps are checked. The unit remains bounded if the Python parent
is interrupted. Failed or missing cleanup cannot produce complete acceptance.
The workflow job itself is bounded to 60 minutes and uses no OIDC, repository
write permission, AWS/local CI host, paid runner, secret or private credential.
The read-only GitHub token is used only for immutable public artifact acquisition;
all privileged preparation/runtime children receive a fixed credential-free env.

## Evidence limits and next action

The public KVM capability run `38018115513` proved an empty VM context on the
free AMD64 runner. It did not boot this guest. This packet is source preparation
only. Review its frozen source and inert fixtures before registration/dispatch.
The actual run must pass signature/provenance, snapshot authentication, runtime
admission, lifecycle, changed boot, preserved state and confirmed cleanup. Failure
is incomplete, not a waiver or proof of unsupported hardware. Receipt stage names
are fixed and public; full guest logs and disks are deleted and never uploaded.

## Primary references

- [Canonical image verification](https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/)
- [Ubuntu Noble archive keyring vendor package](https://packages.ubuntu.com/noble/all/ubuntu-keyring/download)
- [Ubuntu snapshot service](https://ubuntu.com/server/docs/how-to/software/snapshot-service/)
- [Ubuntu archive authentication](https://documentation.ubuntu.com/security/software-integrity/archive-verification/)
- [QEMU character devices and options](https://www.qemu.org/docs/master/system/qemu-manpage.html)
- [QMP KVM query](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html)

`test_public_guest.py` uses only temporary public files and mocked syscalls,
processes and sockets. It never runs a candidate, package manager, service,
virtualization helper, guest, elevated command, private protocol or provider.

The shared vendor input is untrusted public data. Root-owned directory shape
and a stable no-follow bounded descriptor are checked; vendor-data parent
writability is not used as authentication. Executable/runtime ancestors `/usr`
and `/` must remain root-owned directories without group/other write access. Only the exact independently pinned vendor digest
is admitted. Owned staging remains root0700 with a create-only root0600 copy,
and the signed snapshot and package chain remain mandatory. The shared input
and its parents are never modified.

## Postboot ordering correction

Actual run38024073354 passed signed paper install, explicit restart, owned crash recovery, reinstall/state preservation and acknowledged the single guest reboot. It failed while waiting for the new kernel hello; owned QEMU cleanup was confirmed. No full reboot acceptance is claimed.

The observer had After=cloud-final.service while being WantedBy=multi-user.target. The canonical cloud-final service is ordered After=multi-user.target, creating an ordering cycle on normal subsequent boot. The original first boot started the observer from cloud-final runcmd after enable, which does not establish correct subsequent boot ordering. The observer is now enabled under cloud-init.target and remains after cloud-final.service. Guard's shipped service, actual changed-boot proof, same QEMU identity, original clocks and refusal/cleanup rules are unchanged. This is a source-based diagnosis awaiting actual hosted execution.
