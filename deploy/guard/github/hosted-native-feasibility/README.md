# Hosted native feasibility

Run only on standard free runners in the public `zunderlabs/zunder-guard` repository. This workflow has read-only contents permission, no OIDC, no secrets, no environment grants, no AWS access and no local-device dependency. It checks its actual immutable workflow source and fixed public file hashes before probing. Root reviews, registers and dispatches it; source preparation does not authorize execution or publication.

The five jobs use explicit Ubuntu24.04 AMD64/ARM64, Windows2025 AMD64, macOS15 ARM64 and macOS15 Intel labels. They record exact OS/architecture/image/runtime facts, available storage/tools, and native virtualization APIs. Mac jobs also record public FileVault/swap/core-limit status and counts of runner launchd plist filenames, without opening configurations or credentials. No package installation, guest image download, vCPU/memory mapping, guest boot, host reboot, credential storage, licence activation or trading operation occurs.

Linux opens `/dev/kvm`, requires API 12 before allocating one empty VM file descriptor, then closes it. The kernel specifies that this empty context has no vCPUs or memory. macOS queries Virtualization.framework and creates/destroys one empty Hypervisor.framework context using an owned temporary, ad-hoc signed probe; it does not use Apple signing credentials. Windows queries public CIM facts and WHP, creates/deletes one empty partition, and never enables Windows features. These observations measure context allocation only, not successful guest execution or unattended reboot.

Each job has a 12-minute hard limit; at most 2 run concurrently. Every child command is bounded and has no credential-bearing environment; Unix timeout cleanup kills only its owned process group. Mac's temporary probe executable is removed. Outputs are bounded public structured facts; only `capability.json` is uploaded, never home/config files or raw process/environment dumps. Runner OS/tools remain GitHub's vendor image TCB and their actual versions/hashes are recorded. Every action is pinned to its complete commit.

## Reusable source and architecture

| Route | Existing source | Reuse and remaining condition |
|---|---|---|
| Linux AMD64 systemd/Docker | `deploy/guard/test/container-native/vm.py`; `deploy/guard/e2e/native/run.py` | QEMU ownership, signed pinned Ubuntu image, loopback transport and changed real kernel boot IDs are useful. Existing `guest.py`/`installer.py` run synthetic binaries/images/licences; their PASS cannot qualify the real release. Replace the guest workload with unchanged real signed-v1.0.4 producers under the separately reviewed protected branch. |
| Linux ARM64 systemd/Docker | `native/run.py` supports ARM routes | Use a same-architecture ARM guest when measured KVM/tool/image support permits. Existing `vm.py` is AMD64-only and cannot establish ARM coverage. ARM image hash/firmware/packages remain an immutable input preparation task. |
| Windows AMD64 SCM | `native/windows.ps1`, production Windows service helpers | A LinuxAMD64 KVM guest or Windows WHP guest could persist a real Windows boot. Need measured accelerator, a legally usable exact signed Windows guest image, unattended setup/source closure, actual installed candidate and budget. This capability probe does not reboot Windows; a later disposable-host reboot would require a surviving controller and measured continuity. A new job is not reboot proof. |
| Mac ARM Keychain | `native/run.py`, launchd/Keychain production helpers | GitHub explicitly documents unsupported ARM nested virtualization. The API probe records actual capability, without treating support flags or a new job as a real native reboot. A second route reboots only the disposable GitHub Mac itself, with a separate surviving GitHub controller and a source-authenticated per-boot observer. That route remains unmeasured; unsupported nesting alone does not rule it out. See `HOSTED-MAC-REBOOT.md`. |
| Mac Intel | Existing signed-build/smoke route | Probe feasibility only. The user waived separate Intel native rehearsal; do not substitute Intel guest observations for ARM Keychain reboot proof. |

`candidate.json` pins the already verified v1.0.4 source, signed manifest, exact asset/binary hashes and immutable OCI image descriptor. It explicitly does not claim publication or actual execution. Capability jobs do not download the private draft, change a release gate or emit machine-native acceptance. The separate real signed producer must verify signature/attestation subjects and exact inventory before any native installation. Genuine licence retention, native protected credentials, source-bound reboot continuity, independent fresh venue observations and owned cleanup remain part of that separate branch.

## Official evidence

- [GitHub standard public runner labels and free use; ARM Mac restriction](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
- [GitHub nested virtualization is experimental and unsupported](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners).
- [Linux KVM API12 and empty VM descriptor](https://www.kernel.org/doc/html/latest/virt/kvm/api.html).
- [Microsoft WHvGetCapability](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvgetcapability) and [WHvCreatePartition](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcreatepartition).

## What the green workflow means

Only that the public probes completed and wrote observations. `release_ready`, `native_rehearsal`, `candidate_executed`, `guest_started`, `guest_rebooted` and `host_rebooted` stay false. Missing APIs/tools or refused context allocation remain reported as unavailable. A reported allocated context without confirmed closure fails the job after writing its public receipt. No native coverage waiver, risk change, mainnet permission or authenticity upgrade follows from these reports.
