# Disposable hosted Mac reboot route

This is an unexecuted feasibility plan. It concerns only a disposable GitHub-hosted Mac VM, with a separate GitHub-hosted Linux controller. It does not authorize rebooting a working device, creating an AWS CI host, adding paid runners, or treating a new job as the same machine.

## What is established

GitHub documents provisioning a VM per hosted job and decommissioning it after the job finishes. Its runner service documentation describes launchd for self-hosted runners; it does not establish that the hosted Mac worker, current job or VM lease survives reboot. The first capability workflow therefore records actual Mac boot time, Hypervisor/Virtualization.framework results and public runner launchd filename counts. Those observations cannot prove continuity or make a reboot safe.

Unsupported ARM nesting leaves this direct disposable-host route open. Intel observations cannot satisfy ARM Keychain coverage. The existing native producer requires the unchanged real signed release, actual platform credential retention, a changed kernel boot identity, pre-login operation and owned cleanup.

## Smallest useful next experiment

After the passive packet is reviewed and run, prepare a separate public-only experiment with an original surviving controller and a fixed source-pinned per-boot LaunchDaemon. Before reboot, the controller must establish the actual target VM identity, original boot identity, source and candidate digests, workflow run/attempt, one fresh challenge, and a finite deadline. The post-boot helper must report the same target and a distinct actual boot identity, with root-owned source and launchd admission observed before login. It must never manufacture proof by loading an earlier receipt or accepting a restarted user process.

The observation transport must be explicitly chosen and reviewed before installation. A tokenless public callback is not authenticated merely because it includes a challenge. A fixed short-lived per-run authenticated channel would need proof of origin, replay refusal, source/target binding and a bounded teardown path; it must not become a generic command server. No platform token, runner credential, private licence or wallet data may be printed, stored in artifacts or copied into a boot helper. This packet provides neither a callback nor a credential protocol.

The original controller must remain running while the target worker is unavailable, distinguish actual new boot from worker restart, and stop on unknown identity. It must observe the hosted provider's behavior: whether reboot retains the VM, whether loss of the worker ends/decommissions the original job, and whether cancellation still removes the owned helper and target. A target self-expiry path and controller cancellation must be bounded without extending the original deadline. Provider cleanup must be verified rather than inferred from a workflow timeout.

Only after that public experiment proves actual survival, same-target boot continuity and cleanup can the separately reviewed native producer use the route. Private Keychain/licence and Testnet gates retain their own admission and original clocks. If hosted lifecycle semantics prevent the observation, report the unmet gate; do not substitute a new hosted job, generated receipt or gate waiver.

## Primary references

- [GitHub provisions and decommissions each job VM](https://docs.github.com/en/actions/how-tos/manage-runners/github-hosted-runners/use-github-hosted-runners).
- [Hosted runner limits and ARM Mac nesting restriction](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
- [Runner launchd service configuration is documented for self-hosted runners](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/configure-the-application).
- [Actual service status and launchd naming](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/monitor-and-troubleshoot?platform=mac).

No hosted reboot, helper installation, callback, token, private input or candidate execution has occurred in this preparation.
