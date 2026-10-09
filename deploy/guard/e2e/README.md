# Signed release testnet checks

This suite runs the actual signed release binary through a bounded Hyperliquid testnet journey on a free GitHub Ubuntu runner. It verifies release signatures and provenance, pairs the shipped MCP server, opens a small risk-approved BTC position, confirms the venue fill and protective stop, closes only its own position and orders, and proves the account is flat across the complete perp-DEX inventory.

The workflow is not enabled until the deployment requirements below are complete. The reusable workflow has no independent push, pull request or release trigger.

## Coverage

The report covers signed artifact verification, actual testnet Guard/MCP execution, stop ownership, cleanup, complete account reconciliation, and pause/restore of the existing testnet runner. It explicitly sets `release_ready:false`.

It does not prove paid checkout and email recovery, mainnet fee collection, browser wallet approval, native Keychain or DPAPI storage, every installer platform, or distribution channels. The release publication gate must require their independent evidence. A machine attestation proves the reported execution and its source binding; it does not expand the report's coverage.

The testnet API wallet is already approved at the venue. Its public address is configuration. The unchanged signed Guard validates that the input key matches the configured address and has the correct venue role before signing. This suite cannot approve a wallet, transfer funds, deposit, withdraw, alter risk defaults or resume a risk halt.

## Components

| File | Responsibility |
|---|---|
| `orchestrator.py` | Trigger admission, signed release verification, test execution, runner control and bounded public report |
| `journey.py` | Actual signed Guard/MCP order, fill, stop and owned cleanup |
| `scan.py` | Complete rate-limited public account scan, including a second inventory check |
| `verify-release-assets.sh` | Actual Sigstore/SLSA verification of all signed subjects and the OCI image |
| `actions-artifacts.py` | Read-only Actions download bound to the exact successful release run, source, tag and attempt |
| `staged-subjects.py` | Strict byte staging for the same mandatory cryptographic verifier |
| `host-control.py` | Root-owned fixed-service controller with a durable exclusive lease |
| `runner-lease.conf` | Prevents the old runner restarting after a host reboot during the suite |
| `ssm-document.json` | Fixed command document with enumerated, validated parameters |
| `policy.json` | Reviewed code hashes, approved public wallet and exact SSM document hash |
| `render.py` | Offline configuration renderer; no AWS or GitHub writes |

The privileged test job and the attestation job run on separate free `ubuntu-24.04` machines. Only the test job can assume the narrow AWS role. The attestation job downloads only the explicitly constructed report and has no AWS credentials, venue key or shared test filesystem.

## Immutable control source

The thin workflow is installed separately from this payload:

1. Review and commit this payload, including `.github/workflows/release-e2e-run.yml`, and obtain its actual commit SHA.
2. Render `release-e2e.yml.in` using that immutable SHA and install it as `.github/workflows/release-e2e.yml` in a subsequent commit.
3. Configure the dedicated testnet AWS role for the existing exact immutable repository/environment subject below. Keep the caller and evidence policy pinned to the reviewed reusable workflow SHA; never substitute a branch name or wildcard there.

The reusable workflow resolves its own `job_workflow_sha` from GitHub's authenticated HTTPS OIDC response before checkout. It refuses redirects, checks canonical repository IDs and main ref, and checks that `job_workflow_ref` names that same SHA. It then checks out that immutable source. AWS independently verifies the OIDC JWT when issuing credentials. The caller supplies no checkout ref or executable input.

The policy stores file hashes, not its own Git commit. Its execution commit comes from the authenticated reusable-workflow claim, avoiding a circular commit reference. Updating orchestration requires a newly reviewed immutable reusable SHA and updated literal caller/evidence policy; ordinary product releases use the existing pinned control source. The AWS credential trust does not pin this workflow SHA.

## Testnet OIDC trust

The repository uses GitHub's default **immutable** subject format, with `use_default:true` and `use_immutable_subject:true`. The dedicated testnet role trusts the exact repository IDs and environment:

```
repo:zunderlabs@338317604/zunder-guard@1409357189:environment:release-testnet-e2e
```

**AWS credentials bind this repository and environment, not `job_workflow_ref` or the immutable policy SHA.** Any protected-main workflow admitted to this environment with OIDC permission could request this dedicated testnet role. This is an explicit testnet-only trust choice. Environment deployment is restricted to protected main, and the role can access only the fixed testnet key, narrow decryption context and fixed host-control document. It cannot read mainnet parameters or mutate secrets, risk defaults or account funding.

The literal reusable caller and publication evidence consumer separately require the exact reviewed workflow SHA. That evidence boundary does not prevent another admitted workflow from obtaining testnet credentials. Preserve this distinction in reviews.

No repository-wide subject customization is required. Existing template publishing and roles in account `313260780004` remain unchanged. Verify the actual issued default subject before deployment without printing bearer tokens; do not replace exact trust with wildcards.

## AWS deployment

Account `436632189317`, region `eu-central-1`:

- Create role `ZunderReleaseTestnetE2E` with maximum session duration 7200 seconds, the exact rendered immutable repository/environment OIDC trust and only the rendered permissions.
- Allow `ssm:GetParameter` only for `/zunder/testnet/api-wallet-key`.
- The parameter uses customer-managed KMS key `arn:aws:kms:eu-central-1:436632189317:key/20d7fdda-950b-4101-a391-b3749f892939`, alias `zunder-exec-testnet`. Allow `kms:Decrypt` only for that key, through eu-central-1 SSM, with the exact parameter ARN encryption context.
- Allow `ssm:SendCommand` only for `ZunderReleaseTestnetControl` and existing instance `i-0ca66c349ad743928`. No general shell document, session, instance creation or document mutation permission.
- `ssm:GetCommandInvocation` requires `Resource:*`, because AWS does not support resource-level scoping for that readback operation. An explicit `StringEquals aws:RequestedRegion=eu-central-1` condition restricts this readback grant to that region. The role could still read other command outputs in eu-central-1. The implementation requests only its own returned command ID. Removing that residual capability would require a separate readback broker.
- Create document version 1 from exact `ssm-document.json`. Read back AWS's actual document content/hash and match `policy.json` before enabling. Each call supplies both exact version and SHA256.
- Require SSM Agent >=3.3.2746.0 for ENV_VAR interpolation. No legacy string-substitution fallback is provided.

Install root-owned files under `/usr/local/libexec/zunder-release-e2e/`: `host-control.py`, `journey.py` and `host-policy.json`. Create root-owned0700 `/var/lib/zunder-release-e2e`. Install `runner-lease.conf` as `/etc/systemd/system/zunder-exec-testnet.service.d/release-lease.conf`, daemon-reload, and inspect the effective unit and boot condition before enabling.

The account has two authorized writers: its existing runner and this serialized suite. Other tools and operators must honor the durable lease. Stopping one systemd unit cannot prove the absence of an unknown external writer.

The suite stops and reads back the existing runner before scanning. Restore requires a successful owned-cleanup receipt and an independent complete host-side flat scan. The durable lease prevents a host reboot from automatically restarting the competing runner during the journey. It is removed only after cleanup and flat proof; failed start restores the lease.

Before stopping or claiming exclusivity, the host controller checks root ownership, regular files and exact installed controller/journey/drop-in hashes. It reads the effective loaded unit over D-Bus and requires the expected unit ID, loaded state, no pending daemon reload, the expected drop-in, and the mandatory non-trigger negated `ConditionPathExists` for the exact durable lease. An installed file alone is insufficient. Stop/readback also requires no pending systemd job.

If runner start fails or times out, the controller reinstalls the lease, explicitly stops/cancels the submitted start job, and verifies actual inactivity, no pending job and loaded boot inhibition. If any of these cannot be established, it reports an ambiguous runner state requiring reconciliation; it does not claim the recreated lease has stopped an already submitted start job.

There is no timer-based recovery. A cancelled job or ambiguous cleanup retains the runner pause and venue protection. It may require deliberate reconciliation after an infrastructure failure; the suite never invents a pass or restarts a competing writer merely to recover availability.

## GitHub deployment

- Create environment `release-testnet-e2e`, restricted to protected main, with no required manual reviewer for routine testnet checks.
- Keep workflow and control-code changes under the existing main-branch status gates. Do not change branch protection to enable this suite.
- Enable the thin caller only after AWS resources are independently reviewed and read back, the protected-main environment restriction is verified, and the installed host controller/drop-in pass their checks.
- The caller accepts a strict numeric release tag through `workflow_dispatch`, or a successful completed canonical `release` push run. It rejects forks, PRs, other workflows and non-main callers. The exact release source must be an ancestor of protected main and have the successful main CI and tag release runs required by the real verifier.
- GITHUB_TOKEN uses `actions:read` to download the exact successful release's `dist` and `zunder-guard-TAG.intoto.jsonl` Actions artifacts. It requires no draft-release read broker or release write permission. Private OCI image access still requires the existing narrow package read permission.
- No venue secret is stored in GitHub. AWS credentials are short-lived. Registry authentication is removed before venue-key access. The signed Guard subprocess receives neither GitHub nor AWS credentials in its environment.

Render after obtaining the real automation commit:

```sh
python3 deploy/guard/e2e/render.py \
  --automation-commit REVIEWED_40_CHARACTER_COMMIT \
  --public-api-wallet 0xa9860ba817e405d17ef0acbc790cc68de030c5d3 \
  --kms-key-arn arn:aws:kms:eu-central-1:436632189317:key/20d7fdda-950b-4101-a391-b3749f892939 \
  --destination /absolute/new/configuration-directory
```

The renderer emits expected existing OIDC claims for readback, not a repository subject mutation request. Preserve existing repository OIDC settings and publishing-role trust.

## Verified tool staging

The pinned SLSA installer authenticates its verifier binary and then installs it at `$HOME/.slsa/bin/v2.7.1/slsa-verifier` with mode0100. The workflow requires that exact PATH lookup, runner-owned regular single-link file, expected original mode and non-writable parent directories. It adds only owner-read permission on that file, then stages identical bytes as a runner-owned0500 executable in the fresh0700 tool directory. Unexpected paths, ownership, permissions or existing destinations fail before AWS credentials or venue-key access. No sudo, replacement download or verification bypass is involved.

The installer action remains pinned to `ea584f4502babc6f60d9bc799dbbb13c1caa9ee6`; its [installation source](https://github.com/slsa-framework/slsa-verifier/blob/ea584f4502babc6f60d9bc799dbbb13c1caa9ee6/actions/installer/src/index.ts) establishes the authenticated installation and execute-only mode. Twelve offline staging regressions exercise the actual workflow block without executing verifier binaries. They do not replace hosted verification.

This workflow correction requires a new reviewed immutable reusable-workflow commit, followed by a separate literal caller update and corresponding evidence-consumer pin. The runtime policy commit still comes from authenticated OIDC claims. It changes no orchestrator, signed-release verifier, policy file hash, host controller, boot inhibition, SSM document, IAM trust or credential permission. Existing deployment receipts retain their historical commit bindings; they must not be relabeled as evidence of the new hosted execution.

## Authentic pre-release artifact transport

The transport admits only the canonical repository IDs, completed successful `release.yml` push run, exact tag/source and selected run attempt. It requires one `dist` artifact and one exact-tag provenance artifact, their metadata and downloaded ZIP size/digest, and creation timestamps inside the corresponding successful `package` and `provenance / generator` job windows for that same attempt. It rechecks both the selected attempt and the current run after downloads, refusing a concurrent rerun.

ZIP staging permits at most64 flat regular UNIX files,128MiB per carrier/member and256MiB expanded bytes. It rejects traversal, directories, links, special files, encryption, duplicate/case-colliding names, unsupported compression and unexpected provenance members. Staged files must be private, owned, regular single-link files. Their complete inventory must equal the signed manifest subjects plus its bundle and exact-tag provenance.

These checks establish authentic transport and safe parsing. They do not replace release authenticity. The verifier's source-CI checks, exact Sigstore certificate identity/issuer, manifest checksums, every-subject SLSA source/builder binding and OCI signatures/provenance remain mandatory and unchanged. The staging path cannot create the verified source marker; only the complete verifier does so after all checks pass. No fake GitHub shim, mocked release API, offline verification bypass or source-built binary is used.

Artifacts currently expire after seven days. Routine automatic runs consume them immediately after release completion; a manual retry after expiry fails closed. Extending retention is a separate release-workflow change. There is no fallback to an older attempt, unsigned payload or privileged draft reader.

## Evidence and failures

The attestation job verifies the report's successful journey and runner restore, exact policy commit, bounded coverage and `release_ready:false`, then signs a custom `https://zunderlabs.com/attestations/release-testnet/v1` predicate. Publication consumers must verify canonical repository, immutable reusable workflow identity, exact policy/source/manifest/binary hashes and coverage. A valid signature from another workflow is insufficient.

The venue key is captured within a bounded buffer and passed only through stdin. Core dumps and AWS CLI response history are disabled. No venue key is intentionally written to files, argv, subprocess environment, logs or evidence. Python cannot guarantee removal of immutable copies from process memory. The same OS user, a debugger or a compromised runner can inspect process memory; the key is therefore strictly testnet-only.

The test job allows 85 minutes for bounded full-inventory scans and cleanup, using the existing testnet host and free GitHub runners. No additional paid host is required.

## Checks

```sh
python3 -B deploy/guard/e2e/test-journey.py
python3 -B deploy/guard/e2e/test-orchestrator.py
python3 -B deploy/guard/e2e/test-host-control.py
python3 -B deploy/guard/e2e/test-actions-artifacts.py
python3 -B deploy/guard/e2e/test-tool-staging.py
```

The 125 harness checks, 18 orchestration checks, 12 host-controller checks and 12 artifact-transport checks cover offline accounting bounds, ownership/cleanup refusal, inventory integrity, trigger/ref/fork admission, injection refusal, configuration rendering, permission scope, canonical UTC producer-to-scanner-to-harness contracts, effective boot inhibition, delayed activation after start timeout, exact artifact attempt/job binding, unsafe archive refusal and unchanged cryptographic verifier core. They do not replace the actual signed-binary/venue execution or deployment readbacks.

## References

- [GitHub OIDC claims and immutable subjects](https://docs.github.com/en/actions/reference/security/oidc)
- [OIDC with reusable workflows](https://docs.github.com/en/enterprise-cloud%40latest/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows)
- [Custom artifact attestations](https://github.com/actions/attest)
- [Read-only Actions artifact download API](https://docs.github.com/en/rest/actions/artifacts#download-an-artifact)
- [SSM document version/hash binding](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html)
- [SSM ENV_VAR interpolation requirements](https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-troubleshooting.html)
