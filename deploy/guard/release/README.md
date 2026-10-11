# C2 release metadata

Version 2 separates immutable build bytes from lifecycle revisions. Version 1 is retained at
`manifest-v1.schema.json` with its behavioural tests while consumers move to v2.

- `manifest.schema.json`: immutable `release-manifest.json` (`schema: 2`), signed by release.yml
  and included in SHA256SUMS. Contains version/tag/commit, assets, signing identity, platforms
  and `distribution` descriptors (commands, image digest, template URL), with no mutable status.
  The asset map excludes itself and SHA256SUMS to avoid checksum cycles.
- `state.schema.json`: lifecycle predicate (`schema: 2`) served as release.json. Contains the
  same version/tag/commit, `manifest_sha256` of the exact signed build-manifest bytes, `revision`,
  `previous`, `stage`, `issued_at`, `channels` and `evidence`. Each channel copies its immutable
  distribution descriptor and adds `status`. Revision 1 is staged with a null predecessor.
  Every next revision adds one and names the preceding canonical predicate's SHA256 digest.
- Stages: staged → gated → promoted → withdrawn; staged/gated may also become withdrawn.
  verify.yml signs staged/gated predicates; promote.yml signs promoted/withdrawn predicates.
  Predicate type: `https://zunderlabs.com/guard/release-state/v1`. The in-toto subject is the
  immutable manifest digest. A release candidate can be gated but never promoted.
- `/guard/release.json.sigstore` holds the promoted revision's bundle;
  `/guard/release-staging.json.sigstore` holds its staging twin. Revision and bundle are published
  atomically. The publisher must serialize updates and compare against a durable trusted head;
  hash chaining by itself does not prevent competing forks or replay.

Canonical predicate encoding is UTF-8 JSON with lexically sorted keys, no whitespace and no NaN
(`guard_harness.release_state.canonical_bytes`). The schema uses integer revision fields and UTC
timestamps. Immutable manifest hashes use the original file bytes, not a re-serialized copy.

The Python validators run after cryptographic verification. They bind build/state subjects,
check the trusted predecessor and signer role, preserve signed distribution descriptors, and
require authenticated P1–P8, I1–I7, T1/T2 and M1–M3 results before a gate/promotion claim. They do not
verify Sigstore themselves. Withdrawal clears verified channel statuses; P9 is the post-release
monitor, not a pre-release gate. M4 is the operator’s manual pilot after promotion and cannot appear
in automated gate evidence. V1 retains its original journey set during migration. `examples/build-v2.json` is synthetic contract data, not a release.

The release package step renders payloads with `packaging/render.sh --payloads-only`, then runs
`python -m guard_harness.build_manifest --checksums <dist>/SHA256SUMS` with the explicit payload
inventory. The resulting checksum set includes `release-manifest.json` and every payload;
metadata excludes itself and the checksum file. Both outputs are created exclusively, and a
sealed directory may not contain unlisted files. The existing release.yml cosign signing and
checksum verification then cover the immutable metadata too. The workflow requires repository
variable `AWS_TEMPLATE_BASE_URL`; it supplies infrastructure location at runtime, with the signed
template descriptor ending in `/guard/<tag>/cloudformation.yaml`.

`python -m guard_harness.staged_state --tag vX.Y.Z --commit FULL_PUBLIC_SHA --work
/absolute/fresh-directory` authenticates the assembled release through the real asset verifier,
then writes `staged.predicate.json`. It binds the original manifest bytes and produces revision
1 with no predecessor, all channels unavailable and no journey evidence. The predicate is an
input for `verify.yml` attestation, not an authenticated published state by itself. Signing,
staging endpoint publication and the complete verify workflow remain integration requirements.
