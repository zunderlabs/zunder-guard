# Guard release harness

One Python package for black-box release verification. From this directory:

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check . ../release
.venv/bin/ruff format --check . ../release
.venv/bin/mypy --strict
.venv/bin/pytest
```

`guard_harness.manifest.validate_manifest` validates C2 and refuses verified channel claims
unless the caller supplies the independently authenticated journey set and expected public
commit. Attestation URLs in JSON alone grant no trust. The release gate must verify attestation
subjects, signer identity, predicate and result before calling this function.

`guard_harness.runner.run` runs one bounded command without a shell and retains sanitised stdout
and stderr on success, failure and timeout. Pass all sensitive values as `secrets` and inject
credentials through environment variables, never command arguments. Use one log per lifecycle
step. This is not yet a platform lifecycle harness.

`guard_harness.cli` pins C3's required JSON fields while allowing additive fields. It never
parses human status text. Pairing output is deliberately withheld from retained logs because it
creates a client key unknown before execution; the key is also excluded from object reprs.
The C3 unit tests cover missing fields, malformed types and secret-safe diagnostics. Running
these checks against the released Guard CLI is required before accepting its C3 contract.

`guard_harness.attestation.verify_predicate` calls the official `gh attestation verify` with
signer workflow, issuer, source commit, hosted-runner and predicate-type constraints. It only
returns the verifier's authenticated statement. Unit tests use a fake verifier to attack this
boundary; they are not evidence that any real release attestation exists or verifies.

`python -m guard_harness.build_manifest --help` generates immutable C2 v2 metadata from an
explicit payload list, requiring all five platform archives and refusing to overwrite its output.

`guard_harness.paper_bot.PaperBot` signs prepared order cases with the official MIT-licensed
Hyperliquid Python SDK. The caller supplies a `Pair` from the isolated CLI and valid order cases
expected to allow, resize and veto, with the specific reason code for each case. The bot accepts only literal loopback HTTP URLs, ignores
proxies, refuses redirects and checks `/guard/status` is paper before every signed request.
It fails closed unless `capabilities.exchange_expected_mode` is true; requests carry
`"expectedMode": "paper"` in the strict exchange envelope, which Guard must enforce before
handling any action. Older servers reject the unknown body field, preventing silent downgrade
across process replacement (an HTTP header could be ignored). This
additive C3 capability must be implemented by Guard before this client can run a paper journey.
It waits for Guard’s five-second restart nonce fence before signing, and rejects a start
timestamp ahead of the local clock. It checks the reply against exactly one matching journal decision (client, nonce, action,
verdict and reason), and refuses a venue-send event. Tests independently recover the signatures
with the SDK and exercise non-paper refusal and inconsistent journal evidence. This module is
not yet evidence of a paper journey against released bytes; the lifecycle runner must supply
real policy-valid cases and run it on the staged installation.

`guard_harness.state_verifier.authenticate_state` verifies a bundle against a private snapshot
of the exact immutable manifest bytes, compares served JSON with the authenticated predicate,
then validates its link to the authenticated predecessor. Pass independently verified journey
IDs and retain the trusted head durably. New clients need the authenticated chain starting at
staged genesis; losing the head or failing to discover a newer withdrawn revision can permit
replay, so this helper alone is not a freshness oracle or a complete publisher.

`GuardCLI.set_licence` requests the additive C3 `licence set --stdin` command, keeps the key out
of argv and redacts it from retained output. Purchase journeys require a Guard binary that
implements this command. `runner.run` accepts stdin bytes while preserving its bounded, sanitized log behavior.

`guard_harness.testnet_scan.flat_scan` extracts the durable all-DEX cleanup check from the old
public journey, without borrowed-runner receipts, leases or host control. It reads abstraction,
inventory, positions and frontend orders for every DEX, then rereads inventory. Unknown values,
nonzero positions, any open order, inventory changes and main-DEX equity below 200 USDC refuse
passing observations. It never repairs state. Returned hashes/timestamps are observations for a
later workflow attestation; they are not independent cryptographic proof or an account lease.
The C6 workflow must serialize all uses of that dedicated account.

`TestnetReads` fixes the public testnet info endpoint, disables proxies/redirects, bounds reply
size and total time, and paces even failed calls to at most 30 reads/minute. These four info types
cost at most 20 weight each under the venue's
[documented limits](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/rate-limits-and-user-limits).
Only the legacy journey's `disabled` abstraction is admitted; `default`, unified, portfolio and
DEX abstraction modes remain refused until C6 pins their semantics. No key or configurable
exchange endpoint is accepted.

`guard_harness.journey_evidence.authenticate_gate` verifies the complete automated journey set
with the official Sigstore verifier before accepting a gated/promoted lifecycle. Each journey
attests the exact immutable manifest, expected release commit and its own row ID, with the pinned
install-matrix or journey workflow. Contract fixtures and skipped/failed results cannot count.
Mainnet setup/refusal aggregates require every route and case, and the signing aggregate includes
the live testnet path. Lifecycle references must match the authenticated bundle reference map.
The manifest and bundle inputs are captured before verification. This consumer is ready for
workflow integration; its mocked-verifier tests are not hosted release acceptance evidence.

Real paper-binary check (in addition to local contract fixtures): set
`GUARD_TEST_BINARY` to the built/installed Guard and `GUARD_PAPER_READ_ACCOUNT`
to a funded, flat testnet account in standard (`disabled`) mode, then run
`pytest tests/test_binary_paper.py`. It creates an isolated home, reads that
account on testnet, runs Guard in paper mode, pairs a local client, and verifies
signed veto, allow and resize cases against the journal with no venue-send event.
A 20 USDC entry with its supplied stop must retain its quantity; an oversized
entry must shrink, with its reduce-only stop matching the forwarded quantity.
Inputs use Decimal and the SDK order-action constructor, and the test waits for
the default request budget to refill between entry cases.
It also validates the actual CLI status schema. The local client key stays out
of logs. No API wallet key is supplied. Without both inputs this test skips;
a skipped result is not install-matrix evidence. Service lifecycle and staged
release checks remain separate requirements.

`actions_artifacts.ReleaseAttempt` checks the exact successful tag-push attempt,
canonical repository and artifact-producing job before admitting transport metadata.
Get the repository ID from the current canonical repository API; archived repository
IDs never identify a new repository. `extract` checks the downloaded ZIP digest and
size, snapshots the bytes once, and accepts only the exact expected bounded set of
regular files. It rejects unsafe paths, special files, duplicates, case collisions,
corruption and oversized expansion. Output appears as a private directory only
when extraction finishes. These checks identify transported bytes; they provide no
Sigstore, provenance or journey credit. The downloader must validate complete API
inventories and recheck the selected attempt after download before admission.

`staged_subjects.copy` is the POSIX seed/subject copier for the release-verification
workspace. It requires private owned paths, an exact checksum inventory, regular
single-link files and a fresh destination. Seed copies the checksum list, its
Sigstore bundle and SLSA provenance; the caller verifies those before copying
subjects with the authenticated checksum-list digest. Each subject is captured
once and hash-checked before any output directory appears. A checksum list changed
after seed verification cannot authorize replacement assets. Copying bytes itself
grants no signature or provenance credit.

`guard_harness.actions_download.stage` obtains complete bounded Actions artifact/job inventories
with `gh api` on github.com, using the current canonical repository ID and exact successful
release attempt. It verifies both ZIP digests/inventories, limits their combined expansion and
rechecks the selected attempt and latest run after download before exposing private subjects.
The caller supplies the exact packaging inventory. Its receipt grants no signature/provenance
credit; those checks must succeed before any downloaded executable runs. POSIX only.
