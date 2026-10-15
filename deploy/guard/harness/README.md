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

Hosted evidence and publishing jobs install `requirements-runtime.lock` with
`--require-hashes --only-binary=:all:` before installing this package with
`--no-deps --no-build-isolation`. The lock includes the SDK, every transitive runtime
requirement, the build backend and Windows terminal support. Regenerate with
`pip-tools==7.5.0` / `pip==25.1.1` and `pip-compile --allow-unsafe --generate-hashes`,
then include all PyPI wheel hashes for the conditional Windows dependency and verify
wheel availability on every hosted platform. Development dependencies remain separate.

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
All rows come from the gate's own run, but rows may come from different attempts of it (a rerun
of failed jobs keeps the passed rows' artifacts): `guard_harness.run_attempts.latest` selects
each producer's `<row>-<run>-<k>` artifact with the highest `k` at or before the consumer's
attempt, ignores superseded lower attempts, refuses another run id or a malformed name, and the
row's signature must then carry exactly attempt `k`. The staged chain and the in-run consumers
of other jobs' artifacts (M1, M3, the SDK jobs) select the same way. The gated state itself is
bound to the gate job's exact attempt.

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

`guard_harness.mcp_client.MCP` ports the testnet journey's subprocess transport into the shared
package. It requires a private paired client-key file and the expected binary digest, fixes the
network to testnet and excludes inherited credentials. Writes and reads have one bounded deadline;
protocol errors never include response bodies. An entry is attempted at most once per client,
including after a timeout or refused reply. Current binaries expose only read tools to this client:
place/close/cancel require initialize `capabilities.experimental.exchange_expected_mode: true`,
which must guarantee that every exchange envelope carries the MCP mode as Guard's atomic
`expectedMode`. Testnet signatures alone cannot enforce this boundary because Guard accepts both
client signing domains. T1/T2 writes wait for the producer change and its contract tests.
The real paper-binary check also exercises MCP account/limits reads on the source-built binary;
this does not prove released-byte trading or cleanup. POSIX only.

`guard_harness.testnet_protection.prove_stop` retains the old journey's read-only default-stop
check. It binds the unique active BTC market and size precision to the wire asset, exactly one
paired-client entry and its unchanged forwarded IOC order, and the default 2% stop with the
10% execution buffer. The validated proof holds immutable scalar values; its rendered wire is
fresh on every access. `validate_stop_order` then matches the venue cloid, side, reduce-only
flag, type, quantity, trigger, limit and optional trigger direction. This is one reconciliation
step, not permission to close or cancel: fresh fills, successful acknowledgement and current
open-order lookup must also establish ownership. No API requests or keys are used here.

`guard_harness.testnet_reconcile` continues the read-only T1/T2 reconciliation. Owned buy fills
must have unique trade IDs and exact entry OID, stay within the requested quantity/limit and
40 USDC notional, and explain the remaining BTC exposure. The protected-entry acknowledgement
must be unique, successful, linked to the durable decision and complete for entry plus stop;
contradictory OIDs or optional cloids are refused. Deferred stop acknowledgement grants no
stop OID by itself. The frontend order and fresh stop-cloid lookup must both match the validated
stop and agree on its OID. The controller must still establish fresh entry-cloid ownership,
exclusive flat preflight, complete order ownership and safe mutation ordering before cleanup.
These functions never send requests, close positions or cancel orders.

`guard_harness.testnet_ownership.reconcile_ownership` combines the durable proof with
entry-cloid lookup, timestamped fills, isolated BTC exposure and the complete open-order
list. An unrelated/stale entry lookup cannot supply the fill OID, and unrelated orders or
post-start fills refuse the observation. A partial fill is admitted only for cleanup; an
unfilled entry requires two exact resting readbacks and its deferred acknowledgement.
Returned observations contain immutable scalar values only. The controller must collect fresh
inputs before every mutation and independently establish all-DEX flatness at the end.
Cleanup-only observations also authenticate close/stop fills and reconcile exact net exposure.
The ordinary journey gate still requires the full owned entry with its live stop. Flat cleanup
requires closed stop lookup or an exact live orphan stop eligible for later cancellation;
a canceled unfilled entry can prove flat cleanup only with unchanged remaining size and no
positions/orders. Cleanup validates immutable protection against its recorded entry reference;
a crossed current stop price rejects journey credit without blocking owned cleanup.

`guard_harness.testnet_collect.collect_ownership` gathers fresh inputs through the fixed
public testnet read transport. It checks disabled abstraction, market identity and entry/stop
cloid lookups; reads primary and every secondary DEX twice; and requires stable entry-fill,
primary exposure/open-order and DEX inventory observations. Secondary DEX exposure refuses.
Responses at the conservative 500-fill pagination boundary refuse; the small exclusive journey
must not accept truncated history. Fill requests reserve their worst-case returned-item weight
before transmission, including failures. No redirects, proxies, keys or mutation endpoints are
accepted. Exclusive flat preflight, controller ordering and
an independent final all-DEX scan remain required. These sequential reads are not an atomic
snapshot and cannot replace serialization or fresh reads before each mutation.

Exit accounting invariants (`testnet_exits`): an exit OID comes only from a fresh lookup of
its durable cloid. It must match either the unchanged entry stop or a paired client's later,
unchanged reduce-only BTC sell IOC plus its successful acknowledgement. All post-start fills
must belong to the entry or these proved exits, with unique trade IDs. Decimal net quantity
must never turn negative and must equal the current isolated BTC exposure exactly; missing
exits, foreign fills and replacement exposure refuse. Exit fills cannot predate their order.
This read-only component does not replace fresh collection, serial preflight, or final all-DEX
flatness. The collector fetches each paired-client durable close cloid (at most 16) and the
historical stop even after exposure becomes flat. Unreadable, missing, duplicated or racing
reads refuse. The mutation controller remains to port; none of these functions sends orders.

`guard_harness.testnet_cleanup.cleanup` orders bounded cleanup from freshly collected ownership
observations. It cancels only a proved unfilled entry, closes only the exact current owned BTC
remainder, and cancels an orphan stop only after exposure is proved flat. Each successful mutation
requires a new observation with unchanged entry identity and total bought quantity. At most three
successful partial closes are allowed, each making proved progress. Failed or uncertain sends
are never retried. An independent all-DEX scan is required even when owned exposure is already
zero. Failure grants no cleanup evidence and leaves Guard running; the controller does not kill
processes or protection. Its 900-second maximum admission deadline depends on bounded collectors
and MCP requests; it is not a mechanism for interrupting an arbitrary injected callback.

MCP cleanup closes require initialize capability `experimental.close_expected_size: true` and
an exact positive `expected_size` with coin BTC, never an unbounded whole-position close or a
relative fraction. Older producers fail before a close request is transmitted. The producer
must refuse when its current absolute position size differs and must send exactly that size.
Producer support is requested through the private shared status. Actual T1/T2 remain blocked on
this guarantee and the expected-mode sender guarantee. The orchestrator still must supply
exclusive flat preflight, account serialization, authenticated binary/process setup, fresh local
journal collection and Guard lifetime handling. No fixture result proves an actual venue cleanup.

`guard_harness.testnet_journey.execute` integrates the real ownership collector and cleanup
controller for T1/T2 on an already authenticated, caller-owned testnet Guard and MCP process.
It requires both sender capabilities before entry, a fresh synchronized matching-account/version
runtime with active risk and fee mode off, then a C6 all-DEX flat preflight and an exact allow
preview. It attempts one bounded BTC entry, requires an actual isolated fill with the unchanged
live stop, and always attempts owned cleanup after an ambiguous entry outcome. It stops Guard
only through the supplied verified stop operation after successful cleanup and independent
flatness. An entry/protection failure never earns journey credit merely because cleanup passed.
Fixture integration exercises the real collector and net accounting, including partial state,
entry timeout, cleanup timeout and pre-entry refusals. It does not establish live T1/T2 evidence.
The launcher still must authenticate released bytes, own process/service lifetime and account
serialization, reserve complete cleanup time before entry, pair a fresh client, and retain
sanitized evidence on all paths. Producer capabilities remain prerequisites for live execution.

`guard_harness.testnet_process.Foreground` connects T1 foreground custody to that journey core.
It copies bytes matching the caller's independently authenticated release-archive digest into a
fresh private work directory, initializes keyless testnet, pairs using C3 JSON, and binds only
the public API-wallet address while preserving all policy/auth settings. Guard alone inherits
wallet input through a nonterminal stdin descriptor; init/pair have closed stdin and a minimal
secret-free environment. Child output is withheld, paired-client state is private, and local
observations refuse a dead child or changed executable. Successful cleanup stops the owned
process group and confirms exit; failures have no automatic process teardown. Global C6 workflow
serialization, entry planning, complete cleanup time reservation/transport lifetime and signed
release authentication by the caller remain required. The fixture tests exercise real subprocess
custody but are not live testnet or release evidence. T2 service ownership remains to integrate.

Foreground `journey` now requires the caller's actual monotonic job deadline. After all-DEX
preflight and exact allow preview, admission rechecks the owned process and requires at least
1,200 seconds left: 225 seconds for entry/proof, 900 for cleanup admission, 45 for an in-flight
MCP call, 20 for process exits and 10 margin. Entry reads get a 180-second phase; cleanup gets
720 seconds on the same paced transport, so an expired preflight window cannot disable cleanup
or reset its request budget. These bounds depend on the documented bounded HTTP/MCP calls and
the caller supplying the real remaining job lifetime. T2 must wire equivalent admission hooks.
The optional entry plan reads testnet BTC metadata/mids, targets 15 USDC using Decimal and the
venue grids, and refuses inactive/ambiguous markets or size granularity outside 10–40 USDC.
Global account serialization and signed-release authentication by the orchestrator remain open;
producer sender capabilities are still required before any actual entry.

`python -m guard_harness.testnet_run` is the T1 foreground command. Its caller supplies an
explicit release tag/full commit, C6 account and approved public API-wallet address, a fresh
private `--work` directory, and `--deadline` from the calling job's monotonic start/timeout.
The calling reusable workflow must serialize all C6 trading jobs. Wallet input enters only
through a pipe inherited by Guard; Python never reads it. The command invokes the real release
asset verifier (source CI, signatures and provenance) before accepting the C2 manifest/checksum
inventory and copying a bounded regular archive binary. It retains a private sanitized
`receipt.json` before custody, before the journey and on completion/failure. A passing receipt
requires protected entry, owned cleanup, independent flat scan and confirmed Guard exit; the
receipt alone does not grant release-gate admission. Incomplete cleanup preserves protection.
The reusable workflow and live T1 evidence are still pending producer capabilities.

The reusable `journey.yml` currently runs T1. It requires the calling source commit to equal
its release commit and runs in `e2e` with concurrency group `guard-e2e-testnet`, cancellation
disabled. T2/nightly trading jobs must share that group. `job_deadline` binds the unique active
runner job to its run/attempt/source and counts setup against the 45-minute timeout, retaining
90 seconds for clock skew and artifact upload. The wallet variable is removed from Python's
environment while its input pipe is inherited by Guard. Successful T1 writes the existing C2
journey predicate bound to the authenticated manifest; `actions/attest` signs that manifest.
Artifacts use explicit sanitized file paths, excluding runtime config and client keys.
T2, purchase jobs and the complete verify/gate caller remain to be wired.

`python -m guard_harness.homebrew_stage --tag TAG --commit FULL_SHA --work FRESH_PRIVATE_DIR`
verifies the release assets in that invocation, captures the C2/checksum-bound formula, then
uses an environment-only `HOMEBREW_TAP_TOKEN` scoped to the tap (the lifecycle workflow can
mint it from the C7 App). `GH_TOKEN` is separately used for public release verification.
The publisher changes only `Formula/zunder-guard.rb` on the tap's `staging` branch, preserving
its base tree. Successful branch inventory must include `main`; unknown reads refuse.
Updates are never forced or retried after conflict. The receipt records the immutable staged
tap commit; I3 must consume that commit. No canonical branch or Homebrew PR is published here.
Lifecycle workflow serialization and real channel testing remain to integrate.

`verify.yml` now supports an initial staged publication by dispatch on the exact released
commit/tag. It authenticates the assembled release, attests staged genesis on its immutable
manifest, re-verifies that attestation and publishes original signed loaders to the C2 store.
The `promote` environment supplies only the publication step's token; Python removes it before
verification subprocesses. The initial empty-head compare-and-swap cannot overwrite an existing
release. An unknown POST outcome must be reconciled before any further publication; this command
does not retry or acquire a replacement head. Retained output excludes credentials.
The same workflow uses the scoped Homebrew App to run `homebrew_stage`, preserving the tap's
canonical branch, and the C7 OIDC role to publish the signed AWS template at its immutable version
URL. The configured bucket, region and base must match the signed URL before AWS credentials are
issued; authenticated and public downloads must match the template bytes. AWS credentials are
removed from the installer publisher's environment. A later failure can leave some channels
staged; it grants no gate credit and requires reconciliation before attempting installer writes.
This job publishes unavailable staged state only. The complete install/journey gate, subsequent
release head reconciliation, hosted channel evidence and promotion still need integration; a green
staging job is not S3. The workflow must be present in a new RC's source before it can attest
that RC. It cannot retrospectively attest an older RC from a newer workflow commit.

`canonical_readback.check` consumes the authenticated `Publication` returned by
`publication.prepare` for a promoted state. It reads only the four canonical C5 release
endpoints and compares every header and body to that captured publication: both loader
bytes, the lifecycle predicate and its bundle. Redirects, non-200 answers, changed bytes or
mixed publication revisions fail without retries. The transport uses no credentials and
bounds each response to 2 MiB. This check does not discover or authenticate a promotion
chain itself; the monitor and promotion caller must retain that verified chain and complete
journey evidence before calling it. Hosted scheduling, alerts and rollback wiring remain
required before claiming P9 or canonical smoke coverage.

`guard_harness.docker_run` accepts `--previous-tag` and `--previous-commit` together
to exercise upgrades. The preceding published release must have an older version and
distinct source and image bytes. Both complete release admissions finish before Docker
pulls either image. Plain Docker and Compose initialize and pair on the old image, then
reuse the same state volume and loopback port with the candidate's signed distribution
payload. The candidate must retain every old decision and accept another round trip from
the old client before restart, crash recovery and reinstall checks proceed. A passing
receipt includes both immutable release identities. This remains keyless paper coverage;
testnet lifecycle and hosted I5 attestation are separate requirements.
