# Proposed C2 canonical rollback operation

This extends storage publication without changing either signed schema or any release asset.
The parent release owner must incorporate this operation into C2 and request deployment of
both the public store implementation and the private publication proxy route.

Authenticated `POST /guard/restore` accepts exactly `expected` and `restore`, both lowercase
SHA256 strings. `expected` identifies the current canonical **withdrawn** capsule.
`restore` identifies the exact promoted canonical capsule replaced by that build's promotion.
The same `INSTALLER_PUBLISH_TOKEN` protects this route. Its body is capped at 1024 bytes.

The store archives every accepted capsule by predicate digest and records the prior canonical
promoted capsule at promotion. A restore atomically requires the exact channel CAS head,
that withdrawal's matching durable build head, its archived promoted predecessor, the recorded
prior canonical digest, and a prior target whose own durable build head remains promoted.
It returns HTTP 201 with that restored digest; stale CAS, arbitrary targets, replay,
unavailable targets and any attempt to restore before withdrawal return 409.

Restore serves the original prior predicate, bundle and loader bytes. The failed build's
withdrawn lifecycle and archive remain intact. This is a channel rollback, not a lifecycle
revision decrement. The target was authenticated at its original publication; restoration
admits no caller-supplied replacement capsule or loader. Consumers see the old authenticated
capsule's original `x-zunder-state-sha256` across all four canonical paths.

A first stable release has no prior promoted capsule: automatic rollback publishes its signed
withdrawal and keeps canonical loaders unavailable (HTTP 410). There is no null-head restore
and no fabricated fallback. HTTP uncertainty requires a fresh durable-head read before any
subsequent action; never blindly replay a publication or restore request.

## Recover an interrupted rollback

Use `promote.yml`'s **rollback** dispatch mode. Select the original stable tag as the workflow
ref so the workflow source remains the released commit. Supply the original `tag`, full
`commit`, verification `run_id` and `attempt` (the gate job's attempt, recorded in the signed
snapshot as `verify_attempt`), and the original promotion's `source_run` and `source_attempt`.
A reusable promotion shares its caller's run ID; its own attempt can follow the gate's when
failed jobs were rerun. A standalone promotion has its own run and attempt. Do not rerun the
promotion or `prepare` phase.

```sh
gh workflow run promote.yml --repo zunderlabs/zunder-guard --ref "$TAG" \
  -f mode=rollback -f tag="$TAG" -f commit="$COMMIT" \
  -f run_id="$VERIFY_RUN" -f attempt="$VERIFY_ATTEMPT" \
  -f source_run="$PROMOTION_RUN" -f source_attempt="$PROMOTION_ATTEMPT"
```

Recovery first downloads `promotion-recovery-<source_run>-<source_attempt>` from the
original run. This immutable artifact is uploaded immediately after snapshot signing, before
channel credentials or mutations, so recovery remains available if that runner disappears.
GitHub's official Sigstore verifier authenticates its exact workflow, source commit, run and
attempt. The signed snapshot binds captured channel identities, the prior canonical identity,
the promoted proposal, subject hash, candidate manifest, checksum inventory, formula and source
marker. Mutable progress or late artifacts cannot replace this baseline.

The tap, OCI `latest` and GitHub latest are reconciled independently **before** gate network
admission, canonical reads or withdrawal signing. Each still checks its captured live ownership;
a newer or foreign head is refused. One channel failure is recorded without stopping the other
two, and an already-restored owned channel is accepted. These outcomes are retained in
`channels-rollback.json`. A positive indication that the publication step never ran skips
automatic recovery; uncertain interruption still requires reconciliation. Manual dispatch always
permits authenticated recovery.

Only afterwards does recovery obtain the optional late transaction artifact, copying solely its
original promoted signature. Canonical withdrawal and restore still require the original full
candidate and predecessor C2 chains and exact live CAS proof. Missing gate evidence, a missing
original promoted signature, signing failure, unknown canonical CAS or unavailable live withdrawal
proof stop canonical writes without blocking the earlier independent channel restores. Never
invent a canonical proof or blindly replay a request. A runner lost before retaining its promoted
signature may need that original signature recovered from its attestation before canonical repair.
A channels-only success does not establish complete rollback. Inspect both `channels-rollback.json`
and `rollback.json`, plus the new `rollback-<recovery_run>-<recovery_attempt>` artifact. A signed
withdrawal proposal is distinguished from a published withdrawal by `withdrawal_published`.

For an operator holding the original pre-mutation artifact, the independent recovery phase can
also be run directly. Keep the scoped tap credential and GitHub credential in their environment
variables, with the authenticated registry login; never put credentials in arguments. This phase
needs no installer publisher credential or gate evidence, and cannot mutate the canonical store.

```sh
python -m guard_harness.promotion --phase channels-rollback --tag "$TAG" --commit "$COMMIT" \
  --run-id "$VERIFY_RUN" --attempt "$VERIFY_ATTEMPT" \
  --source-run "$PROMOTION_RUN" --source-attempt "$PROMOTION_ATTEMPT" \
  --evidence "$EVIDENCE" --work "$WORK"
```

Artifacts are retained for 30 days. Preserve the original signed transaction and complete
verification evidence in a protected operator archive before they expire if longer recovery
is required. Missing or unverifiable inputs stop recovery; never invent a snapshot, edit
captured hashes or substitute another run's artifacts. Recovery does not rewrite immutable
release assets or published release tags.

## Restore only the canonical capsule

Prefer the dispatch above because it also reconciles the other channels. For a canonical-only
repair, obtain the original authenticated work directory, its complete verification evidence,
and an already-signed withdrawal bundle (from a rollback outcome artifact). Keep
`INSTALLER_PUBLISH_TOKEN` in the environment; never put it on the command line.

```sh
python -m guard_harness.promotion --phase restore --tag "$TAG" --commit "$COMMIT" \
  --run-id "$VERIFY_RUN" --attempt "$VERIFY_ATTEMPT" \
  --source-run "$PROMOTION_RUN" --source-attempt "$PROMOTION_ATTEMPT" \
  --evidence "$EVIDENCE" --work "$WORK"
```

This command authenticates the original snapshot and both full C2 chains. It accepts only
that signed withdrawal as the current CAS head and that snapshot's exact predecessor as the
target; an already-restored predecessor is a no-op. A first stable release has no target and
is refused. It cannot choose an arbitrary old release and cannot replace a newer canonical
head. A canonical-only success does not establish that the tap, image and GitHub latest were
restored; inspect and recover those channels separately.

Verify staging/gate and promotion/rollback mutation jobs share
`guard-release-channel-mutation` with durable `queue: max`. The caller and reusable workflow retain distinct
workflow-level locks: using the same workflow-level group would deadlock a verify run waiting
for its reusable promotion. Canonical smoke runs hold no mutation lock, and every later
rollback still checks the captured ownership before changing a channel.
