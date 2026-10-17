# Flow-model and native Windows CI partitions

The `rust` and `windows` required checks each combine a main job with matrix shards. All jobs use standard GitHub-hosted runners: Ubuntu 24.04 and Windows 2025. No paid runner, secret, AWS host or publication permission is added.

## Flow-model leaves

Each OS runs these exact `zunder-venue` / `flows_model` tests in separate matrix leaves:

- `the_generator_reaches_every_path`
- `the_implementation_is_the_reference`
- `the_implementation_is_the_reference_when_told_in_time`
- `the_order_of_the_reports_does_not_matter`

Linux retains 4,000 histories per property; Windows retains 400. Each leaf first runs the same package, test binary and exact test filter with `--list`. `check-flow-selection.py` rejects unreviewed names, zero/multiple matches, unexpected output and a failed listing command. The actual test uses that exact filter again. Listing compiles the binary but does not execute the property.

The Linux main job keeps its workspace scope and skips only those four complete test names using `--exact --skip`; so does every native Windows test shard below. The eight other flow properties, five fixed flow regressions, Guard core cash-ledger coverage, native unit tests, clippy, Windows installer checks under PowerShell 5.1 and 7, and Windows ACL diagnostics remain.

## Native Windows test shards

`windows-main` keeps the HTTP worker regression, the protected file creation checks, clippy, the local release and both installer shells. Its native tests run in `windows-tests`, a three-leaf matrix planned by `windows-test-shards.py`:

- `pilot`: the `pilot` integration test (about 14 of the 29 minutes the single command took)
- `io`: the `end_to_end`, `journal` and `stream` integration tests (about 8 minutes)
- `rest`: every library, binary and doc test, every other integration test, and the example builds

Every shard selects the same six packages as the single command (`zunder-venue`, `zunder-venue-types`, `zunder-guard-core`, `zunder-guard-mcp`, `zunder-guard-rules`, `zunder-guard`), so Cargo resolves features exactly as before: zunder-guard's dev-dependency on itself still turns on `test-hooks` in zunder-guard-core. Shards differ only in target selection, and every invocation passes the original libtest arguments. Before it runs anything, each leaf reads `cargo metadata` and refuses an unreviewed target kind, a target with `required-features` or non-default `test`/`doctest` flags, a missing package or a named test that no longer exists. `rest` is computed as every integration test no other shard names, so a new test file runs there without a workflow change. `cargo test` without target flags also builds the examples; `rest` builds them once in the same `test` profile.

The leaves keep 400 flow histories per property and `RUST_TEST_THREADS=1`, and run each planned invocation through the same process handle retention, CPU/I/O heartbeat, exit-code collection and child cleanup as the flow leaves. Every invocation runs even after a failure, as `--no-fail-fast` did, and the step fails with the first failing exit code. The ACL diagnostics also run when a leaf fails. All leaves restore one shared Cargo cache (same packages, features and dependencies); only `rest` saves it, so the leaves never race to save a partial one.

## Aggregates

All matrix strategies set `fail-fast: false`. The stable `rust` and `windows` aggregator jobs run with `always()` and require their main job and their complete matrix jobs to report `success` (`windows`: `windows-main`, `windows-tests` and `windows-flows`). Failure, cancellation, skipped dependencies, missing dependencies or unexpected dependency names fail the required check. The `ci` aggregate requires `rust` and `windows` unchanged. No job or step uses `continue-on-error`. Existing branch protection and required GitHub Actions app bindings remain deployment configuration; this workflow does not change them.

These partitions offer parallel execution without reducing coverage. Cold compilation repeats work in every leaf, and the account's free runner concurrency and queue length can delay the shards. Faster wall-clock CI is an expectation to measure after activation, not a demonstrated result.

The two workflow copies must remain identical. `test_flow_shards.py` checks selection refusals, the shard plan against fixture metadata (exact invocations, disjoint and complete partitions, refusals), commands, case counts, wrapper equality, workflow copies and strict aggregate outcomes without executing Cargo. The existing scripts job installs pinned PyYAML before running these contracts. Actual hosted execution remains necessary to validate performance and platform behavior.
