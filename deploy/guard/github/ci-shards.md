# Flow-model CI partitions

The `rust` and `windows` required checks each combine a main job with a four-leaf flow-model matrix. All jobs use standard GitHub-hosted runners: Ubuntu 24.04 and Windows 2025. No paid runner, secret, AWS host or publication permission is added.

Each OS runs these exact `zunder-venue` / `flows_model` tests in separate matrix leaves:

- `the_generator_reaches_every_path`
- `the_implementation_is_the_reference`
- `the_implementation_is_the_reference_when_told_in_time`
- `the_order_of_the_reports_does_not_matter`

Linux retains 4,000 histories per property; Windows retains 400. Each leaf first runs the same package, test binary and exact test filter with `--list`. `check-flow-selection.py` rejects unreviewed names, zero/multiple matches, unexpected output and a failed listing command. The actual test uses that exact filter again. Listing compiles the binary but does not execute the property.

Main jobs keep their original workspace/package scopes and skip only those four complete test names using `--exact --skip`. The eight other flow properties, five fixed flow regressions, Guard core cash-ledger coverage, native unit tests, clippy, Windows installer checks under PowerShell 5.1 and 7, and Windows ACL diagnostics remain. The native Windows main job and each Windows leaf use the same process handle retention, CPU/I/O heartbeat, exit-code collection and child cleanup wrapper.

Both matrix strategies set `fail-fast: false`. The stable `rust` and `windows` aggregator jobs run with `always()` and require both their main job and their complete matrix job to report `success`. Failure, cancellation, skipped dependencies, missing dependencies or unexpected dependency names fail the required check. No job or step uses `continue-on-error`. Existing branch protection and required GitHub Actions app bindings remain deployment configuration; this workflow does not change them.

This partition offers parallel execution without reducing random coverage. Each OS now has five Rust compilation jobs. Cold compilation repeats work, and the account's free runner concurrency and queue length can delay the shards. Faster wall-clock CI is an expectation to measure after activation, not a demonstrated result. This change adds no shared cache or prebuilt binary transport.

The two workflow copies must remain identical. `test_flow_shards.py` checks selection refusals, commands, case counts, wrapper equality, workflow copies and strict aggregate outcomes without executing Cargo. The existing scripts job installs pinned PyYAML before running these contracts. Actual hosted execution remains necessary to validate performance and platform behavior.
