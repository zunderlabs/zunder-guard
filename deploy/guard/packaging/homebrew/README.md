# Homebrew publication and lifecycle proof

Homebrew distributes the same signed-release binaries as the direct installer. It is not a separate build or signing pipeline. The tap is `zunderlabs/homebrew-tap`; its formula is `Formula/zunder-guard.rb`, copied **unchanged** from the verified release asset. `packaging/render.sh` renders the version, four archive URLs and SHA-256 values before signing.

This guide is a release procedure, not a record that publication or installation passed. Record actual evidence per platform below. A rendered formula, `ruby -c`, `brew audit` or a successful version command alone is not lifecycle proof.

## CI publication: signed release → verified formula → reviewed tap PR

The release owner bootstraps `zunderlabs/homebrew-tap` once with README/LICENSE/NOTICE and
`tap-verify.yml` from this folder copied to `.github/workflows/verify.yml`. Use `main` as its
default branch. The formula is added by the product's release workflow, not hand-rendered.

1. Register a company GitHub App and install it on **only `zunderlabs/homebrew-tap`**. Give it
   repository contents and pull requests write; no administration, organization or workflow
   write permission. Store its client ID as repository variable `HOMEBREW_APP_CLIENT_ID` and
   its private key as Actions secret `HOMEBREW_APP_PRIVATE_KEY` in `zunderlabs/zunder-guard`.
   Restrict access to release workflow changes. Set `HOMEBREW_TAP=enabled` before publication.
   There is no personal-PAT fallback. App creation, installation and secret provisioning are
   release-owner steps; never commit the private key.
2. Protect the tap's `main` branch: require a PR, human review and the `verified-native-install`
   checks from all four `verify-formula` platform jobs, with branches required to be up to
   date before merging; no App bypass. This reruns stale PRs against the current base and
   prevents an older green release PR from undoing a newer formula. Publication is globally
   serialized, rejects versions older than the current formula, and both publisher and tap
   CI require the latest stable release. Permit the App to create release branches and
   PRs. The workflow must already exist on the tap default branch before its first formula PR.
3. Publish the fully gated signed release. `publish.yml` first runs `verify-release.sh`, which
   checks successful CI and release runs at the exact commit, the checksum signature,
   every asset, SLSA provenance and immutable image signature/provenance. If any check fails,
   the Homebrew job never runs. It rechecks the formula hash after artifact handoff, then
   mints an installation token limited to `homebrew-tap` with exactly contents and PR write.
   The token expires and is revoked at the end of the job.
4. The job opens `zunder-guard-vX.Y.Z` with the exact verified `zunder-guard.rb` asset, unchanged.
   The tap's CI checks that candidate against the upstream signed formula before letting
   Homebrew execute it, then audits, installs, runs formula tests, starts/restarts a paper
   service, reinstalls and checks state preservation on native macOS/Linux ARM64 and x86-64.
   It reads the existing public installer-test account, requiring standard mode and positive
   equity before setup; changed external state fails the run rather than bypassing Guard.
   It has no venue keys or write permissions and submits no orders. These are four-platform
   paper/package lifecycle checks, not customer mainnet credential or host-reboot proof.
5. Review and merge the passing PR. Record the tag, product commit, tap commit, formula hash
   and native CI URL. Then run the lifecycle checks below. Enabling the variable after the
   event does not replay publication; rerun the failed/skipped publication as appropriate,
   or use the verified manual recovery path. Reruns reuse the release branch and open PR,
   never force-push, and no-op if the default branch already holds the exact signed formula.

The initial/recovery manual path uses the same gate, with existing authorized GitHub access:

```sh
GITHUB_REPOSITORY=zunderlabs/zunder-guard \
  bash deploy/guard/github/verify-release.sh vX.Y.Z /absolute/path/to/new-verified-release
```

Use the verifier's documented tools (`gh`, `cosign`, `slsa-verifier`, `jq`, GNU checksum tools).
Copy only the verified `zunder-guard.rb` into the tap's `Formula/zunder-guard.rb`, compare the
hash, and use the same reviewed PR and tap CI. Do not publish the `.in` template, mutate an
asset after verification, or skip unavailable signatures/provenance to publish early.

App token behavior and inputs: https://github.com/actions/create-github-app-token. The pinned
v3 action uses `client-id`, explicit owner/repository and explicit minimal permissions.

## Release proof matrix

Keep an explicit result for each supported bottle-free archive: macOS ARM64, macOS x86-64, Linux ARM64 and Linux x86-64. Use native machines/VMs where practical; mark emulation as such. A Linux stand-in in a packaging test does not prove a Mac binary runs.

| Check | Required evidence |
|---|---|
| Formula and download | Tap commit; rendered formula hash equals verified signed asset; OS/architecture; exact archive URL; verified archive and installed binary hashes. |
| Package checks | `brew audit --strict --online zunderlabs/tap/zunder-guard`; `brew test zunderlabs/tap/zunder-guard`; installed version and bundled licence notices. Explain any audit exception; do not silently ignore it. |
| Setup and home | Fresh `$(brew --prefix)/var/zunder-guard`; guided init completes; owner-only config/key permissions as applicable; foreground CLI and service use the same home. Never overwrite an existing user's config to obtain a clean test. |
| Pairing | Initial pairing consumed by the intended client; second client created if testing `pair`; restart then `client list` confirms the running Guard accepts it. Do not save client keys or pairing codes in public test logs. |
| Mainnet foreground | Person confirms the real account, API-wallet identity, rules and equity cap; init checks the key without storing it; explicit journal initialization; per-start stdin key and account confirmation; health/status confirm the expected network/account. No bot order is needed for this installation check. |
| Paper service | A separate paper home/config; `brew services start`, health and status; stop and verify stopped; start again, preserving journal/config. Verify its installed service configuration explicitly requests paper. Never repurpose a live home for this test. |
| Licence | Existing valid licence for the configured account via `licence set`; `licence show` and running status report `fee_free`; same result after restart. A version/health check alone is insufficient. Use the already authorized paid rehearsal licence, not a new purchase. |
| Upgrade | Pause the bot and stop Guard, snapshot protected state, upgrade from a real preceding released version when one exists, then compare account/network/rules/client identities/licence and journal continuity; no `init --force`, journal deletion or reset. |
| Removal/reinstall | Stop process/service; `brew uninstall`; verify no process or service remains while Guard home and records remain intact; reinstall the verified version, explicitly start, then verify the same state and licence. |

For the first version, there is no real prior version to upgrade from. Report **upgrade-from-previous-release untested**. Reinstall and state-preservation checks are useful evidence but do not prove a future migration. Do not invent an old release or claim simulated packaging tests are a released-version upgrade.

## Commands for the operator

Run Homebrew as the intended user, not through `sudo`. Start from a clean user account or disposable host if the normal home is already in use:

```sh
brew install zunderlabs/tap/zunder-guard
export ZUNDER_GUARD_HOME="$(brew --prefix)/var/zunder-guard"
zunder-guard init --interactive
zunder-guard check-config
```

Mainnet is supported by the Unix binary in a foreground process, with the existing consent, journal and stdin-key requirements. Do not downgrade the customer's intended network to paper just to make the service check pass. Use a separate paper configuration for `brew services` proof. There is no mainnet service credential handoff in the Homebrew formula; unattended mainnet goes through the Linux systemd-creds installer.

Follow the customer instructions in `/docs/deploy/packages/` for network-specific startup, activation, pairing, restart, upgrade and uninstall. Before resuming a bot, inspect:

```sh
zunder-guard --version
zunder-guard health
zunder-guard licence show
zunder-guard status --json
```

Retain only redacted status assertions, versions, exit codes and artifact hashes in the release receipt. Do not collect config contents, API keys, client keys, complete licence keys or renewal tokens. Hash a protected backup for a state-preservation check if needed; do not attach the backup to the release evidence.

## Completion record

For every row/platform, record `passed`, `failed`, `not applicable` or `pending`, with the command/check, date, release tag, tap commit and a reason for any gap. At preparation time, public tap publication, all signed-artifact installs, mainnet starts, licence/restart, service lifecycle and reinstall checks are **pending**. The release owner is responsible for publication and the installation rehearsals.
