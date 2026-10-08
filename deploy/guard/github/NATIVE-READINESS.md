# Native observations and staged channel publication

Build and sign a draft first. Native service proof gates public Guard release assets; it
does not prove Homebrew or AWS entrypoints. Those channels have separate gates below. `verify-release-assets.sh TAG NEW_DIRECTORY` verifies the
software and source checks needed for a real signed-installer rehearsal. It does not approve
publication. Candidate CI receipts, including Windows `releaseReady=false`, synthetic
fixtures and source-built test programs do not prove the released installer or a host reboot.

Use the actual signed installers on each supported machine-service route. Record the
observations below with redacted logs. Do not turn a pending observation into a passing one
to satisfy the schema. Do not include credentials, full licence keys, configuration files or
client pairing secrets. A maintainer uploads the completed report and adopts its exact logs
as their own attestation; the verifier labels this **operator-attested native rehearsal**.
GitHub uploader identity and software signatures do not cryptographically prove a reboot.

## Collect and upload

1. Authenticate existing human `gh` access to `github.com`. The report uploader must currently
   hold the repository's exact `admin` or `maintain` role. The verifier checks GitHub's uploader
   ID and current permission, not a locally claimed name. Bot/App uploads, plain write access,
   unknown custom roles and unavailable permission APIs are refused. No new credentials or
   approval environment are required.
2. Verify the signed draft in a new folder:

   ```sh
   GITHUB_REPOSITORY=zunderlabs/zunder-guard \
     bash deploy/guard/github/verify-release-assets.sh v1.0.0 /absolute/new/verified-assets
   ```

3. Perform the real signed-installer checks. Upload UTF-8 redacted logs named
   `native-evidence-NAME.txt` to that draft using `gh release upload TAG LOG --repo
   zunderlabs/zunder-guard`. Obtain their GitHub asset IDs and byte sizes from
   `gh api repos/zunderlabs/zunder-guard/releases/RELEASE_ID/assets --paginate`, and hash
   the exact uploaded bytes with SHA-256. Logs must each be nonempty and at most 1 MiB;
   at most 32 logs and 8 MiB combined. No external log URLs or archives are accepted.
4. Write `native-readiness.json` using the contract below, naming your actual GitHub user
   ID/login from `gh api user`. Upload it with existing human `gh release upload` access.
   The report itself is limited to 256 KiB. Replacing evidence requires a deliberate new
   report with the new IDs/hashes. Do not modify the already signed `SHA256SUMS`.
5. Use the official promotion command with a fresh output directory:

   ```sh
   GITHUB_REPOSITORY=zunderlabs/zunder-guard \
     bash deploy/guard/github/promote-release.sh v1.0.0 /absolute/new/promotion-assets
   ```

This calls the full `verify-release.sh` gate and rechecks the exact draft/evidence immediately
before promotion. It authenticates the actual human CLI token through `/user`; a GitHub
Actions/App token cannot silently use this route. Human CLI publication triggers the existing
`publish.yml`, which repeats the full gate before downstream writes. Inspect that workflow's
result. Do not use the unguarded Publish button or the asset-only helper to bypass readiness.
Repository administrators inherently retain the ability to bypass repository tooling; this
gate prevents omissions in the official route, not malicious administrator actions.

## Report contract (schema 1)

The top-level object has exactly these fields:

| Field | Value |
|---|---|
| `schema` | Integer `1` |
| `kind` | `operator-attested-native-rehearsal` |
| `operator` | Object with your numeric `id` and `login`; must match the asset's authenticated uploader |
| `repository` | Object with current numeric repository `id` and `name` equal to `zunderlabs/zunder-guard` |
| `release_id`, `tag`, `source` | Actual numeric GitHub release ID, exact `vX.Y.Z` tag and its 40-character source commit |
| `manifest_sha256` | SHA-256 of the exact signed `SHA256SUMS` bytes |
| `image` | Exact immutable reference from the signed image descriptor |
| `artifacts` | Object mapping **every** signed manifest filename to its SHA-256, not a selected subset |
| `logs` | Array of objects with numeric `id`, `name`, positive byte `size` and lowercase `sha256` |
| `platforms` | Complete matrix below; not a report-selected subset |

The platform keys are `linux-amd64-systemd`, `linux-arm64-systemd`,
`darwin-amd64-keychain`, `darwin-arm64-keychain`, `windows-amd64-scm`,
`linux-amd64-container` and `linux-arm64-container`. Each has `os` (observed OS/build),
`host` (redacted identifier) and `checks`. Required signed archives and helpers are also
checked against release inventory. Every software asset's current GitHub SHA-256 digest
must agree with the authenticated manifest; missing API digest fails closed.

Every platform's checks contain exactly:

- `signed_install`: actual published installer bytes and fresh setup.
- `credential_confinement`: protected credential and stdin handoff; redacted leak checks.
- `account_network_risk`: intended account/network/cap and risk readiness.
- `pairing`: initial client can connect without exposing its key in logs.
- `fee_licence`: intended licence or approved builder state, preserved across restart.
- `explicit_stop`, `restart`, `crash_recovery`: actual lifecycle, including staying stopped.
- `state_preservation`: same configuration/client/licence/journal continuity.
- `host_reboot`: an actual host restart with distinct `boot_before` and `boot_after` identifiers.
- `signed_reinstall`, `interrupted_replacement_rollback`: actual signed reinstall and failed
  replacement/recovery, retaining state.
- `prior_version_upgrade`: upgrade from a preceding stable release, if one exists.

Windows additionally needs `pre_login_readiness`; its UTC `ready_at` must precede
`first_interactive_login_at` on that reboot, with supporting SCM/session/boot evidence.
A post-login health command alone is insufficient. Containers additionally need
`daemon_restart`, `single_instance` and `interrupted_setup_boot_inhibition`.

Each check is an object with `result`, `observed_at`, `observation` and `logs` (nonempty list
of referenced log asset IDs). `result` must be `passed`; observations are bounded explanatory
text, and UTC timestamps use `YYYY-MM-DDTHH:MM:SSZ`, after software upload and before report
upload. `host_reboot` also contains the two boot IDs; `pre_login_readiness` also contains its
two timestamps. No other fields are accepted. All attached logs must be referenced.

Only `prior_version_upgrade` may use `not_applicable:first_release`, and only when GitHub
has no preceding stable release. Reinstall/rollback remain mandatory. There is no arbitrary
expiry date: changed tag/source/software/evidence invalidates the exact binding. Unknown,
missing, failed, pending or boolean shortcuts are refused. Keep incomplete reports locally;
there is no auto-generated successful report template.

## Verification and limits

The verifier uses GitHub release asset metadata and the current collaborator-permission API,
requires the same numeric identities, bounds API pages/timeouts/bytes and JSON depth, and
rechecks metadata and authority before promotion. It downloads only same-release asset IDs;
it never executes evidence or extracts an archive. Its tests use conspicuously synthetic API
fixtures, not real readiness receipts. Passing validator tests does not complete any native
observation or prove the real token can call the GitHub endpoints.

## Homebrew and AWS: prove the actual public entrypoint before channel publication

Do not add these checks to the draft-to-public Guard gate: the unchanged signed formula and
rendered CloudFormation template refer to `/releases/download/TAG/...`, which is inaccessible
anonymously while the GitHub release is a draft. Rewriting URLs, substituting fixtures, or
seeding an archive cache does not prove the customer download/bootstrap path.

After native proof permits the immutable Guard release to become public:

1. **Homebrew:** on native Linux and macOS, each AMD64 and ARM64, place the exact signed
   `zunder-guard.rb` in a disposable local rehearsal tap without changing its bytes or URLs.
   Use a fresh Homebrew cache so installation actually fetches the published signed archive.
   Check install, version/notices, configured paths, initialization/pairing, licence activation,
   service start/stop/restart, state-preserving signed reinstall and uninstall. Test a prior
   stable upgrade when one exists. This validates the formula before the official tap PR;
   the tap's own CI and reviewed merge remain subsequent checks.
2. **AWS:** submit the exact signed `cloudformation.yaml` through CloudFormation's template
   file upload in Tokyo, on ARM64. No official S3 launch-link copy is needed for this
   rehearsal. Observe the real pinned loader bootstrap, stack creation signal and health,
   SSM access, pairing, safe defaults, service lifecycle/state retention and cleanup of the
   disposable stack/retained storage. Hash the unchanged template and retain redacted
   observations. Use existing authorized resources/accounts; this validator provisions none.
3. Upload a separate `homebrew-readiness.json` or `aws-readiness.json`, with its bounded
   redacted log assets. These use the same identity, release/source/manifest/image and full
   artifact-map binding as the native report. The expected kind is respectively
   `operator-attested-homebrew-channel` or `operator-attested-aws-channel`. Channel observation
   timestamps must be after this release's `published_at`. Missing/pending evidence blocks
   its publisher independently; native success cannot substitute for it.

Homebrew's exact platform keys are `linux-amd64-homebrew`, `linux-arm64-homebrew`,
`darwin-amd64-homebrew`, `darwin-arm64-homebrew`. Each uses the same `os`, `host`, `checks`
shape, with these exact checks: `signed_formula_install`, `installed_binary_and_notices`,
`configuration_paths`, `init_pairing`, `licence_activation`, `service_start_stop_restart`,
`signed_reinstall_state_preservation`, `uninstall_preserves_state`, `prior_version_upgrade`.
Only the final check has the same narrowly verified first-release exception.

AWS's single key is `aws-ap-northeast-1-arm64`. Its checks are `signed_template_stack`,
`pinned_loader_bootstrap`, `creation_signal_health`, `ssm_access`, `pairing`, `safe_defaults`,
`lifecycle_state_preservation`, `cleanup_retained_state`. `signed_template_stack` additionally
requires `region: "ap-northeast-1"` and `architecture: "arm64"`. No generic first-release
exception applies to these checks. All checks retain `result`, `observed_at`, `observation`
and bound `logs`; the global artifact map must include the exact signed formula/template.

Run a read-only preflight after the full verifier has prepared a fresh local folder:

```sh
GITHUB_REPOSITORY=zunderlabs/zunder-guard   python3 -B deploy/guard/github/native-readiness.py verify v1.0.0 /absolute/verified-assets --channel homebrew
# Use --channel aws for the template route.
```

The publisher runs this check before minting the tap token or acquiring AWS publishing
credentials. It rechecks native evidence too. The shared verified Actions artifact contains
only release bytes and public source/evidence bindings, including the hidden source marker.

If publishing variables are enabled before evidence exists, only the corresponding channel
job fails. After uploading genuine evidence, rerun that specific failed job from the existing
publish run, not the entire release pipeline: `gh run rerun RUN_ID --job JOB_ID --repo
zunderlabs/zunder-guard`. GitHub's job rerun includes dependent jobs, and these channel jobs
have none. Check its result and current artifact availability. Enabling a previously disabled
variable does not schedule publication: request a rerun of that specific skipped job and
confirm GitHub actually starts it with the variable enabled. If it stays skipped or the
verified artifact has expired, stop and repair the scoped publication run; do not republish
Guard merely to trigger every channel again. No channel success is inferred from a skip.

**Website activation is an operator gate.** The site currently has one
`PUBLIC_GUARD_RELEASED` flag. Leave it off until native release readiness, all four Homebrew
entrypoints and official tap installation, AWS bootstrap and the published launch template,
and the other advertised install links have actually passed. The publication code enforces
native and per-channel gates; it does not read or enforce the website flag. Source preparation
or a public Guard asset alone does not mean all advertised entrypoints are ready.

Winget remains deferred and unadvertised; this addition does not create a winget readiness
claim or enable its publication variable.
