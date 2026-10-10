# Public repository handoff controllers

Source preparation only. No grants, workflow registration, repository writes,
release acceptance or publication were performed. The previous private
credential-bearing handoff jobs must not receive publisher secrets: the private
organization's free plan cannot enforce their assumed protection/environment
boundary. This successor places both write controllers in public Guard's
protected main and branch-type-main-only public environments.

## Private source → public snapshot PR

Install the credential-free private template
`deploy/repo-handoffs/guard-source-artifact.yml` as
`.github/workflows/guard-source-artifact.yml`, together with
`deploy/repo-handoffs/source-artifact.py`. It runs only on private push main and
exports the exact platform SHA using the unchanged existing exporter, closure,
licence generation and scan. No `--no-cargo`, extra accepted private crate,
publisher App, provider key, environment or OIDC grant is used. Its short-lived
private artifact contains only the sanitized tar, private exporter report and
schema-2 sealed inventory. Private source/history never enters public artifacts.

The protected public controller's reviewed `repo-admissions/<id>.json` record
has exact keys `{schema:1,id,mode:"source",version,admission,sourceCi}`.
`admission` is the existing strict public artifact admission schema, with target
`guard-source-export`, kind `source-snapshot`, null `config`/`releasePin`, exact
private repository ID/source/workflow blob/run/latest attempt/artifact ID/digest
and inventory hash. `sourceCi` binds `{workflowId,workflowPath,workflowBlob,runId,
runAttempt,jobName}` to `.github/workflows/ci.yml` and actual job
`fmt · clippy · test · deny`. The controller requires that successful push-main
job and all four named steps to succeed, and rechecks the latest run/source
before writes. Current private main is a freshness check; authorization is the
reviewed public record, not mutable private main.

The archive is admitted using the existing public reader, extracted without
links, traversal, special files, duplicates or set-id modes, and rescanned using
`repo-scan.py`. That scanner preserves the existing exporter predicates, public
fixture exceptions and crate set. Its generated encoded predicate table prevents
the scanner source matching its own diagnostic patterns; this is ordinary public
policy data, not a secret encoding or a policy exception. The focused tests
compare every original predicate/flag and behavior before export. No exporter
allow-list was changed, and the full private exporter remains private.

Only after verification does the official action mint a dedicated public App
token. The trusted controller uses Git data APIs to prepare the sanitized tree
and a new PR branch, preserving executable modes. It never runs candidate code,
workflows, hooks, Git configuration or package installation. No main update,
force push, merge, tag or release exists. Workspace downgrades are refused; an
existing branch fails closed until its candidate, base, head and PR state are
explicitly reconciled; no existing PR is reported as this admitted proposal.
Changes to the public workflow authority
remain subject to the public PR's review/check boundary.

## Accepted public release → private website pin PR

A site record has exact keys `{schema:1,id,mode:"site",releasePin}`. `releasePin`
is the full existing schema-1 accepted release data, including every signed asset
and selected delivered channel. The public controller calls the same complete
public `verify-release.sh`/native/channel gate used by delivery: source CI,
signature, SLSA, OCI, native lifecycle/activation/cleanup, exact release ID/source,
signed inventory and actual enabled-channel endpoint bytes must all agree.
Draft, unaccepted or invented release metadata fails closed.

Only the prior `web/release-pins/guard.json` blob is read from private main as
JSON data; the controller never checks out, imports or executes private code.
`repo-release-schema.ts` is a reviewed byte-identical copy of the website's
schema parser, and `repo-compare-pin.ts` applies its existing downgrade,
same-version identity and channel-regression contract. Synchronize this public
schema explicitly whenever the private schema changes. A missing prior JSON
permits first integration, not bypass of new-pin verification. A malformed or
linked prior JSON is refused.

After minting a separate private-site PR App, the controller repeats the complete
release admission and prepares only that JSON blob through Git APIs against
fresh private main. A changed destination base aborts before branch/PR creation.
Private application scripts, package manifests and checkout hooks never execute
with the token. This workflow opens a PR; it neither merges nor deploys. The
website builds must still consume the tracked pin, run both profiles and recheck
accepted release identity before delivery.

## Exact unapplied configuration

- Public main's effective review/check/no-bypass/force-push settings and public
  environments `guard-source-export` and `guard-site-release-update` must be
  observed. Each permits **branch-type main only**, excluding all tags. Normal
  protected-source review replaces unavailable private protection; no additional
  discretionary per-run reviewer gate is proposed.
- Both public environments use the existing proposed private-reader App, installed
  only on `zunderlabs/zunder`: Metadata read, Actions read, Contents read. Names:
  `PRIVATE_ARTIFACT_READER_APP_CLIENT_ID` and
  `PRIVATE_ARTIFACT_READER_APP_PRIVATE_KEY`. No private write/Admin/Workflows scope.
- Public `guard-source-export` receives a separate App installed only on public
  `zunderlabs/zunder-guard`, with Contents, Pull requests and Workflows write:
  `GUARD_EXPORT_APP_CLIENT_ID` / `GUARD_EXPORT_APP_PRIVATE_KEY`. Workflows write is
  necessary to open an exported workflow diff, not merge it.
- Public `guard-site-release-update` receives a different App installed only on
  private `zunderlabs/zunder`, with Contents and Pull requests write:
  `GUARD_SITE_APP_CLIENT_ID` / `GUARD_SITE_APP_PRIVATE_KEY`. No Actions/Workflows
  write is needed. Do not reuse the Homebrew App or a personal token.
- Set public environment `HOSTED_REPO_HANDOFFS_ENABLED=true` only after the actual
  boundary and scopes are verified. The workflow uses minimum public read rights
  and pinned official App-token actions, with automatic token revocation.
- Real public admission records disclose private SHA/run/artifact/workflow-blob
  identities. That limited metadata disclosure and each newly scoped App grant
  require explicit acceptance before application. No real records are installed
  here, and no private payload, report or customer data is uploaded publicly.
- Public controller integration must include the current independently reviewed
  `admit.py`, `cloud_delivery.py` and full public signed/native/channel verifier
  dependencies. This lane neither copied obsolete verifier code nor changed
  other owners' files. The new public controller is source-only until those
  exact dependencies, source producer and grants are integrated.
- Retire the credential-bearing private handoff jobs when enabling this successor.
  No secrets should remain in mutable private Actions during transition.

Dispatch selects only an existing protected record ID and its mode. `publish:
false` verifies without a destination token; `publish: true` verifies before
minting and then readmits immediately before writing. There is no arbitrary
`latest`, source SHA, control file, destination or caller-supplied verification
marker. This minimal record path can be invoked by the release coordinator once
an accepted record reaches public main; no broad cross-repository dispatch key
or automatic self-admission is introduced.

## Source validation

`python3 -I -B deploy/guard/github/hosted-delivery/repo-test.py` exercises source
archive policy, exact CI/rerun/skipped-step refusal, writer operation fences,
private pin data-only handling, actual TypeScript schema comparison and base-race
refusal. The private producer has three inert sealing tests. Run actionlint on
both templates and strict TypeScript checks on the two public schema helpers.
These checks prove finite helper behavior, not installed App scope, hosted
execution, release acceptance or deployed user-journey success.

R2 packet freezes the exact final cloud-adapter dependency bytes alongside the
source. Review that separate cloud-adapter receipt; mutable worktree files must
not substitute for the recorded dependency digest. The missing native machine
policy remains an explicit fail-closed integration prerequisite.
