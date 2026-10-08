# Canonical installer publication

`publish.yml`'s `installers` job serves the exact signature-verified release assets at
`https://zunderlabs.com/i` and `https://zunderlabs.com/i.ps1`. It does not rebuild the
website or rewrite other routes. Public query-string aliases are not promised; use these
canonical URLs exactly. The loaders still independently verify the downloaded installer.

## One-time setup

Create protected GitHub environment `installer-publish`. Set `INSTALLER_PUBLISH=enabled`
in repository variables. Set `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_ZONE_ID` in this
environment. Secret `CLOUDFLARE_INSTALLER_TOKEN` is a narrowly scoped Cloudflare API token:
Workers Scripts Edit on the one account, Workers Routes Edit and Zone Read on the
`zunderlabs.com` zone. No DNS edits or global API key. Keep environment approval rules
consistent with the release gate; ordinary workflow code must not bypass it.

The fixed Worker is `zunder-guard-installers`; reserve that name for this publisher.
Before every upload, the publisher checks the account-wide script inventory. An existing
script must carry exactly the managed tag `zunder-guard-canonical-installers-v1` and have
no bindings, logpush or tail consumers. An unrecognized existing script is refused even
when it has no route in this zone. Do not tag another application to bypass this check;
choose and review a migration separately. First publication adds the marker, allowing safe
retries after a partial routing failure. Reserve this script exclusively for this pipeline;
do not attach other domains, routes, bindings or workflows to it.
Canonical DNS must already be proxied through Cloudflare. Existing exact `/i` or `/i.ps1`
Worker routes owned by another script cause publication to stop before mutation. Resolve
that ownership deliberately, not by deleting unrelated routes. The uploader validates the
zone's account and domain before making any change.

## Pipeline

Release publication → full existing signature/provenance/exact-source verification →
verified artifact → serialized installer job → latest-stable release recheck → local
loader checksum recheck → Worker upload → two exact routes → public SHA256 comparison.

Older delayed runs refuse to replace current loaders. Repeating the current release is
idempotent. Partial upload/routing/propagation failure fails the job; rerun the same current
release after diagnosis. This is not an atomic multi-route transaction. Do not delete a
published tag or change its assets to fix a deployment. Worker route fail-open behavior,
plan quotas and zone routing must be checked in the real rehearsal.

## Local validation

```sh
python3 deploy/guard/github/test_publish_loaders.py
python3 deploy/guard/github/publish-loaders.py --release-dir rel --tag v1.0.0 --render-only /tmp/guard-installers.mjs
```

Rendering needs verified `i`, `i.ps1` and `SHA256SUMS` from the same release. It does not
contact Cloudflare. Tests use synthetic loader bytes and mocked API calls, including actual
Node execution of the generated Worker. A protected CI publication and public-byte proof
remain required before marking the route available.

API contracts: [Worker module upload](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/methods/update/),
[Worker routes](https://developers.cloudflare.com/api/resources/workers/subresources/routes/),
[routing semantics](https://developers.cloudflare.com/workers/configuration/routing/routes/).
