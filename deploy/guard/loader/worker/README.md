# Installer publication storage

`store.ts` serves the eight installer and release-state paths on `zunderlabs.com`.
A single SQLite-backed Durable Object commits each channel's predicate, Sigstore
bundle and Unix/Windows loader bytes together. The same transaction records each
build's lifecycle head. Stale channel heads, skipped revisions, wrong predecessors,
superseded staging builds and transitions after withdrawal return HTTP 409 without
changing published bytes. A withdrawn channel returns HTTP 410 for its loaders and
continues to expose the withdrawal predicate and bundle.

The trusted publisher POSTs `/guard/publish` with a bearer token from the Worker
secret `INSTALLER_PUBLISH_TOKEN`. Its JSON has exactly these fields:

- `channel`: `staging` or `canonical`.
- `expected`: the current channel's predicate digest, or null for an empty channel.
- `predicate`: the original canonical JSON string authenticated by the publisher.
- `bundle`: the verified Sigstore bundle as a JSON string.
- `unix`, `windows`: the associated loader scripts as strings.

**The publisher must authenticate the build manifest, lifecycle, journey evidence
and loader signatures before making this request.** This storage service performs
transactional lifecycle checks; it does not implement Sigstore verification. The
publisher token grants release-writing authority and must never appear in logs.
The request is capped at 2 MiB. Success returns HTTP 201 with the predicate digest;
unknown outcomes must be reconciled by reading the channel before retrying.

Public responses use `cache-control: no-cache`, CORS `*`, and
`x-zunder-state-sha256`. Consumers reading multiple endpoints must compare that
header and retry if an update occurred between reads. Verify the original predicate
and bundle before trusting state. Atomic storage does not make separate HTTP reads
an atomic snapshot.

The Wrangler configuration has no account identifiers, routes or credentials.
Provision the Worker secret and exact public paths plus `/guard/publish` in the
intended account before deployment. Local tests use the pinned stable Miniflare
runtime and the same compatibility date as deployment. Run `npm run check` and
`npm test` from `deploy/guard/journeys`. Strict checking includes this source;
`skipLibCheck` skips incompatible declarations in external runtime dependencies.
Miniflare's sharp and undici dependencies are pinned to patched releases.

`guard_harness.publication.prepare` verifies the captured build manifest and loaders
against Sigstore-signed SHA256SUMS, checks the immutable loader descriptors, and
uses the lifecycle/journey verifiers before preparing the capsule. Its `publish`
function sends only to the fixed TLS endpoint, refuses redirects and checks the
exact receipt digest. It preserves Windows CRLF bytes.

Durable-head acquisition, lifecycle workflow integration, canonical rollback to a
previous verified release and hosted deployment remain separate release work.
