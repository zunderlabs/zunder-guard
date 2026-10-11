# Canonical installer publication

`verify.yml` stages signed loaders and lifecycle state through the installer-store API.
`promote.yml` admits a stable release only after the independently authenticated complete
journey gate, then publishes canonical `/i`, `/i.ps1`, `/guard/release.json` and its
`.sigstore` bundle atomically with a captured predecessor digest. The website consumes
this authenticated state; publication does not rebuild website source.

The private producer owns installer-store deployment, durable storage, exact route custody
and token provisioning. Consumer workflow environments `staging` and `promote` receive
`INSTALLER_PUBLISH_TOKEN`; production monitor receives only `MONITOR_ALERT_TOKEN`. No
Cloudflare account or zone administration credential is needed by these consumers.

Publication authenticates checksums, provenance, source and lifecycle/journey attestations
before sending a bounded request to the fixed TLS endpoint. Both loaders remain unchanged
signed release assets. Public query aliases are not promised. Exact readback compares both
loader bytes, predicate and bundle against one authenticated capsule with equal digest
headers. Redirects, races, partial responses and unknown POST outcomes fail without retry.

Promotion captures prior channel subjects. A failed canonical smoke invokes authenticated
withdrawal and compare-and-swap restoration. An absent predecessor cannot be invented.
A prepared rollback path or unsuccessful command does not establish actual restoration.

The former direct Cloudflare publisher and its mock tests are historical helper regressions,
not the active release entrypoint. Never dispatch an operator publisher to bypass the full
gate. Required consumer behavior is covered by harness publication, state, gate, promotion
and canonical-readback tests; hosted evidence is still required.
