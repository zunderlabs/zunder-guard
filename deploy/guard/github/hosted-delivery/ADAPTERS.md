# Public operations adapters

These are source-only Pages and existing production Worker adapters for the public admission controller. They do not grant authority, register a workflow, populate a target/admission, or prove a cloud deployment. The private producer artifact is treated as data throughout. Private JavaScript, configuration, SQL, npm hooks and helper scripts are never executed on the credential-bearing runner.

## Integration

The protected `zunderlabs/zunder-guard` main checkout is the control source. Its effective branch protection and branch-type main-only environments must be established; a label called main is not sufficient. The immutable OIDC repository prefix remains `repo:zunderlabs@338317604/zunder-guard@1409357189`. A dedicated App installed only on private `zunderlabs/zunder` needs Metadata, Actions and Contents read. App authority is separate from Cloudflare and signer grants. The existing `admit.py` reader must authenticate the reviewed public admission and exact schema-2 producer payload, return its data mapping, and run again immediately before publication via the required `recheck` callback. No arbitrary dispatch source/run/path is admitted.

The future public controller calls `reviewed_policy(target)` and `publish_pages(...)` or `publish_worker(...)` from this public source. It must never import a helper from the private payload. Install the single public MIT dependency before adding publisher/reader credentials:

```sh
npm ci --ignore-scripts --no-audit --no-fund --prefix deploy/guard/github/hosted-delivery/tools
```

The lock pins `@noble/hashes` 2.0.1 by npm SHA-512 integrity. Node 24 or newer and Python 3.11 or newer are required. No Wrangler/sharp/libvips dependency tree is introduced. The public release gate additionally requires the normal pinned GitHub CLI, cosign and SLSA verifier tool installation used by the existing public release workflow. Integrate these exact current authority files from the reviewed handover source, without replacing them with a parser or old website copies:

- `deploy/guard/github/verify-release.sh`
- `deploy/guard/github/verify-release-assets.sh`
- `deploy/guard/github/native-readiness.py`
- `deploy/guard/github/machine-evidence-policy.json`

Missing files/marker output, signature, provenance, native/channel acceptance, checksum inventory, tag/source or release identity mismatch fail before a Pages provider operation. The verifier subprocess receives only public GitHub read authority and normal runtime paths. It receives no private App, Cloudflare, Access or signer credentials.

The public controller must supply separately scoped grants: Pages Edit/Read for the reviewed account/project (Cloudflare's actual available scope must be verified); Worker Scripts Edit/Read for the existing worker; Zone Read and Worker Routes Read for existing `zunderlabs.com`; public GitHub Actions/release and GHCR read needed by the full gate; and Access service-token credentials only for preview/staging readonly smoke. No D1 write, route edit, account allocation, private signing-key or SQL authority is needed by these adapters. Do not print the private payload, provider bodies, grants or token JWT, or upload/cache any private artifact in a public run. Receipts contain opaque IDs and hashes only. Tokens must remain masked by the caller even if a library fails outside these bounded helpers.

## Reviewed target policies

Commit actual policies under this public source's `targets/<target>.json` through ordinary protected-main review. None are included or fabricated here. Common fields are `schema: 1`, fixed `target`, actual 32-hex `accountId`. Pages adds fixed `project`, actual production `branch`, and `requireAccess` true for preview/staging and false for production. Staging also adds an actual isolated `stagingMerchant`, not a synthetic fixture. Fixed destinations are:

| Target | Folder | Project | Runtime origin |
| --- | --- | --- | --- |
| website-preview | preview | zunder-design-preview | https://zunder-design-preview.pages.dev |
| website-staging | staging | zunder-testnet-journey | https://staging.zunderlabs.com |
| website-production | production | zunderlabs | https://zunderlabs.com |

Production Pages branch uploads are used for each distinct project, including the preview project. Existing preview `CUSTOMER_API` binding and staging profile, explicit enablement, isolated API/inbox bindings are checked before and after upload. Staging artifacts currently produced with the offline merchant fixture will fail until the actual producer handoff exists. Applied Access policies need their separate owner readback; an authenticated GET alone is deliberately not reported as policy proof.

The [official Pages project GET contract](https://developers.cloudflare.com/api/resources/pages/subresources/projects/methods/get/) exposes `deployment_configs.production.services`, not Wrangler's configuration field `service_bindings`. These shapes are not aliased. Root's authorized readonly inspection observed the preview API object `services: {CUSTOMER_API: {service: "zunder-waitlist", environment: ""}}`; this source lane did not perform that account read. The adapter accepts only that empty vendor-default production environment or explicit `production`, the exact expected service names and binding inventory, and absent entrypoint (default handler). Missing environment, named/unknown entrypoint, additional bindings and legacy/internal provider-field shapes fail closed. The root observation establishes metadata shape only, not a publication or complete runtime proof.

Worker policy adds actual `zoneId`, `worker: "zunder-waitlist"`, exact `compatibilityDate`, `compatibilityFlags: []`, reviewed public `vars`, exact D1 `databaseId`, and `migrations: "none"`. Public vars must include production/mainnet/site identity and `SALES_EVM_NETWORKS: "arbitrum,base"`. Existing production vars and DB binding are checked against active metadata; all existing binding types, including secret bindings, are preserved without reading secret values. The adapter neither changes vars nor routes nor secrets. A configuration change must first have an explicit separately reviewed provisioning path; this uploader cannot silently establish it.

## Direct upload and observation

Pages uses the official REST direct-upload form and asset protocol. The account publisher token obtains the project upload JWT; only that JWT is used for `/pages/assets/check-missing`, `/upload` and `/upsert-hashes`. The publisher token is used only at the fixed account/project API. The exact SDK content hash is BLAKE3 of base64 file contents plus extension, truncated to 32 hex characters. Static manifests use leading-slash paths. `_worker.js`, `_headers`, `_redirects` and `_routes.json` travel as separate form file parts, never static assets. Raw bundled `_worker.js` bytes are not imported or rebuilt. Unsupported Worker directories/bundles, functions and private tool/config hooks fail closed. All provider requests refuse redirects. Writes are not automatically retried after an uncertain response.

The deployment response and subsequent reads must bind project, production environment, ad-hoc trigger, clean commit, branch and exact admitted source SHA. Polling must reach successful deploy. Python then checks that the project's canonical deployment is the returned ID, checks exact remote release-pin/profile bytes and six readonly site routes, and rechecks the canonical ID. This observes applied state; it does not prove purchase/email/licence success or cryptographic per-request identity.

Worker performs one script PUT of admitted flat modules and public-authored upload metadata. It checks the existing zone/account, single 100% active version, compatibility/runtime/bindings, exact D1, route ownership and absence of an overriding licence-status route. After upload it joins version metadata ETag to raw content `/content/v2`, verifies every module hash, unchanged bindings/routes, observes an uncached readonly `/api/licence/status` GET, and rereads the applied snapshot. The status must report open mainnet and exactly Hyperliquid/Arbitrum/Base. No quote, order, email, admin, wallet or payment action occurs.

The content readback requires strong matching ETag, `cf-entrypoint`, and named multipart modules. Those response headers must be confirmed with the first authorized readonly live inspection; an unsupported API shape stops before uploading rather than assuming a match. Status carries no version ID, so the receipt honestly reports `responseVersionIdentity: false`. Other Worker settings such as cron/observability/tail configuration are not asserted by this bounded adapter.

D1 SQL remains admitted data and is never run. `migrations: "apply"` is refused. Therefore this adapter is ready only for a no-migration update of an already provisioned, compatible database. A release requiring schema changes still needs an explicit public-reviewed exact SQL/migration ledger path and database backup/recovery acceptance; this implementation does not claim to close that path.

## Validation and sources

Offline tests exercise the provider protocol, credential separation, private raw Worker transport, symlink/config refusal, full-gate-before-write ordering, exact source/deployment binding, existing routes/DB/binding preservation and bracketed uncached status observation. Synthetic release markers are unit-test fixtures only, never accepted evidence for a real release.

```sh
python3 -I -B deploy/guard/github/hosted-delivery/test_cloud_delivery.py
node --test deploy/guard/github/hosted-delivery/pages-upload.test.mjs
```

Primary contracts checked during implementation: [Cloudflare deployment form](https://developers.cloudflare.com/api/resources/pages/subresources/projects/subresources/deployments/methods/create/), [official asset upload protocol](https://github.com/cloudflare/workers-sdk/blob/main/packages/wrangler/src/pages/upload.ts), [official hash contract](https://github.com/cloudflare/workers-sdk/blob/main/packages/deploy-helpers/src/deploy/helpers/hash.ts), [asset exclusions](https://github.com/cloudflare/workers-sdk/blob/main/packages/wrangler/src/pages/validate.ts), [noble MIT licence](https://github.com/paulmillr/noble-hashes/blob/2.0.1/LICENSE). External live operations have not been performed by this source lane.
