# Receipt Worker registration

This source packet prepares a new standalone Worker and a new separate D1
database. No existing customer Worker, licence service, signer module, binding,
table or secret belongs to the deployment. Source bytes are inventoried in
`worker-inventory.json`; that inventory is not an applied deployment receipt.

## Fixed deployment contents

Upload exactly the five ESM modules listed in the inventory, with
`worker-entry.mjs` as the entrypoint. The only bindings are `DB` (the new D1)
and `PUBLIC_REBOOT_SCOPE` (a closed public JSON record). The schema is the exact
inventoried `relay-schema.sql`. No native helper, test module, workflow, Node
runtime, customer module or private credential is part of this Worker bundle.
Outside `/api/waitlist/ci-reboot/`, the entrypoint returns 404. Missing scope
refuses all experiment routes before D1 access.

The deploying operator must choose and record the actual new Worker/database
identities and compatibility date. Create-only schema application, exact module
readback, binding readback and applied version must be captured from the provider.
Retain the exclusive D1 session; there is no automatic takeover, reset or deletion.
No deployment values in this preparation are placeholders that authorize action.

## Admission after source registration

1. Review and commit the exact projected source in the public repository. The
   three registered workflows and their mirrors must be byte-identical pairs.
2. Record the resulting actual source commit. No source hash is invented here.
3. Create and deploy the new receipt-only Worker/database with scope absent.
   Independently compare actual provider module/binding/schema readbacks with
   the exact source inventory. No signing credential is granted to this Worker.
4. Obtain the actual fixed HTTPS Worker origin and actual deployment/version
   evidence. Apply the closed `PUBLIC_REBOOT_SCOPE` only after these checks.
5. The scope fields are exactly: schema, kind, origin, deployment_sha256, source,
   workflow_ref, repository_id, owner_id, audience, expires_ms and enabled.
   The kind is `applied-public-reboot-relay-scope`; repository ID is
   `1409357189`, owner ID `338317604`, and audience `zunder-public-reboot`.
   The caller workflow is
   `zunderlabs/zunder-guard/.github/workflows/public-reboot.yml@refs/heads/main`.
   Choose the actual bounded expiry at admission, never during preparation.
6. Configure the main-only `release-public-reboot` GitHub environment and actual
   `PUBLIC_REBOOT_EXPECTED_SCOPE`, exact `PUBLIC_REBOOT_NODE_VERSION`, and
   independently admitted vendor `PUBLIC_REBOOT_MAC_NODE_SHA256`. All remain
   missing here. No secret or paid runner is needed for the public receipt path.
7. Dispatch only after independent source and applied-provider admission. The
   Linux controller keeps the original 12-minute observation/15-minute disposal
   bounds; the target performs at most one reboot. Retain actual provider and
   original run/attempt/source/native/boot/cleanup receipts separately.

Source checks, fake SQL/client fixtures and public scanner success do not prove
applied provider scope, a native store, changed physical boot, cleanup, private
credential retention or release readiness. Those values remain false or missing.
