# Public host reboot observation

This is a source implementation for one public observation on an original
`macos-15` Apple Silicon runner, with an independent `ubuntu-24.04` controller.
It has not been deployed, registered or executed. It receives no trading,
licence, issuer, AWS or Cloudflare administration keys. The Mac receipt identity
only signs public observations. FileVault-off runners remain ineligible for
private credential retention acceptance.

## Execution path

1. Both jobs run concurrently in the same public run, attempt and source. The
   Linux controller samples its sole wall/monotonic origin before waiting for
   the public helper inventory. The Mac target builds the exact reviewed helper
   and publishes one data-only inventory. Linux checks current-attempt Actions
   metadata, archive SHA256, the bounded single-entry ZIP, actual target Jobs
   identity, source module hashes and the selected Node binary digest.
2. Fixed HTTPS scope readback must match the deployment/source that the release
   pipeline independently admitted from actual provider readback. Missing,
   disabled, expired or mismatched configuration refuses dispatch. Unsigned
   caller JSON cannot create the sealed scope object. The scope is public;
   neither job nor boot helper receives a provider administration credential.
3. The relay verifies GitHub RS256/JWKS, exact immutable repository/owner IDs,
   run/attempt/source, main ref, environment and separate reusable workflow
   roles, plus the unique actual in-progress target Jobs identity. Controller
   enrollment records its ephemeral public receipt key. A create-only D1 row
   and single exclusive slot cannot be replaced or renewed on a conflict.
4. The controller signs each fresh challenge. The Mac stores its separate
   Ed25519 identity in a session-specific System Keychain item with an exact
   helper access list. Only anonymous bounded pipes carry receipt seeds. Native
   calls disable interactive Keychain prompts. Kernel boot UUID/time, hardware
   UUID hash, uptime and actual parent process birth come from the pinned C/Swift
   getter, rather than caller-supplied timestamps.
5. Actual PREBOOT and ARMED ACKs precede one create-only durable reboot marker
   and one `/sbin/shutdown -r now`. The system LaunchDaemon uses a pinned copied
   runtime, fixed arguments and clean environment. Its one-shot wrapper exits;
   `AbandonProcessGroup` permits its separately captured collectors to continue.
   Every actual boot starts an independent disposal watcher before any scope or
   network-dependent POSTBOOT collector. Failure to spawn the watcher refuses
   the observer. An expired or slow boot starts disposal only.
   No user login, runner resumption or replacement job is accepted as reboot.
6. POSTBOOT requires the same machine/marker and a changed kernel boot UUID,
   boot time and observer birth, with uptime at most 120 seconds. The surviving
   controller retains its original 12-minute observation and 15-minute cleanup
   cutoffs. Native postboot clocks never restore the Linux monotonic clock.
7. A separate collector confirms the original facts child exited, removes only
   the exact inactive registration, checks a positive launchd control and known
   absence response, deletes only the captured Keychain persistent item after
   matching its public key, and unlinks captured file identities. Only after
   those operations and fresh absence does it sign CLEANUP. The preboot expiry
   collector, replacement postboot watcher and expired-boot path dispose owned
   resources without signing or rebooting. Every watcher uses the original
   absolute 15-minute cutoff and remaining monotonic interval. Clock rollback
   stops waiting and disposes conservatively; it cannot renew observation. Unknown ownership or mutation response leaves HOLD, not a retry.

Every challenge/event D1 write compares original binding, origin, expected
version, state, sequence, enrolled key and outstanding nonce in one conditional
statement requiring exactly one returned row. Lost mutation responses are
UNKNOWN. Target readback admits the distinct CAS challenge transition: one
version forward with the same sequence, prior signed phase and fresh nonce.
Changed phase, prior binding or nonce refuses. An already completed slot remains retained; subsequent experiments
require an explicitly reviewed retirement procedure, not an automatic takeover.

## Applied configuration before dispatch

Deploy `worker-entry.mjs` as a new dedicated receipt-only Worker with a new
separate D1 database. Apply only the exact `relay-schema.sql` to that database.
The deployment module inventory is `worker-inventory.json`; it contains no
customer route, signing service, administration credential or customer table.
The wrapper returns 404 outside the unchanged `/api/waitlist/ci-reboot/` prefix.
`PUBLIC_REBOOT_SCOPE` defaults absent and must describe the independently
verified active module/deployment, fixed HTTPS origin, exact source, workflow
reference, immutable IDs, audience and bounded expiry. Its response is not a
substitute for independent provider module/version readback. The unused
`relay-worker.ts` export remains for source compatibility; it is not deployed.
Actual Worker identity, database identity, source commit, provider deployment,
expiry and selected runtime pins remain unset until their actual admission.

Register the three exact files in `.github/workflows/` (mirrored under
`deploy/guard/github/workflows/`), with a
main-only `release-public-reboot` environment. Set `PUBLIC_REBOOT_EXPECTED_SCOPE`
to the matching closed JSON record, `PUBLIC_REBOOT_NODE_VERSION` to an exact
reviewed Node 24 version, and `PUBLIC_REBOOT_MAC_NODE_SHA256` to the independently
verified vendor binary digest for that Apple Silicon runtime. Missing values or
a different toolcache binary refuse before native setup. No additional config
signer, private key grant, paid runner or AWS compute is required.

The native store, launchd output/API shapes, hosted persistence and actual reboot
remain runtime facts to obtain from the first admitted hosted experiment. Syntax
checks and fake transport/SQL fixtures do not prove them. Windows is a separate
subsequent helper/experiment; this source refuses other operating systems.

## Limits and evidence

The preserved protocol files are byte-for-byte reviewed r2. The new controller
adds sticky HOLD on clock rollback and exclusive append-only fsynced intent/ACK
journals. Data-only test fixtures use ephemeral mathematical signing keys in
memory and modeled OS fields; they are explicitly unrelated to a native or venue
identity. No native helper, store, launchd registration or provider operation is
executed by those fixtures.

Public reports keep `release_ready=false`,
`native_credential_retention_proven=false` and `all_owned_processes_gone=false`.
A final sender cannot observe its own terminal death or independently prove VM
removal. This experiment establishes public continuity only if actual source,
provider, kernel and signature joins pass. It is not candidate install/licence,
protected credential, trading journey or release acceptance. JavaScript/runtime
copies of receipt key objects are not claimed to be zeroized.
