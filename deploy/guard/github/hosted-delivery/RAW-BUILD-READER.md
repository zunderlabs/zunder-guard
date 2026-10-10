# Private raw source reader: fixed inert transport

This is a separate purpose from ordinary website/Worker/issuer publication.
`admit.py`, its target set, schema and gate behavior remain unchanged. The new
`raw_build_reader.py` reuses only its fixed public metadata reader, hashing and
exact producer-run validator. The reader never compiles, installs, imports,
executes or publishes downloaded source. No new provider or GitHub scope is
introduced; the separately approved private reader App remains read-only and
installed only on private `zunderlabs/zunder`.

## Closed admission and payload

Reviewed public records live at `raw-admissions/ID.json`. No real record is
installed by this source preparation. The exact schema-1 record has:

- `id`, `purpose: original-guard-website-build-input`;
- `privateRepository: {id,fullName}`, `sourceCommit`, `sourceRef`;
- `producer: {workflowId,workflowPath,workflowBlob,runId,runAttempt,jobName}`;
- `artifact: {id,name,digest}`, `inventorySha256`, `manifestSha256`.

The producer is the registered `.github/workflows/guard-website-build-input.yml`,
job `package`, successful push to private main, at the exact reviewed source/blob
and latest run attempt. Reads authenticate public repository/owner/current
protected main, private repository ID/name, registered workflow/path/blob,
run/head repository/event/source/attempt, one successful package job and exact
artifact metadata. The API archive digest must equal the downloaded ZIP bytes;
run attempt and protected public main are checked again afterward. The ordinary
200 MiB archive limit is unchanged; this distinct raw transport caps archive
bytes at 800 MiB and expanded bytes, including metadata, at 768 MiB. Each file
is at most 64 MiB, the raw manifest at most 16 MiB, and entries at most 62010.
Source inventory remains at most 12000; the original complete runtime inventory
20000-file limit is not increased.

The flat GitHub archive contains `build-source/PATH`, `inventories/source.json`,
`candidate.json`, and `raw-build-input-manifest.json`. The manifest has closed
keys `schema,kind,repository,sourceCommit,sourceRef,event,workflowRef,runId,
runAttempt,files,transformations`. Files are sorted by raw path codepoint, each
exactly `{path,size,sha256,mode}`. `mode` is integer 384 (0600). The two control
files are inventoried; the manifest does not inventory itself. Transformations
must be `[]`. The ordered inventory and full raw manifest are separately pinned.
`inventories/source.json` is exact `{schema:1,files:{relativePath:sha256}}` and
must equal every staged source byte. Candidate is inert complete release-pin
data; the existing release-schema/signature gate remains mandatory separately.

Only the declared Rust workspace manifests/source and website/live/waitlist/
provisioning source namespaces are accepted. Generated live JS/WASM, generated
WASM licences, installed tools, workflows, helpers, history, caches, credentials,
path escapes, aliases, case collisions and special files are refused. Literal
`[]` in Astro route names is supported. The exact private source roster is still
independently reviewed; a hash inventory or successful packaging run does not
authorize arbitrary private code execution.

GitHub's flat upload normalizes wire permissions. Regular ZIP files may have
0600, 0644 or omitted permission attributes; executables and special types are
refused. Every logical row and staged file is 0600. Archive permission bits never
authorize execution. The reader creates new regular single-link files only.

## Reader closure and fixed staging

The CLI accepts only a reviewed admission ID, on the fixed public branch-main
dispatch. It consumes the existing separate private/public read tokens; it has
no destination/path/environment override. Artifact redirects are HTTPS on known
GitHub storage hosts, without the installation token. Payloads, file names,
presigned URLs and API exception bodies do not enter public output. Unknown
archive, metadata, runtime or API states fail closed without retries.

After acquisition the reader makes one actual installation-token DELETE and
requires HTTP 204 before staging. A failure/unknown revocation permits neither
staging nor preparation. It removes reader tokens from its own environment and
closes the client. This does not prove deletion of immutable Python strings,
ancestor environments, Actions secret context or the reader App private key.
Later execution requires a separately credential-free trusted preparation
context plus independently admitted source. Token revocation is not a substitute
for that source/runtime boundary.

Extraction creates fixed siblings under the existing packages root:

- `/opt/zunder-hosted-ordinary/runtime/website/build-source`;
- `/opt/zunder-hosted-ordinary/runtime/website/build-input/source.json`;
- `build-input/candidate.json`, `build-input/raw-manifest.json` and
  `build-input/stage-receipt.json`.

All ancestors are canonical, root-owned and not group/world writable. Namespaces
are fresh, directories 0700 and files create-only 0600. The public controller
SOURCE and existing focused runtime `website/source` are untouched. Failure
leaves an inert, ineligible namespace for the bootstrap owner's cleanup; it does
not start a private epoch. The helper returns only the stage-receipt FileRef.

The stage receipt has closed keys `schema,purpose,privateRepository,sourceCommit,
sourceRef,producer,artifact,inventorySha256,manifestSha256,source,candidate,
rawManifest,readerTokenRevoked`. `source` is `{root,manifest:FileRef}`, candidate
and rawManifest are FileRefs. The CLI emits only opaque IDs/digests and false
private-input/release-ready flags. A saved stage receipt is data, not a capability
or a restored original admission. Source/runtime approval and caller binding
must independently admit it before preparation.

## Separate public preparation and original P0/P1 joins

The release lead owns the fixed public, credential-free preparation recipe.
Private packaging builds nothing. That recipe produces fresh live JS/WASM and
WASM licences, installs exact locked tools without lifecycle hooks, and records
only source-approved fixed stub/native normalizations. Exact esbuild native ELF
reification belongs there, not in this source-only reader. Tool bytes occupy the
separate `build-tools` sibling; r4 website input is a new allowed web-only subset
inventory, retaining the raw source inventory unchanged.

Freeze all actual source, tools, manifests and retained metadata into the original
complete packages runtime map BEFORE original admission and custody. No extra
runtime root, source-cap relaxation or material appended after keeper starts is
needed. Existing `backend_assembly.public_inputs` verifies every final website/
tool member against original authenticated source/runtime hashes. The actual
P1 uses the unchanged original Admission, paired clock and post-custody identity.
This transport constructs none of those objects and cannot renew their clocks.
Whole-journey, signed-release, installed-native, payment and cleanup evidence
remain separate actual application work.

Focused validation: `python3 -I -B .../test_raw_build_reader.py` and the unchanged
`test_admit.py`. Fixtures are synthetic; local filesystem tests verify inert
create-only behavior but do not prove hosted root ownership or actual grants.
