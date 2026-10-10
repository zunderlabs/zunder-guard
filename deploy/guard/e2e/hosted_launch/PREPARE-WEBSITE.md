# Public pre-custody website preparation

`prepare_website.prepare(stageReceiptRef, toolRefs)` is a public-authored library
recipe, not a standalone workflow, saved admission or runtime grant. The source
packet supplies no credentials and performs no publication. Integrate it in the
reviewed public-main controller before the original keeper's runtime freeze.

The caller must bind the stage receipt's exact SHA to the authenticated raw reader
result AND the independently reviewed private source roster. It must revoke the
actual reader token and launch this stage without reader App, publisher,
provider, signing or payment credentials. An asserted `readerTokenRevoked` field
and environment-name check do not prove the whole host or Actions context lacks
credentials. Source maintainer trust, credential wiring and process isolation
remain application responsibilities, not authority conferred by file hashes.

The retained layout uses only siblings beneath the existing packages root:
`build-source`, `build-input` and `build-tools`. Public controller SOURCE and the
focused `website/source` runtime are untouched. Scratch Cargo, rustup, npm,
compiler output and temporary logs live outside the packages root and are removed
on completion or failure. They must never be uploaded or cached in the public
repo. Public stderr/stdout must remain generic stage results; compiler/npm/test
output is discarded, except bounded Cargo licence rows in private scratch.

Tool refs are exact `{file,sha256}` references to the caller's independently
reviewed public Node, npm CLI and rustup tool. Setup and native tool authority
remain caller-owned; passing a ref does not authenticate an executable's origin.
The fixed recipe installs only Rust 1.97.0 and the exact wasm-bindgen CLI version
from the byte-verified Cargo lock. It fetches locked crates, builds the wasm32 risk
engine offline, generates glue with fixed flags, checks/tests/compiles live
TypeScript, and installs the site lock without lifecycle hooks. It executes no
downloaded `run.sh`, npm script, WASM licence script or alternate caller command.
Rust build scripts and the live tests are reviewed compilation/test inputs; this
is not a claim of sandboxing arbitrary private code or an execution-free build.

The source receipt is rechecked against all actual raw source bytes. Wire ordered
inventory SHA and `source.json` SHA are distinct. Candidate release-pin data stays
byte-bound; the existing original signature/candidate gate is still mandatory.
The current site lock uses local stub overrides and therefore needs fixed
`npm install --ignore-scripts`, with exact unchanged-lock readback. No switch to
unlocked resolution or a lifecycle fallback is provided.

Fresh JS/WASM and WASM licences replace previous generated browser assets.
Licences come from actual Cargo dependency rows and the existing permissive
allowlist, with unknown/copy-left foreign crates rejected. Site tooling must have
the selected Astro/Vite/Rolldown/esbuild versions and actual AMD64 ELF native
components. The exact locked esbuild optional native binary replaces its JS
launcher explicitly; only npm bin aliases and the two fixed source-owned
sharp/lightningcss stubs and 43 exact locked empty text members are normalized.
Those empty JS/typing modules and one exact test.txt fixture become a harmless
LF, with exact before/after hashes recorded; unknown empty JSON/native/other
files refuse. Literal `$` in actual locked language-server filenames is accepted
only by input grammar; final artifact output grammar remains stricter.
Unexpected links, escapes, hardlinks,
case collisions, empty files, path-prefix collisions and oversized files refuse.

`built-source.json` is a fresh web-only r5 input inventory, distinct from the
retained raw inventory. `built-tools.json` inventories every retained tool byte.
`preparation.json` binds the raw receipt, public tool refs, generated assets and
explicit transformations and remains `runtimeAdmitted:false, releaseReady:false`.
The original controller must freeze EVERY retained source/tool/control file into
the complete existing packages runtime map before P0 admission and custody.
Post-custody `backend_assembly.public_inputs` joins each r5 input byte to that
original map; r5 then uses the original Admission/clock and newly created merchant
identity. This recipe creates none of those, renews no epoch and is not journey,
release, native-installation, licence or payment evidence.

Focused tests are inert synthetic fixtures; they never invoke npm, Cargo,
rustup, a network service or a provider. Actual free public Ubuntu preparation,
the native closure, final original admission and whole user journey still need
hosted application evidence. No local Rust/site build is allowed by this packet.
