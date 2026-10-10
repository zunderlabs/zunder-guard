# Original post-custody artifact build

`buildOriginalArtifacts(input, actualAdmission, originalClock)` is called by the
original P1 coordinator after its custody ACK and `keeper.publicIdentity()`, before
Plan exists. It returns `{artifactDirectory, artifactManifest:{file,sha256}}`.
It does not acquire custody, authenticate a parent, grant deployment, or renew a
deadline. The caller joins these exact source/tool inventories and the Node
executable to the already authenticated original source/runtime inventory.

Input has exactly `context`, `identity`, `website`, `tools`, `executable`,
`releasePin`, and `outputParent`. Context has the original public
`run_id,attempt,binding_sha256,started_ms,deadline_ms`; identity has only the actual
public `merchant,publicKey`. Neither artifact nor controller SHA exists yet.
Website/tools each have `root` and a pinned manifest FileRef. Inventories use the
existing `{schema:1,files:{relativePath:sha256}}` format. Website paths are rooted
at `web/`; tools paths are rooted at `node_modules/`, the complete installed
Linux tool closure, including native esbuild. Symlinks are not inputs. The
original executable is the existing pinned Node executable, not a new runtime.

The admitted website inventory contains `web/site` source/config/public files
(including the already compiled live JS/WASM), `web/docs-content`, the shared
deployment/release modules, waitlist source and the five SQL migrations, and the
three leased provision entries plus lease/policy. The exact `web/site/LICENSES.md`
and `web/site/LICENSES.wasm.md` imports are required; the fixed licence script
generates `LICENSES.generated.md`. No private repository script
is accepted as a command: the exact source-selected site build entries below are
fixed. This is an original source-authorized build lane; a hash manifest alone
does not authorize executing otherwise untrusted private source.

The wrapper copies verified input bytes into a fresh `0700` child scope. It never
runs npm, installs dependencies, reads `.env`, uses ambient PATH/HOME, inherits
stdin or journal/private descriptors, or passes provider/custody/signer tokens.
Child environment is built from scratch: private scratch HOME/TMPDIR, C locale,
disabled Astro telemetry, staging/testnet profile, the exact public release pin,
`PUBLIC_TESTNET_MERCHANT` from custody, and `SNAPSHOT=skip`. Key material is not
compiled into the Worker: runtime bindings supply it later. The public licence
key is bound in the final artifact manifest and runtime plan, not substituted
into source text.

Commands are sequential direct Node invocation of copy-fonts, engine-defaults,
sample-snapshot (skip), sync-docs, licenses --check, Astro bin/astro.mjs build,
after-paint, approve-csp, check-pages, check-placeholders, and deployment-build.
Node receives only `--no-global-search-paths` and `--no-addons`, except the exact
credential-free Astro build child omits `--no-addons`: actual Vite8.3.2 imports
Rolldown1.2.12, whose loader requires its native `.node` binding. The existing
Linux x64 glibc tool inventory must contain the exact MIT package metadata,
Rolldown JS loader and `@rolldown/binding-linux-x64-gnu`1.2.12 ELF64/x86-64 addon;
all bytes are independently pinned and checked before copying/executing. No
generic native override, new runtime or privileged actor flag exception exists.
Then the pinned
native `node_modules/esbuild/bin/esbuild` bundles the three fixed leased entries
as ESM/browser without sourcemaps into `api.js`, `inbox.js` and
`pages/_worker.js`. No callback, command, args, module loader, script RPC or
environment override is part of the input ABI.

The three leased entry/output pairs are literal tuples, retaining exact fixed
argv under the inherited runtime's strict Bundler configuration and
`noUncheckedIndexedAccess`. No assertion or compiler flag is relaxed. Ethers
6.17.0 is already locked by the site's package files and loaded by the original
P1 runtime from its independently admitted installed site closure; it is not
imported by this producer's fixed build commands. Its installed runtime bytes
remain a caller staging/admission prerequisite, not an ambient resolution or a
new builder command.

Site navigation uses the existing exact staging-navigation policy, retaining
official installer links and marked production links. Executable script blocks
are excluded from this normalization. Merchant selection uses Astro's existing
public build variable rather than a text replacement. The generated wallet CSP
is checked again after packaging. `_routes.json` covers `/*`; the leased Pages
Worker delegates non-API requests to ASSETS.

Final output is create-only `0700` directories and `0600` regular files, with
the seven backend/migration files and bounded safe `pages/*` files only. The
compact JSON manifest is `{version:1,merchant,publicKey,files:[{path,sha256}]}`;
rows are sorted and hash the actual packaged bytes. Required staging wallet
markers/CSP/release pin and the compiled licence script's exact merchant are
checked before publication of that manifest. Each file is at most 8 MiB, total
32 MiB and inventory at most 1024 files, matching assembly limits. Final
identity/hash binding is data proof, not custody/provider acceptance.

Actual Admission/clock guards surround input, filesystem and child operations.
A shortened Admission retains its original parent clock. The build recovers the
original end from `originWallNs + deadlineMonoNs - originMonoNs`, requiring an
exact integer millisecond and original material end at most sixty minutes from
original start. P1 irreversibly tightens its effective Admission at custody ACK:
both Context end and effective Admission end must be at most twenty minutes
from that same original start and no later than the retained material end;
effective Admission end must also be at most Context end. The build validates
that retained projection and calls actual `assertOriginalClock`, preserving
the first wall/monotonic pair. No fresh capture, twenty-minute extension or extra
clock carrier is introduced. The separate P3 purchase clock remains unchanged.
A bounded guard timer kills a build child on expiry; an error latches HOLD and
never returns a deployable result. Logs are discarded, no subprocess is retried,
and failed scratch remains within the original private scope for its existing
cleanup owner. Focused tests exercise pure plans/identity/env/output validation;
they do not claim a hosted build or a provider rehearsal.

## Source route grammar correction r5

The actual site source includes literal Astro dynamic route filenames [legal].astro,
[slug].md.ts and [...slug].md.ts. Input inventory segments now admit literal []
alongside the existing characters, with unchanged traversal, secret, prototype,
case-alias and path-prefix fences. The final artifact output predicate remains
unchanged and rejects bracketed output names. No source/runtime approval, clock,
tool, native-addon or credential semantics change.

## Installed tool input grammar correction r6

The actual locked language-server closure contains protocol.$.js and
protocol.$.d.ts, both directly under vscode-languageserver-protocol and its nested
copy beneath vscode-languageserver/node_modules. Input segments now admit a
literal dollar character as data. No shell evaluates input names; encoded dollar,
command substitution punctuation, traversal and aliases remain refused. The
strict final artifact output predicate remains unchanged and refuses dollar names.
No tool/source authority, clock, bounds, runtime root or native-addon rule changes.
