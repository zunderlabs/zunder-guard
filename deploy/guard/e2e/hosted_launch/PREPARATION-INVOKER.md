# Public website preparation invoker

## Finite route

1. A main-only `workflow_dispatch` selects one committed raw admission by its ID.
   The clean checkout is the actual `github.workflow_sha`. The source roster and
   private producer/artifact identities must be real, reviewed committed inputs;
   this source supplies no usable admission or invented producer pins.
2. Standard Ubuntu 24.04 runs the existing public no-secret bootstrap first.
   Failure stops this route. The existing `website-staging` environment grants
   only its approved read App for `zunderlabs/zunder` contents/actions read.
3. The existing raw reader authenticates exact private producer/artifact bytes,
   obtains inert source, requires actual installation-token DELETE HTTP 204, then
   stages the bytes. Only installation/public read tokens and exact public GitHub
   identity context enter the privileged reader process. Credentials are neither
   exported nor passed to compilation.
4. A clean `env -i` root process validates the clean public checkout, original
   bootstrap report/source inventory, committed admission and exact staged raw
   source roster. It uses only managed Node/npm and fixed official rustup-init
   1.29.1 SHA/size/ELF bytes. It calls the existing fixed website recipe; no private
   bootstrap, shell installer, lifecycle fallback, SourceAdmission or epoch is
   created. The candidate must remain draft.
5. Only bounded metadata counts/digests/fixed status may be uploaded. Raw source,
   filenames, build output, caches, compiler output and private stage receipts
   stay on the disposable runner. Failures expose fixed stage/codename only.

## Boundaries and prerequisites

Actual committed admission IDs, private producer identities, reviewed raw source
roster and source-admission pin remain root-owned prerequisites. No fixture may
be selected as a live admission. This prepares runtime for later independent
review; `runtimeAdmitted`, `privateEpoch`, `fullJourney` and `releaseReady` remain
false.

Token DELETE proves that specific installation credential was revoked. A clean
child environment proves only the child's explicit environment, not absence of
credentials from the whole host, Actions runner, ancestor memory or control plane.
The App-mint action and runner still require trusted source/maintainers and exact
workflow wiring. This route must never be reused as private custody admission or
as evidence that the entire machine is credential-free.

## Committed source-roster companion

The live record is `raw-admissions/ID.json` in the existing raw-reader schema.
`raw-admissions/ID.source.json` is a separate exact source-review roster:
`schema:1`, `id`, `rawAdmissionSha256`, `sourceCommit`, `sourceJsonSha256`,
`sourceInventorySha256`, `sourceFiles`, `sourceBytes`, `candidateSha256`.
The inventory digest is SHA256 of the canonical complete `{schema:1,files}` map;
`sourceJsonSha256` separately pins actual wire inventory bytes. Counts and total
bytes are reread from every protected staged source member. The candidate hash
binds the original complete candidate bytes and must have `published:false`.
Both records must be actual committed Git bytes also present in the original
bootstrap source inventory. No usable record or invented pin is installed here.

The wrapper's `reader` mode executes only the original trusted raw-reader CLI
with scoped read credentials, suppresses its stderr and retains bounded metadata
under the protected original public report root. Its successful CLI requires
actual token DELETE204 before staging. The token action retains post-action
revocation as failure cleanup. `validate` and `prepare` run as separate managed
Python processes with explicit clean environments. This does not remove the
App key or Actions credentials from ancestor/runner memory; source trust and a
single disposable pre-custody job remain required, never private admission.

Fixed rustup is created once at the existing managed Node `bin/rustup`, mode0500,
from official archive1.29.1 AMD64 URL; exact21,113,232 bytes, SHA256
`dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71`, ELF64
little-endian AMD64. No redirect, proxy, shell installer or latest-tool fallback
is accepted. All actual retained generated source/tools/rustup bytes still need
a subsequent complete runtime inventory and independent review before custody.
