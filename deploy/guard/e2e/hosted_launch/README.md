# Free hosted ordinary launch

The first lane prepares actual source and runtime inventories on a standard
`ubuntu-24.04` runner. It has only `contents: read`. It obtains neither OIDC nor
AWS credentials, reads no Testnet wallet, and makes no provider or venue write.
The source rejection fixture job is **not** the required live negative STS probe.

`bootstrap.py` performs bounded preparation before any private epoch:

1. Verify the actual clean public checkout at the current workflow commit.
2. Observe no swap, zero core limits, systemd and unified cgroup kill/swap
   primitives; remove only its own empty capability probe group.
3. Materialize the actual public source into a fresh root-owned
   `/opt/zunder-hosted-ordinary/source`. Each controller file fits the existing
   two MiB read bound. Genuine Git objects and HEAD remain in a separate actual
   root-owned `/opt/zunder-hosted-ordinary/checkout`; the private process must
   start there. Its database is inventoried separately as runtime input.
4. Fetch Node 26.8.1 Linux x64 at the exact SHA256 from the previously verified
   official signed checksum. Reject redirects, oversized archives, unsafe
   members and unexpected aliases. This is not actual runtime admission.
5. Place the current authored website fork in
   `/opt/zunder-hosted-ordinary/runtime/website/source`, outside the bounded
   controller tree. Derive a focused npm
   lock from the existing lock's exact package records, versions, resolution
   URLs and integrity values. Select ethers 6.17.0, Playwright Core 1.62.1,
   postal-mime 4.0.5 and esbuild 0.28.2 plus their exact transitive records.
   Install with `npm ci --ignore-scripts`; remove only internal npm `.bin`
   aliases. Omit all historical `artifacts/private-journey` generated files and
   `predecessor-manifest.json` from the public support projection. Build a new
   bundle, metafile, relative input hashes and minimal build metadata using the
   actual installed exact esbuild. Original private evidence stays immutable.
   No semver resolution, Astro build or legacy AWS/local build occurs.
6. Install the exact existing SHA-pinned Linux Python admission wheels with
   `--require-hashes --only-binary --no-deps --no-compile` inside the managed
   Python root's `lib/python3.12/site-packages`. The managed interpreter omits
   Ubuntu's ambient `sitecustomize.py` alias. Complete root membership covers
   Python wheels, Node and the website plus npm packages in three exact roots.
7. Protect staged trees and emit complete source, website, observed runtime and
   Python package hashes. Observe native linked and mapped files. The declared
   system tools come from the fresh runner's signed package repositories and
   remain observations pending review and exact private runtime pins.

The export command permits only six named JSON files containing public hashes,
paths and fixed capability results. It never exports installed code, environment
variables, package logs, `.git` contents, a token or a credential. Preparation
and failure reports keep `privateInput` and `releaseReady` false.

## Review and projection boundary

This checkout contains proprietary website support sources. Before placing this
workflow in the public repository, the release owner must explicitly project
and scan only the reviewed required support closure. The preparer archives the
already reviewed **public** repository; it does not authorize broad export of
the private canonical repository. Alternatively, a private source artifact must
use a separately admitted minimal reader. A public `GITHUB_TOKEN` is not assumed
to read a private artifact. These application boundaries remain mandatory.

## Deliberate next source boundary

This preparation workflow is independently runnable. It does not claim to have
closed private launch, signed native acceptance, custody, purchases, accounting,
the complete journey or publication. In particular:

- The existing checkout and genuine extension consumers pin an older website,
  bundle and 1,862-file package inventory. They need an independently reviewed
  exact successor for the **actual** current materialization above. Retaining
  those old pins or making them optional cannot admit this fork.
- Official cosign, SLSA verifier and Chromium vendor/tool inventories are not
  guessed or replaced with latest downloads. The observed runtime records these
  three missing subjects and is explicitly incomplete. Actual mapped and native
  runtime observations still require independent review and exact pinning.
- A subsequent closed constructor must consume the live `HostedPlatform` in its
  original `CommonOrigin`, derive the local host binding from actual admission,
  compose complete browser/backend plans and call `entry.execute_admitted` in
  that same context. No saved admission receipt can authorize it.
- The final caller must use separately finalized immutable reusable commits.
  Current local workflow calls are preparation only. There is no invented
  forty-character commit pin and no private execution path to bypass the gap.
- Actual positive and genuine different-reusable-workflow negative STS probes,
  exact provider roles/custody table/version-1 inputs, fresh baseline, and all
  original 100/20/25 and child deadlines remain required before private input.

The first hosted preparation is evidence gathering for those finite source and
application steps; its successful exit does not substitute for them.

`browser/provenance.json` pins the minimal prior reviewed NSS/probe dependency
and inert fixture closure. Only the NSS type import is redirected to the current
authored runtime fork; no old website or overlay is selected. The actual private
consumers must use an independently reviewed successor inventory for this layout.
