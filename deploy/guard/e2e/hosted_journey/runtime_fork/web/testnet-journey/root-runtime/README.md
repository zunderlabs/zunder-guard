> Hosted Linux fork: the 10 October approved one-attempt Testnet exception
> supersedes this copied baseline's advance FeeEvidence gate only. Active
> return admission is full-return.ts and FULL-BALANCE-RETURN.md at the owned
> hosted_journey root. Legacy return.ts exact-fee helpers remain for baseline
> fixtures; index.ts does not use them for policy/fee admission.

# Root staging memory runtime

**Root-only source; independent review and process-containment closure required before use.** Importing this module does not generate keys or connect to any service. Calling `createRootRuntime` does. Author verification is offline only.

Use one clean, long-lived Node 26 process, exact reviewed source and dependency installation, disabled core dumps (soft and hard limits both zero), and either Linux without swap or the root-approved macOS encrypted-swap policy. The module verifies inherited core/swap state with a harmless pinned Python child before generation. It rejects diagnostic/preload flags. Root must authenticate the entrypoint/import closure before importing it; a running module cannot undo malicious pre-import code. The reviewed lockfile does not authenticate installed package bytes. No SSM merchant storage is implemented.

`createRootRuntime(config)` is a single-use factory per loaded module. It returns public staged methods and holds all generated private values in memory. The process deliberately has a keepalive until reconciled disposal, including after the finite admission window. Root must keep the machine/process alive: SIGKILL, forced app shutdown and host failure can lose custody. No restart or persistence guarantee exists; reference dropping/buffer clearing is best effort, not V8/ethers zeroization.

## Inputs

All paths are absolute and canonical. A `FileRef` is `{file, sha256}` with raw-file SHA256. Public proof/config files require current-UID regular single-link mode0600 under an immediate current-UID mode0700 parent. Source/executable files may be root-owned/current-UID but cannot be group/other writable. No secret is a file, argument or environment value.

Config is exactly:

```ts
{
  version: 1,
  optIn: 'reviewed-root-testnet-runtime-only',
  runId: '<fresh UUIDv4>',
  startedAt: /* creation epoch milliseconds, at most60seconds old */,
  expires: /* explicit original deadline, at most startedAt+60minutes */,
  evidenceDirectory: '<new owned run directory>',
  website: {root: '<this website tree>', manifest: FileRef},
  coordinator: {root: '<reviewed coordinator tree>', manifest: FileRef},
  executables: {node: FileRef, python: FileRef, aws: FileRef},
  awsConfig: FileRef,
  awsProfile: '<reviewed owner-custody profile>',
  home: '<actual canonical home>',
  memoryPolicy: 'mac-encrypted-swap' // or linux-no-swap
}
```

Both source manifests have shape `{schema:1,files:{'<relative path>':'<sha256>'}}`; they include the full reviewed closure, not just the required minimum list in `index.ts`. Relative TS/JS imports omitted from that manifest are refused. Coordinator Python closure must be independently reviewed; runtime does not claim Python static import analysis. The AWS provider remains pinned to its existing account436632189317/owner SSM contract, unrelated to merchant custody. Root must preflight source and credentials independently before generating material.

## Invocation order

1. Create once and retain returned runtime. Read `publicIdentity()` for merchant and Ed25519 public key. Feed only those public values to existing staging build/package. Review exact artifacts, complete signedDRAFT acceptance and provision plan. For the retained-project lane, authenticate the exact reviewed existing staging Pages baseline, configuration, deployment and alias bindings, and its static rollback artifact; preserve that project. These preparations happen under the original fixed window; no automatic extension.
2. `provision({plan,approval,artifactDirectory,artifactManifest,controllerManifest,journalDirectory})`. All manifest/plan/approval values except directories are `FileRef`s. It binds public merchant/key and exact controller/artifact digests; existing controller validates its full15-module runtime and DRAFT proofs. Before launch, effective deadline irreversibly becomes plan.end (no later than original). No external writes before this binding. Secret stdin is exactly `{unsubscribe,issuer,inbox}`.
3. `startIssuer()`. Existing reviewed receiver gets exact staging site/public key plus issuer token/Ed seed through stdin. No licence or raw inbox output is exposed.
4. `purchase({setup:FileRef,outputDirectory})`. Root supplies existing immutable purchase metadata; runId, owner N, merchant, publicKey must match. Recipient is `guard-e2e-20261009@zunderlabs.com`; `outputFile` is exactly `<outputDirectory>/actual-stage.jsonl`; maxUsdc<=355.61. Existing provider alone retrieves funded owner, claims private broker and executes the one real testnet purchase. Only inbox token passes this supervisor's stdin. This is test-key issuance/inbox/Rust test-key verification, not official production entitlement verification. No retries.
5. Wait for `status().issuerDone` and no child process before return. Final purchase JSONL and independent provider `result.json` must both pass; receipt includes actual ledger/mail/licence digests, never raw mail/key. Runtime validates exact run/owner/merchant/amount/token/chain/source-bound producer success and broker cleanup.
6. Root obtains evidence of the exact transfer fee/account model. **Unknown fee means no return.** `armReturn(policy)` validates the public fields below, fee receipt and purchase receipt, then independently reads canonical token, both roles/modes/open orders, merchant spot balance, perps balances and payment ledgers. Fresh merchant history must be exactly one known purchase credit, with no other funding. Before signing, explicit amount plus evidenced expected fee must equal entire observed merchant perps balance, and entire balance/debit<=355.61. No fee is guessed/subtracted automatically.
7. `returnOnce()` permits one signature and one canonical Testnet SendAsset merchant→N request before the same effective deadline. Attempt is consumed before any await/sign; no automatic retry. It rereads source/accounts before dispatch and independently reconciles merchant/owner ledgers and balance differences. Unknown permanently prohibits all future signing. `reconcileReturn()` is one additional explicit read-only bounded pass; it never clears unknown. `reconcileEmptyMerchant()` permanently closes all ordinary write admissions, then proves zero perps/spot balances and no incoming/history for a no-payment disposal.
8. `cleanup(newPublicInputs,originalJournalDirectory)` uses existing exact-journal cleanup with new root-approved<=5minute cleanup lease. Ordinary expiry/hold never permits another apply, issuer, purchase or return. Cleanup uses same original plan/artifact/controller hashes and exact original journal; successful return alone is not cloud cleanup proof.
9. `dispose()` only after proven return or proven never-funded empty merchant, no live child, and cloud cleanup if apply was attempted. It independently repeats the final balance/ledger proof after cleanup, then closes receipts, drops private references/buffers and stops keepalive. Background issuer failure immediately stops every owned child; failed stop preserves uncertain custody. Refusal means custody remains open; do not terminate root process as a substitute for reconciliation.

## Protected-caller input storage

`storePurchaseInputs(binding: FileRef)` reuses this same live keeper after successful
provisioning. It is mutually exclusive with the legacy `startIssuer()` / `purchase()`
lane. It publishes only the disposable issuer token, inbox token and signing seed
through the pinned, supervised AWS CLI's stdin. The merchant key stays in this keeper;
no private getter or merchant SSM storage is added. The protected caller claims the
three inputs through its existing separate role only after its actual fresh Page proof.

The hash-pinned public binding is exactly:

```ts
{
  schema: 1, run: /* actual workflow run ID */, attempt: /* actual attempt */,
  source: '<candidate PRODUCT commit SHA>', runId: '<keeper UUID>',
  startedAt: /* keeper ORIGINAL config.startedAt */,
  deadline: /* keeper's tightened admission deadline */,
  merchant: '<keeper publicIdentity merchant>',
  issuerPublicKey: '<keeper publicIdentity publicKey>'
}
```

`deadline - startedAt` must be at most twenty minutes. Preparation does not create a
new start time. `source` identifies the candidate product commit, exactly as the
protected caller's `OneClaimInputs` expects in its SSM `Source` tag. It is distinct
from the authenticated controller commit. The root supplies and authenticates the
exact product/run/attempt binding; this keeper has no independent product-commit
field in its existing configuration. The first child verifies AWS account `436632189317`; storage then
creates Version 1 Standard SecureString parameters under
`/zunder/testnet/e2e/purchase/<run>-<attempt>/` named `issuer-token`, `inbox-token` and
`signing-seed`, using the fixed eu-central-1 KMS key and exact run/source/owner/merchant/
expiry tags. Overwrite is false. After every write, exact name/type/tier/Version 1/KMS
metadata and all tags are independently read back before confirmation; no value is
read or decrypted. Any failed/mismatched readback or partial/uncertain write consumes the attempt
and retains all three public names in the keeper's checkpoints and unresolved state.

`cleanupPurchaseInputs(binding: FileRef, approval: FileRef)` accepts this exact original
binding plus the hash-pinned public cleanup approval:

```ts
{
  schema: 1, purpose: 'cleanup-purchase-inputs', approved: true,
  bindingSha256: '<original binding raw-file SHA256>',
  deadline: /* absolute cutoff <= original effective deadline + 300000 AND invocation time + 300000 */
}
```

Cleanup claims one interval of at most five minutes at invocation, retaining that
same absolute cutoff and captured monotonic start/budget throughout every dispatch.
Repeated checks and failed attempts cannot renew the interval. Cleanup verifies the account and each existing parameter's Version 1/KMS/tags before
deleting only those three names, then reads back absence. It never decrypts parameters
or reads the owner key. Its clock derives from the keeper's original UTC/monotonic
origin; it does not renew signing authority or clear HOLD. Expiry tags do not delete
SSM parameters automatically. Disposal remains blocked until all three names have
confirmed absence. A lost cleanup outcome retains unresolved custody.

The protected successor calls `createRootRuntime(config, originalParentGate,
originalKeeperMetadata)` and authenticates the real stable Mac parent before the
existing generator. `receiveCompletedPurchasePublication(expected)` consumes the
original anonymous FD3 once, matching its admitted challenge/controller and the
successful stored purchase binding. It accepts one bounded canonical frame through
EOF; a saved receipt cannot create completion authority. The same original keeper
admission may tighten from at most 60 minutes to the purchase's at most 20 minutes.

After live completion, `armReturn()` corroborates the pinned receipt against the
exact bytes already consumed, then requires the existing independent venue,
fee, balance and one-use return checks. It does not manufacture legacy broker
reports. The reviewed fixed Python probe/launcher and a real coordinated run are
still required; the offline tests do not prove live purchase or return acceptance.

Public return policy:

```ts
{
  version:1, runId, merchant,
  destination:'0x0d708cfc4316b58f4ab00ee641a54baacc89cb14',
  amount:'<explicit decimal>', paidUsdc:'<exact payment decimal>',
  token:'USDC:0x<canonical token id>', paymentHash:'0x<ledger hash>',
  paymentAfter:/* exact receipt payment nonce */,
  startedAt:/* now */, expires:/* <=startedAt+120seconds and effective deadline */,
  maxFeeUsdc:'<explicit <=1>', maxDebitUsdc:'<explicit <=355.61>',
  feeEvidence:FileRef, purchaseReceipt:FileRef
}
```

Fee receipt is exactly `{version:1,scope:'root-reviewed-testnet-sendasset-fee',merchant,destination,token,expectedFeeUsdc,observedAt,expires,rootVerified:true}`. It must be no older than60seconds at arming and cover the return window. This is a root evidence attestation, not a venue quote API or cryptographic protocol fee cap. Root must preserve its actual underlying primary evidence separately; setting a boolean cannot create that evidence. Official [activation fee docs](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/activation-gas-fee) describe the1quote-token first destination activation. [SendAsset schema](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/exchange-endpoint#send-asset) provides no fee cap field. Trading `userFees` does not establish transfer fees. If there is no defensible exact fee evidence, remain in HOLD without signing.

## Remaining containment boundary

Existing provider starts some descendants in new sessions. Parent group death alone is not a descendant-death proof; forced termination must retain UNKNOWN/HOLD and custody. Before live use, root must bind a reviewed coordinator ownership/death contract covering these descendants. This version is not authorized to claim that gap closed by process polling. Do not execute real custody under this unresolved prerequisite.

## Offline checks

From the website tree:

```sh
node web/site/node_modules/typescript/bin/tsc -p web/testnet-journey/root-runtime/tsconfig.json
node --test web/testnet-journey/root-runtime/runtime.test.ts
```

Tests use fixed inert public fixtures, fake transport/signatures and harmless owned children. They never call the factory or generate keys, read credentials, sign, call venues/clouds or invoke production issuers. Durable `events.jsonl` stores only bounded public stage facts, IDs, hashes and statuses. Root-reported genuine email-recovery PASS is independent evidence; it is not a signed-candidate official activation PASS.
