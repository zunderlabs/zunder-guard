# Guard purchase journeys

```sh
npm ci
npm run check
npm test
```

The C4 fixture binds only to loopback. Playwright tests authenticate order and inbox reads,
cover every order-state response, reject a missing order, and check the inbox shape and timestamp
filter with a nonempty positive control. Fixture checks are not staging or P1–P8 acceptance
evidence; the paid browser flow is an explicit opt-in released-source test.

To run the read-only contract checks against staging, supply `GUARD_STAGING_URL`,
`GUARD_ACCESS_CLIENT_ID`, `GUARD_ACCESS_CLIENT_SECRET`, `GUARD_ORDER_TOKEN`,
`GUARD_INBOX_TOKEN`, `GUARD_INBOX_URL` and `GUARD_EMAIL_DOMAIN` through the environment.
No real URL or credential belongs in this tree. Fixture-only seed tests are skipped remotely.
Credential-bearing API tracing is disabled because Playwright traces retain request headers.

The fixture uses C4's staging status fields and network identifiers (`hyperliquid`, `arbitrum`,
`base`, with `chain: testnet`). Its authenticated expiry control expires a quoted order once
and refuses other states. Status assertions do not dump runtime payment addresses. The fixture
implements status, order, expiry, inbox and finite quote examples; renewal and payment journeys
remain to build. It does not copy the private checkout, issuer or website.

Remote calls and JSON parsing suppress original HTTP errors, which may contain bearer/Access
headers or message bodies. Inbox assertions check booleans instead of dumping licence emails;
recipient, nonempty string ID and integer timestamp are checked as well as body types. Debug
logging is refused remotely, and both staging/inbox URLs require HTTPS without credentials.
The real staging inbox still needs a nonempty control from a purchase journey before its shape
can count as validated; an empty authenticated read proves only reachability.

All API calls use helpers with `maxRedirects: 0`, so a response cannot forward credentials to
another origin or HTTP endpoint. Only the terminal list reporter is enabled: HTML/JSON reporters
serialize failed API steps' original errors even when caught. Keep sanitized terminal logs as
CI artifacts; do not override the reporter or enable API tracing for credential-bearing runs.

`quote.test.ts` covers P4's German VAT, EU reverse charge, non-EU and invalid VAT-ID
cases, plus P7's blocked-country refusal. Every mutation requires a positive open C4 staging
status first. Successful quotes assert C4's hand-computed cents and expire the exact unpaid
order in cleanup; no payment is sent. Local fixture passes prove consumer contracts only.
The reusable `journey.yml` runs each row separately against real staging, verifies the exact
release subjects first and attests successful evidence against the immutable manifest.
Its three nonsecret URL/domain variables live in environment `e2e`; credentials use C4 names.
There is no local credential fallback in the workflow, and no journey credit until a real
signed-release run succeeds. Quote logs use the sanitized terminal reporter only.

`paid.test.ts` implements P1–P3 through the pricing page and business quote, a single
Hyperliquid **testnet** (P1), Arbitrum Sepolia (P2) or Base Sepolia (P3) payment, delivered order
and inbox polling, then licence installation via stdin on an authenticated Linux release binary.
It requires `GUARD_PAID_JOURNEY=P1`, `P2` or `P3`, exact release
identity/assets, covered testnet account and private work directory, plus C4 payer credentials.
The reusable workflow verifies release assets before custody. Never retry an ambiguous payment:
retain and reconcile its private attempt receipt. Only sanitized receipts enter artifacts.
Browser Access defaults are cleared; the routing helper injects credentials into individual
staging requests only and blocks redirects. Its real-browser regression runs before each hosted paid row.
The Sepolia helper pins both RPC and signing chain IDs to the selected testnet, sends exact
integer micro-USDC to the admitted merchant, and caps gas at 0.0002 test ETH. It refuses pending
payer transactions before signing. A durable exclusive attempt precedes the only broadcast;
confirmation polling never replaces, cancels or resends it. The licence receipt binds the row.
A passing fixture or source review does not prove a paid licence was delivered or accepted.

The production checkout/issuer subset of P9 is separate:

```sh
npm test -- --config monitor.config.ts
```

This config uses only C5's production origin, no staging credentials, no retries and no redirects.
It reads branded page HTML, checks the open checkout, sends exactly three **dry-run** quotes
using the monitor email, checks malformed renewal refusal and the issuer heartbeat. Quotes must
have the hand-computed cents and no stored-order identity/token. Run at most once per 30 minutes;
a failed check does not authorize an earlier retry. Default offline tests never call production.
These checks do **not** establish complete P9: signed canonical metadata/loader authentication,
scheduling and failure alerts still need integration. Preserve C5's required renewal HTTP status
until its producer resolves any disagreement with the deployed endpoint.
