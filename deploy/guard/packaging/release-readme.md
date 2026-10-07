# Zunder Guard

A self-hosted risk firewall between trading bots or AI agents and Hyperliquid. It starts in
paper mode, listens on 127.0.0.1 only, and talks to nothing but Hyperliquid unless you opt in.

    zunder-guard init --interactive --rules zr1_…   # rules from zunderlabs.com, account, mode, key
    zunder-guard pair                               # the client key for your bot (shown once)
    zunder-guard run --network paper

After a testnet setup, run `zunder-guard run --network testnet` instead.

Verify this release before running it (the identity is this repository's release workflow at
this tag):

    cosign verify-blob --bundle SHA256SUMS.sigstore.json \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/<version> \
      SHA256SUMS
    sha256sum --ignore-missing -c SHA256SUMS

The signed checksums also cover the immutable container image reference in
`zunder-guard-<version>.image.txt`. Verify and use that digest rather than a moving tag.

Documentation: https://zunderlabs.com/docs. Source: https://github.com/zunderlabs/zunder-guard.
