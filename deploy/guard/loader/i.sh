#!/bin/sh
# zunderlabs.com/i: the Zunder Guard loader (deploy/guard/README.md, "The loader").
#   ssh -t you@server "curl -fsSL https://zunderlabs.com/i | sh -s -- --rules zr1_…"
#   (every option goes to install.sh: --licence zgl1_… sets a licence key, sh i --help lists them)
# Checks install.sh against the release's Sigstore-signed checksums, then runs it. Read it first:
#   curl -fsSLO https://zunderlabs.com/i && less i && sh i --rules zr1_…
set -eu
main() {
  V=@VERSION@ C=v3.1.3 R=https://github.com/zunderlabs/zunder-guard
  U=${ZUNDER_GUARD_BASE_URL:-$R/releases/download/$V}
  case "$(uname -s)-$(uname -m)" in # cosign release binaries and their SHA-256 (cosign_checksums.txt)
    Linux-x86_64) P=linux-amd64 H=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;;
    Linux-aarch64 | Linux-arm64) P=linux-arm64 H=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;;
    Darwin-x86_64) P=darwin-amd64 H=2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c ;;
    Darwin-arm64) P=darwin-arm64 H=5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76 ;;
    *) echo "zunder-guard: unsupported system $(uname -s) $(uname -m)" >&2 && exit 1 ;;
  esac
  T=$(mktemp -d) && trap 'rm -rf "$T"' EXIT
  no() { echo "zunder-guard: $1; refusing, nothing was run" >&2 && exit 1; }
  get() { curl -fsSL --proto '=https,file' --retry 3 -o "$T/$1" "$2" || no "download failed: $2"; }
  sum() { { sha256sum "$1" 2>/dev/null || shasum -a 256 "$1"; } | cut -d' ' -f1; }
  for f in install.sh SHA256SUMS SHA256SUMS.sigstore.json; do get "$f" "$U/$f"; done
  S=$(command -v cosign || true)
  if [ -z "$S" ]; then
    get cosign "https://github.com/sigstore/cosign/releases/download/$C/cosign-$P"
    [ "$(sum "$T/cosign")" = "$H" ] || no "cosign does not match its pinned SHA-256"
    chmod 0755 "$T/cosign" && S=$T/cosign
  fi
  "$S" verify-blob --bundle "$T/SHA256SUMS.sigstore.json" --certificate-oidc-issuer \
    https://token.actions.githubusercontent.com --certificate-identity \
    "$R/.github/workflows/release.yml@refs/tags/$V" "$T/SHA256SUMS" >/dev/null 2>&1 \
    || no "the Sigstore signature of $V's checksums does not verify"
  [ "$(awk '$2 == "install.sh" { print $1 }' "$T/SHA256SUMS")" = "$(sum "$T/install.sh")" ] \
    || no "install.sh does not match the signed checksums"
  if (: </dev/tty) 2>/dev/null; then I=/dev/tty; else I=/dev/null; fi
  ZUNDER_GUARD_COSIGN=$S sh "$T/install.sh" "$@" <"$I"
}
main "$@"
