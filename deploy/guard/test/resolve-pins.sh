#!/usr/bin/env bash
# Prints the current digests and commit SHAs that deploy/guard pins, so a person can refresh
# them deliberately (deploy/guard/README.md, "Pins"). Reads public registries and GitHub only;
# changes nothing. Run on the Linux build host:
#
#   bash deploy/guard/test/resolve-pins.sh
set -euo pipefail
cd /tmp  # git ls-remote must not read the checkout's .git file
DOCKER=docker
id -nG | grep -qw docker || DOCKER="sudo docker"

echo "== images (multi-arch index digests)"
for ref in rust:1.97.0-alpine3.22 rust:1.97.0-alpine3.23 rust:1.97.0-alpine gcr.io/distroless/static-debian12:nonroot \
  gcr.io/distroless/static-debian13:nonroot node:24-alpine; do
  d=$($DOCKER buildx imagetools inspect "$ref" 2>/dev/null | awk '/^Digest:/ {print $2; exit}') || true
  echo "$ref ${d:-<not found>}"
done

echo "== GitHub Actions (newest release tag and its commit)"
for repo in actions/checkout actions/upload-artifact actions/download-artifact \
  docker/setup-buildx-action docker/setup-qemu-action docker/login-action docker/build-push-action \
  sigstore/cosign-installer anchore/sbom-action EmbarkStudios/cargo-deny-action \
  slsa-framework/slsa-github-generator rhysd/actionlint; do
  tag=$(git ls-remote --tags --refs "https://github.com/$repo" 'v*' | awk -F/ '{print $3}' \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1)
  sha=$(git ls-remote "https://github.com/$repo" "refs/tags/$tag^{}" | awk '{print $1}')
  [ -n "$sha" ] || sha=$(git ls-remote "https://github.com/$repo" "refs/tags/$tag" | awk '{print $1}')
  echo "$repo $tag $sha"
done

echo "== cosign (newest v2 and v3 releases and their linux/darwin checksums)"
for major in 2 3; do
  tag=$(git ls-remote --tags --refs https://github.com/sigstore/cosign "v$major.*" | awk -F/ '{print $3}' \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1)
  echo "cosign $tag"
  curl -fsSL "https://github.com/sigstore/cosign/releases/download/$tag/cosign_checksums.txt" \
    | grep -E ' cosign-((linux|darwin)-(amd64|arm64)|windows-amd64\.exe)$' || true
done
