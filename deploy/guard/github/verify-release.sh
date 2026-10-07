#!/usr/bin/env bash
# Read-only publication gate. Download all release assets, verify their signed checksums and
# SLSA source/builder provenance and the immutable image, and require both CI and the complete release run to have succeeded for
# this tag's commit. publish.yml uses the resulting folder only after this script succeeds.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: verify-release.sh <vX.Y.Z> <empty-output-dir>" >&2; exit 2; }
TAG=$1 OUT=$2
[[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "unexpected release tag" >&2; exit 1; }
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
if [ -e "$OUT" ]; then
  echo "release output must not exist" >&2
  exit 1
fi
COMMIT=$(gh api "repos/$GITHUB_REPOSITORY/commits/$TAG" --jq .sha)
[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || { echo "cannot resolve release commit" >&2; exit 1; }
for workflow in ci release; do
  runs=$(gh api --method GET "repos/$GITHUB_REPOSITORY/actions/workflows/$workflow.yml/runs" \
    -f head_sha="$COMMIT" -f event=push -f status=success -f per_page=100)
  # release must be the tag run; CI must be the main-branch run of the same source.
  branch=main
  [ "$workflow" != release ] || branch=$TAG
  if ! jq -e --arg sha "$COMMIT" --arg branch "$branch" \
    '.workflow_runs | any(.head_sha == $sha and .head_branch == $branch and .status == "completed" and .conclusion == "success")' \
    <<<"$runs" >/dev/null; then
    echo "$workflow has no successful completed push run for $branch at $COMMIT; publication stopped" >&2
    exit 1
  fi
done
mkdir -p "$OUT"
gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --dir "$OUT"
cd "$OUT"
IDENTITY="https://github.com/$GITHUB_REPOSITORY/.github/workflows/release.yml@refs/tags/$TAG"
cosign verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
# All downloaded checksummed assets must be present. --ignore-missing could hide omissions.
sha256sum -c SHA256SUMS
for asset in "zunder-guard-$TAG.image.txt" zunder-guard.rb \
  ZunderLabs.ZunderGuard.yaml ZunderLabs.ZunderGuard.installer.yaml ZunderLabs.ZunderGuard.locale.en-US.yaml; do
  awk -v file="$asset" '$2 == file { n++ } END { exit n != 1 }' SHA256SUMS \
    || { echo "$asset is missing or repeated in the signed checksums" >&2; exit 1; }
done
[ -s "zunder-guard-$TAG.intoto.jsonl" ] || { echo "SLSA provenance is missing" >&2; exit 1; }
# Authenticate every signed checksum subject against the generic SLSA attestation.
# Verifier success alone permits any commit reached by this tag; also bind each
# verified statement to the exact commit and caller workflow gated above.
SUBJECTS=()
while read -r digest file; do
  [[ $digest =~ ^[0-9a-f]{64}$ && $file =~ ^[A-Za-z0-9._-]+$ ]] \
    || { echo "invalid provenance subject" >&2; exit 1; }
  SUBJECTS+=("$file")
done < SHA256SUMS
[ "${#SUBJECTS[@]}" -gt 0 ] || { echo "no provenance subjects" >&2; exit 1; }
GENERIC_BUILDER=https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0
slsa-verifier verify-artifact "${SUBJECTS[@]}" \
  --provenance-path "zunder-guard-$TAG.intoto.jsonl" \
  --source-uri "github.com/$GITHUB_REPOSITORY" --source-tag "$TAG" \
  --builder-id "$GENERIC_BUILDER" --print-provenance \
  | jq -se --arg commit "$COMMIT" \
    'length > 0 and all(.predicate.invocation.configSource.digest.sha1 == $commit and .predicate.invocation.configSource.entryPoint == ".github/workflows/release.yml")' >/dev/null
REF=$(cat "zunder-guard-$TAG.image.txt")
[[ $REF =~ ^ghcr.io/zunderlabs/zunder-guard@sha256:[0-9a-f]{64}$ ]] \
  || { echo "invalid signed image reference" >&2; exit 1; }
cosign verify "$REF" --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
CONTAINER_BUILDER=https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0
slsa-verifier verify-image "$REF" \
  --source-uri "github.com/$GITHUB_REPOSITORY" --source-tag "$TAG" \
  --builder-id "$CONTAINER_BUILDER" --print-provenance \
  | jq -se --arg commit "$COMMIT" \
    'length > 0 and all(.predicate.invocation.configSource.digest.sha1 == $commit and .predicate.invocation.configSource.entryPoint == ".github/workflows/release.yml")' >/dev/null
printf '%s\n' "Verified $TAG at $COMMIT and $REF"
