#!/usr/bin/env bash
# Draft asset verification only: signatures, checksums, provenance and source CI.
# Build authentication alone does not authorize publication; verify.yml and promote.yml require the complete authenticated journey gate.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: verify-release-assets.sh <vX.Y.Z> <empty-output-dir>" >&2; exit 2; }
TAG=$1 OUT=$2
[[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[1-9][0-9]*)?$ ]] || { echo "unexpected release tag" >&2; exit 1; }
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
# BEGIN gh_retry
# GitHub answers an occasional 5xx or 429 (rc.16 verify 38569322248, T2: HTTP 500 on a
# release asset). Only those GitHub answers are retried, at most three attempts, and only
# for gh; no verification below is ever retried. A failed attempt's output is
# never passed on, and every downloaded byte is still checked against the signed
# checksums, signatures and provenance below.
gh_retry() {
  local attempt status out err
  out=$(mktemp)
  err=$(mktemp)
  for attempt in 1 2 3; do
    if gh "$@" >"$out" 2>"$err"; then
      cat "$out"
      rm -f "$out" "$err"
      return 0
    else
      status=$?
    fi
    cat "$err" >&2
    if [ "$attempt" -lt 3 ] && grep -Eq '(^|[^0-9])HTTP (5[0-9]{2}|429)([^0-9]|$)' "$err"; then
      sleep "$((attempt * ${GH_RETRY_PAUSE:-15}))"
      continue
    fi
    rm -f "$out" "$err"
    return "$status"
  done
}
# END gh_retry
# BEGIN slsa_retry
# slsa-verifier reaches Rekor and the registry; a transport failure there (v1.0.1's gate:
# "giving up after" one Rekor attempt) is not a verdict. Only such failures are
# retried, at most three attempts with backoff. A verification refusal names none of
# these markers and is never retried; a failed attempt's output is never passed on.
slsa_retry() {
  local attempt status out err
  out=$(mktemp)
  err=$(mktemp)
  for attempt in 1 2 3; do
    if slsa-verifier "$@" >"$out" 2>"$err"; then
      cat "$err" >&2
      cat "$out"
      rm -f "$out" "$err"
      return 0
    else
      status=$?
    fi
    cat "$err" >&2
    if [ "$attempt" -lt 3 ] && grep -Eiq \
      'context deadline exceeded|connection reset|giving up after|i/o timeout|TLS handshake timeout|(status code|HTTP|status)[^0-9a-z]{0,3}5[0-9]{2}([^0-9]|$)' \
      "$err"; then
      echo "slsa-verifier $1: transport failure on attempt $attempt; retrying" >&2
      sleep "$((attempt * ${SLSA_RETRY_PAUSE:-15}))"
      continue
    fi
    rm -f "$out" "$err"
    return "$status"
  done
}
# END slsa_retry
if [ -e "$OUT" ]; then
  echo "release output must not exist" >&2
  exit 1
fi
# The job's Sigstore trust root, fetched once with a bounded retry by
# fetch-trusted-root.sh, replaces cosign's own unretried TUF fetch. Without it cosign
# fetches as before; a partial or unbound pair is refused, never replaced.
TRUST=()
GH_ROOT=${RUNNER_TEMP:+$RUNNER_TEMP/trusted_root.jsonl}
COSIGN_ROOT=${RUNNER_TEMP:+$RUNNER_TEMP/trusted_root.json}
if [ -n "${RUNNER_TEMP:-}" ] && { [ -e "$GH_ROOT" ] || [ -L "$GH_ROOT" ] || [ -e "$COSIGN_ROOT" ] || [ -L "$COSIGN_ROOT" ]; }; then
  for root in "$GH_ROOT" "$COSIGN_ROOT"; do
    if [ ! -f "$root" ] || [ -L "$root" ]; then
      echo "Sigstore trusted root was fetched incompletely" >&2
      exit 1
    fi
    # The same bounds as the harness (attestation.trusted_roots): 1 MiB each, every
    # JSONL line and the cosign root a Sigstore TrustedRoot object.
    [ "$(wc -c <"$root" | tr -d ' ')" -le 1048576 ] \
      || { echo "Sigstore trusted root exceeds its size limit" >&2; exit 1; }
  done
  jq -e -s --arg media 'application/vnd.dev.sigstore.trustedroot+json' \
    'length >= 1 and all(.[]; type == "object" and (.mediaType | type == "string" and startswith($media)))' \
    "$GH_ROOT" >/dev/null || { echo "fetched Sigstore trusted root has an unexpected type" >&2; exit 1; }
  jq -e -s --slurpfile public "$COSIGN_ROOT" '($public | length) == 1 and (map(select(. == $public[0])) | length) == 1' \
    "$GH_ROOT" >/dev/null || { echo "cosign trusted root is not exactly one fetched gh root" >&2; exit 1; }
  TRUST=(--trusted-root "$COSIGN_ROOT")
fi
COMMIT=$(gh_retry api "repos/$GITHUB_REPOSITORY/commits/$TAG" --jq .sha)
[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || { echo "cannot resolve release commit" >&2; exit 1; }
for workflow in ci release; do
  runs=$(gh_retry api --method GET "repos/$GITHUB_REPOSITORY/actions/workflows/$workflow.yml/runs" \
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
gh_retry release download "$TAG" --repo "$GITHUB_REPOSITORY" --dir "$OUT" --clobber \
  --pattern SHA256SUMS --pattern SHA256SUMS.sigstore.json --pattern "zunder-guard-$TAG.intoto.jsonl"
cd "$OUT"
IDENTITY="https://github.com/$GITHUB_REPOSITORY/.github/workflows/release.yml@refs/tags/$TAG"
cosign verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com ${TRUST[@]+"${TRUST[@]}"} SHA256SUMS
# Download only signed software subjects. Native report/log downloads have separate
# strict byte/count limits; gh release download without patterns would bypass them.
ASSET_PATTERNS=()
while read -r digest file; do
  [[ $digest =~ ^[0-9a-f]{64}$ && $file =~ ^[A-Za-z0-9._-]+$ && $file != *..* ]] \
    || { echo "invalid signed asset name" >&2; exit 1; }
  ASSET_PATTERNS+=(--pattern "$file")
done < SHA256SUMS
if ! { [ "${#ASSET_PATTERNS[@]}" -gt 0 ] && [ "${#ASSET_PATTERNS[@]}" -le 512 ]; }; then
  echo "signed subject count outside limit" >&2
  exit 1
fi
gh_retry release download "$TAG" --repo "$GITHUB_REPOSITORY" --dir . --clobber "${ASSET_PATTERNS[@]}"
# All checksummed assets must be present. --ignore-missing could hide omissions.
sha256sum -c SHA256SUMS
for asset in install-windows-service.ps1 install-macos-service.sh uninstall-macos-testnet.py install-container.py container-supervisor.py container-operations.py \
  zunder-guard-container.service zunder-guard-setup-guardian.service \
  "zunder-guard-$TAG.image.txt" zunder-guard.rb \
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
slsa_retry verify-artifact "${SUBJECTS[@]}" \
  --provenance-path "zunder-guard-$TAG.intoto.jsonl" \
  --source-uri "github.com/$GITHUB_REPOSITORY" --source-tag "$TAG" \
  --builder-id "$GENERIC_BUILDER" --print-provenance \
  | jq -se --arg commit "$COMMIT" \
    'length > 0 and all(.predicate.invocation.configSource.digest.sha1 == $commit and .predicate.invocation.configSource.entryPoint == ".github/workflows/release.yml")' >/dev/null
REF=$(cat "zunder-guard-$TAG.image.txt")
[[ $REF =~ ^ghcr.io/zunderlabs/zunder-guard@sha256:[0-9a-f]{64}$ ]] \
  || { echo "invalid signed image reference" >&2; exit 1; }
cosign verify "$REF" --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com ${TRUST[@]+"${TRUST[@]}"}
CONTAINER_BUILDER=https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0
slsa_retry verify-image "$REF" \
  --source-uri "github.com/$GITHUB_REPOSITORY" --source-tag "$TAG" \
  --builder-id "$CONTAINER_BUILDER" --print-provenance \
  | jq -se --arg commit "$COMMIT" \
    'length > 0 and all(.predicate.invocation.configSource.digest.sha1 == $commit and .predicate.invocation.configSource.entryPoint == ".github/workflows/release.yml")' >/dev/null
printf '{"tag":"%s","source":"%s"}\n' "$TAG" "$COMMIT" > .verified-release-source.json
printf '%s\n' "Verified draft assets $TAG at $COMMIT and $REF; native readiness not yet checked"
