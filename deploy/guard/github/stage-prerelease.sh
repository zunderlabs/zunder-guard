#!/usr/bin/env bash
# Called only after release.yml's asset, provenance, image and smoke jobs succeed.
set -euo pipefail
: "${GITHUB_REPOSITORY:?}" "${GITHUB_REF:?}" "${GITHUB_SHA:?}"
[[ "$GITHUB_REPOSITORY" == zunderlabs/zunder-guard ]]
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]
tag=${GITHUB_REF#refs/tags/}
[[ "$GITHUB_REF" == "refs/tags/$tag" ]]
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[1-9][0-9]*)?$ ]]
# Exported tags are immutable. Check the tag checkout rather than release target_commitish,
# which GitHub may report as a branch name instead of the commit to which the tag resolves.
[[ "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]]
[[ "$(git rev-parse "refs/tags/$tag^{commit}")" == "$GITHUB_SHA" ]]
release=$(gh release view "$tag" --repo "$GITHUB_REPOSITORY" --json tagName,isDraft,isPrerelease)
jq -e --arg tag "$tag" '.tagName == $tag and .isDraft == true' <<<"$release"
# No canonical channel writes. A failure/unknown write outcome is never retried here.
gh release edit "$tag" --repo "$GITHUB_REPOSITORY" --draft=false --prerelease --latest=false
release=$(gh release view "$tag" --repo "$GITHUB_REPOSITORY" --json tagName,isDraft,isPrerelease)
jq -e --arg tag "$tag" '.tagName == $tag and .isDraft == false and .isPrerelease == true' <<<"$release"
