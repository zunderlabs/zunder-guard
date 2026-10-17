#!/usr/bin/env bash
# Container builds that survive a public registry's throttling (HTTP 429 "toomanyrequests") and
# its 5xx or timed-out pulls, without ever building from a different image. Anonymous pulls from
# shared GitHub runner addresses are throttled now and then; release.yml and ci.yml build through
# this script (deploy/guard/README.md, "Release pipeline and publishing").
#
#   registry-retry.sh warm <Dockerfile> <platforms|-> <stage>...
#       Fetches the image each named stage starts FROM, and the `# syntax=` frontend of the
#       Dockerfile's first line, into the current buildx builder, with the retries below. `-` is
#       the builder's own platform; otherwise a comma-separated list such as
#       linux/amd64,linux/arm64 (nothing runs inside the images, so no emulation is needed).
#       The build that follows on the same builder then reads them from the builder's own store
#       and sends the registry no request for them: BuildKit reuses content it holds for a
#       reference pinned by digest, --no-cache included. A `docker pull` would not do: the
#       docker-container builder that docker/setup-buildx-action creates keeps its own store,
#       apart from the Docker daemon's. A stage whose FROM is not pinned by digest is refused,
#       so what is fetched is always the image the Dockerfile names, verified by its digest.
#   registry-retry.sh run -- <command>...
#       Runs the command. When it fails and its output shows a registry request that got HTTP
#       429 or 5xx or timed out, waits 60, 120, then 240 s and runs it again: at most 3 retries.
#       Any other failure returns the command's exit status at once.
set -euo pipefail

DELAYS=(60 120 240)
# A line counts only when it is an error line, names a registry request, and carries a transient
# status, so a failure of the build itself (a compile error, a refused check) is never retried.
ERROR_LINE='^(#[0-9]+ )?ERROR: |^Error response from daemon: '
REGISTRY='toomanyrequests|https?://[^ ]+/v2/|https?://[^ ]+/token|failed to (resolve source metadata|copy|fetch|do request|authorize)|unexpected status|httpReadSeeker'
TRANSIENT='toomanyrequests|(^|[^0-9A-Za-z])(429|5[0-9][0-9]) [A-Z]|status( code)?:? (429|5[0-9][0-9])([^0-9]|$)|i/o timeout|TLS handshake timeout|Client[.]Timeout exceeded'

usage() {
  echo "usage: registry-retry.sh run -- <command>... | registry-retry.sh warm <Dockerfile> <platforms|-> <stage>..." >&2
  exit 2
}
die() { echo "registry-retry: $*" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

transient() ( # $1: the failed attempt's output
  set +o pipefail
  grep -E "$ERROR_LINE" "$1" | grep -E "$REGISTRY" | grep -Eq "$TRANSIENT"
)

run() {
  local attempt=0 status delay
  while :; do
    set +e
    "$@" 2>&1 | tee "$TMP/output"
    status=${PIPESTATUS[0]}
    set -e
    [ "$status" -ne 0 ] || return 0
    if [ "$attempt" -ge "${#DELAYS[@]}" ] || ! transient "$TMP/output"; then
      return "$status"
    fi
    delay=${DELAYS[$attempt]}
    attempt=$((attempt + 1))
    echo "::warning::registry-retry: a registry pull failed with HTTP 429 or 5xx or timed out; retry $attempt of ${#DELAYS[@]} in $delay s" >&2
    sleep "$delay"
  done
}

warm() {
  [ $# -ge 3 ] || usage
  local dockerfile=$1 platforms=$2 stage ref first n=0 i
  shift 2
  [ -f "$dockerfile" ] || die "no Dockerfile at $dockerfile"
  mkdir "$TMP/warm"
  first=$(head -n 1 "$dockerfile")
  {
    case "$first" in '# syntax='*) printf '%s\n' "$first" ;; esac
    for stage; do
      ref=$(awk -v s="$stage" 'toupper($1) == "FROM" && NF == 4 && tolower($3) == "as" && $4 == s { print $2 }' "$dockerfile")
      [[ $ref =~ ^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$ ]] \
        || die "stage '$stage' of $dockerfile does not start FROM exactly one image pinned by digest"
      printf 'FROM %s AS base%d\n' "$ref" "$n"
      n=$((n + 1))
    done
    # Copying each image's whole file system makes BuildKit fetch every layer, not only the
    # manifest and configuration; the result is kept in the builder's cache, never exported.
    printf 'FROM scratch\n'
    for ((i = 0; i < n; i++)); do printf 'COPY --from=base%d / /base%d/\n' "$i" "$i"; done
  } >"$TMP/warm/Dockerfile"
  local args=(buildx build --progress=plain --output type=cacheonly -f "$TMP/warm/Dockerfile")
  [ "$platforms" = - ] || args+=(--platform "$platforms")
  run docker "${args[@]}" "$TMP/warm"
}

case "${1:-}" in
  run)
    shift
    [ "${1:-}" = -- ] || usage
    shift
    [ $# -gt 0 ] || usage
    run "$@"
    ;;
  warm)
    shift
    warm "$@"
    ;;
  *) usage ;;
esac
