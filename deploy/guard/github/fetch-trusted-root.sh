#!/usr/bin/env bash
# Fetch Sigstore's trust root once per job, before any verification.
#
# gh attestation verify and cosign otherwise each fetch it over the network (TUF) with
# no retry, so one connection reset failed a whole gate or promote job. gh fetches it
# here through TUF, authenticated against the TUF root embedded in gh; it needs no
# GitHub credential. Only that fetch is retried: at most three attempts, each killed
# after TRUSTED_ROOT_TIMEOUT seconds (default 60). Verifications are never retried:
# they read these files and each still runs once and fails closed.
#
#   $RUNNER_TEMP/trusted_root.jsonl  every root gh trusts (gh --custom-trusted-root)
#   $RUNNER_TEMP/trusted_root.json   the public-good root only (cosign --trusted-root)
#
# Both appear together or not at all; consumers refuse a partial or unbound pair.
set -euo pipefail
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
GH_ROOT=$RUNNER_TEMP/trusted_root.jsonl
COSIGN_ROOT=$RUNNER_TEMP/trusted_root.json
for root in "$GH_ROOT" "$COSIGN_ROOT"; do
  if [ -e "$root" ] || [ -L "$root" ]; then
    echo "Sigstore trusted root already exists; fetch it once per job" >&2
    exit 1
  fi
done
LIMIT=${TRUSTED_ROOT_TIMEOUT:-60}
[[ $LIMIT =~ ^[1-9][0-9]{0,3}$ ]] || { echo "TRUSTED_ROOT_TIMEOUT must be 1 to 9999 seconds" >&2; exit 1; }
work=$(mktemp -d "$RUNNER_TEMP/trusted-root.XXXXXX")
trap 'rm -rf "$work"' EXIT
# One fetch, killed after $LIMIT seconds. A watcher process rather than timeout(1):
# macOS runners have no timeout(1), and in Git Bash `timeout` can resolve to Windows'
# own wait command. The watcher holds no stdio, so it never keeps a caller's pipe open.
bounded_fetch() {
  local pid watcher status=0
  gh attestation trusted-root >"$work/roots.jsonl" 2>"$work/error" &
  pid=$!
  (
    for ((tick = 0; tick < LIMIT; tick++)); do
      kill -0 "$pid" 2>/dev/null || exit 0
      sleep 1
    done
    : >"$work/timed-out"
    kill -TERM "$pid" 2>/dev/null
    sleep 2
    kill -KILL "$pid" 2>/dev/null
  ) </dev/null >/dev/null 2>&1 &
  watcher=$!
  wait "$pid" || status=$?
  kill "$watcher" 2>/dev/null || true
  wait "$watcher" 2>/dev/null || true
  return "$status"
}
for attempt in 1 2 3; do
  rm -f "$work/timed-out"
  if bounded_fetch && [ ! -e "$work/timed-out" ]; then
    break
  fi
  cat "$work/error" >&2
  [ ! -e "$work/timed-out" ] || echo "Sigstore trusted root fetch attempt $attempt timed out after ${LIMIT}s" >&2
  if [ "$attempt" -eq 3 ]; then
    echo "Sigstore trusted root unavailable after 3 attempts" >&2
    exit 1
  fi
  sleep "$((attempt * ${TRUSTED_ROOT_PAUSE:-10}))"
done
media='application/vnd.dev.sigstore.trustedroot+json'
size=$(wc -c <"$work/roots.jsonl" | tr -d ' ')
[ "$size" -le 1048576 ] || { echo "fetched Sigstore trusted root exceeds 1 MiB" >&2; exit 1; }
jq -e -s --arg media "$media" \
  'length >= 1 and all(.[]; type == "object" and (.mediaType | type == "string" and startswith($media)))' \
  "$work/roots.jsonl" >/dev/null || { echo "fetched Sigstore trusted root is malformed" >&2; exit 1; }
# cosign takes one TrustedRoot: the public-good instance (Rekor and Fulcio at sigstore.dev)
# that signs Guard's release checksums and image. GitHub's own instance stays gh-only.
jq -c -s '[.[] | select(any(.tlogs[]?; .baseUrl == "https://rekor.sigstore.dev")
    and any(.certificateAuthorities[]?; .uri == "https://fulcio.sigstore.dev"))]
  | if length == 1 then .[0] else error("expected exactly one public-good trusted root") end' \
  "$work/roots.jsonl" >"$work/public-good.json"
chmod 0444 "$work/roots.jsonl" "$work/public-good.json"
# The cosign file first: an interrupted move leaves a partial pair, which is refused.
mv "$work/public-good.json" "$COSIGN_ROOT"
mv "$work/roots.jsonl" "$GH_ROOT"
echo "Sigstore trusted root fetched on attempt $attempt"
