#!/usr/bin/env bash
# The red-team suite against a real Guard in paper mode (docs/redteam.md, "Against a running
# Guard"): a fresh home, a paper config reading a public testnet account, no key, then the
# whole catalogue over HTTP. Paper mode sends nothing; the reads go to the testnet API.
#
#   bash deploy/guard/test/redteam-paper.sh [ACCOUNT] [RULES]
#
# ACCOUNT: a public testnet account to read (default: one seen trading BTC on testnet on
# 6 Oct 2026). RULES: a zr1_ code (default: every market of the main dex and of HIP-3 dex
# xyz, so the HIP-3 cases run). Writes the reports to $HOME/redteam-paper/. REDTEAM_ARGS passes
# more to the suite, e.g. "--only market_hip3 --pace-ms 7500" to judge those cases on their
# merits: a burst meets Guard's request-read budget (rate_limited, still a refusal).
set -euo pipefail
cd "$(dirname "$0")/../../.."
ACCOUNT="${1:-0x5972698398d8c5bbe67c0db74906236691020417}"
RULES="${2:-zr1_eyJ2IjoxLCJtYXhMZXZlcmFnZSI6NSwibWF4TG9zc0F0U3RvcFBjdCI6Miwic3RvcFBvbGljeSI6ImF0dGFjaCIsImRlZmF1bHRTdG9wRGlzdGFuY2VQY3QiOjIsIm1pbkxpcURpc3RhbmNlUGN0IjoxMCwibWF4UG9zaXRpb25QY3QiOjIwMCwibWF4T3BlblJpc2tQY3QiOjYsImRhaWx5TG9zc1N0b3BQY3QiOjYsImRyYXdkb3duSGFsdFBjdCI6MjUsIm1hcmtldHMiOlsiKiIsInh5ejoqIl19}"
LISTEN=127.0.0.1:18547
OUT="$HOME/redteam-paper"
cargo build -q -p zunder-guard -p zunder-redteam
BIN="${CARGO_TARGET_DIR:-target}/debug"
HOME_DIR=$(mktemp -d)
rm -rf "$OUT" && mkdir -p "$OUT"
"$BIN/zunder-guard" init --home "$HOME_DIR" --non-interactive --network paper \
  --account "$ACCOUNT" --account-network testnet --no-key \
  --client-key-out "$HOME_DIR/client" --listen "$LISTEN" --rules "$RULES" >"$OUT/init.log" 2>&1
"$BIN/zunder-guard" run --home "$HOME_DIR" >"$OUT/guard.log" 2>&1 &
GUARD=$!
trap 'kill $GUARD 2>/dev/null || true; rm -rf "$HOME_DIR"' EXIT
# The first sync, and nonces from after Guard's start plus 5 s.
sleep 20
curl -s "http://$LISTEN/guard/status" >"$OUT/status-before.json"
# shellcheck disable=SC2086 # REDTEAM_ARGS is a list of arguments, split on purpose
"$BIN/zunder-redteam" --url "http://$LISTEN" --client-key "$(head -1 "$HOME_DIR/client")" \
  --json "$OUT/redteam.json" --report "$OUT/redteam.txt" ${REDTEAM_ARGS:-} >"$OUT/run.log" 2>&1 || true
curl -s "http://$LISTEN/guard/status" >"$OUT/status-after.json"
tail -n 40 "$OUT/redteam.txt"
echo "== 429s in Guard's log: $(grep -c '429' "$OUT/guard.log" || true)"
grep -o '"dexes":\[[^]]*\]' "$OUT/status-after.json" || true
