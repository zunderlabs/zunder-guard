#!/usr/bin/env bash
# Official promotion uses existing authenticated human gh CLI access. No new credentials.
# Run from reviewed release tooling; API /user and current role are checked before promotion.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: promote-release.sh <vX.Y.Z> <empty-output-dir>" >&2; exit 2; }
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bash "$HERE/verify-release.sh" "$1" "$2"
python3 -B "$HERE/native-readiness.py" promote "$1" "$2"
