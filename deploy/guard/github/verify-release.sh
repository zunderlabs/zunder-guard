#!/usr/bin/env bash
# Complete customer-publication gate, including maintainer-attested native readiness.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: verify-release.sh <vX.Y.Z> <empty-output-dir>" >&2; exit 2; }
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bash "$HERE/verify-release-assets.sh" "$1" "$2"
python3 -B "$HERE/native-readiness.py" verify "$1" "$2"
