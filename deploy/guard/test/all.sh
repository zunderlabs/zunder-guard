#!/usr/bin/env bash
# Every Guard packaging test, on the Linux build host (deploy/guard/README.md, "Testing"):
#
#   bash deploy/guard/test/box-setup.sh   # once: Docker, QEMU, shellcheck, Ruby
#   bash deploy/guard/test/all.sh
set -euo pipefail
cd "$(dirname "$0")"
python3 release-policy.py
python3 native-readiness.py
python3 macos-shell.py
./rules.sh
./lint.sh
./image.sh
./installer.sh
echo "all Guard packaging tests passed"
