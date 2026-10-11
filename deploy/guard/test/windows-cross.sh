#!/usr/bin/env bash
# Windows on the Linux build host (deploy/guard/README.md, "Testing"): Guard's crates cross-compiled
# for x86_64-pc-windows-gnu with MinGW-w64, clippy on the Windows code paths (cfg(windows)),
# and a release build of zunder-guard.exe. The box cannot run Windows binaries (arm64, no
# Windows); the tests run on GitHub's Windows runners (ci.yml, release.yml).
#
#   bash deploy/guard/test/windows-cross.sh
set -euo pipefail
cd "$(dirname "$0")/../../.."
TARGET=x86_64-pc-windows-gnu
CRATES=(-p zunder-guard -p zunder-guard-core -p zunder-guard-mcp -p zunder-guard-rules -p zunder-venue -p zunder-risk -p zunder-core -p zunder-redteam)
command -v x86_64-w64-mingw32-gcc >/dev/null || sudo apt-get install -yq gcc-mingw-w64-x86-64 >/dev/null
rustup target list --installed | grep -qx "$TARGET" || rustup target add "$TARGET"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc

echo "== clippy for $TARGET (all targets, -D warnings)"
cargo clippy --target "$TARGET" "${CRATES[@]}" --all-targets --locked -- -D warnings
echo "== release build of zunder-guard.exe for $TARGET"
cargo build --release --target "$TARGET" -p zunder-guard --bin zunder-guard --locked 2>&1 | tail -1
EXE=${CARGO_TARGET_DIR:-target}/$TARGET/release/zunder-guard.exe
file "$EXE"
ls -l "$EXE"
echo "windows cross-compile passed"
