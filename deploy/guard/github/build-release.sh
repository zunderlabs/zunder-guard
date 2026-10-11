#!/usr/bin/env bash
# Builds the release binary for one target, reproducibly (deploy/guard/README.md, "Release
# pipeline"). release.yml uses it for macOS and Windows (Linux binaries come from the
# Dockerfile's pinned build stage); on Windows it runs in Git Bash.
#
#   build-release.sh <rust-target-triple>
#
# Reproducible: the toolchain is pinned by rust-toolchain.toml, dependencies by Cargo.lock
# (--locked), build paths are remapped, symbols stripped, and SOURCE_DATE_EPOCH is the tagged
# commit's time. Linux targets are musl and fully static.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: build-release.sh <target-triple>" >&2; exit 2; }
TRIPLE=$1
PACKAGE=${GUARD_PACKAGE:-zunder-guard}
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH
# rustc sees Windows paths (D:\a\...) where Git Bash shows /d/a/...: remap what rustc sees.
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
flags=(
  "--remap-path-prefix=$(native "$PWD")=/build"
  "--remap-path-prefix=$(native "${CARGO_HOME:-$HOME/.cargo}")=/cargo"
  "--remap-path-prefix=$(native "${RUSTUP_HOME:-$HOME/.rustup}")=/rustup"
  "-C" "strip=symbols"
)
if [[ $TRIPLE == *-linux-musl ]]; then
  flags+=("-C" "target-feature=+crt-static")
fi
if [[ $TRIPLE == *-windows-msvc ]]; then
  # No link time stamp in the PE header, and the C runtime linked in statically (no
  # vcruntime DLL to install).
  flags+=("-C" "link-arg=/Brepro" "-C" "target-feature=+crt-static")
fi
RUSTFLAGS="${flags[*]}"
export RUSTFLAGS
cargo build --release --locked --target "$TRIPLE" -p "$PACKAGE" --bin zunder-guard
