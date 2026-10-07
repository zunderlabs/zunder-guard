#!/usr/bin/env bash
# Packs one built binary into its release archive, byte for byte reproducibly
# (deploy/guard/README.md, "Release pipeline"). Used by the release workflow and the box tests.
#
#   package.sh <version> <os-arch> <binary> <out-dir>
#   package.sh v1.0.0 linux-amd64 target/x86_64-unknown-linux-musl/release/zunder-guard dist
#
# linux-* and darwin-* become zunder-guard-<version>-<os-arch>.tar.gz (flat: zunder-guard,
# README.md, LICENSE, NOTICE, THIRD_PARTY_LICENSES.md when the repository root has them, and
# for Linux the systemd unit); windows-amd64 becomes zunder-guard-<version>-windows-amd64.zip
# with zunder-guard.exe and the same text files. Timestamps come from SOURCE_DATE_EPOCH (the
# tagged commit's time in the workflow), owners and order are fixed, gzip stores no name or
# time, the zip no extra fields. Needs GNU tar and Python 3 ($PYTHON, default python3).
#
# GUARD_REQUIRE_NOTICES=1 (the public repository's release workflow) refuses to pack without
# the licence files.
set -euo pipefail
[ $# -eq 4 ] || { echo "usage: package.sh <version> <os-arch> <binary> <out-dir>" >&2; exit 2; }
VERSION=$1 TARGET=$2 BINARY=$3 OUT=$4
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
EPOCH=${SOURCE_DATE_EPOCH:-0}
[[ $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must look like v1.2.3, got $VERSION" >&2; exit 2; }
[ -f "$BINARY" ] || { echo "no binary at $BINARY" >&2; exit 2; }
# The stub's version string is in its bytes; grep works for binaries of any platform.
if grep -aq 'STUB: a packaging test double' "$BINARY" && [ "${ZUNDER_GUARD_ALLOW_STUB:-}" != "test-only" ]; then
  echo "refusing to package the STUB binary (deploy/guard/stub) as a release" >&2
  exit 1
fi
mkdir -p "$OUT"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp "$HERE/release-readme.md" "$STAGE/README.md"
files=()
notices() { # stage-dir: copies the licence files there and adds them to files
  for notice in LICENSE NOTICE THIRD_PARTY_LICENSES.md; do
    if [ -f "$ROOT/$notice" ]; then
      install -m 0644 "$ROOT/$notice" "$1/$notice"
      files+=("$notice")
    elif [ "${GUARD_REQUIRE_NOTICES:-}" = 1 ]; then
      echo "no $notice at the repository root; a release ships the licence files" >&2
      return 1
    fi
  done
}
case "$TARGET" in
  linux-amd64 | linux-arm64 | darwin-amd64 | darwin-arm64)
    install -m 0755 "$BINARY" "$STAGE/zunder-guard"
    files+=(README.md zunder-guard)
    if [[ $TARGET == linux-* ]]; then
      install -m 0644 "$HERE/../systemd/zunder-guard.service" "$STAGE/zunder-guard.service"
      files+=(zunder-guard.service)
    fi
    chmod 0644 "$STAGE/README.md"
    notices "$STAGE" || exit 1
    ARCHIVE="$OUT/zunder-guard-$VERSION-$TARGET.tar.gz"
    tar --sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner --format=gnu \
      -C "$STAGE" -cf - "${files[@]}" | gzip -n -9 >"$ARCHIVE"
    ;;
  windows-amd64)
    install -m 0755 "$BINARY" "$STAGE/zunder-guard.exe"
    notices "$STAGE" || exit 1
    ARCHIVE="$OUT/zunder-guard-$VERSION-$TARGET.zip"
    "${PYTHON:-python3}" - "$STAGE" "$ARCHIVE" "$EPOCH" <<'PY'
import os, sys, time, zipfile
stage, archive, epoch = sys.argv[1], sys.argv[2], max(int(sys.argv[3]), 315532800)
stamp = time.gmtime(epoch)[:6]
names = sorted(os.listdir(stage))
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
    for name in names:
        info = zipfile.ZipInfo(name, stamp)
        mode = 0o755 if name.endswith(".exe") else 0o644
        info.external_attr = (0o100000 | mode) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        with open(os.path.join(stage, name), "rb") as f:
            z.writestr(info, f.read())
PY
    ;;
  *) echo "unknown target $TARGET (linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, windows-amd64)" >&2; exit 2 ;;
esac
echo "$ARCHIVE"
