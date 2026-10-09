#!/usr/bin/env bash
# Renders the per-release files from their templates and writes SHA256SUMS over the whole
# release (deploy/guard/README.md, "Release pipeline"). Used by the release workflow and the
# box tests.
#
#   render.sh <version> <dist-dir>
#
# Needs the five archives package.sh made in <dist-dir> (Linux, macOS, Windows). Adds
# install.sh, i (the loader for zunderlabs.com/i), i.ps1 (the Windows installer for
# zunderlabs.com/i.ps1), zunder-guard.rb (Homebrew tap), the three winget manifests, the
# AWS template and Docker Compose with the image pinned to its immutable digest, then SHA256SUMS over every
# file. Signing SHA256SUMS (cosign, in the workflow) covers them all.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: render.sh <version> <dist-dir>" >&2; exit 2; }
VERSION=$1 DIST=$2
HERE=$(cd "$(dirname "$0")" && pwd)
[[ $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must look like v1.2.3, got $VERSION" >&2; exit 2; }
NUMBER=${VERSION#v}
# Deferred providers are not part of this release; stale files must not enter its signed manifest.
for deferred in fly.toml render.yaml railway.json cloud-init.yaml azuredeploy.json linode-stackscript.sh vultr-cloud-init.yaml oci-terraform.zip; do
  [ ! -e "$DIST/$deferred" ] || { echo "deferred provider artifact: $deferred" >&2; exit 1; }
done
EPOCH=${SOURCE_DATE_EPOCH:-0}
RELEASE_DATE=$(date -u -d "@$EPOCH" +%F)
IMAGE=ghcr.io/zunderlabs/zunder-guard
IMAGE_FILE=$DIST/zunder-guard-$VERSION.image.txt
[ -f "$IMAGE_FILE" ] || { echo "missing $IMAGE_FILE" >&2; exit 1; }
IMAGE_REF=$(python3 - "$IMAGE_FILE" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
reference = text[:-1] if text.endswith("\n") else text
if not re.fullmatch(r"ghcr\.io/zunderlabs/zunder-guard@sha256:[0-9a-f]{64}", reference):
    sys.exit("image reference must be exactly ghcr.io/zunderlabs/zunder-guard@sha256:<64 lowercase hex>")
print(reference)
PY
)

declare -A SHA
for target in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64; do
  ext=tar.gz
  [[ $target == windows-* ]] && ext=zip
  file="$DIST/zunder-guard-$VERSION-$target.$ext"
  [ -f "$file" ] || { echo "missing $file" >&2; exit 1; }
  SHA[$target]=$(sha256sum "$file" | cut -d' ' -f1)
done

render() { # template output
  sed -e "s|@VERSION@|$VERSION|g" \
    -e "s|@VERSION_NUMBER@|$NUMBER|g" \
    -e "s|@RELEASE_DATE@|$RELEASE_DATE|g" \
    -e "s|@SHA256_LINUX_AMD64@|${SHA[linux-amd64]}|g" \
    -e "s|@SHA256_LINUX_ARM64@|${SHA[linux-arm64]}|g" \
    -e "s|@SHA256_DARWIN_AMD64@|${SHA[darwin-amd64]}|g" \
    -e "s|@SHA256_DARWIN_ARM64@|${SHA[darwin-arm64]}|g" \
    -e "s|@SHA256_WINDOWS_AMD64_UPPER@|${SHA[windows-amd64]^^}|g" \
    "$1" >"$2"
  if grep -n '@[A-Z0-9_]*@' "$2"; then
    echo "unrendered placeholder in $2" >&2
    exit 1
  fi
}

render "$HERE/../install.sh" "$DIST/install.sh"
# Internal macOS helper is independently covered by the signed release manifest.
render "$HERE/../macos/install-service.sh" "$DIST/install-macos-service.sh"
render "$HERE/../loader/i.sh" "$DIST/i"
render "$HERE/../loader/i.ps1" "$DIST/i.ps1"
render "$HERE/../windows/service.ps1" "$DIST/install-windows-service.ps1"
render "$HERE/homebrew/zunder-guard.rb.in" "$DIST/zunder-guard.rb"
for m in ZunderLabs.ZunderGuard ZunderLabs.ZunderGuard.installer ZunderLabs.ZunderGuard.locale.en-US; do
  render "$HERE/winget/$m.yaml.in" "$DIST/$m.yaml"
done
# The signed release templates bind the immutable image reference in the checksummed image
# descriptor. A version tag can move, so it is never used as the release deployment reference.
for t in compose.yaml templates/cloudformation.yaml; do
  out="$DIST/$(basename "$t")"
  sed -e "s|$IMAGE:latest|$IMAGE_REF|g" "$HERE/../$t" >"$out"
  if sed "s|$IMAGE_REF||g" "$out" | grep -Fq "$IMAGE"; then
    echo "$out still names an image other than the immutable release image" >&2
    exit 1
  fi
done
# Cloud bootstrap is also a signed release payload: download this release's loader to a
# private temporary file and check its exact bytes before executing any setup command.
[ -f "$DIST/i" ] || { echo "missing rendered loader $DIST/i" >&2; exit 1; }
LOADER_SHA=$(sha256sum "$DIST/i" | cut -d' ' -f1)
python3 - "$DIST" "$VERSION" "$LOADER_SHA" <<'PY'
import pathlib, sys
dist, version, sha = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
url = f"https://github.com/zunderlabs/zunder-guard/releases/download/{version}/i"
def replace_once(text, old, new, name):
    if text.count(old) != 1:
        sys.exit(f"{name}: expected cloud bootstrap block absent or duplicated")
    return text.replace(old, new)

path = dist / "cloudformation.yaml"
text = path.read_text()
text = replace_once(text,
    'curl -fsSL --proto \'=https\' --retry 3 -o "$loader" https://zunderlabs.com/i',
    f'curl -fsSL --proto \'=https\' --retry 3 -o "$loader" \'{url}\'\n'
    f'            printf \'%s  %s\\n\' \'{sha}\' "$loader" | sha256sum -c -', path.name)
text = replace_once(text,
    "Follow deploy/guard/systemd/ACTIVATION.md at the source commit named in this release.",
    f"Follow https://github.com/zunderlabs/zunder-guard/blob/{version}/deploy/guard/systemd/ACTIVATION.md "
    "and verify that tag against the source commit in this release's provenance.", path.name)
path.write_text(text)
PY
# The installer/guardian are release bytes, authenticated before privilege/key handling.
for pair in 'install-container.py:install-container.py' 'supervisor.py:container-supervisor.py' 'operations.py:container-operations.py' 'zunder-guard-container.service:zunder-guard-container.service' 'zunder-guard-setup-guardian.service:zunder-guard-setup-guardian.service'; do
  cp "$HERE/../container/${pair%%:*}" "$DIST/${pair#*:}"
done
chmod 0644 "$DIST"/*

(cd "$DIST" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -printf '%f\n' | LC_ALL=C sort \
  | xargs sha256sum >SHA256SUMS)
cat "$DIST/SHA256SUMS"
