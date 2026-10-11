#!/usr/bin/env bash
# Installer tests on the Linux build host (deploy/guard/README.md, "Testing"). Builds a fake release
# v0.0.0 from the real zunder-guard binary with the real package.sh and render.sh, then
# drives the loader and install.sh through a terminal (installer_test.py):
#   - in Ubuntu (dash) and Alpine (busybox ash) containers as a non-root user: guided paper,
#     edit with bounds checks, testnet and mainnet with a hidden key the venue check refuses,
#     mainnet confirmation and equity cap, no-TTY refusal, non-interactive, invalid rules, and
#     four kinds of tampering;
#   - in a container without cosign: the pinned cosign download and its SHA-256;
#   - on the box itself: the systemd path (paper running; a refused key storing nothing; an
#     encrypted credential reaching the binary on standard input; mainnet refused without
#     systemd-creds), then everything removed again; and `docker run -it … init --interactive`.
# GUARD_INSTALLER_BIN_DIR optionally reuses the two real Linux binaries from completed
# preflight images: <dir>/{amd64,arm64}/zunder-guard and source-images.json recording each
# architecture's image, immutable image id and binary sha256. Default: build both binaries.
# The binary reads public Hyperliquid data for two public accounts (installer_test.py); it
# sends nothing. The keyed success paths need a real API wallet key (docs/guard.md, "Setup").
set -euo pipefail
cd "$(dirname "$0")/../../.."
REPO=$PWD
for notice in LICENSE NOTICE THIRD_PARTY_LICENSES.md; do
  [ -f "$notice" ] || { echo "installer tests require a public export containing $notice" >&2; exit 1; }
done
export GUARD_REQUIRE_NOTICES=1
DOCKER=docker
id -nG | grep -qw docker || DOCKER="sudo docker"
BUILDER=zunder-guard
VERSION=v0.0.0
W=$(mktemp -d)
chmod 0755 "$W"
trap 'rm -rf "$W"' EXIT
REL=$W/rel

echo "== fake release $VERSION from the real binary"
if [ -n "${GUARD_INSTALLER_BIN_DIR:-}" ]; then
  python3 - "$GUARD_INSTALLER_BIN_DIR" <<'PY'
import hashlib, json, pathlib, re, struct, sys
root = pathlib.Path(sys.argv[1])
sources = json.loads((root / "source-images.json").read_text())
assert set(sources) == {"amd64", "arm64"}, "both real preflight images are required"
for arch, machine in (("amd64", 62), ("arm64", 183)):
    source = sources[arch]
    assert source["image"] == f"zunder-guard:test-{arch}", "not a preflight image"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", source["id"]), "immutable image id required"
    data = (root / arch / "zunder-guard").read_bytes()
    assert data[:6] == b"\x7fELF\x02\x01", "a real 64-bit Linux ELF binary is required"
    assert struct.unpack_from("<H", data, 18)[0] == machine, "wrong binary architecture"
    assert b"STUB: a packaging test double" not in data, "stub binary refused"
    digest = hashlib.sha256(data).hexdigest()
    assert digest == source["sha256"], "binary differs from its extracted image evidence"
    print(f"  reuse linux/{arch}: {source['image']} {source['id']} binary sha256:{digest}")
PY
  for arch in amd64 arm64; do
    install -D -m 0755 "$GUARD_INSTALLER_BIN_DIR/$arch/zunder-guard" "$W/bin-$arch/zunder-guard"
  done
else
  for arch in amd64 arm64; do
    $DOCKER buildx build --builder "$BUILDER" -f deploy/guard/Dockerfile --build-arg GUARD_PACKAGE=zunder-guard \
      --platform "linux/$arch" --target bin-build -o "type=local,dest=$W/bin-$arch" . >/dev/null 2>&1
  done
fi
export SOURCE_DATE_EPOCH=1700000000
mkdir -p "$REL/$VERSION"
for arch in amd64 arm64; do
  deploy/guard/packaging/package.sh "$VERSION" "linux-$arch" "$W/bin-$arch/zunder-guard" "$REL/$VERSION" >/dev/null
  # Placeholders: the box cannot build macOS binaries; only their packaging is tested.
done
deploy/guard/packaging/package.sh "$VERSION" darwin-amd64 "$W/bin-amd64/zunder-guard" "$REL/$VERSION" >/dev/null
deploy/guard/packaging/package.sh "$VERSION" darwin-arm64 "$W/bin-arm64/zunder-guard" "$REL/$VERSION" >/dev/null
# The renderer requires all five archives. This Linux binary only exercises Windows archive
# names, checksums and manifest rendering; it is not a Windows build or runtime test.
echo "  windows-amd64: Linux stand-in for packaging/rendering only (not executable on Windows)"
deploy/guard/packaging/package.sh "$VERSION" windows-amd64 "$W/bin-amd64/zunder-guard" "$REL/$VERSION" >/dev/null
# Synthetic digest only for rendering this private installer fixture; no image is published.
printf 'ghcr.io/zunderlabs/zunder-guard@sha256:%064d\n' 0 >"$REL/$VERSION/zunder-guard-$VERSION.image.txt"
deploy/guard/packaging/render.sh "$VERSION" "$REL/$VERSION" | sed 's/^/  /'
sum=$(sha256sum "$REL/$VERSION/SHA256SUMS" | cut -d' ' -f1)
printf '{"identity": "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/%s", "sha256": "%s"}\n' \
  "$VERSION" "$sum" >"$REL/$VERSION/SHA256SUMS.sigstore.json"
mkdir "$W/fakebin" && install -m 0755 deploy/guard/test/fake-cosign "$W/fakebin/cosign"
chmod -R a+rX "$W"

echo "== reproducible archives: packing again gives the same bytes"
mkdir "$W/again"
deploy/guard/packaging/package.sh "$VERSION" linux-arm64 "$W/bin-arm64/zunder-guard" "$W/again" >/dev/null
cmp "$W/again/zunder-guard-$VERSION-linux-arm64.tar.gz" "$REL/$VERSION/zunder-guard-$VERSION-linux-arm64.tar.gz"
echo "  ok: tar.gz identical"

echo "== test images"
$DOCKER build -q -t guard-installer-test:ubuntu -f - . >/dev/null <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -q && apt-get install -yq --no-install-recommends curl ca-certificates python3-pexpect >/dev/null \
 && useradd -m tester
EOF
$DOCKER build -q -t guard-installer-test:alpine -f - . >/dev/null <<'EOF'
FROM alpine:3.22
RUN apk add --no-cache curl python3 py3-pexpect util-linux-misc >/dev/null && adduser -D tester
EOF

in_container() { # image mode [extra docker args]
  local image=$1 mode=$2
  shift 2
  $DOCKER run --rm -u tester -v "$REL:/rel:ro" -v "$REPO/deploy/guard/test:/t:ro" -v "$W/fakebin:/fakebin:ro" \
    -e REL=/rel -e FAKE_COSIGN_DIR=/fakebin "$@" "$image" python3 /t/installer_test.py "$mode"
}
echo "== Ubuntu 24.04 (dash), non-root, no systemd"
in_container guard-installer-test:ubuntu container
echo "== Alpine 3.22 (busybox ash), non-root"
in_container guard-installer-test:alpine container
echo "== no cosign installed: pinned download"
in_container guard-installer-test:ubuntu bootstrap

echo "== the Linux build host itself: systemd, credentials, docker -it"
python3 -c 'import pexpect' 2>/dev/null || sudo apt-get install -yq python3-pexpect >/dev/null
REL=$REL FAKE_COSIGN_DIR=$W/fakebin HOME_BASE=$W python3 deploy/guard/test/installer_test.py systemd
$DOCKER image inspect zunder-guard:test >/dev/null 2>&1 \
  || $DOCKER buildx build --builder "$BUILDER" -f deploy/guard/Dockerfile --build-arg GUARD_PACKAGE=zunder-guard --load -t zunder-guard:test . >/dev/null 2>&1
python3 deploy/guard/test/installer_test.py docker
echo "installer tests passed"
