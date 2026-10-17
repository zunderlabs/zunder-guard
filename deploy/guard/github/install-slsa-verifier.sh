#!/usr/bin/env bash
# Install slsa-verifier v2.7.1 for this runner, pinned by SHA-256 in this file.
#
# Replaces slsa-framework/slsa-verifier/actions/installer, whose bootstrap verified the
# download through Rekor once and gave up on one failed attempt (two docker install
# rows of v1.0.1's gate). Here the binary is admitted only by its pinned digest, so no
# network service beyond the download is involved. Transport errors (connection
# failures, timeouts, HTTP 429 or 5xx) are retried, at most three attempts; any other
# answer and any checksum mismatch fail closed at once.
#
# Pins: SHA256SUM.md of slsa-framework/slsa-verifier at commit 748161aa ("chore: update
# docs for v2.7.1 (#860)"), identical to the digests GitHub records for the v2.7.1
# release assets. The tag v2.7.1 is commit ea584f4502babc6f60d9bc799dbbb13c1caa9ee6,
# the commit the replaced installer action was pinned to.
set -euo pipefail
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_PATH:?GITHUB_PATH is required}"
VERSION=v2.7.1
platform="$(uname -s)-$(uname -m)"
case "$platform" in
  Linux-x86_64) asset=slsa-verifier-linux-amd64
    pin=946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339 ;;
  Linux-aarch64 | Linux-arm64) asset=slsa-verifier-linux-arm64
    pin=5d3b2349ede7bfec19e7a21569f18b9f7410145ad12e9584b175370669e14061 ;;
  Darwin-x86_64) asset=slsa-verifier-darwin-amd64
    pin=4baf25415727821f847a38bccedc86c3e5b17cbfc2eb534cd554feb6c856d6f1 ;;
  Darwin-arm64) asset=slsa-verifier-darwin-arm64
    pin=39abfcf5f1d690c3e889ce3d2d6a8b87711424d83368511868d414e8f8bcb05c ;;
  MINGW*-x86_64 | MSYS*-x86_64 | CYGWIN*-x86_64) asset=slsa-verifier-windows-amd64.exe
    pin=1d8f61ad747ecc3d375d2a563cebf2991748b7da1a9bda9a500804c3c499e3c0 ;;
  MINGW*-aarch64 | MSYS*-aarch64 | MINGW*-arm64 | MSYS*-arm64) asset=slsa-verifier-windows-arm64.exe
    pin=44144e98328d221f0490ef6b4a58a465defe8f697f387abbbf07ef5adb68d4ac ;;
  *) echo "no pinned slsa-verifier $VERSION for $platform" >&2; exit 1 ;;
esac
name=slsa-verifier
[[ $asset != *.exe ]] || name=slsa-verifier.exe
root=$RUNNER_TEMP/slsa-verifier-$VERSION
if [ -e "$root" ] || [ -L "$root" ]; then
  echo "slsa-verifier install directory already exists" >&2
  exit 1
fi
mkdir -p "$root/bin"
download=$root/$asset.download
url=https://github.com/slsa-framework/slsa-verifier/releases/download/$VERSION/$asset
for attempt in 1 2 3; do
  rm -f "$download"
  status=0
  code=$(curl -sS -L --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 300 \
    -o "$download" -w '%{http_code}' "$url") || status=$?
  if [ "$status" -eq 0 ] && [ "$code" = 200 ]; then
    break
  fi
  echo "slsa-verifier download attempt $attempt: curl exit $status, HTTP ${code:-none}" >&2
  # curl's connection, TLS, timeout and mid-transfer failures, or GitHub's 429 and 5xx.
  transport=no
  case "$status" in 5 | 6 | 7 | 18 | 28 | 35 | 52 | 55 | 56) transport=yes ;; esac
  if [ "$status" -eq 0 ] && [[ $code =~ ^(429|5[0-9][0-9])$ ]]; then transport=yes; fi
  if [ "$transport" != yes ] || [ "$attempt" -eq 3 ]; then
    rm -f "$download"
    echo "slsa-verifier $VERSION download failed" >&2
    exit 1
  fi
  sleep "$((attempt * ${SLSA_INSTALL_PAUSE:-10}))"
done
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$download" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$download" | cut -d' ' -f1)
fi
if [ "$actual" != "$pin" ]; then
  rm -f "$download"
  echo "slsa-verifier $VERSION $asset differs from its pinned SHA-256; refused" >&2
  exit 1
fi
chmod 0755 "$download"
mv "$download" "$root/bin/$name"
echo "$root/bin" >>"$GITHUB_PATH"
echo "slsa-verifier $VERSION $asset installed, SHA-256 $pin"
