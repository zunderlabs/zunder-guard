#!/usr/bin/env bash
# Docker tests on the Linux build host (deploy/guard/README.md, "Testing"), with the real zunder-guard binary:
#   1. native build and the smoke test (image-smoke.sh);
#   2. multi-arch build (linux/amd64 through QEMU, linux/arm64 native) to an OCI archive, and
#      both platforms present and runnable;
#   3. reproducibility: two builds without cache give the same binary and the same image layers;
#   4. the prebuilt path the release uses (GUARD_SOURCE=prebuilt) holds exactly the given bytes;
#   5. compose: guided-equivalent init, up, healthy, published on 127.0.0.1 only.
set -euo pipefail
cd "$(dirname "$0")/../../.."
for notice in LICENSE NOTICE THIRD_PARTY_LICENSES.md; do
  [ -f "$notice" ] || { echo "image tests require a public export containing $notice" >&2; exit 1; }
done
DOCKER=docker
id -nG | grep -qw docker || DOCKER="sudo docker"
BUILDER=zunder-guard
$DOCKER buildx inspect "$BUILDER" >/dev/null 2>&1 \
  || $DOCKER buildx create --name "$BUILDER" --driver docker-container >/dev/null
OUT=$(mktemp -d)
trap '$DOCKER compose -f deploy/guard/compose.yaml down -v >/dev/null 2>&1 || true; sudo rm -rf "$OUT"' EXIT
BUILD=(--build-arg GUARD_PACKAGE=zunder-guard -f deploy/guard/Dockerfile)
RULES=zr1_eyJ2IjoxLCJtYXhMZXZlcmFnZSI6NSwibWF4TG9zc0F0U3RvcFBjdCI6Miwic3RvcFBvbGljeSI6ImF0dGFjaCIsImRlZmF1bHRTdG9wRGlzdGFuY2VQY3QiOjIsIm1pbkxpcURpc3RhbmNlUGN0IjoxMCwibWF4UG9zaXRpb25QY3QiOjIwMCwibWF4T3BlblJpc2tQY3QiOjYsImRhaWx5TG9zc1N0b3BQY3QiOjYsImRyYXdkb3duSGFsdFBjdCI6MjUsIm1hcmtldHMiOlsiKiJdfQ

echo "== 1. native build ($(uname -m)) and smoke test"
$DOCKER buildx build --builder "$BUILDER" "${BUILD[@]}" --load -t zunder-guard:test . 2>&1 | tail -3
deploy/guard/test/image-smoke.sh zunder-guard:test

echo "== 2. multi-arch build: linux/amd64 + linux/arm64"
$DOCKER buildx build --builder "$BUILDER" "${BUILD[@]}" --platform linux/amd64,linux/arm64 \
  -o "type=oci,dest=$OUT/multi.tar" . 2>&1 | tail -2
mkdir "$OUT/oci" && tar -xf "$OUT/multi.tar" -C "$OUT/oci"
python3 - "$OUT/oci" <<'PY'
import json, sys, pathlib
root = pathlib.Path(sys.argv[1])
index = json.loads((root / "index.json").read_text())
def blob(d): return json.loads((root / "blobs" / d.split(":")[0] / d.split(":")[1]).read_text())
inner = blob(index["manifests"][0]["digest"])
plats = sorted(f'{m["platform"]["os"]}/{m["platform"]["architecture"]}' for m in inner["manifests"] if m.get("platform", {}).get("os") != "unknown")
print("  platforms:", plats)
assert plats == ["linux/amd64", "linux/arm64"], plats
for m in inner["manifests"]:
    if m.get("platform", {}).get("os") == "unknown": continue
    cfg = blob(blob(m["digest"])["config"]["digest"])["config"]
    assert cfg["User"] == "65532:65532", cfg["User"]
    assert cfg["Entrypoint"] == ["/usr/local/bin/zunder-guard"], cfg["Entrypoint"]
    assert "ZUNDER_GUARD_LISTEN=127.0.0.1:8547" in cfg["Env"], cfg["Env"]
print("  ok: both platforms, non-root, entrypoint, 127.0.0.1 default")
PY
for platform in linux/amd64 linux/arm64; do
  $DOCKER buildx build --builder "$BUILDER" "${BUILD[@]}" --platform "$platform" --load -t "zunder-guard:test-${platform#linux/}" . >/dev/null 2>&1
  echo "  $platform: $($DOCKER run --rm --platform "$platform" "zunder-guard:test-${platform#linux/}" --version)"
done

echo "== 3. reproducibility: two builds without cache"
for n in 1 2; do
  $DOCKER buildx build --builder "$BUILDER" "${BUILD[@]}" --no-cache --target bin-build \
    -o "type=local,dest=$OUT/bin$n" . >/dev/null 2>&1
  SOURCE_DATE_EPOCH=1700000000 $DOCKER buildx build --builder "$BUILDER" "${BUILD[@]}" --no-cache \
    --build-arg SOURCE_DATE_EPOCH=1700000000 \
    -o "type=oci,dest=$OUT/img$n.tar,rewrite-timestamp=true" . >/dev/null 2>&1
done
sha256sum "$OUT"/bin1/zunder-guard "$OUT"/bin2/zunder-guard
cmp "$OUT/bin1/zunder-guard" "$OUT/bin2/zunder-guard" && echo "  ok: identical binaries"
mkdir "$OUT/i1" "$OUT/i2" && tar -xf "$OUT/img1.tar" -C "$OUT/i1" && tar -xf "$OUT/img2.tar" -C "$OUT/i2"
diff <(cd "$OUT/i1" && find blobs -type f | sort) <(cd "$OUT/i2" && find blobs -type f | sort) \
  && cmp "$OUT/i1/index.json" "$OUT/i2/index.json" \
  && echo "  ok: identical image (every blob and the index equal)"

echo "== 4. prebuilt path: the image holds exactly the given binary"
arch=$(dpkg --print-architecture)
install -D -m 0755 "$OUT/bin1/zunder-guard" "dist/linux-$arch/zunder-guard"
$DOCKER buildx build --builder "$BUILDER" -f deploy/guard/Dockerfile --build-arg GUARD_SOURCE=prebuilt \
  --load -t zunder-guard:prebuilt . >/dev/null 2>&1
id=$($DOCKER create zunder-guard:prebuilt)
$DOCKER cp "$id:/usr/local/bin/zunder-guard" "$OUT/from-image"
$DOCKER rm "$id" >/dev/null
rm -rf dist
cmp "$OUT/bin1/zunder-guard" "$OUT/from-image" && echo "  ok: image binary is byte-identical to the release binary"

echo "== 5. compose"
export ZUNDER_GUARD_IMAGE=zunder-guard:test
$DOCKER compose -f deploy/guard/compose.yaml config -q && echo "  ok: compose file valid"
$DOCKER compose -f deploy/guard/compose.yaml run --rm -T guard init --non-interactive --rules "$RULES" --network paper --account 0x67f7aa8fb95c47e6ea9c517b623e0701cbf9d9ba >/dev/null
$DOCKER compose -f deploy/guard/compose.yaml up -d 2>/dev/null
for _ in $(seq 1 30); do
  [ "$($DOCKER inspect -f '{{.State.Health.Status}}' zunder-guard-guard-1)" = healthy ] && break
  sleep 2
done
[ "$($DOCKER inspect -f '{{.State.Health.Status}}' zunder-guard-guard-1)" = healthy ] && echo "  ok: healthy"
published=$($DOCKER port zunder-guard-guard-1 8547)
echo "  published: $published"
[ "$published" = "127.0.0.1:8547" ] && echo "  ok: published on 127.0.0.1 only"
curl -fsS http://127.0.0.1:8547/healthz && echo
public_ip=$(hostname -I | awk '{print $1}')
if curl -fsS --max-time 3 "http://$public_ip:8547/healthz" >/dev/null 2>&1; then
  echo "  FAIL: reachable on $public_ip" >&2
  exit 1
fi
echo "  ok: not reachable on the host's own address $public_ip"
$DOCKER compose -f deploy/guard/compose.yaml down -v >/dev/null 2>&1
echo "image tests passed"
