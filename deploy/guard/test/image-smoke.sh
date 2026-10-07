#!/usr/bin/env bash
# Smoke test of a built Guard image (deploy/guard/README.md, "Testing"): non-root, no shell,
# refuses to start uninitialised, becomes healthy in paper mode from ZUNDER_GUARD_RULES, and
# with the image's default listen address a published port reaches nothing.
#
#   image-smoke.sh <image>
set -euo pipefail
IMAGE=$1
DOCKER=docker
id -nG | grep -qw docker || DOCKER="sudo docker"
# The default rules string (deploy/guard/rules: Rules::default().encode()), and an account to
# read in paper mode (its address only; the first start needs both).
ACCOUNT=0x67f7aa8fb95c47e6ea9c517b623e0701cbf9d9ba  # a public mainnet account in standard mode
RULES=zr1_eyJ2IjoxLCJtYXhMZXZlcmFnZSI6NSwibWF4TG9zc0F0U3RvcFBjdCI6Miwic3RvcFBvbGljeSI6ImF0dGFjaCIsImRlZmF1bHRTdG9wRGlzdGFuY2VQY3QiOjIsIm1pbkxpcURpc3RhbmNlUGN0IjoxMCwibWF4UG9zaXRpb25QY3QiOjIwMCwibWF4T3BlblJpc2tQY3QiOjYsImRhaWx5TG9zc1N0b3BQY3QiOjYsImRyYXdkb3duSGFsdFBjdCI6MjUsIm1hcmtldHMiOlsiKiJdfQ
pass() { echo "  ok: $*"; }
fail() { echo "  FAIL: $*" >&2; exit 1; }
NOTICE_TMP=$(mktemp -d)
cleanup() {
  $DOCKER rm -f guard-smoke guard-smoke-pub guard-smoke-notices >/dev/null 2>&1 || true
  rm -rf "$NOTICE_TMP"
}
trap cleanup EXIT

echo "== image smoke test: $IMAGE"
if [ "$($DOCKER image inspect -f '{{.Config.User}}' "$IMAGE")" = "65532:65532" ]; then pass "runs as uid 65532"; else fail "not the non-root user"; fi
$DOCKER create --name guard-smoke-notices "$IMAGE" >/dev/null
$DOCKER export guard-smoke-notices >"$NOTICE_TMP/rootfs.tar"
python3 - "$NOTICE_TMP/rootfs.tar" "$(cd "$(dirname "$0")/../../.." && pwd)" <<'PY'
import pathlib, tarfile, sys
root = pathlib.Path(sys.argv[2])
with tarfile.open(sys.argv[1]) as archive:
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"):
        member = archive.getmember("usr/share/licenses/zunder-guard/" + name)
        assert member.isfile() and member.uid == 0 and member.gid == 0 and member.mode == 0o644, name
        assert archive.extractfile(member).read() == (root / name).read_bytes(), name
print("  ok: all distribution notices retained byte for byte, root-owned and readable (0644)")
PY
$DOCKER rm guard-smoke-notices >/dev/null
if $DOCKER image inspect -f '{{json .Config.Healthcheck.Test}}' "$IMAGE" | grep -q '"health"'; then
  pass "healthcheck is the binary's own"
else
  fail "no healthcheck"
fi
if $DOCKER run --rm --entrypoint /bin/sh "$IMAGE" -c true >/dev/null 2>&1; then fail "the image has a shell"; else pass "no shell in the image"; fi
$DOCKER run --rm "$IMAGE" --version
if $DOCKER run --rm "$IMAGE" run >/dev/null 2>&1; then fail "started without being initialised"; else pass "refuses to run uninitialised"; fi
if $DOCKER run --rm -e ZUNDER_GUARD_RULES=zr1_eyJ2IjoyfQ "$IMAGE" run >/dev/null 2>&1; then
  fail "started with an invalid rules string"
else
  pass "refuses an invalid rules string"
fi
if $DOCKER run --rm -e ZUNDER_GUARD_RULES="$RULES" -e ZUNDER_GUARD_NETWORK=testnet "$IMAGE" run >/dev/null 2>&1; then
  fail "started testnet without an account and a key"
else
  pass "refuses testnet without account and key"
fi

$DOCKER run -d --name guard-smoke -e ZUNDER_GUARD_RULES="$RULES" -e ZUNDER_GUARD_ACCOUNT="$ACCOUNT" "$IMAGE" >/dev/null
for _ in $(seq 1 30); do
  [ "$($DOCKER inspect -f '{{.State.Health.Status}}' guard-smoke)" = healthy ] && break
  sleep 2
done
if [ "$($DOCKER inspect -f '{{.State.Health.Status}}' guard-smoke)" = healthy ]; then
  pass "healthy in paper mode"
else
  $DOCKER logs guard-smoke
  fail "never healthy"
fi
if $DOCKER exec guard-smoke /usr/local/bin/zunder-guard config get network | grep -qx paper; then
  pass "initialised in paper mode"
else
  fail "not paper"
fi

# A careless `-p 8547:8547` with the image's defaults: Guard listens on the container's
# loopback, so nothing answers on the published port.
$DOCKER run -d --name guard-smoke-pub -p 127.0.0.1:18547:8547 -e ZUNDER_GUARD_RULES="$RULES" -e ZUNDER_GUARD_ACCOUNT="$ACCOUNT" "$IMAGE" >/dev/null
sleep 3
if curl -fsS --max-time 3 http://127.0.0.1:18547/healthz >/dev/null 2>&1; then
  fail "the default listen address is reachable through a published port"
else
  pass "default listen address unreachable through a published port"
fi
echo "image smoke test passed"
