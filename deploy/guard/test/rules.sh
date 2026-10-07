#!/usr/bin/env bash
# Rules schema v1 on the Linux build host: the Rust crate and Guard (fmt, clippy, tests), then the
# TypeScript twin (type check with tsc --strict, tests with Node's runner) in a pinned Node
# container. Part of deploy/guard/test/all.sh.
set -euo pipefail
cd "$(dirname "$0")/../../.."
DOCKER=docker
id -nG | grep -qw docker || DOCKER="sudo docker"
NODE=node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1

echo "== rules + Guard: fmt, clippy, tests"
cargo fmt --all -- --check
cargo clippy -p zunder-guard-rules -p zunder-guard --all-targets -- -D warnings
cargo test -q -p zunder-guard-rules -p zunder-guard

echo "== zr1.ts: tsc --strict and node --test"
$DOCKER run --rm -v "$PWD/deploy/guard/rules:/w:ro" -w /w "$NODE" sh -ec '
  node --version
  npm install --silent --no-save --prefix /tmp/tsc typescript@5 >/dev/null
  /tmp/tsc/node_modules/.bin/tsc --strict --noEmit --target es2022 --module nodenext \
    --lib es2022,dom --allowImportingTsExtensions --erasableSyntaxOnly zr1.ts
  echo "tsc --strict: ok"
  node --test zr1.test.ts'
