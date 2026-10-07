#!/usr/bin/env bash
# Formats the workspace and refreshes Cargo.lock on the Linux build host, then prints the changed
# Guard files and the lockfile as a base64 tarball on standard output, so a checkout on a
# machine that does not build can take them back:
#
#   bash deploy/guard/test/fmt-and-lock.sh > guard-format.tar.base64
set -euo pipefail
cargo fmt --all >&2
cargo metadata --format-version 1 >/dev/null
tar cz Cargo.lock deploy/guard/rules/src crates/zunder-guard/src crates/zunder-guard/tests crates/zunder-guard-mcp/src crates/zunder-venue/src | base64 -w0
