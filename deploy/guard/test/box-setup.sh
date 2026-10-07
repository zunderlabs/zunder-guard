#!/usr/bin/env bash
# One-time setup of an Ubuntu Linux build host for Guard packaging tests (deploy/guard/README.md,
# "Testing"). Installs Docker with buildx and compose, QEMU emulation for the second
# architecture, shellcheck and Ruby (syntax check of the Homebrew formula), all from Ubuntu's
# archive. Idempotent. Run from the repository root:
#
#   bash deploy/guard/test/box-setup.sh
#
# The invoking user joins the docker group, granting root-equivalent access. Use a dedicated
# build host and choose its users accordingly.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
need=()
for pkg in docker.io docker-buildx docker-compose-v2 shellcheck ruby qemu-user-static binfmt-support python3-venv python3-pexpect; do
  dpkg -s "$pkg" >/dev/null 2>&1 || need+=("$pkg")
done
if [ ${#need[@]} -gt 0 ]; then
  sudo apt-get update -q >/dev/null
  sudo apt-get install -yq "${need[@]}" >/dev/null
fi
BUILD_USER=${SUDO_USER:-$(id -un)}
sudo usermod -aG docker "$BUILD_USER"
sudo systemctl enable --now docker >/dev/null 2>&1
# QEMU (qemu-user-static, registered through binfmt-support) runs the amd64 build stages on
# an ARM Linux host. The tests create their buildx builder (docker-container driver, needed
# for multi-platform builds and OCI output) as the invoking user on first use.
if [ -e /proc/sys/fs/binfmt_misc/qemu-x86_64 ]; then echo "QEMU amd64 emulation: registered"; fi
sudo docker version | grep -E '^ *Version' | head -2
shellcheck --version | sed -n 2p
ruby --version
