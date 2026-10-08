#!/bin/sh
# Zunder Guard installer (deploy/guard/README.md, "install.sh"). POSIX sh: dash, bash, busybox
# ash and macOS sh.
#
# Normally started by the loader (zunderlabs.com/i), which has already checked this file's
# signature. It checks everything again itself, so it is just as safe to download and run by
# hand:
#
#   sh install.sh --rules zr1_…                    # guided setup on a terminal (ssh -t)
#   sh install.sh --non-interactive --rules zr1_… --network paper
#   sh install.sh --non-interactive --rules zr1_… --network testnet \
#      --account 0x… --key-file /root/hl-key        # the file is read, never put on a command line
#
# What it does, in order, refusing at the first thing that does not check out:
#   1. downloads the release archive, SHA256SUMS and its Sigstore bundle;
#   2. verifies the bundle with cosign against this repository's release workflow and tag
#      (fetching a pinned cosign, checked by its pinned SHA-256, if none is installed);
#   3. checks the archive against the signed checksums; only then extracts and installs it;
#   4. runs `zunder-guard init`, which shows the rules and asks for the account and the mode;
#   5. for testnet or mainnet asks for the API wallet key with hidden input, has the binary check
#      it, and stores it with systemd-creds (host key or TPM), or as a 0600 file of the service
#      user if systemd-creds is missing (with a warning);
#   6. installs the hardened systemd unit and starts it (Linux with systemd; elsewhere it prints
#      how to start Guard);
#   7. prints the client key for the bot (once), the pairing code and the next step.
set -eu

VERSION="@VERSION@"
REPO="zunderlabs/zunder-guard"
ISSUER="https://token.actions.githubusercontent.com"
IDENTITY="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$VERSION"
BASE_URL="${ZUNDER_GUARD_BASE_URL:-https://github.com/$REPO/releases/download/$VERSION}"
# cosign used when none is installed: github.com/sigstore/cosign releases, SHA-256 from that
# release's cosign_checksums.txt. Bump deliberately (deploy/guard/test/resolve-pins.sh); the
# same pins are in loader/i.sh.
COSIGN_VERSION="v3.1.3"
COSIGN_URL="https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION"

SERVICE_HOME=/var/lib/zunder-guard
CRED_NAME=hl-api-wallet-key
CRED_ENCRYPTED=/etc/credstore.encrypted/zunder-guard.$CRED_NAME
CRED_PLAIN=/etc/zunder-guard/$CRED_NAME
MAINNET_ENV=/etc/zunder-guard/mainnet-confirm.env

say() { printf '%s\n' "$*"; }
die() {
  printf 'install.sh: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: sh install.sh [options]
  --rules zr1_…         rules from zunderlabs.com (shown and editable before anything is saved)
  --non-interactive     no prompts; then --rules and --network are required, and for testnet or
                        mainnet also --account and --key-file (mainnet: --confirm-mainnet too)
  --network NAME        paper (default when asked), testnet or mainnet
  --account 0x…         Hyperliquid account address
  --key-file PATH       file holding the API wallet key (read by this script, never echoed)
  --key-stdin           protected managed TESTNET only: private framed stdin, no prompts
                        Linux needs systemd-creds; macOS/container use their secure broker
  --confirm-mainnet 0x… the account address again; required for mainnet without prompts
  --equity-cap USDC     mainnet: the most equity Guard sizes from (at most 2500); required for
                        mainnet without prompts
  --listen HOST:PORT    where Guard listens (default 127.0.0.1:8547). Anything but a loopback
                        address is reachable from outside this machine: a warning, not a default
  --ip-share S          this Guard's part of the IP address's request weight (default 1);
                        1/N for each of N Guards on one machine, e.g. 0.5
  --licence zgl1_…      a licence key for the account (from the licence email); checked by the
                        binary before anything is saved. Not a secret. Later: zunder-guard licence set
  --prefix DIR          binary directory (default /usr/local/bin as root, else ~/.local/bin);
                        notices go in ../share/licenses/zunder-guard for a bin directory,
                        otherwise DIR/share/licenses/zunder-guard
  --container           protected Linux mainnet/testnet Docker service with encrypted credential
  --volume NAME         explicit named volume for container setup (default zunder-guard-data)
  --install-only        verify and replace binary/notices only; no setup or service changes
                        stop Guard first; restart it yourself after checking the release
  --no-service          install and set up, but do not install the systemd unit
  --force               replace an existing configuration without asking (the journal is kept)
  --version             print the release this installer belongs to
EOF
}

RULES="" NETWORK="" ACCOUNT="" KEY_FILE="" KEY_STDIN=0 CONFIRM="" CAP="" PREFIX="" LISTEN="" SHARE="" LICENCE="" NONINTERACTIVE=0 NO_SERVICE=0 FORCE=0 INSTALL_ONLY=0 SETUP_OPTIONS=0 CONTAINER=0 VOLUME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --rules | --network | --account | --key-file | --confirm-mainnet | --equity-cap | --prefix | --listen | --ip-share | --licence | --volume)
      [ $# -ge 2 ] || die "$1 needs a value"
      [ "$1" = --prefix ] || SETUP_OPTIONS=1
      case "$1" in
        --rules) RULES=$2 ;;
        --network) NETWORK=$2 ;;
        --account) ACCOUNT=$2 ;;
        --key-file) KEY_FILE=$2 ;;
        --confirm-mainnet) CONFIRM=$2 ;;
        --equity-cap) CAP=$2 ;;
        --prefix) PREFIX=$2 ;;
        --listen) LISTEN=$2 ;;
        --ip-share) SHARE=$2 ;;
        --licence) LICENCE=$2 ;;
        --volume) VOLUME=$2 ;;
      esac
      shift 2
      ;;
    --key-stdin) KEY_STDIN=1 && SETUP_OPTIONS=1 && shift ;;
    --container) CONTAINER=1 && SETUP_OPTIONS=1 && shift ;;
    --install-only) INSTALL_ONLY=1 && shift ;;
    --non-interactive) NONINTERACTIVE=1 && shift ;;
    --no-service) NO_SERVICE=1 && shift ;;
    --force) FORCE=1 && SETUP_OPTIONS=1 && shift ;;
    --version) say "$VERSION" && exit 0 ;;
    -h | --help) usage && exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

if [ "$CONTAINER" -eq 1 ]; then
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  export PATH
  case "$NETWORK" in mainnet | testnet) ;; *) die "--container requires --network mainnet or testnet" ;; esac
  [ "$INSTALL_ONLY$NO_SERVICE$FORCE" = 000 ] || die "container mode requires managed setup"
  if [ "$NETWORK" = mainnet ]; then
    [ "$NONINTERACTIVE$KEY_STDIN" = 00 ] || die "mainnet container setup retains interactive confirmation and hidden input"
  else
    [ "$NONINTERACTIVE$KEY_STDIN" = 00 ] || [ "$NONINTERACTIVE$KEY_STDIN" = 11 ] \
      || die "unattended testnet container setup requires --non-interactive --key-stdin"
  fi
  [ -z "$KEY_FILE$CONFIRM$PREFIX$LISTEN" ] || die "container mode does not accept key-file, confirm-mainnet, prefix or listen"
elif [ -n "$VOLUME" ]; then
  die "--volume requires --container"
fi

if [ "$KEY_STDIN" -eq 1 ]; then
  [ "$NETWORK" = testnet ] && [ "$NONINTERACTIVE" -eq 1 ] && [ "$NO_SERVICE" -eq 0 ] \
    || die "--key-stdin requires explicit testnet, non-interactive managed setup"
  [ -z "$KEY_FILE$CONFIRM" ] || die "testnet private stdin cannot be combined with a key file or mainnet consent"
fi
if [ "$NETWORK" = testnet ] && [ -n "$CONFIRM" ]; then
  die "testnet setup accepts no mainnet confirmation"
fi

if [ "$INSTALL_ONLY" -eq 1 ] && [ "$SETUP_OPTIONS" -eq 1 ]; then
  die "--install-only cannot be combined with setup options (rules, network, account, key, licence, limits, listen or --force)"
fi

# Values that reach a command line are checked for shape here; the binary checks them again.
case "$RULES" in "" | zr1_*) ;; *) die "a rules string starts with zr1_" ;; esac
case "$RULES" in *[!A-Za-z0-9_-]*) die "the rules string contains characters base64url does not use" ;; esac
case "$NETWORK" in "" | paper | testnet | mainnet) ;; *) die "--network is paper, testnet or mainnet" ;; esac
case "$LISTEN" in
  "" | 127.* | localhost:* | "[::1]":*) ;;
  *) say "WARNING: --listen $LISTEN is reachable from other machines. Anyone who reaches it can send orders signed with a paired client key. Firewall it to your bot's address." ;;
esac
case "$SHARE" in "" | [0-9]*) ;; *) die "--ip-share is a decimal such as 0.5" ;; esac
case "$SHARE" in *[!0-9.]*) die "--ip-share is a decimal such as 0.5" ;; esac
case "$LICENCE" in "" | zgl1_*) ;; *) die "a licence key starts with zgl1_" ;; esac
case "$LICENCE" in *[!A-Za-z0-9_.-]*) die "the licence key contains characters a key does not use" ;; esac
case "$CAP" in "" | [0-9]*) ;; *) die "--equity-cap is a number of USDC" ;; esac
case "$CAP" in *[!0-9.]*) die "--equity-cap is a number of USDC" ;; esac
for a in "$ACCOUNT" "$CONFIRM"; do
  case "$a" in "" | 0x[0-9a-fA-F]*) ;; *) die "an account address is 0x and 40 hex digits" ;; esac
done

if [ "$INSTALL_ONLY" -eq 1 ]; then
  : # No terminal, setup values or credentials are needed to replace verified release files.
elif [ "$NONINTERACTIVE" -eq 1 ]; then
  [ -n "$RULES" ] || die "--non-interactive needs --rules"
  [ -n "$NETWORK" ] || die "--non-interactive needs --network"
  if [ "$NETWORK" != paper ]; then
    [ -n "$ACCOUNT" ] || die "$NETWORK needs --account"
    if [ "$KEY_STDIN" -eq 0 ] && { [ -z "$KEY_FILE" ] || [ ! -r "$KEY_FILE" ]; }; then
      die "$NETWORK needs --key-file with a readable file (protected testnet also accepts --key-stdin)"
    fi
  fi
  if [ "$NETWORK" = mainnet ] && [ "$CONFIRM" != "$ACCOUNT" ]; then
    die "mainnet needs --confirm-mainnet naming the same account"
  fi
  if [ "$NETWORK" = mainnet ] && [ -z "$CAP" ]; then
    die "mainnet needs --equity-cap (the most equity Guard sizes from, at most 2500 USDC)"
  fi
else
  # Prompts read from the terminal, not from standard input (which is the script when piped).
  (: </dev/tty) 2>/dev/null || die "no terminal. Use 'ssh -t', or --non-interactive with every value given."
fi

# ---------------------------------------------------------------- platform
case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *) die "unsupported system $(uname -s); on Windows run Guard in Docker or in WSL (Linux)" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
case "$OS-$ARCH" in
  linux-amd64) COSIGN_SHA256=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;;
  linux-arm64) COSIGN_SHA256=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;;
  darwin-amd64) COSIGN_SHA256=2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c ;;
  darwin-arm64) COSIGN_SHA256=5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76 ;;
esac
ARCHIVE="zunder-guard-$VERSION-$OS-$ARCH.tar.gz"
command -v curl >/dev/null 2>&1 || die "curl is required"

TMP=$(mktemp -d)
NOTICE_STAGE=""
BINARY_STAGE=""
SUDO_BIN=""
cleanup() {
  stty echo 2>/dev/null </dev/tty || true
  if [ -n "${BINARY_STAGE:-}" ]; then $SUDO_BIN rm -f "$BINARY_STAGE"; fi
  if [ -n "${NOTICE_STAGE:-}" ]; then $SUDO_BIN rm -rf "$NOTICE_STAGE"; fi
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

fetch() {
  curl -fsSL --proto '=https,file' --retry 3 -o "$TMP/$1" "$2" || die "download failed: $2"
}

# Container mode never installs/replaces a native Guard binary.
if [ "$CONTAINER" -eq 1 ]; then
  [ "$OS" = linux ] || die "--container requires Linux systemd and local Docker"
  [ -x /usr/bin/python3 ] || die "Python 3.11 or newer is required for container installation"
  /usr/bin/python3 -I -c 'import sys; sys.exit(sys.version_info < (3, 11))' || die "Python 3.11 or newer is required"
  for asset in SHA256SUMS SHA256SUMS.sigstore.json install-container.py container-supervisor.py container-operations.py zunder-guard-container.service zunder-guard-setup-guardian.service "zunder-guard-$VERSION.image.txt"; do
    fetch "$asset" "$BASE_URL/$asset"
  done
  fetch container-cosign "$COSIGN_URL/cosign-linux-$ARCH"
  if [ "$(/usr/bin/id -u)" -eq 0 ]; then
    CONTAINER_SUDO=""
  else
    [ -x /usr/bin/sudo ] || die "container installation needs root or sudo"
    /usr/bin/sudo -v || die "administrator installation was not authorized"
    CONTAINER_SUDO=/usr/bin/sudo
  fi
  CONTAINER_BOOTSTRAP_CODE=$(cat <<'CONTAINER_BOOTSTRAP'
import hashlib, os, pathlib, re, resource, shutil, stat, subprocess, sys, tempfile
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.umask(0o077)
source, pinned, version, volume, account, rules, cap, share, licence, network, noninteractive, key_stdin = sys.argv[1:]
if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version):
    raise SystemExit('Invalid release version')
env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'}
def trusted(path, directory=False):
    info = path.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
        raise SystemExit('Untrusted installer staging path')
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise SystemExit('Unexpected installer path type')
base = pathlib.Path('/var/lib/zunder-guard-install')
for parent in base.parents:
    trusted(parent, True)
base.mkdir(mode=0o700, exist_ok=True)
trusted(base, True)
if stat.S_IMODE(base.stat().st_mode) != 0o700:
    raise SystemExit('Installer staging directory must be root-only')
stage = pathlib.Path(tempfile.mkdtemp(prefix='release-', dir=base))
assets = ['install-container.py', 'container-supervisor.py', 'container-operations.py',
          'zunder-guard-container.service', 'zunder-guard-setup-guardian.service',
          'zunder-guard-' + version + '.image.txt']
try:
    for name in ['SHA256SUMS', 'SHA256SUMS.sigstore.json', 'container-cosign', *assets]:
        target = stage / name
        with open(pathlib.Path(source) / name, 'rb') as src, open(target, 'xb') as dst:
            shutil.copyfileobj(src, dst)
        target.chmod(0o700 if name == 'container-cosign' else 0o600)
    verifier = stage / 'container-cosign'
    if hashlib.sha256(verifier.read_bytes()).hexdigest() != pinned:
        raise SystemExit('Pinned verifier checksum mismatch')
    check = subprocess.run([str(verifier), 'verify-blob', '--bundle', str(stage / 'SHA256SUMS.sigstore.json'),
        '--certificate-identity', 'https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/' + version,
        '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com', str(stage / 'SHA256SUMS')],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, timeout=120)
    if check.returncode:
        raise SystemExit('Release signature verification failed')
    checksums = {}
    for line in (stage / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64}) [ *]([A-Za-z0-9._-]+)', line)
        if not match or match[2] in checksums:
            raise SystemExit('Malformed or duplicate signed checksum')
        checksums[match[2]] = match[1]
    for name in assets:
        if checksums.get(name) != hashlib.sha256((stage / name).read_bytes()).hexdigest():
            raise SystemExit('Signed installer asset checksum mismatch')
    # Preserve a different administrator-installed verifier; never overwrite silently.
    destination = pathlib.Path('/usr/local/bin/cosign')
    for parent in destination.parents:
        trusted(parent, True)
    if destination.exists() or destination.is_symlink():
        trusted(destination)
        if hashlib.sha256(destination.read_bytes()).hexdigest() != pinned:
            raise SystemExit('Install the pinned cosign version at /usr/local/bin/cosign before retrying')
    else:
        fd, pending = tempfile.mkstemp(prefix='.cosign-', dir=destination.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(verifier.read_bytes()); stream.flush(); os.fsync(stream.fileno())
            os.chmod(pending, 0o755)
            os.link(pending, destination)  # refuse a concurrent replacement
        finally:
            os.unlink(pending)
    options = ['--version', version, '--network', network]
    if noninteractive == '1':
        if network != 'testnet' or key_stdin != '1':
            raise SystemExit('Unattended container setup is protected testnet only')
        options += ['--non-interactive', '--key-stdin']
    for name, value in [('volume', volume), ('account', account), ('rules', rules),
                        ('equity-cap', cap), ('ip-share', share), ('licence', licence)]:
        if value:
            options += ['--' + name, value]
    command = ['/usr/bin/python3', '-I', str(stage / 'install-container.py'), *options]
    if key_stdin == '1':
        result = subprocess.run(command, stdin=sys.stdin.buffer, env=env, check=False)
    else:
        with open('/dev/tty', 'rb') as terminal:
            result = subprocess.run(command, stdin=terminal, env=env, check=False)
    raise SystemExit(result.returncode)
finally:
    shutil.rmtree(stage)
CONTAINER_BOOTSTRAP
  )
  # Code is public and signed; stdin remains the caller's private pipe across
  # sudo. No credential is placed in argv/environment or an extra inherited FD.
  $CONTAINER_SUDO /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C.UTF-8 \
    /usr/bin/python3 -I -c "$CONTAINER_BOOTSTRAP_CODE" "$TMP" "$COSIGN_SHA256" "$VERSION" "$VOLUME" "$ACCOUNT" "$RULES" "$CAP" "$SHARE" "$LICENCE" "$NETWORK" "$NONINTERACTIVE" "$KEY_STDIN"
  exit $?
fi

# ---------------------------------------------------------------- 1-3: download and verify
say "Zunder Guard $VERSION for $OS-$ARCH: downloading and verifying the release"
fetch SHA256SUMS "$BASE_URL/SHA256SUMS"
fetch SHA256SUMS.sigstore.json "$BASE_URL/SHA256SUMS.sigstore.json"
fetch "$ARCHIVE" "$BASE_URL/$ARCHIVE"

# The loader passes the cosign it already used (and verified, if it fetched one).
COSIGN=${ZUNDER_GUARD_COSIGN:-}
if [ -z "$COSIGN" ] || [ ! -x "$COSIGN" ]; then COSIGN=$(command -v cosign 2>/dev/null || true); fi
if [ -z "$COSIGN" ]; then
  say "cosign is not installed: fetching cosign $COSIGN_VERSION and checking its pinned SHA-256"
  fetch cosign "$COSIGN_URL/cosign-$OS-$ARCH"
  [ "$(sha256 "$TMP/cosign")" = "$COSIGN_SHA256" ] || die "the cosign download does not match its pinned SHA-256; refusing"
  chmod 0755 "$TMP/cosign"
  COSIGN=$TMP/cosign
fi
if ! "$COSIGN" verify-blob --bundle "$TMP/SHA256SUMS.sigstore.json" \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
  "$TMP/SHA256SUMS" >"$TMP/cosign.log" 2>&1; then
  cat "$TMP/cosign.log" >&2
  die "signature check FAILED: SHA256SUMS was not signed by $REPO's release workflow for $VERSION; refusing"
fi
say "  signature: SHA256SUMS signed by $REPO, release workflow, tag $VERSION (Sigstore)"
EXPECTED=$(awk -v f="$ARCHIVE" '$2 == f || $2 == "*" f { print $1 }' "$TMP/SHA256SUMS")
[ -n "$EXPECTED" ] || die "$ARCHIVE is not in the signed checksums; refusing"
[ "$(sha256 "$TMP/$ARCHIVE")" = "$EXPECTED" ] || die "checksum mismatch for $ARCHIVE; refusing"
say "  checksum:  $ARCHIVE matches"

mkdir "$TMP/x"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP/x"
[ -f "$TMP/x/zunder-guard" ] || die "the archive holds no zunder-guard binary"
for notice in LICENSE NOTICE THIRD_PARTY_LICENSES.md; do
  if [ ! -f "$TMP/x/$notice" ] || [ -L "$TMP/x/$notice" ]; then
    die "the archive holds no regular $notice; refusing to install without licence notices"
  fi
done

# ---------------------------------------------------------------- 4: install the binary
SERVICE=0
if [ "$INSTALL_ONLY" -eq 0 ] && [ "$OS" = linux ] && [ "$NO_SERVICE" -eq 0 ] && [ -d /run/systemd/system ]; then SERVICE=1; fi
SUDO=""
if [ "$(id -u)" -ne 0 ] && { [ "$SERVICE" -eq 1 ] || [ -z "$PREFIX" ]; }; then
  if command -v sudo >/dev/null 2>&1 && { [ "$NONINTERACTIVE" -eq 0 ] || sudo -n true 2>/dev/null; }; then
    SUDO=sudo
  elif [ "$SERVICE" -eq 1 ]; then
    say "No root and no sudo: installing for this user only, without the systemd unit."
    SERVICE=0
  fi
fi
if [ -z "$PREFIX" ]; then
  if [ -n "$SUDO" ] || [ "$(id -u)" -eq 0 ]; then PREFIX=/usr/local/bin; else PREFIX=$HOME/.local/bin; fi
fi
case "$PREFIX" in "$HOME"/*) SUDO_BIN="" ;; *) SUDO_BIN=$SUDO ;; esac
# Use the binary's privilege policy for the accompanying distribution notices. Replace only
# our three files, using staged renames so an interrupted upgrade never truncates a notice.
# Symlinks are refused rather than following a destination outside the selected prefix.
PREFIX=${PREFIX%/}
PREFIX=${PREFIX:-/}
case "$PREFIX" in
  */bin) NOTICE_ROOT=${PREFIX%/bin}/share ;;
  *) NOTICE_ROOT=$PREFIX/share ;;
esac
NOTICE_DIR=$NOTICE_ROOT/licenses/zunder-guard
for dir in "$NOTICE_ROOT" "$NOTICE_ROOT/licenses" "$NOTICE_DIR"; do
  [ ! -L "$dir" ] || die "licence notice directory is a symlink: $dir"
  [ ! -e "$dir" ] || [ -d "$dir" ] || die "licence notice directory is not a directory: $dir"
done
for notice in LICENSE NOTICE THIRD_PARTY_LICENSES.md; do
  if [ -L "$NOTICE_DIR/$notice" ] || [ -d "$NOTICE_DIR/$notice" ]; then
    die "licence notice destination is a symlink or directory: $NOTICE_DIR/$notice"
  fi
done
NOTICE_UID=$(id -u)
NOTICE_GID=$(id -g)
if [ -n "$SUDO_BIN" ]; then NOTICE_UID=0; NOTICE_GID=0; fi
$SUDO_BIN install -d -m 0755 -o "$NOTICE_UID" -g "$NOTICE_GID" "$NOTICE_DIR"
NOTICE_STAGE=$($SUDO_BIN mktemp -d "$NOTICE_DIR/.install.XXXXXXXX")
for notice in LICENSE NOTICE THIRD_PARTY_LICENSES.md; do
  $SUDO_BIN install -m 0644 -o "$NOTICE_UID" -g "$NOTICE_GID" "$TMP/x/$notice" "$NOTICE_STAGE/$notice"
done
for notice in LICENSE NOTICE THIRD_PARTY_LICENSES.md; do
  $SUDO_BIN mv -f "$NOTICE_STAGE/$notice" "$NOTICE_DIR/$notice"
done
$SUDO_BIN rmdir "$NOTICE_STAGE"
NOTICE_STAGE=""
$SUDO_BIN mkdir -p "$PREFIX"
if [ "$INSTALL_ONLY" -eq 1 ]; then
  # Stage beside the destination: rename replaces the executable without truncating the old
  # inode, even if someone has left a process running. No process is stopped or restarted.
  if ! { [ ! -L "$PREFIX/zunder-guard" ] && [ ! -d "$PREFIX/zunder-guard" ]; }; then
    die "binary destination is a symlink or directory; refusing --install-only"
  fi
  BINARY_STAGE=$($SUDO_BIN mktemp "$PREFIX/.zunder-guard.XXXXXXXX")
  $SUDO_BIN install -m 0755 "$TMP/x/zunder-guard" "$BINARY_STAGE"
  $SUDO_BIN mv -f "$BINARY_STAGE" "$PREFIX/zunder-guard"
  BINARY_STAGE=""
else
  $SUDO_BIN install -m 0755 "$TMP/x/zunder-guard" "$PREFIX/zunder-guard"
fi
BIN=$PREFIX/zunder-guard
say "Installed $("$BIN" --version) to $BIN"
say "Licence notices: $NOTICE_DIR"
case ":$PATH:" in *":$PREFIX:"*) ;; *) say "  note: $PREFIX is not on your PATH" ;; esac

if [ "$INSTALL_ONLY" -eq 1 ]; then
  say "Installed release files only. Configuration, licences, keys, pairings, journals and services were not changed."
  say "A running Guard still uses its old binary. Restart it yourself with its existing configuration when ready."
  exit 0
fi

# macOS mainnet uses a protected launchd broker, never a user-writable binary.
# This branch is deliberately AFTER the reviewed --install-only early return.
if [ "$OS" = darwin ] && { [ "$NETWORK" = mainnet ] || [ "$NETWORK" = testnet ]; } && [ "$NO_SERVICE" -eq 0 ]; then
  PATH=/usr/bin:/bin:/usr/sbin:/sbin
  export PATH
  if ! { [ -z "$KEY_FILE$CONFIRM" ] && [ "$FORCE" -eq 0 ]; }; then
    die "macOS managed mainnet requires hidden key input and interactive account confirmation; key-file, confirm-mainnet and force are refused"
  fi
  if [ "$NETWORK" = mainnet ]; then
    [ "$NONINTERACTIVE$KEY_STDIN" = 00 ] || die "macOS mainnet provisioning needs an interactive terminal; nothing was started"
  else
    [ "$NONINTERACTIVE$KEY_STDIN" = 00 ] || [ "$NONINTERACTIVE$KEY_STDIN" = 11 ] \
      || die "unattended macOS testnet setup requires --non-interactive --key-stdin"
  fi
  if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    [ -x /usr/bin/sudo ] || die "macOS mainnet needs administrator installation"
    /usr/bin/sudo -v || die "administrator installation was not authorized"
    MAC_SUDO=/usr/bin/sudo
  else
    MAC_SUDO=""
  fi
  fetch install-macos-service.sh "$BASE_URL/install-macos-service.sh"
  # Always use the exact pinned verifier, even if a different cosign verified
  # the unprivileged download. It is checked again after root-private copying.
  fetch macos-service-cosign "$COSIGN_URL/cosign-darwin-$ARCH"
  [ "$(sha256 "$TMP/macos-service-cosign")" = "$COSIGN_SHA256" ] || die "macOS service verifier checksum mismatch"
  MAC_STAGE=$($MAC_SUDO /bin/sh -s <<'ROOT_STAGE'
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077
root_path() {
  component=$1
  while :; do
    [ ! -L "$component" ] && [ "$(stat -f %u "$component")" = 0 ] || exit 2
    permissions=$(stat -f %Lp "$component")
    [ "$((0$permissions & 022))" = 0 ] || exit 2
    [ "$component" != / ] || break
    component=$(dirname "$component")
  done
}
for directory in '/Library/Application Support' '/Library/Application Support/Zunder Guard' '/Library/Application Support/Zunder Guard/staging'; do
  if [ ! -e "$directory" ]; then mkdir -m 0755 "$directory"; fi
  root_path "$directory"
done
mktemp -d '/Library/Application Support/Zunder Guard/staging/install.XXXXXXXX'
ROOT_STAGE
  ) || die "could not establish root-private macOS staging"
  for asset in SHA256SUMS SHA256SUMS.sigstore.json "$ARCHIVE" install-macos-service.sh; do
    $MAC_SUDO /usr/bin/install -o root -g wheel -m 0600 "$TMP/$asset" "$MAC_STAGE/$asset"
  done
  $MAC_SUDO /usr/bin/install -o root -g wheel -m 0700 "$TMP/macos-service-cosign" "$MAC_STAGE/cosign"
  # Only OS tools run privileged before the pinned verifier authenticates the
  # helper. Caller arguments contain public paths/hashes, never credentials.
  $MAC_SUDO /bin/sh -s -- "$MAC_STAGE" "$COSIGN_SHA256" "$VERSION" <<'ROOT_VERIFY'
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
stage=$1; verifier_hash=$2; version=$3
actual=$(shasum -a 256 "$stage/cosign" | awk '{print $1}')
[ "$actual" = "$verifier_hash" ] || exit 2
"$stage/cosign" verify-blob --bundle "$stage/SHA256SUMS.sigstore.json" \
  --certificate-identity "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/$version" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$stage/SHA256SUMS" \
  >"$stage/bootstrap-verification.log" 2>&1
expected=$(awk '$2 == "install-macos-service.sh" || $2 == "*install-macos-service.sh" { print $1 }' "$stage/SHA256SUMS")
[ "${#expected}" = 64 ] || exit 2
[ "$(shasum -a 256 "$stage/install-macos-service.sh" | awk '{print $1}')" = "$expected" ] || exit 2
ROOT_VERIFY
  # Helper is now a verified, root-owned signed asset in root-private staging.
  $MAC_SUDO /bin/sh "$MAC_STAGE/install-macos-service.sh" "$MAC_STAGE" "$VERSION" "$RULES" "$ACCOUNT" "$CAP" "$LISTEN" "$SHARE" "$LICENCE" "$NETWORK" "$NONINTERACTIVE"
  $MAC_SUDO /bin/rm -rf "$MAC_STAGE"
  exit 0
fi

if [ "$KEY_STDIN" -eq 1 ] && [ "$SERVICE" -ne 1 ]; then
  die "protected testnet stdin requires the managed systemd service on Linux"
fi

# ---------------------------------------------------------------- 5: set up
if [ "$SERVICE" -eq 1 ]; then
  GUARD_HOME=$SERVICE_HOME
  RUN_AS=$SUDO
  id zunder-guard >/dev/null 2>&1 \
    || $SUDO useradd --system --home-dir "$SERVICE_HOME" --shell /usr/sbin/nologin zunder-guard
  $SUDO install -d -m 0700 -o zunder-guard -g zunder-guard "$SERVICE_HOME"
  $SUDO install -d -m 0755 /etc/zunder-guard
else
  GUARD_HOME=${ZUNDER_GUARD_HOME:-$HOME/.zunder-guard}
  RUN_AS=""
fi

guard() { $RUN_AS env ZUNDER_GUARD_HOME="$GUARD_HOME" "$BIN" "$@"; }

# Mainnet is set up only as a systemd service with systemd-creds: Guard takes a mainnet key on
# standard input only, and the service gets it there from an encrypted credential. Anywhere
# else init is told to refuse mainnet before it writes anything.
HAS_CREDS=0
if command -v systemd-creds >/dev/null 2>&1 && systemd-creds --help 2>/dev/null | grep -q encrypt; then HAS_CREDS=1; fi
NO_MAINNET=""
if [ "$SERVICE" -eq 0 ]; then
  NO_MAINNET="mainnet is set up only as a systemd service on Linux (root or sudo), where the key reaches Guard from an encrypted credential; here, run it by hand with the key piped in: zunder-guard run --network mainnet --key-stdin"
elif [ "$HAS_CREDS" -eq 0 ]; then
  NO_MAINNET="mainnet under systemd needs systemd-creds (systemd 250 or newer), so the key is never on disk in plain text; upgrade systemd, or run Guard by hand with the key piped in: zunder-guard run --network mainnet --key-stdin"
fi
if [ "$KEY_STDIN" -eq 1 ]; then
  [ "$HAS_CREDS" -eq 1 ] || die "protected testnet stdin requires systemd-creds; plaintext fallback is refused"
  if $SUDO test -e "$SERVICE_HOME/guard.toml"; then
    [ "$(guard config get mode)" = testnet ] || die "testnet setup cannot adopt another network or paper state"
  fi
fi
if [ "$NONINTERACTIVE" -eq 1 ] && [ "$NETWORK" = mainnet ] && [ -n "$NO_MAINNET" ]; then
  die "$NO_MAINNET. Nothing was set up."
fi

# The binary asks the questions: it shows the rules (keep or edit), the account and the mode,
# and applies the mainnet confirmation. With the systemd unit it does not store the key
# (--no-key) because this script stores it as a credential below; a mainnet key it still reads
# once, to check it with the venue and record its address, and never stores. Without the unit
# the binary asks for the key itself and stores it the way it does on that system (testnet).
set -- init
[ -n "$RULES" ] && set -- "$@" --rules "$RULES"
[ "$SERVICE" -eq 1 ] && set -- "$@" --no-key
[ -n "$NO_MAINNET" ] && set -- "$@" --refuse-mainnet "$NO_MAINNET"
[ "$FORCE" -eq 1 ] && set -- "$@" --force
[ -n "$LISTEN" ] && set -- "$@" --listen "$LISTEN"
[ -n "$SHARE" ] && set -- "$@" --ip-share "$SHARE"
[ -n "$LICENCE" ] && set -- "$@" --licence "$LICENCE"
[ -n "$CAP" ] && set -- "$@" --equity-cap "$CAP"
if [ "$NONINTERACTIVE" -eq 1 ]; then
  set -- "$@" --non-interactive --network "$NETWORK"
  [ -n "$ACCOUNT" ] && set -- "$@" --account "$ACCOUNT"
  [ -n "$CONFIRM" ] && set -- "$@" --confirm-mainnet "$CONFIRM"
  if [ "$NETWORK" = mainnet ] || { [ "$SERVICE" -eq 0 ] && [ "$NETWORK" != paper ]; }; then
    guard "$@" --key-stdin <"$KEY_FILE"
  else
    guard "$@"
  fi
else
  [ -n "$ACCOUNT" ] && set -- "$@" --account "$ACCOUNT"
  [ -n "$NETWORK" ] && set -- "$@" --network "$NETWORK"
  guard "$@" --interactive </dev/tty
fi
NET=$(guard config get network)
ACCOUNT=$(guard config get account)

# Pair before a service loads the config, so the displayed client key works immediately.
guard pair
[ "$SERVICE" -eq 1 ] && $SUDO chown -R zunder-guard:zunder-guard "$SERVICE_HOME"

if [ "$SERVICE" -eq 1 ]; then
  CREDENTIAL=""
  if [ "$NET" = mainnet ] && [ "$HAS_CREDS" -eq 0 ]; then
    # init refuses mainnet here already (--refuse-mainnet); this is the second lock.
    die "mainnet under systemd needs systemd-creds; nothing was stored"
  fi
  if [ "$NET" != paper ]; then
    # The key lives in this shell variable only: never echoed, exported, written to history or
    # put on a command line (printf is a shell builtin, so it does not appear in ps either), and
    # never traced (set -x off from here on).
    { set +x; } 2>/dev/null
    if [ "$NONINTERACTIVE" -eq 1 ]; then
      if [ "$KEY_STDIN" -eq 1 ]; then
        IFS= read -r KEY || die "missing protected testnet key frame"
        [ "${#KEY}" -eq 64 ] || die "protected testnet frame requires exactly 64 hex digits"
        case "$KEY" in *[!0-9a-fA-F]*) die "invalid protected testnet key frame" ;; esac
      else
        IFS= read -r KEY <"$KEY_FILE" || true
      fi
    else
      if [ "$NET" = mainnet ]; then
        say "Once more, for the encrypted credential the service reads it from (Guard checked it above and stored nothing):" >/dev/tty
      fi
      printf 'API wallet private key for %s on %s (input hidden): ' "$ACCOUNT" "$NET" >/dev/tty
      stty -echo </dev/tty
      IFS= read -r KEY </dev/tty || true
      stty echo </dev/tty
      printf '\n' >/dev/tty
    fi
    printf '%s\n' "$KEY" | guard key check --key-stdin || die "the key was refused; nothing was stored"
    if [ "$HAS_CREDS" -eq 1 ]; then
      $SUDO install -d -m 0700 /etc/credstore.encrypted
      printf '%s\n' "$KEY" | $SUDO systemd-creds encrypt --name="$CRED_NAME" - "$CRED_ENCRYPTED" \
        || die "systemd-creds could not encrypt the key"
      $SUDO rm -f "$CRED_PLAIN"
      CREDENTIAL="LoadCredentialEncrypted=$CRED_NAME:$CRED_ENCRYPTED"
      say "  key: encrypted with systemd-creds ($(systemd-creds has-tpm2 >/dev/null 2>&1 && echo 'TPM2 and host key' || echo 'host key')) in $CRED_ENCRYPTED"
    else
      printf '%s\n' "$KEY" | $SUDO sh -c "umask 077 && cat > '$CRED_PLAIN'"
      $SUDO chown zunder-guard:zunder-guard "$CRED_PLAIN"
      $SUDO chmod 0600 "$CRED_PLAIN"
      CREDENTIAL="LoadCredential=$CRED_NAME:$CRED_PLAIN"
      say "  WARNING: systemd-creds is not available (systemd 250 or newer has it). The key is in"
      say "  $CRED_PLAIN, mode 0600, owned by the zunder-guard user: anyone with root on this"
      say "  machine, or a copy of its disk, can read it."
    fi
    KEY=""
    unset KEY
  fi
  if [ "$NET" = mainnet ]; then
    # The person typed the confirmation in `init`; this file carries it to every start.
    printf 'ZUNDER_MAINNET_CONFIRM=%s\n' "$ACCOUNT" | $SUDO sh -c "umask 077 && cat > '$MAINNET_ENV'"
  else
    $SUDO rm -f "$MAINNET_ENV"
  fi
  $SUDO chown -R zunder-guard:zunder-guard "$SERVICE_HOME"
  $SUDO install -m 0644 "$TMP/x/zunder-guard.service" /etc/systemd/system/zunder-guard.service
  $SUDO install -d -m 0755 /etc/systemd/system/zunder-guard.service.d
  {
    say "# Written by install.sh $VERSION. No secrets here: the key is a credential."
    say "[Service]"
    say "Environment=ZUNDER_GUARD_NETWORK=$NET"
    if [ -n "$CREDENTIAL" ]; then
      say "$CREDENTIAL"
      say "ExecStart="
      say "ExecStart=/bin/sh -c 'exec $BIN run --network $NET --key-stdin < \"\$\$CREDENTIALS_DIRECTORY/$CRED_NAME\"'"
    else
      say "ExecStart="
      say "ExecStart=$BIN run --network $NET"
    fi
    [ "$NET" = mainnet ] && say "EnvironmentFile=$MAINNET_ENV"
  } | $SUDO sh -c "umask 022 && cat > /etc/systemd/system/zunder-guard.service.d/10-install.conf"
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable zunder-guard >/dev/null 2>&1
  if [ "$NET" = mainnet ] && ! $SUDO test -e "$SERVICE_HOME/risk-mainnet.jsonl"; then
    # The mainnet risk journal is started by a person at the account's equity then, and only
    # then does Guard start (docs/guard.md, "Mainnet").
    $SUDO systemctl stop zunder-guard >/dev/null 2>&1 || true
    say ""
    say "Mainnet is set up and NOT started. When you are ready to trade, start the risk journal and"
    say "then Guard, which reads the confirmation from $MAINNET_ENV at every start:"
    say "  sudo -u zunder-guard env ZUNDER_GUARD_HOME=$SERVICE_HOME ZUNDER_MAINNET_CONFIRM=$ACCOUNT \\"
    say "    $BIN journal-init --mode mainnet --note \"your name, why, today's date\""
    say "  sudo systemctl start zunder-guard"
    say "To stop mainnet for good, remove $MAINNET_ENV: Guard then refuses to start."
    if [ -n "$KEY_FILE" ]; then
      say "WARNING: $KEY_FILE still holds the API wallet key in plain text. Guard does not need it any"
      say "more: delete it (shred -u \"$KEY_FILE\" where available)."
    fi
    exit 0
  fi
  $SUDO systemctl restart zunder-guard
  i=0
  HEALTH_LISTEN=$(guard config get listen)
  until "$BIN" health --listen "$HEALTH_LISTEN" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 20 ]; then
      $SUDO journalctl -u zunder-guard -n 20 --no-pager >&2 || true
      die "Guard did not become healthy; see the log above (journalctl -u zunder-guard)"
    fi
    sleep 1
  done
  say "Guard is running ($NET) as the systemd service zunder-guard, on 127.0.0.1 only."
fi

if [ -n "$KEY_FILE" ]; then
  say "WARNING: $KEY_FILE still holds the API wallet key in plain text. Guard does not need it any"
  say "more: delete it (shred -u \"$KEY_FILE\" where available)."
fi
if [ "$SERVICE" -eq 1 ]; then
  say "Logs: journalctl -u zunder-guard -f    Stop: sudo systemctl stop zunder-guard"
else
  say "Start Guard: ZUNDER_GUARD_HOME=$GUARD_HOME $BIN run --network $NET"
fi
