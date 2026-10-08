#!/bin/sh
# Internal signed release helper. The authenticated Unix installer owns the
# sudo/bootstrap boundary; never invoke a Cellar/user-writable broker as root.
# Usage: install-service.sh ROOT_PRIVATE_RELEASE_STAGE vX.Y.Z [rules] [account] [cap] [listen] [share] [licence]
# Stage: cosign, SHA256SUMS, SHA256SUMS.sigstore.json, versioned Darwin archive.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077
fail() { printf '%s\n' "Guard macOS service: $*" >&2; exit 2; }
[ "$(uname -s)" = Darwin ] || fail 'macOS only'
[ "$(id -u)" = 0 ] || fail 'authenticated installer must perform privileged staging first'
# Darwin /bin/sh supports separate soft/hard limits; both must be disabled.
# shellcheck disable=SC3045
ulimit -Sc 0 || fail 'cannot disable soft core limit'
# shellcheck disable=SC3045
ulimit -Hc 0 || fail 'cannot disable hard core limit'
# shellcheck disable=SC3045
if ! { [ "$(ulimit -Sc)" = 0 ] && [ "$(ulimit -Hc)" = 0 ]; }; then
  fail 'core dump limits not disabled'
fi
if ! { [ "$#" -ge 2 ] && [ "$#" -le 8 ]; }; then
  fail 'expected private release stage, version, optional public setup values'
fi
stage=$1
version=$2
rules=${3:-}
account=${4:-}
cap=${5:-}
listen=${6:-}
share=${7:-}
licence=${8:-}
case "$version" in v[0-9]*) ;; *) fail 'expected a versioned release' ;; esac
case "$version" in *[!a-zA-Z0-9.-]*) fail 'invalid release tag' ;; esac
trusted() {
  subject=$1
  case "$subject" in /*) ;; *) fail 'trusted paths must be absolute' ;; esac
  while :; do
    [ ! -L "$subject" ] || fail 'symlink in trusted path'
    [ -e "$subject" ] || fail 'missing trusted path'
    [ "$(stat -f %u "$subject")" = 0 ] || fail 'trusted path is not root-owned'
    mode=$(stat -f %Lp "$subject")
    [ "$((0$mode & 022))" = 0 ] || fail 'trusted path is writable by another user'
    [ "$subject" != / ] || break
    subject=$(dirname "$subject")
  done
}
trusted "$0"
trusted "$stage"
[ "$(stat -f %Lp "$stage")" = 700 ] || fail 'release stage must be root-private mode 0700'
case "$(uname -m)" in
  arm64) arch=arm64; cosign_sha=5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76 ;;
  x86_64) arch=amd64; cosign_sha=2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c ;;
  *) fail 'unsupported macOS architecture' ;;
esac
archive="zunder-guard-$version-darwin-$arch.tar.gz"
for asset in cosign SHA256SUMS SHA256SUMS.sigstore.json "$archive"; do
  trusted "$stage/$asset"
  [ -f "$stage/$asset" ] || fail 'release asset is not a regular file'
done
[ "$(shasum -a 256 "$stage/cosign" | awk '{print $1}')" = "$cosign_sha" ] || fail 'pinned verifier checksum mismatch'
"$stage/cosign" verify-blob --bundle "$stage/SHA256SUMS.sigstore.json" \
  --certificate-identity "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/$version" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$stage/SHA256SUMS" \
  >"$stage/verification.log" 2>&1 || fail 'signed release verification failed'
expected=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$stage/SHA256SUMS")
[ "${#expected}" = 64 ] || fail 'archive missing or duplicated in signed checksums'
[ "$(shasum -a 256 "$stage/$archive" | awk '{print $1}')" = "$expected" ] || fail 'archive checksum mismatch'
# Read one authenticated archive member, never extract archive-controlled paths.
[ "$(tar -tzf "$stage/$archive" | awk '$0 == "zunder-guard" { n++ } END { print n+0 }')" = 1 ] || fail 'archive must contain exactly one binary'
bin_stage=$(mktemp "$stage/binary.XXXXXXXX")
trap 'rm -f "$bin_stage"' EXIT HUP INT TERM
tar -xOzf "$stage/$archive" zunder-guard >"$bin_stage"
sha=$(shasum -a 256 "$bin_stage" | awk '{print $1}')
base='/Library/Application Support/Zunder Guard'
for dir in '/Library/Application Support' "$base" "$base/releases" "$base/bindings"; do
  if [ ! -e "$dir" ]; then mkdir -m 0755 "$dir"; fi
  trusted "$dir"
done
release="$base/releases/$sha"
if [ ! -e "$release" ]; then mkdir -m 0755 "$release"; fi
trusted "$release"
exe="$release/zunder-guard"
if [ -e "$exe" ]; then
  trusted "$exe"
  [ "$(shasum -a 256 "$exe" | awk '{print $1}')" = "$sha" ] || fail 'immutable installed release differs'
else
  install -o root -g wheel -m 0755 "$bin_stage" "$exe"
fi
trusted "$exe"
for notice in LICENSE NOTICE THIRD_PARTY_LICENSES.md; do
  [ "$(tar -tzf "$stage/$archive" | awk -v n="$notice" '$0 == n { count++ } END { print count+0 }')" = 1 ] || fail 'required release notice missing'
  tar -xOzf "$stage/$archive" "$notice" >"$stage/$notice"
  if [ -e "$release/$notice" ]; then
    trusted "$release/$notice"
    cmp -s "$stage/$notice" "$release/$notice" || fail 'immutable release notice changed'
  else
    install -o root -g wheel -m 0644 "$stage/$notice" "$release/$notice"
  fi
done
# Dedicated identity creation is separate from binding/keys. Never adopt an
# existing similarly named account without our root-owned ownership marker.
service_user=_zunder_guard
identity="$base/service-identity"
if id "$service_user" >/dev/null 2>&1; then
  [ -f "$identity" ] || fail 'existing service account lacks Guard ownership marker'
  trusted "$identity"
  [ "$(cat "$identity")" = "$(id -u "$service_user"):$(id -g "$service_user")" ] || fail 'service identity changed'
else
  [ ! -e "$identity" ] || fail 'service identity disappeared; explicit repair required'
  candidate=350
  while [ "$candidate" -lt 500 ]; do
    if ! dscl . -list /Users UniqueID | awk '{print $2}' | grep -qx "$candidate" \
      && ! dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | grep -qx "$candidate"; then break; fi
    candidate=$((candidate + 1))
  done
  [ "$candidate" -lt 500 ] || fail 'no unused service identity available'
  dscl . -create "/Groups/$service_user"
  dscl . -create "/Groups/$service_user" PrimaryGroupID "$candidate"
  dscl . -create "/Groups/$service_user" Password '*'
  dscl . -create "/Users/$service_user"
  dscl . -create "/Users/$service_user" UniqueID "$candidate"
  dscl . -create "/Users/$service_user" PrimaryGroupID "$candidate"
  dscl . -create "/Users/$service_user" UserShell /usr/bin/false
  dscl . -create "/Users/$service_user" NFSHomeDirectory /var/empty
  dscl . -create "/Users/$service_user" IsHidden 1
  dscl . -create "/Users/$service_user" Password '*'
  printf '%s:%s\n' "$candidate" "$candidate" >"$identity"
  chmod 0644 "$identity"
fi
uid=$(id -u "$service_user")
gid=$(id -g "$service_user")
if ! { [ "$uid" != 0 ] && [ "$gid" != 0 ]; }; then
  fail 'service identity must not be root'
fi
home="$base/state"
if [ ! -e "$home" ]; then install -d -o "$uid" -g "$gid" -m 0700 "$home"; fi
if ! { [ ! -L "$home" ] && [ -d "$home" ]; }; then
  fail 'unsafe service state directory'
fi
if ! { [ "$(stat -f %u "$home")" = "$uid" ] && [ "$(stat -f %Lp "$home")" = 700 ]; }; then
  fail 'state ownership or permissions mismatch'
fi
label=com.zunderlabs.guard.mainnet
plist="/Library/LaunchDaemons/$label.plist"
active="$base/bindings/active.json"
# Do not perform upgrade or credential replacement while a broker is running.
if launchctl print "system/$label" >/dev/null 2>&1; then
  fail 'stop your bot and boot out the existing Guard service before upgrading'
else
  code=$?
  [ "$code" = 113 ] || fail 'cannot establish service is unloaded'
fi
if [ ! -e "$home/guard.toml" ]; then
  set -- "$exe" --home "$home" init --interactive --network mainnet
  [ -z "$rules" ] || set -- "$@" --rules "$rules"
  [ -z "$account" ] || set -- "$@" --account "$account"
  [ -z "$cap" ] || set -- "$@" --equity-cap "$cap"
  [ -z "$listen" ] || set -- "$@" --listen "$listen"
  [ -z "$share" ] || set -- "$@" --ip-share "$share"
  [ -z "$licence" ] || set -- "$@" --licence "$licence"
  sudo -n -u "$service_user" -- "$@"
else
  [ -z "$rules$account$cap$listen$share$licence" ] || fail 'existing service configuration is preserved; upgrade without setup options, then use explicit service management commands'
fi
account=$(sudo -n -u "$service_user" -- "$exe" --home "$home" config get account)
next="$base/bindings/$sha.json"
[ ! -e "$next" ] || fail 'next binding exists; inspect or explicitly recover the interrupted install'
"$exe" --home "$home" service prepare --credential-id mainnet --uid "$uid" --gid "$gid" \
  --confirm-mainnet "$account" >"$next"
chmod 0644 "$next"
if [ -f "$active" ]; then
  trusted "$active"
  old_exe=$(plutil -extract executable raw -o - "$active")
  old_sha=$(plutil -extract executable_sha256 raw -o - "$active")
  trusted "$old_exe"
  [ "$(shasum -a 256 "$old_exe" | awk '{print $1}')" = "$old_sha" ] || fail 'previous admitted executable changed'
  "$old_exe" service migrate-credential --binding "$active" --next-binding "$next" --confirm-mainnet "$account"
else
  "$exe" service provision --binding "$next" --confirm-mainnet "$account"
fi
"$exe" service check --binding "$next"
# The final service pointer changes only after the new creator can read its item.
active_next="$base/bindings/.active-next.json"
[ ! -L "$active_next" ] || fail 'unsafe binding destination'
install -o root -g wheel -m 0644 "$next" "$active_next"
# Constant paths and hex release hash only: no user text enters XML.
trusted /Library/LaunchDaemons
[ ! -L "$plist" ] || fail 'unsafe launchd plist destination'
[ ! -e "$plist" ] || trusted "$plist"
plist_next="$base/bindings/.launchd-next.plist"
[ ! -L "$plist_next" ] || fail 'unsafe plist staging destination'
cat >"$plist_next" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$label</string>
<key>ProgramArguments</key><array><string>$exe</string><string>service</string><string>run</string><string>--binding</string><string>$active</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>10</integer>
<key>ExitTimeOut</key><integer>35</integer>
<key>AbandonProcessGroup</key><false/>
<key>SoftResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>
<key>HardResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>
<key>StandardOutPath</key><string>/var/log/zunder-guard.log</string>
<key>StandardErrorPath</key><string>/var/log/zunder-guard.log</string>
</dict></plist>
PLIST
chown root:wheel "$plist_next"
chmod 0644 "$plist_next"
plutil -lint "$plist_next" >/dev/null
# Create the log privately, never follow an existing symlink or relax its mode.
[ ! -L /var/log/zunder-guard.log ] || fail 'unsafe service log destination'
if [ ! -e /var/log/zunder-guard.log ]; then install -o root -g wheel -m 0600 /dev/null /var/log/zunder-guard.log; fi
if ! { [ "$(stat -f %u /var/log/zunder-guard.log)" = 0 ] && [ "$(stat -f %Lp /var/log/zunder-guard.log)" = 600 ]; }; then
  fail 'service log must be root-only'
fi
# The job is unloaded. A failure/crash between these renames cannot launch a
# half-admitted broker: old executable/new binding hash mismatch fails closed.
# Immutable prior binding and release remain available for explicit recovery.
mv -f "$active_next" "$active"
mv -f "$plist_next" "$plist"
printf '%s\n' 'Installed mainnet service; nothing was started. Keep previous release and Keychain item until upgrade checks pass.'
printf 'If this account has no mainnet journal, initialize it explicitly:\n  sudo -u %s env ZUNDER_MAINNET_CONFIRM=%s ZUNDER_GUARD_HOME="%s" "%s" journal-init --mode mainnet --note "your name, why, date"\n' "$service_user" "$account" "$home" "$exe"
printf 'Then explicitly start and check:\n  sudo launchctl bootstrap system "%s"\n  sudo -u %s "%s" --home "%s" health\n  sudo -u %s "%s" --home "%s" status\n' "$plist" "$service_user" "$exe" "$home" "$service_user" "$exe" "$home"
