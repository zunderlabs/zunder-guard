#!/bin/bash
# Disposable GitHub-hosted macOS runner ONLY. No real accounts, network or keys.
# Takes a compiled, NON-SHIPPED macos_service_fixture example. Production backend,
# synthetic child: proves OS credential/supervisor behavior without venue traffic.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || { echo 'hosted macOS CI only' >&2; exit 2; }
[[ $(uname -s) == Darwin && $EUID -eq 0 && $# -eq 2 ]] || exit 2
fixture=$1; evidence=$2
[[ -f $fixture && -d $evidence && ! -L $fixture ]] || exit 2
id="ci-$(uuidgen | tr '[:upper:]' '[:lower:]')"
base="/Library/Application Support/Zunder Guard Native CI/$id"
label="com.zunderlabs.guard.$id"
user="_zgci$(printf '%s' "$id" | tr -d '-' | cut -c3-14)"
plist="/Library/LaunchDaemons/$label.plist"
trusted_dir() {
  component=$1
  while :; do
    [[ -d $component && ! -L $component && $(stat -f %u "$component") == 0 ]] || exit 2
    permissions=$(stat -f %Lp "$component")
    [[ $((0$permissions & 022)) == 0 ]] || exit 2
    [[ $component != / ]] || break
    component=$(dirname "$component")
  done
}
trusted_dir '/Library/Application Support'
if [[ ! -e '/Library/Application Support/Zunder Guard Native CI' ]]; then mkdir -m 0755 '/Library/Application Support/Zunder Guard Native CI'; fi
trusted_dir '/Library/Application Support/Zunder Guard Native CI'
mkdir -m 0755 "$base" "$base/a" "$base/b" "$base/deny" "$base/state"
created_user=0; created_group=0; acl_created=0; crash_baseline_ready=0
scanner="$(cd "$(/usr/bin/dirname "$0")" && pwd)/crash-report-scan.py"
cleanup() {
  status=$?
  set +e
  cleanup_errors=0
  launchctl bootout "system/$label" >/dev/null 2>&1 || true
  # Observe newly generated fixture reports before removing fixture processes/state.
  # Reports can arrive asynchronously; zero observed reports remains inconclusive.
  if [[ $crash_baseline_ready == 1 ]]; then
    /usr/bin/python3 "$scanner" scan --fixture-base "$base" --wait-seconds 20 --result "$evidence/crash-report-scan.txt"
    scan_status=$?
    printf '%s\n' "$scan_status" > "$evidence/crash-report-scan-exit-code.txt"
    [[ $scan_status == 0 ]] || status=1
  fi
  if [[ $acl_created == 1 ]]; then "$base/a/broker" service acl-clean --binding "$base/a.json" >/dev/null 2>&1 || cleanup_errors=$((cleanup_errors + 1)); fi
  for version in a b; do
    if [[ -f $base/$version.json ]]; then
      "$base/$version/broker" service remove-credential --binding "$base/$version.json" >/dev/null 2>&1 || cleanup_errors=$((cleanup_errors + 1))
    fi
  done
  # Fixture process command line includes the unique binding path. Never kill by name.
  while IFS= read -r pid; do
    [[ -n $pid ]] || continue
    if ps -p "$pid" -o args= 2>/dev/null | grep -Fq "$base/"; then kill -KILL "$pid" || true; fi
  done < <(awk '/^started / {print $2}' "$base/state/lifecycle.log" 2>/dev/null || true)
  cp "$base/state/lifecycle.log" "$evidence/lifecycle.log" 2>/dev/null || true
  cp "$base/broker.log" "$evidence/broker.log" 2>/dev/null || true
  rm -f "$plist"
  [[ $created_user == 0 ]] || dscl . -delete "/Users/$user"
  [[ $created_group == 0 ]] || dscl . -delete "/Groups/$user"
  rm -rf "$base"
  [[ $cleanup_errors == 0 ]] || status=1
  printf '%s\n' "$cleanup_errors" > "$evidence/cleanup-errors.txt"
  printf '%s\n' "$status" > "$evidence/system-service-exit-code.txt"
  exit "$status"
}
trap cleanup EXIT
/usr/bin/python3 "$scanner" baseline --fixture-base "$base"
crash_baseline_ready=1
# Fresh dedicated identity; never adopt/delete an existing user or group.
# Assignment failures abort: a directory lookup error is not an absent identity.
users=$(dscl . -list /Users UniqueID)
groups=$(dscl . -list /Groups PrimaryGroupID)
if printf '%s\n%s\n' "$users" "$groups" | awk '{print $1}' | grep -Fx "$user" >/dev/null; then
  echo 'fixture user or group already exists' >&2; exit 1
fi
uid=350
while printf '%s\n%s\n' "$users" "$groups" | awk '{print $2}' | grep -x "$uid" >/dev/null; do
  uid=$((uid + 1)); [[ $uid -lt 500 ]]
done
dscl . -create "/Groups/$user"; created_group=1
dscl . -create "/Groups/$user" PrimaryGroupID "$uid"
dscl . -create "/Users/$user"; created_user=1
dscl . -create "/Users/$user" UniqueID "$uid"
dscl . -create "/Users/$user" PrimaryGroupID "$uid"
dscl . -create "/Users/$user" UserShell /usr/bin/false
dscl . -create "/Users/$user" NFSHomeDirectory /var/empty
dscl . -create "/Users/$user" Password '*'
for version in a b deny; do
  install -o root -g wheel -m 0755 "$fixture" "$base/$version/broker"
  codesign --force --sign - --identifier "com.zunderlabs.guard.fixture.$id.$version" "$base/$version/broker" >/dev/null 2>&1
done
for version in a b; do
  "$base/$version/broker" prepare-fixture --home "$base/state" --uid "$uid" --gid "$uid" --id "$id" > "$base/$version.json"
  chmod 0644 "$base/$version.json"
done
chown -R "$uid:$uid" "$base/state"; chmod 0700 "$base/state"
shasum -a 256 "$base/state/guard.toml" "$base/state/risk-mainnet.jsonl" > "$evidence/state-before.txt"
"$base/a/broker" service acl-write --binding "$base/a.json"
acl_created=1
"$base/deny/broker" service acl-denied --binding "$base/a.json"
"$base/a/broker" service provision --binding "$base/a.json"
"$base/a/broker" service check --binding "$base/a.json"
# Production backend must refuse a foreign executable before credential read.
if "$base/deny/broker" service check --binding "$base/a.json" >/dev/null 2>&1; then echo 'foreign executable accepted' >&2; exit 1; fi
launch() {
  version=$1
  cat > "$plist" <<PLIST
<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>
<key>Label</key><string>$label</string><key>ProgramArguments</key><array><string>$base/$version/broker</string><string>service</string><string>run</string><string>--binding</string><string>$base/$version.json</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>1</integer><key>ExitTimeOut</key><integer>35</integer><key>AbandonProcessGroup</key><false/>
<key>SoftResourceLimits</key><dict><key>Core</key><integer>0</integer></dict><key>HardResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>
<key>StandardOutPath</key><string>$base/broker.log</string><key>StandardErrorPath</key><string>$base/broker.log</string></dict></plist>
PLIST
  chmod 0644 "$plist"; plutil -lint "$plist" >/dev/null
  launchctl bootstrap system "$plist"
}
wait_starts() {
  expected=$1
  for ((attempt=0; attempt<60; attempt++)); do
    count=$(awk '/^started / {n++} END{print n+0}' "$base/state/lifecycle.log" 2>/dev/null || echo 0)
    [[ $count -ge $expected ]] && return 0
    sleep 1
  done
  echo 'child did not start before deadline' >&2; return 1
}
# A successful full snapshot distinguishes an exited PID from a broken ps probe.
fixture_process_alive() {
  local processes
  processes=$(ps -ax -o pid= -o args=) || { echo 'cannot inspect fixture processes' >&2; exit 1; }
  printf '%s\n' "$processes" | awk -v pid="$1" -v binding="$base/" '$1 == pid && index($0, binding) { found=1 } END { exit !found }'
}
assert_no_children() {
  pids=$(awk '/^started / {print $2}' "$base/state/lifecycle.log")
  while IFS= read -r pid; do
    [[ -n $pid ]] || continue
    for ((attempt=0; attempt<35; attempt++)); do
      fixture_process_alive "$pid" || break
      sleep 1
    done
    if fixture_process_alive "$pid"; then
      echo 'fixture child survived explicit stop' >&2; exit 1
    fi
  done <<< "$pids"
}
launch a; wait_starts 1
old_child=$(awk '/^started / {p=$2} END{print p}' "$base/state/lifecycle.log")
# SIGABRT exercises a report-producing crash while retaining normal core-limit guards.
kill -ABRT "$old_child"; wait_starts 2
old_child=$(awk '/^started / {p=$2} END{print p}' "$base/state/lifecycle.log")
# A root broker crash must close stdin and leave no old trading child.
launchctl kill SIGKILL "system/$label"; wait_starts 3
for ((attempt=0; attempt<35; attempt++)); do
  fixture_process_alive "$old_child" || break
  sleep 1
done
if fixture_process_alive "$old_child"; then
  echo 'old fixture child survived broker crash' >&2; exit 1
fi
launchctl bootout "system/$label"
assert_no_children
# Rejected next release must leave the old creator/item available.
cp "$base/b.json" "$base/b-invalid.json"
plutil -replace executable_sha256 -string "$(printf '%064d' 0)" "$base/b-invalid.json"
if "$base/a/broker" service migrate-credential --binding "$base/a.json" --next-binding "$base/b-invalid.json" >/dev/null 2>&1; then echo 'invalid migration accepted' >&2; exit 1; fi
"$base/a/broker" service check --binding "$base/a.json"
# Actual A->B default creator-item migration with immutable distinct identities.
"$base/a/broker" service migrate-credential --binding "$base/a.json" --next-binding "$base/b.json"
"$base/b/broker" service check --binding "$base/b.json"
"$base/a/broker" service check --binding "$base/a.json"
launch b; wait_starts 4
launchctl bootout "system/$label"
assert_no_children
shasum -a 256 "$base/state/guard.toml" "$base/state/risk-mainnet.jsonl" > "$evidence/state-after.txt"
cmp "$evidence/state-before.txt" "$evidence/state-after.txt"
# Fixture scalar must never appear in logs. No real secret is used.
if grep -F '0123456789012345678901234567890123456789012345678901234567890123' "$base/broker.log" "$base/state/lifecycle.log" >/dev/null; then
  echo 'fixture credential appeared in logs' >&2; exit 1
else
  # grep 1 means absent; unreadable/missing logs are not passing evidence.
  [[ $? == 1 ]] || { echo 'cannot inspect fixture logs' >&2; exit 1; }
fi
printf '%s\n' 'System Keychain roundtrip and creator ACL isolation; foreign executable denied; launchd child+broker crash restart; A-to-B migration; state retained. Reboot NOT tested.' > "$evidence/system-service-result.txt"
