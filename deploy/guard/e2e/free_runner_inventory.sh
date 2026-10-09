#!/usr/bin/env bash
# Public candidate inventory only. No runtime/private/native acceptance.
set -euo pipefail
[[ ${EUID} == 0 && $(uname -m) == x86_64 ]] || exit 2
umask 077
ulimit -c 0
# Observe only public numeric swap fields; never emit swap filenames or mutate it.
/usr/bin/awk '
  NR == 1 {
    if (NF != 5 || $1 != "Filename" || $2 != "Type" || $3 != "Size" || $4 != "Used" || $5 != "Priority") exit 2
    next
  }
  {
    if (NF != 5 || ($2 != "file" && $2 != "partition") || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ || $5 !~ /^-?[0-9]+$/) exit 2
    printf "swap_entry_type=%s size_kib=%s used_kib=%s priority=%s\n", $2, $3, $4, $5
    entries++
  }
  END { printf "swap_entries_observed=%d\n", entries }
' /proc/swaps
printf '%s\n' 'scope=public-candidate-inventory' 'private_input=false' 'runtime_admission=false' 'release_acceptance=false'
/usr/bin/uname -srmo
/usr/bin/cat /etc/os-release /proc/sys/kernel/random/boot_id
/usr/bin/free --bytes
/usr/bin/df --block-size=1 / /opt /run
for p in /sys/fs/cgroup /sys/fs/cgroup/cgroup.controllers /sys/fs/cgroup/cgroup.kill /sys/fs/cgroup/cgroup.procs /sys/fs/cgroup/cgroup.threads /sys/fs/cgroup/cgroup.subtree_control; do
  if [[ -e $p ]]; then /usr/bin/stat -c '%n %F %u %g %a' "$p"; else printf '%s=ABSENT_AT_ROOT_INVENTORY_ONLY\n' "$p"; fi
done
/usr/bin/cat /sys/fs/cgroup/cgroup.controllers /sys/fs/cgroup/cgroup.type
/usr/bin/systemctl is-system-running || true
/usr/bin/systemctl show --property=Version --property=DefaultLimitCORE
for p in /proc/sys/user/max_user_namespaces /proc/sys/kernel/unprivileged_userns_clone /proc/sys/kernel/apparmor_restrict_unprivileged_userns /proc/sys/kernel/apparmor_restrict_unprivileged_unconfined /sys/module/apparmor/parameters/enabled; do
  if [[ -f $p ]]; then printf '%s=' "$p"; /usr/bin/cat "$p"; else printf '%s=ABSENT\n' "$p"; fi
done
for uid in 62344 62345; do
  if /usr/bin/getent passwd "$uid" >/dev/null; then printf 'reserved_uid_%s=IN_USE\n' "$uid"; else printf 'reserved_uid_%s=no_nss_entry_observed\n' "$uid"; fi
done
for p in /usr/bin/python3 /usr/bin/mount /usr/bin/systemd-run /usr/bin/systemctl /usr/bin/bwrap /usr/sbin/ip /usr/sbin/nft /usr/bin/ss /usr/bin/nsenter /usr/bin/certutil /usr/bin/openssl /usr/sbin/sysctl /usr/bin/gpgv /usr/bin/apt-get /usr/bin/dpkg /usr/bin/dpkg-deb /usr/bin/readelf /usr/bin/unshare /usr/bin/setpriv; do
  if [[ -e $p ]]; then q=$(/usr/bin/readlink -f -- "$p"); /usr/bin/stat -c '%n %F %u %g %a %h' "$q"; /usr/bin/sha256sum -- "$q"; else printf '%s=ABSENT\n' "$p"; fi
done
/usr/bin/sha256sum /var/lib/dpkg/status
/usr/bin/dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'
printf '%s\n' 'inventory_complete=true' 'kernel_verified=false' 'dynamic_loader_verified=false' 'sandbox_verified=false' 'reboot_verified=false'
