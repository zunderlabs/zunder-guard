#include "macos_process.h"
#include <libproc.h>
#include <sys/proc_info.h>
#include <unistd.h>
#include <string.h>
int public_reboot_birth(int pid, uint64_t *seconds, uint64_t *microseconds) {
    struct proc_bsdinfo info;
    memset(&info, 0, sizeof(info));
    if (pid <= 0 || seconds == 0 || microseconds == 0) return -1;
    int received = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (received != sizeof(info) || info.pbi_start_tvsec == 0 || info.pbi_start_tvusec >= 1000000) return -1;
    *seconds = info.pbi_start_tvsec;
    *microseconds = info.pbi_start_tvusec;
    return 0;
}
int public_reboot_uid(void) { return getuid() == 0 && geteuid() == 0 ? 0 : -1; }
