#include "process.h"
#include <libproc.h>
#include <sys/proc_info.h>
#include <string.h>
#include <unistd.h>
int capability_birth(int pid, uint64_t *seconds, uint64_t *microseconds) {
    struct proc_bsdinfo info;
    memset(&info, 0, sizeof(info));
    int received = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (received != sizeof(info) || info.pbi_start_tvsec == 0 || info.pbi_start_tvusec >= 1000000) return 0;
    *seconds = info.pbi_start_tvsec; *microseconds = info.pbi_start_tvusec;
    return 1;
}

static int image_is(const char *expected) {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    memset(path, 0, sizeof(path));
    int received = proc_pidpath(getpid(), path, sizeof(path));
    return received > 0 && received < (int)sizeof(path) && strcmp(path, expected) == 0;
}
int capability_preparation_image(void) { return image_is("/Library/ZunderGitHubRebootCapabilityBuild/broker"); }
int capability_watch_image(void) { return image_is("/Library/ZunderGitHubRebootCapability/broker"); }
