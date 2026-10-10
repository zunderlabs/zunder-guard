#ifndef PUBLIC_REBOOT_PROCESS_H
#define PUBLIC_REBOOT_PROCESS_H
#include <stdint.h>
int public_reboot_birth(int pid, uint64_t *seconds, uint64_t *microseconds);
int public_reboot_uid(void);
#endif
