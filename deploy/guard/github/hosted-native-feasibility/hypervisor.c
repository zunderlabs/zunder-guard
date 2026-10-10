/* An empty owned Hypervisor context only: no vCPU, memory, disk, or boot. */
#include <Hypervisor/Hypervisor.h>
#include <stdio.h>
int main(void) {
#if defined(__arm64__) || defined(__aarch64__)
    hv_return_t made = hv_vm_create(NULL);
#else
    hv_return_t made = hv_vm_create(HV_VM_DEFAULT);
#endif
    hv_return_t closed = made == HV_SUCCESS ? hv_vm_destroy() : 0;
    printf("{\"api\":\"Hypervisor.framework\",\"create_result\":%u,\"destroy_result\":%u,\"empty_context_created\":%s,\"context_closed\":%s,\"guest_started\":false}\n",
      (unsigned)made,(unsigned)closed,made==HV_SUCCESS?"true":"false",made==HV_SUCCESS&&closed==HV_SUCCESS?"true":"false");
    return made==HV_SUCCESS&&closed!=HV_SUCCESS ? 1 : 0;
}
