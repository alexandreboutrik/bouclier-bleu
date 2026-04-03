#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* The license must be GPL to use BPF LSM hooks */
char LICENSE[] SEC("license") = "GPL";

/* Hook into the binary execution security check */
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm) {
    /* * Print to the kernel trace pipe. 
     * In a real EDR, you would send this to a BPF Ring Buffer instead.
     */
    bpf_printk("Bouclier Bleu: Binary executed!\\n");
    
    /* Return 0 to Allow. (Returning -EPERM would block execution) */
    return 0; 
}
