// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2026 The Bouclier Bleu Authors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> // Required for CO-RE

// Required by the kernel to attach to LSM hooks
char LICENSE[] SEC("license") = "GPL";

/* Linux standard error code for Operation Not Permitted */
#define EPERM 1

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_block_bprm_check, struct linux_binprm *bprm) {
    const char *filename_ptr;
    char path_buf[256] = {0};

	/*
	 * CO-RE (Compile Once - Run Everywhere) allows us to safely extract
	 * struct fields dynamically based on the host kernel's BTF data, ensuring
	 * compatibility across different Linux kernel versions without
	 * recompilation.
     */
    filename_ptr = BPF_CORE_READ(bprm, filename);
	// Allow execution if we can't read the pointer
    if (!filename_ptr) return 0;

    long len = bpf_probe_read_kernel_str(path_buf, sizeof(path_buf), filename_ptr);
    if (len <= 0) return 0;

	/*
     * The BPF Verifier strictly limits loops. We use direct memory offset
	 * comparisons here to ensure O(1) execution time and guaranteed verifier
	 * acceptance.
	 * We target world-writable directories commonly used as staging grounds 
     * for post-exploitation payloads.
     */

    // - /tmp/
    if (path_buf[0] == '/' && path_buf[1] == 't' && path_buf[2] == 'm' && 
        path_buf[3] == 'p' && path_buf[4] == '/')
		goto block_exec;

    // - /var/tmp/
    if (path_buf[0] == '/' && path_buf[1] == 'v' && path_buf[2] == 'a' && 
        path_buf[3] == 'r' && path_buf[4] == '/' && path_buf[5] == 't' && 
        path_buf[6] == 'm' && path_buf[7] == 'p' && path_buf[8] == '/')
		goto block_exec;

    // - /dev/shm/
    if (path_buf[0] == '/' && path_buf[1] == 'd' && path_buf[2] == 'e' && 
        path_buf[3] == 'v' && path_buf[4] == '/' && path_buf[5] == 's' && 
        path_buf[6] == 'h' && path_buf[7] == 'm' && path_buf[8] == '/')
		goto block_exec;

	// Defer to subsequent LSMs / allow execution
    return 0; 

block_exec:
	/* Note: Logging is restricted to trace_pipe for the PoC.
     * Production implementation should route this via a BPF RingBuffer to
	 * userland.
     */
    bpf_printk("Bouclier Bleu [BLOCK]: %s\n", path_buf);
	return -EPERM;
}
