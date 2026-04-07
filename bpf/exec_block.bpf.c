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
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

/*
 * Control Plane Synchronization Map
 * Facilitates real-time state synchronization between the Rust userland daemon
 * and this kernel module. A value of 0 indicates the module is 
 * administratively disabled, while 1 indicates active enforcement.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} state_map SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_block_bprm_check, struct linux_binprm *bprm) {
    __u32 key = 0;
    __u32 *is_active;
    struct file *file;
    char path_buf[256] = {0};
    long len;

    /*
     * Verify administrative state. We fail-open (allow execution) if the map
     * lookup fails or if the policy is explicitly disabled by the control
	 * plane.
     */
    is_active = bpf_map_lookup_elem(&state_map, &key);
    if (!is_active || *is_active == 0) {
        return 0;
    }

    /*
     * Extract the file structure to resolve the canonical path.
     * Relying on bprm->filename is insecure as it only reflects the string
	 * passed by user-space, which is vulnerable to symlink and relative path
	 * manipulation.
     */
	file = bprm->file;
    if (!file) {
        return 0;
    }

    /*
     * Resolve the fully canonicalized, absolute path of the underlying inode.
     * bpf_d_path natively handles mount points, namespace translations, and
     * symlink resolution, mitigating bypasses via path normalization.
     */
    len = bpf_d_path(&file->f_path, path_buf, sizeof(path_buf));
    if (len <= 0) {
        return 0;
    }

    /*
     * Path Heuristics Verification
     * Target execution attempts originating from world-writable directories
     * commonly utilized for staging secondary payloads or web-shell droppers.
     * Note: Direct memory offset comparisons are utilized to guarantee O(1)
     * execution time and ensure BPF verifier compliance.
     */

    // /tmp/
    if (path_buf[0] == '/' && path_buf[1] == 't' && path_buf[2] == 'm' && 
        path_buf[3] == 'p' && path_buf[4] == '/')
        goto block_exec;

    // /var/tmp/
    if (path_buf[0] == '/' && path_buf[1] == 'v' && path_buf[2] == 'a' && 
        path_buf[3] == 'r' && path_buf[4] == '/' && path_buf[5] == 't' && 
        path_buf[6] == 'm' && path_buf[7] == 'p' && path_buf[8] == '/')
        goto block_exec;

    // /dev/shm/
    if (path_buf[0] == '/' && path_buf[1] == 'd' && path_buf[2] == 'e' && 
        path_buf[3] == 'v' && path_buf[4] == '/' && path_buf[5] == 's' && 
        path_buf[6] == 'h' && path_buf[7] == 'm' && path_buf[8] == '/')
        goto block_exec;

	// /var/crash/ (Apport dump staging)
    if (path_buf[0] == '/' && path_buf[1] == 'v' && path_buf[2] == 'a' && 
        path_buf[3] == 'r' && path_buf[4] == '/' && path_buf[5] == 'c' && 
        path_buf[6] == 'r' && path_buf[7] == 'a' && path_buf[8] == 's' && 
        path_buf[9] == 'h' && path_buf[10] == '/')
        goto block_exec;

    // /dev/mqueue/ (POSIX message queues)
    if (path_buf[0] == '/' && path_buf[1] == 'd' && path_buf[2] == 'e' && 
        path_buf[3] == 'v' && path_buf[4] == '/' && path_buf[5] == 'm' && 
        path_buf[6] == 'q' && path_buf[7] == 'u' && path_buf[8] == 'e' && 
        path_buf[9] == 'u' && path_buf[10] == 'e' && path_buf[11] == '/')
        goto block_exec;

    // /run/user/ (User-specific volatile runtime)
    if (path_buf[0] == '/' && path_buf[1] == 'r' && path_buf[2] == 'u' && 
        path_buf[3] == 'n' && path_buf[4] == '/' && path_buf[5] == 'u' && 
        path_buf[6] == 's' && path_buf[7] == 'e' && path_buf[8] == 'r' && 
        path_buf[9] == '/')
        goto block_exec;

    return 0;

block_exec:
    /*
     * FIXME: Production implementation required.
     * Telemetry should be routed via a BPF RingBuffer to userland for SIEM
     * ingestion. bpf_printk is utilized temporarily for PoC validation but
     * risks trace_pipe saturation and high CPU overhead under load.
     */
    bpf_printk("Bouclier Bleu [BLOCK]: Executed from protected path: %s\n", path_buf);
    return -EPERM;
}
