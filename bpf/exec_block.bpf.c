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

#define PATH_MAX 4096
#define ENAMETOOLONG 36

/*
 * Canonical Path Resolution Buffer
 * eBPF programs are strictly constrained by a 512-byte stack limit, making 
 * on-stack allocations of PATH_MAX (4096 bytes) impossible. To securely 
 * resolve absolute execution paths without truncation or triggering 
 * -ENAMETOOLONG fail-open vulnerabilities, we allocate a dedicated memory 
 * segment.
 * Utilizing a BPF_MAP_TYPE_PERCPU_ARRAY provides a lock-free, zero-contention
 * memory region dedicated to each CPU core. This ensures that concurrent
 * execve syscalls do not overwrite each other's path resolution buffers 
 * while maintaining O(1) latency.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, char[PATH_MAX]);
    __uint(max_entries, 1);
} path_buffer_map SEC(".maps");

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
    char *path_buf;
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
     * Acquire the CPU-local scratch buffer for canonicalizing the inode path.
     * A lookup failure here typically indicates a severe kernel memory
	 * exhaustion during map initialization, rather than a runtime logic error.
	 * In such extreme edge cases, we fail-open (return 0) to preserve core
	 * system stability.
     */
    path_buf = bpf_map_lookup_elem(&path_buffer_map, &key);
    if (!path_buf) {
        return 0;
    }

    /*
     * Resolve the fully canonicalized, absolute path of the underlying inode.
     * bpf_d_path natively handles mount points, namespace translations, and
     * symlink resolution, mitigating bypasses via path normalization.
     */
    len = bpf_d_path(&file->f_path, path_buf, PATH_MAX);
	if (len == -ENAMETOOLONG) {
		bpf_printk("Bouclier Bleu [BLOCK]: Evasion attempt (Path too long)\n");
        return -EPERM;
	} else if (len <= 0) {
        return 0;
    }

	/*
     * TODO: Mount Namespace & Bind-Mount Evasion Mitigation
     * Threat Model: The current path heuristics rely on string prefix matching
     * (e.g., "/tmp/"). Advanced attackers can trivially bypass this by
	 * creating a new user/mount namespace (`unshare -Ur -m`) and bind-mounting
	 * the world-writable directory to an unmonitored path (e.g.,
	 * `~/safe_tmp`). `bpf_d_path` resolves relative to the process's current
	 * namespace root, causing the string-matching heuristic to fail-open.
     * We must therefore deprecate string-based path heuristics. 
     * The Rust userland daemon should resolve the exact `inode` number and 
     * `s_dev` (superblock device ID) of the target protected directories at
	 * boot. These hardware-level identifiers should be passed to the kernel 
     * via a new eBPF Map. This hook will then extract `file->f_inode->i_ino` 
     * and `file->f_inode->i_sb->s_dev` to perform cryptographic-grade path 
     * validation that cannot be spoofed by namespace manipulation.
     */

    /*
     * Path Heuristics Verification
     * Target execution attempts originating from world-writable directories
     * commonly utilized for staging secondary payloads or web-shell droppers.
     * Note: Direct memory offset comparisons are utilized to guarantee O(1)
     * execution time and ensure BPF verifier compliance.
     */

    // /tmp/
    if (len >= 5 && path_buf[0] == '/' && path_buf[1] == 't' &&
		path_buf[2] == 'm' && path_buf[3] == 'p' && path_buf[4] == '/')
        goto block_exec;

    // /var/tmp/
    if (len >= 9 && path_buf[0] == '/' && path_buf[1] == 'v' &&
		path_buf[2] == 'a' && path_buf[3] == 'r' && path_buf[4] == '/' &&
		path_buf[5] == 't' && path_buf[6] == 'm' && path_buf[7] == 'p' &&
		path_buf[8] == '/')
        goto block_exec;

    // /dev/shm/
    if (len >= 9 && path_buf[0] == '/' && path_buf[1] == 'd' &&
		path_buf[2] == 'e' && path_buf[3] == 'v' && path_buf[4] == '/' &&
		path_buf[5] == 's' && path_buf[6] == 'h' && path_buf[7] == 'm' &&
		path_buf[8] == '/')
        goto block_exec;

	// /var/crash/ (Apport dump staging)
    if (len >= 11 && path_buf[0] == '/' && path_buf[1] == 'v' &&
		path_buf[2] == 'a' && path_buf[3] == 'r' && path_buf[4] == '/' &&
		path_buf[5] == 'c' && path_buf[6] == 'r' && path_buf[7] == 'a' &&
		path_buf[8] == 's' && path_buf[9] == 'h' && path_buf[10] == '/')
        goto block_exec;

    // /dev/mqueue/ (POSIX message queues)
    if (len >= 12 && path_buf[0] == '/' && path_buf[1] == 'd' &&
		path_buf[2] == 'e' && path_buf[3] == 'v' && path_buf[4] == '/' &&
		path_buf[5] == 'm' && path_buf[6] == 'q' && path_buf[7] == 'u' &&
		path_buf[8] == 'e' && path_buf[9] == 'u' && path_buf[10] == 'e' &&
		path_buf[11] == '/')
        goto block_exec;

    // /run/user/ (User-specific volatile runtime)
    if (len >= 10 && path_buf[0] == '/' && path_buf[1] == 'r' &&
		path_buf[2] == 'u' && path_buf[3] == 'n' && path_buf[4] == '/' &&
		path_buf[5] == 'u' && path_buf[6] == 's' && path_buf[7] == 'e' &&
		path_buf[8] == 'r' && path_buf[9] == '/')
        goto block_exec;

	/*
     * TODO: Fileless Execution (memfd_create) Mitigation
     * Advanced droppers frequently utilize memfd_create coupled with fexecve
	 * to execute payloads directly from memory, bypassing the on-disk path
	 * heuristics above. The resolved path typically prefixes with "memfd:" or
	 * "/memfd:".
     * However, an unilateral string-matching block on memfd execution
	 * introduces unacceptable false-positive rates, actively breaking core
	 * container runtimes (runC, Docker), systemd IPC, and sandboxed desktop
	 * applications (Flatpak) which rely on memfd for secure, isolated
	 * execution.
     * In the future, this hook will be expanded to include a refined
	 * behavioral heuristic with Seal Inspection (e.g. F_SEAL_WRITE) and
	 * Process Lineage (e.g. map allowlist).
     */

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
