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

#include "headers/module_core.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

#define PATH_MAX 4096
#define ENAMETOOLONG 36

/**
 * struct exec_alert - Telemetry Payload Contract
 * @pid: The Process ID originating the execve attempt.
 * @path: The canonicalized execution path.
 *
 * Memory layout must strictly mirror the `ExecAlert` struct in the Rust
 * userland to ensure safe zero-copy deserialization.
 */
struct exec_alert {
    __u32 pid;
    char path[PATH_MAX];
};

/**
 * path_buffer_map - Canonical Path Resolution Buffer
 *
 * eBPF programs are strictly constrained by a 512-byte stack limit. To
 * securely resolve absolute execution paths (PATH_MAX = 4096) without
 * triggering -ENAMETOOLONG fail-open vulnerabilities, we allocate a dedicated
 * memory segment. We utilize BPF_MAP_TYPE_PERCPU_ARRAY to provide a lock-free,
 * zero-contention memory region dedicated to each CPU core, maintaining O(1)
 * latency.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, char[PATH_MAX]);
    __uint(max_entries, 1);
} path_buffer_map SEC(".maps");

BOUCLIER_MODULE_ALERTS;
BOUCLIER_MODULE_STATE_MAP;

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_block_bprm_check, struct linux_binprm *bprm) {
    __u32 key = 0;
    struct file *file;
    char *path_buf;
    long len;
    struct exec_alert *event;

	if (!is_module_active(&state_map)) {
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
    event = bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
    
    if (event) {
        // populate the Process ID (Higher 32 bits are TGID, lower are PID)
        event->pid = bpf_get_current_pid_tgid() >> 32;

		// bpf_probe_read_kernel_str guarantees safe memory access and enforces
        // null-termination within our PATH_MAX bounds.
        bpf_probe_read_kernel_str(event->path, PATH_MAX, path_buf);

        bpf_ringbuf_submit(event, 0);
    }

    return -EPERM;
}
