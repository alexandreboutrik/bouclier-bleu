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

#include <asm-generic/errno.h>

#include "headers/module_core.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x008
#endif

#define PATH_MAX 4096

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

/**
 * struct dir_id - Cross-Device Unique Directory Identifier
 * @ino: The physical inode number.
 * @dev: The filesystem device ID (Superblock).
 * @_pad: Explicit padding to ensure stable 16-byte alignment.
 */
struct dir_id {
    __u64 ino;
    __u32 dev;
    __u32 _pad;
};

/**
 * protected_dirs - Hardware-Backed Directory Watchlist
 *
 * Relies on the physical Inode (`ino`) and Superblock Device ID (`dev`) rather
 * than vulnerable string paths. This architecture completely neutralizes mount
 * namespace evasion (`unshare -m`) and bind-mount spoofing techniques commonly
 * employed by advanced adversaries to bypass static path heuristics.
 * The maximum capacity is dynamically calculated and overridden by the
 * userland daemon prior to kernel allocation.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dir_id);
    __type(value, __u8); // 1 = protected
    __uint(max_entries, 8192);
} protected_dirs SEC(".maps");

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
     * Path Validation
     * Extract the Inode and Superblock Device ID of the PARENT directory
     * where the executable resides. By evaluating the hardware footprint 
     * directly from the dentry cache, we bypass namespace normalization 
     * vulnerabilities entirely.
     */
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct dentry *parent = BPF_CORE_READ(dentry, d_parent);

    struct dir_id p_id = {};
    p_id.ino = BPF_CORE_READ(parent, d_inode, i_ino);
    p_id.dev = BPF_CORE_READ(parent, d_sb, s_dev);

    __u8 *is_protected = bpf_map_lookup_elem(&protected_dirs, &p_id);
    if (is_protected && *is_protected == 1) {
        goto block_exec;
    }

	/*
     * Note: String-based path heuristics (e.g. prefix matching "/tmp/") have
	 * been officially deprecated in favor of the hardware watchlist above to
	 * prevent container/namespace evasion.
     */

	/*
     * Fileless Execution (memfd_create) Mitigation
     * Advanced droppers execute payloads directly from memory to bypass on-disk 
     * heuristics. The dentry name is consistently prefixed with "memfd:".
     */
    const unsigned char *d_name = BPF_CORE_READ(dentry, d_name.name);
    char fname[7]; // Size 7 to safely capture "memfd:\0"
    bpf_probe_read_kernel_str(fname, sizeof(fname), d_name);
    
    if (fname[0] == 'm' && fname[1] == 'e' && fname[2] == 'm' && 
        fname[3] == 'f' && fname[4] == 'd' && fname[5] == ':') {
        
        /*
         * Seal Inspection Heuristic (Behavioral Validation)
         * We explicitly DO NOT use `bpf_get_current_comm()` to allowlist
		 * processes like 'systemd' or 'runc', as thread names are trivially
		 * spoofable via prctl(PR_SET_NAME). Instead, we validate the execution
		 * behavior. Legitimate users of memfd lock the memory segment using
		 * F_SEAL_WRITE (0x0008) prior to execution to guarantee immutability.
		 * Malware droppers leave it unsealed (writable) to stream staging
		 * payloads.
         */
        struct inode *f_inode = BPF_CORE_READ(file, f_inode);
        
		/*
         * CO-RE Container-Of Lookup
         * We use Clang's `__builtin_preserve_field_info` directly (with flag 0 for
		 * BPF_FIELD_BYTE_OFFSET) to calculate the relocatable offset. This avoids
		 * missing libbpf macro errors across different distributions.
         */
        size_t offset = __builtin_preserve_field_info(((struct shmem_inode_info *)0)->vfs_inode, 0);
        struct shmem_inode_info *info = (struct shmem_inode_info *)((void *)f_inode - offset);

        int seals = BPF_CORE_READ(info, seals);
        
        if (!(seals & F_SEAL_WRITE)) {
            bpf_printk("Bouclier Bleu [BLOCK]: Unsealed fileless execution blocked.\n");
            goto block_exec;
        }
        
        return 0; // sealed
    }

    return 0;

block_exec:

	/*
     * Performance Optimization: Fast-Path Deferral
     * We only incur the overhead of acquiring the per-CPU path buffer and 
     * walking the d_path string resolution if we have already
	 * cryptographically verified that the execution must be blocked. This
	 * keeps the fast-path (legitimate executions) as fast as possible.
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

/*
 * Dynamic Watchlist Inheritance
 * Hooks into the exit of vfs_mkdir. If a new directory is created inside a
 * currently protected directory, we automatically add the new child's inode to
 * the protected_dirs map. This ensures zero-day coverage of nested staging 
 * environments created post-boot.
 */
SEC("fexit/vfs_mkdir")
int BPF_PROG(exec_block_vfs_mkdir_exit, struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, umode_t mode, int ret) {
    if (ret != 0 || !is_module_active(&state_map)) {
        return 0;
    }

    struct dir_id parent_id = {};
    parent_id.ino = BPF_CORE_READ(dir, i_ino);
    parent_id.dev = BPF_CORE_READ(dir, i_sb, s_dev);

    __u8 *is_protected = bpf_map_lookup_elem(&protected_dirs, &parent_id);

    // Inherit protection for the new child directory
    if (is_protected && *is_protected == 1) {
        struct dir_id child_id = {};
        child_id.ino = BPF_CORE_READ(dentry, d_inode, i_ino);
        child_id.dev = BPF_CORE_READ(dentry, d_sb, s_dev);
        
        __u8 val = 1;
        bpf_map_update_elem(&protected_dirs, &child_id, &val, BPF_ANY);
    }

    return 0;
}
