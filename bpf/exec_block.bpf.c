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
#include "headers/vfs_helpers.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x008
#endif

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

BOUCLIER_PATH_BUFFER_MAP;
BOUCLIER_PROTECTED_DIRS_MAP;
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
	extract_dir_id_from_dentry(parent, &p_id);

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
	 * Attackers bypass on-disk heuristics using memory-backed payloads via
	 * `memfd_create` or nameless temporary files via `open(..., O_TMPFILE |
	 * O_RDWR)`. Relying on the "memfd:" prefix in the dentry cache is insecure
	 * as O_TMPFILE does not set it. Instead, we validate the underlying VFS
	 * link count (`i_nlink`). Both anonymous memory files and O_TMPFILE
	 * creations share a fundamental characteristic: they have zero hard
	 * links.
     */
	struct inode *f_inode = BPF_CORE_READ(file, f_inode);
    __u32 i_nlink = BPF_CORE_READ(f_inode, i_nlink);

    if (i_nlink == 0) {
		/*
         * Seal Inspection Heuristic (Behavioral Validation)
         * Legitimate processes lock the memory segment using F_SEAL_WRITE
		 * (0x0008) prior to execution to guarantee immutability. Malware
		 * droppers leave it unsealed (writable) to stream staging payloads.
		 * CO-RE Container-Of Lookup is used to avoid missing libbpf macro
		 * errors across different distributions.
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
		BPF_SAFE_MEMSET(event, sizeof(*event));

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
	struct dir_id child_id = {};
    
    extract_dir_id_from_inode(dir, &parent_id);
    extract_dir_id_from_dentry(dentry, &child_id);

    inherit_protection(&protected_dirs, &parent_id, &child_id, "exec_block");

    return 0;
}

/*
 * Dynamic Watchlist Inheritance (Rename)
 * An attacker stages a malicious binary inside an obscure, unprotected
 * directory (e.g., /var/lib/...) and subsequently moves (renames) the entire
 * staging directory into a protected path like /tmp. Because a same-filesystem
 * move does not alter the inode and does not trigger `vfs_mkdir`, the system
 * remains blind to the new location. This hook monitors directory moves. If an
 * unprotected directory is moved into a currently protected directory, it
 * immediately inherits the parent's protection status to close the evasion
 * loophole.
 */
SEC("fexit/vfs_rename")
int BPF_PROG(exec_block_vfs_rename_exit, struct renamedata *rd, int ret) 
{
    if (ret != 0 || !is_module_active(&state_map)) {
        return 0;
    }

    struct dir_id target_parent_id = {};
	struct dir_id moved_id = {};
    
    extract_dir_id_from_inode(BPF_CORE_READ(rd, new_dir), &target_parent_id);
    extract_dir_id_from_dentry(BPF_CORE_READ(rd, old_dentry), &moved_id);

    inherit_protection(&protected_dirs, &target_parent_id, &moved_id, "exec_block");

    return 0;
}
