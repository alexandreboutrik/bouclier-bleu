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
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <asm-generic/errno.h>

#include "headers/module_core.h"
#include "headers/vfs_helpers.h"

char LICENSE[] SEC("license") = "GPL";

/* Standard Memory Protection Flags */
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define WX_MASK (PROT_WRITE | PROT_EXEC)

#ifndef VM_WRITE
#define VM_WRITE 0x00000002
#endif
#ifndef VM_EXEC
#define VM_EXEC 0x00000004
#endif

/**
 * struct strict_wx_alert - Telemetry Payload Contract
 *
 * Memory layout must strictly mirror the `StrictWxAlert` struct in the Rust
 * userland to ensure safe zero-copy deserialization.
 */
struct strict_wx_alert {
	__u32 pid;
	char syscall[16];
};

/**
 * strict_wx_binaries - Hardware-Backed Opt-In Watchlist
 *
 * Stores the physical Inode and Device ID of compiled binaries that have
 * been explicitly flagged with the `user.bouclier.strict_wx` extended
 * attribute by the system administrator.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dir_id);
	__type(value, __u8);
	__uint(max_entries, 2048);
} strict_wx_binaries SEC(".maps");

BOUCLIER_MODULE_ALERTS;
BOUCLIER_MODULE_STATE_MAP;

/**
 * enforce_strict_wx() - Universal Write XOR Execute Mitigator
 * @prot: The requested memory protection flags.
 * @vma_flags: The current active state of the memory segment.
 * @mapped_file: The specific file being mapped into memory (if applicable).
 * @syscall_name: String literal identifying the originating syscall.
 */
static __always_inline int enforce_strict_wx(unsigned long prot,
											 unsigned long vma_flags,
											 struct file *mapped_file,
											 const char *syscall_name) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	/*
	 * Sequential W^X Bypass Mitigation
	 * We also block state transitions where a currently writable page is made
	 * executable, or a currently executable page is made writable.
	 */
	bool is_wx_violation = ((prot & WX_MASK) == WX_MASK) ||
						   ((prot & PROT_EXEC) && (vma_flags & VM_WRITE)) ||
						   ((prot & PROT_WRITE) && (vma_flags & VM_EXEC));

	if (!is_wx_violation) {
		return 0;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return 0;

	bool is_enforced = false;

	/*
	 * The Executing Process
	 * Check if the parent process itself opted into W^X
	 */
	struct file *exe_file = BPF_CORE_READ(mm, exe_file);
	if (exe_file) {
		struct inode *inode = BPF_CORE_READ(exe_file, f_inode);
		if (inode) {
			struct dir_id bin_id = {};
			extract_dir_id_from_inode(inode, &bin_id);
			__u8 *val = bpf_map_lookup_elem(&strict_wx_binaries, &bin_id);
			if (val && *val == 1)
				is_enforced = true;
		}
	}

	/* Mapped File (Shared Libraries)
	 * Check if the file being actively mapped into memory opted in. This
	 * ensures that a protected .so library loaded by an unprotected binary
	 * still receives W^X safeguards.
	 */
	if (!is_enforced && mapped_file) {
		struct inode *mapped_inode = BPF_CORE_READ(mapped_file, f_inode);
		if (mapped_inode) {
			struct dir_id mapped_id = {};
			extract_dir_id_from_inode(mapped_inode, &mapped_id);
			__u8 *val = bpf_map_lookup_elem(&strict_wx_binaries, &mapped_id);
			if (val && *val == 1)
				is_enforced = true;
		}
	}

	if (is_enforced) {
		struct strict_wx_alert *event =
			bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);

		if (event) {
			BPF_SAFE_MEMSET(event, sizeof(*event));
			event->pid = bpf_get_current_pid_tgid() >> 32;

			/*
			 * BPF String Read Overhead Removed
			 * syscall_name is a literal from .rodata. Using __builtin_strncpy
			 * relies on Clang's compiler built-ins, eliminating the expensive
			 * bpf_probe_read_kernel_str helper call.
			 */
			__builtin_strncpy(event->syscall, syscall_name,
							  sizeof(event->syscall));

			bpf_ringbuf_submit(event, 0);
		}

		bpf_printk("Bouclier Bleu [BLOCK]: W^X violation mitigated via %s\n",
				   syscall_name);
		return -EACCES;
	}

	return 0;
}

/*
 * Hook existing memory protection modifications
 */
SEC("lsm/file_mprotect")
int BPF_PROG(strict_wx_file_mprotect, struct vm_area_struct *vma,
			 unsigned long reqprot, unsigned long prot) {
	// Extract the previous memory flags and underlying file to catch
	// sequential bypasses
	struct file *mapped_file = BPF_CORE_READ(vma, vm_file);
	unsigned long vm_flags = BPF_CORE_READ(vma, vm_flags);

	return enforce_strict_wx(prot, vm_flags, mapped_file, "mprotect");
}

/*
 * Hook new memory segment allocations
 */
SEC("lsm/mmap_file")
int BPF_PROG(strict_wx_mmap_file, struct file *file, unsigned long reqprot,
			 unsigned long prot, unsigned long flags) {
	return enforce_strict_wx(prot, 0, file, "mmap");
}
