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

/*
 * Standard ptrace access modes.
 * Redefined here to avoid dependencies on host-specific user-space headers
 * during CO-RE compilation.
 */
#ifndef PTRACE_MODE_READ
#define PTRACE_MODE_READ 0x01
#endif
#ifndef PTRACE_MODE_ATTACH
#define PTRACE_MODE_ATTACH 0x02
#endif

/*
 * VFS & File Status Flags
 * Redefined to avoid conflicting macros from <linux/fcntl.h> and
 * <linux/magic.h> when compiling against the generated vmlinux.h skeleton.
 */
#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC 0x9fa0
#endif

#ifndef O_ACCMODE
#define O_ACCMODE 00000003
#endif
#ifndef O_RDONLY
#define O_RDONLY 00000000
#endif
#ifndef O_WRONLY
#define O_WRONLY 00000001
#endif
#ifndef O_RDWR
#define O_RDWR 00000002
#endif

/* Telemetry Action Identifiers */
#define ACTION_CRED_DUMP 1
#define ACTION_INJECTION 2
#define ACTION_PROC_MEM 3

/**
 * struct ptrace_alert - Telemetry Payload Contract
 * @pid: The Process ID of the tracer (the attacker).
 * @target_pid: The Process ID of the tracee (the victim).
 * @action_type: Enum mapping to the specific ptrace heuristic triggered.
 * @target_comm: The 16-byte short name of the targeted process.
 *
 * Memory layout must strictly mirror the `PtraceAlert` struct in the Rust
 * userland to ensure safe zero-copy deserialization over the ring buffer.
 */
struct ptrace_alert {
	__u32 pid;
	__u32 target_pid;
	__u32 action_type;
	char target_comm[16];
};

/**
 * protected_processes - Hardware-Backed Critical Process Watchlist
 *
 * Stores the physical Inode and Device ID of critical system binaries
 * (e.g., sshd, pam, gnome-keyring, lsass). Bypasses string path evasion
 * entirely. Any process executing a binary in this map cannot be ptraced,
 * read, or tampered with, regardless of the tracer's privileges.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dir_id);
	__type(value, __u8);
	__uint(max_entries, 256);
} protected_processes SEC(".maps");

BOUCLIER_MODULE_ALERTS;
BOUCLIER_MODULE_STATE_MAP;

/**
 * dispatch_ptrace_alert() - Telemetry Payload Compilation
 * @tracer_tgid: The thread group ID of the attacker.
 * @child: The task_struct of the targeted process.
 * @action_type: The specific heuristic triggered.
 *
 * Centralizes the safe reservation and population of the ring buffer, avoiding
 * inline repetition and reducing verifier complexity.
 */
static __always_inline void dispatch_ptrace_alert(__u32 tracer_tgid,
												  struct task_struct *child,
												  __u32 action_type) {
	struct ptrace_alert *event =
		bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
	if (!event) {
		return;
	}

	BPF_SAFE_MEMSET(event, sizeof(*event));

	event->pid = tracer_tgid;
	event->target_pid = BPF_CORE_READ(child, tgid);
	event->action_type = action_type;

	/*
	 * Memory-Boundary Safe Extraction
	 * The TASK_COMM_LEN in the kernel is universally 16 bytes. We use
	 * bpf_probe_read_kernel_str to safely extract the victim's process name
	 * for the EDR telemetry without risking page faults.
	 */
	if (bpf_probe_read_kernel_str(event->target_comm,
								  sizeof(event->target_comm),
								  BPF_CORE_READ(child, comm)) < 0) {
		char unknown_str[] = "<unknown>";
		__builtin_memcpy(event->target_comm, unknown_str, sizeof(unknown_str));
	}

	bpf_ringbuf_submit(event, 0);
}

/*
 * Defense Heuristic : Cross-Process Memory Tampering & Credential Dumping
 * Intercepts the overarching LSM hook that guards `ptrace` capabilities, as
 * well as direct `/proc/<pid>/mem` reads/writes utilized by advanced dumpers
 * (e.g., Mimikatz equivalents on Linux).
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_block_access_check, struct task_struct *child,
			 unsigned int mode) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	struct task_struct *tracer = bpf_get_current_task_btf();
	__u32 tracer_uid = get_global_uid();
	__u32 tracer_tgid = BPF_CORE_READ(tracer, tgid);
	__u32 child_tgid = BPF_CORE_READ(child, tgid);

	/*
	 * Thread-Group (Self) Debugging Fast-Path
	 * Processes inherently have permission to inspect and manipulate their own
	 * internal threads. Permitting this early avoids incurring map lookups and
	 * heavy processing during high-frequency multithreaded operations.
	 */
	if (tracer_tgid == child_tgid) {
		return 0;
	}

	bool is_violation = false;
	__u32 triggered_action = 0;

	/*
	 * Heuristic 1: Credential Dumping Protection (Hardware-Backed)
	 * Attackers often attempt to read the memory (`PTRACE_MODE_READ`) or
	 * attach (`PTRACE_MODE_ATTACH`) to password managers or SSH agents. We
	 * extract the physical hardware ID of the binary currently executing
	 * inside the victim process. If it matches our protected map, we block ALL
	 * access completely. This applies even if the attacker is root, serving as
	 * a robust anti-tamper layer against all ptrace modes.
	 */
	struct file *child_exe = BPF_CORE_READ(child, mm, exe_file);
	if (child_exe) {
		struct inode *child_inode = BPF_CORE_READ(child_exe, f_inode);
		if (child_inode) {
			struct dir_id target_id = {};
			extract_dir_id_from_inode(child_inode, &target_id);

			__u8 *is_protected =
				bpf_map_lookup_elem(&protected_processes, &target_id);
			if (is_protected && *is_protected == 1) {
				is_violation = true;
				triggered_action = ACTION_CRED_DUMP;
			}
		}
	}

	/*
	 * Heuristic 2: Process Injection Mitigator
	 * If the target is not a explicitly protected credential binary, we still
	 * strictly govern who can attach (`PTRACE_MODE_ATTACH`) to foreign
	 * processes. We use `get_global_uid()` to evaluate the true UID, bypassing
	 * container/namespace mappings where a local process might falsely appear
	 * as root (UID 0). Unprivileged cross-process attachment is universally
	 * blocked.
	 */
	if (!is_violation && (mode & PTRACE_MODE_ATTACH) && (tracer_uid != 0)) {
		is_violation = true;
		triggered_action = ACTION_INJECTION;
	}

	/* Enforcement & Telemetry */
	if (is_violation) {
		dispatch_ptrace_alert(tracer_tgid, child, triggered_action);

		return -EACCES;
	}

	return 0;
}

/*
 * Defense Heuristic : Hollow Process Injection
 * Process Hollowing relies heavily on the `PTRACE_TRACEME` call. The attacker
 * forks a benign executable (e.g., `svchost` or `bash`), the child process
 * calls `ptrace(PTRACE_TRACEME)` and executes the binary, pausing execution so
 * the malicious parent can hollow out the legitimate memory space and inject
 * a payload. This hook isolates and blocks unprivileged processes from
 * authorizing trace actions from untrusted parents.
 */
SEC("lsm/ptrace_traceme")
int BPF_PROG(ptrace_block_traceme, struct task_struct *parent) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	/*
	 * In a PTRACE_TRACEME scenario, the currently executing task is the child,
	 * inherently asking the kernel to allow the 'parent' to trace it.
	 *
	 * Extract the global UID of the parent safely via CO-RE.
	 * Inside the kernel, `cred->uid` is stored as a `kuid_t` (Kernel UID),
	 * which represents the true, global namespace-independent UID.
	 * Reading `uid.val` natively prevents attackers from bypassing the check
	 * by creating a localized user namespace where they map to UID 0.
	 */
	struct task_struct *child = bpf_get_current_task_btf();
	__u32 parent_uid = BPF_CORE_READ(parent, cred, uid.val);

	/*
	 * If the parent process orchestrating the traceme is not universally
	 * privileged (Global UID 0), we block the tracing relationship. This
	 * mirrors Yama's strict scope natively at the LSM level, immune to
	 * user-space `sysctl` evasion.
	 */
	if (parent_uid != 0) {
		dispatch_ptrace_alert(BPF_CORE_READ(parent, tgid), child,
							  ACTION_INJECTION);
		return -EACCES;
	}

	return 0;
}

/*
 * Defense Heuristic : VFS-based Memory Tampering
 * Advanced exploits (e.g., Dirty Cow) and stealth credential dumpers bypass
 * ptrace hooks entirely by directly opening /proc/<pid>/mem or /proc/self/mem
 * via the Virtual File System (VFS). This allows them to map and overwrite
 * memory spaces utilizing standard file I/O operations (O_RDWR / O_WRONLY).
 */
SEC("lsm/file_open")
int BPF_PROG(ptrace_block_file_open, struct file *file) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	/*
	 * Fast-Path: Read-only access is ignored.
	 * We are specifically hunting for memory corruption and injection.
	 */
	unsigned int f_flags = BPF_CORE_READ(file, f_flags);
	if ((f_flags & O_ACCMODE) == O_RDONLY) {
		return 0;
	}

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode) {
		return 0;
	}

	/* Validate we are interacting with the proc filesystem */
	__u32 magic = BPF_CORE_READ(inode, i_sb, s_magic);
	if (magic != PROC_SUPER_MAGIC) {
		return 0;
	}

	/*
	 * Safely isolate the exact filename being opened.
	 * BPF_CORE_READ returns a pointer, so we must use bpf_probe_read_kernel
	 * to copy the string into our BPF stack securely.
	 */
	const unsigned char *name_ptr =
		BPF_CORE_READ(file, f_path.dentry, d_name.name);
	if (!name_ptr) {
		return 0;
	}

	char name[4];
	if (bpf_probe_read_kernel(name, sizeof(name), name_ptr) < 0) {
		return 0;
	}

	/*
	 * Ensure strict match for the file "mem".
	 * Validating the null terminator at index 3 prevents false positives
	 * on unrelated files that just happen to start with "mem" (e.g., "memory").
	 */
	if (name[0] == 'm' && name[1] == 'e' && name[2] == 'm' && name[3] == '\0') {
		__u32 uid = get_global_uid();

		/*
		 * Unprivileged users have no legitimate reason to establish a write
		 * handle directly into live process memory via the VFS. This behavior
		 * is almost exclusively the domain of legitimate root debuggers (like
		 * gdb) or user-space privilege escalation exploits.
		 */
		if (uid != 0) {
			struct task_struct *current_task = bpf_get_current_task_btf();
			__u32 tgid = BPF_CORE_READ(current_task, tgid);

			/*
			 * By passing the current_task as the victim, we accurately
			 * attribute self-injection (e.g., Dirty Cow opening
			 * /proc/self/mem) in SIEM telemetry stream.
			 */
			dispatch_ptrace_alert(tgid, current_task, ACTION_PROC_MEM);
			return -EACCES;
		}
	}

	return 0;
}
