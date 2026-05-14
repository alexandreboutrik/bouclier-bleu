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

#include "headers/bpf_fallbacks.h"
#include "headers/module_core.h"
#include "headers/vfs_helpers.h"

char LICENSE[] SEC("license") = "GPL";

/* Telemetry Action Identifiers */
#define ACTION_COREDUMP_FILE 1
#define ACTION_PRCTL_TAMPER 2
#define ACTION_PIPED_HANDLER 3

/**
 * struct dump_alert - Telemetry Payload Contract
 * @pid: The Process ID of the crashing/tampering process.
 * @uid: The Global UID of the process.
 * @action_type: Enum mapping to the specific heuristic triggered.
 * @comm: The 16-byte short name of the targeted process.
 *
 * Memory layout must strictly mirror the `DumpAlert` struct in the Rust
 * userland to ensure safe zero-copy deserialization over the ring buffer.
 */
struct dump_alert {
	__u32 pid;
	__u32 uid;
	__u32 action_type;
	char comm[16];
};

/**
 * pending_crash_blocks - State Tracking Queue
 *
 * A native eBPF Queue utilized as an atomic, temporal lockbox between the
 * synchronous observer hook and the asynchronous enforcement hook.
 * By utilizing a BPF_MAP_TYPE_QUEUE, the observer can safely push multiple
 * pristine telemetry tokens (capturing the unprivileged attacker's original
 * UID and PID) onto a stack during concurrent crash events. This prevents
 * overwrite races and guarantees absolute 1:1 event matching when the root
 * kworker thread subsequently spawns the handler and pops the token.
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, struct dump_alert);
	__uint(max_entries, 512);
} pending_crash_blocks SEC(".maps");

BOUCLIER_MODULE_ALERTS;
BOUCLIER_MODULE_STATE_MAP;
BOUCLIER_PROTECTED_FILES_MAP;

/**
 * dispatch_dump_alert() - Telemetry Payload Compilation
 * @task: The task_struct of the crashing or tampering process.
 * @action_type: The specific heuristic triggered.
 *
 * Centralizes the safe reservation and population of the ring buffer, avoiding
 * inline repetition and reducing verifier complexity.
 */
static __always_inline void dispatch_dump_alert(struct task_struct *task,
												__u32 action_type) {
	struct dump_alert *event = bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
	if (!event) {
		return;
	}

	BPF_SAFE_MEMSET(event, sizeof(*event));

	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->uid = get_global_uid();
	event->action_type = action_type;

	extract_safe_comm(event->comm, sizeof(event->comm));

	bpf_ringbuf_submit(event, 0);

	bpf_debug_printk("Bouclier Bleu [BLOCK]: Core dump evasion mitigated "
					 "(Action Type: %d).\n",
					 action_type);
}

/*
 * Defense Heuristic : Core Dump File Write Interception
 * When a process crashes (e.g., SIGSEGV) and the kernel attempts to generate
 * a core dump, it continues executing in the context of the crashing thread
 * but elevates its flags to include `PF_DUMPCORE`. By intercepting `file_open`,
 * we can cleanly block the kernel from creating the core file on disk or
 * piping it to an external handler.
 */
SEC("lsm/file_open")
int BPF_PROG(dump_restrict_file_open, struct file *file) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	struct task_struct *task = bpf_get_current_task_btf();

	/*
	 * Fast-Path Deferral
	 * The kernel sets task->signal->core_state extremely early in
	 * do_coredump() before it attempts to open the core file. If this pointer
	 * is NULL, the process is not crashing, so we exit instantly to preserve
	 * I/O performance.
	 */
	void *core_state = BPF_CORE_READ(task, signal, core_state);
	if (!core_state) {
		return 0;
	}

	__u32 uid = get_global_uid();

	/*
	 * Enforcement: Unprivileged Worker Thread Constraint
	 * Exploit writers often rely on crashing worker threads (which are
	 * inherently unprivileged to reduce attack surface) to leak memory
	 * structures and bypass ASLR. We categorically deny core dumps for all
	 * non-root processes.
	 */
	if (uid != 0) {
		dispatch_dump_alert(task, ACTION_COREDUMP_FILE);

		/*
		 * Returning -EACCES halts the core dump pipeline entirely,
		 * cleanly bypassing the ASLR leak without causing kernel panic.
		 */
		return -EACCES;
	}

	return 0;
}

/*
 * Defense Heuristic : PR_SET_DUMPABLE Defense-in-Depth
 * Attackers who gain initial code execution might attempt to bypass system
 * defaults by re-enabling core dumping via `prctl()` immediately prior to
 * intentionally crashing. This hook intercepts the syscall and denies it.
 */
SEC("lsm/task_prctl")
int BPF_PROG(dump_restrict_task_prctl, int option, unsigned long arg2,
			 unsigned long arg3, unsigned long arg4, unsigned long arg5) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	/*
	 * Fast-Path Deferral
	 * We only care if the process is actively trying to alter its dumpable
	 * state to true (1).
	 */
	if (option == PR_SET_DUMPABLE && arg2 == 1) {
		__u32 uid = get_global_uid();

		/* Same privilege constraints as the physical file generation */
		if (uid != 0) {
			struct task_struct *task = bpf_get_current_task_btf();

			dispatch_dump_alert(task, ACTION_PRCTL_TAMPER);

			return -EPERM;
		}
	}

	return 0;
}

/*
 * Defense Heuristic : Piped Core Dump Interception (Observer Phase)
 * REPLACES: kprobe/do_coredump (Unstable/Inlined)
 * REPLACES: lsm/file_alloc_security (Disabled on target kernel)
 * When `core_pattern` utilizes a pipe (|), the kernel routes the dump to a
 * user-mode helper. It prepares this by invoking `call_usermodehelper_setup`
 * directly from within `do_coredump()`. This exported API is a highly stable
 * kprobe target. Because we are still executing in the context of the crashing
 * thread, we can reliably extract the unprivileged attacker's exact UID and
 * PID before the asynchronous root `kworker` takes over.
 */
SEC("kprobe/call_usermodehelper_setup")
int BPF_KPROBE(dump_restrict_observer) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	struct task_struct *task = bpf_get_current_task_btf();

	/*
	 * Fast-Path Deferral
	 * call_usermodehelper_setup is used system-wide for many tasks (e.g.,
	 * udev, cgroups). If core_state is NULL, this execution has nothing
	 * to do with a core dump, so we exit instantly.
	 */
	void *core_state = BPF_CORE_READ(task, signal, core_state);
	if (!core_state) {
		return 0;
	}

	__u32 uid = get_global_uid();

	/* Fast-Path: We do not intercept administrative root crashes */
	if (uid == 0) {
		return 0;
	}

	/* Capture the pristine context of the unprivileged attacker */
	struct dump_alert payload = {};
	payload.pid = bpf_get_current_pid_tgid() >> 32;
	payload.uid = uid;
	payload.action_type = ACTION_PIPED_HANDLER;

	extract_safe_comm(payload.comm, sizeof(payload.comm));

	/*
	 * Temporal Lockbox: Push
	 * We atomically push the attacker's true UID/PID onto the queue for the
	 * Enforcement hook (bprm_check_security) to consume when the kworser
	 * spawns the handler.
	 */
	bpf_map_push_elem(&pending_crash_blocks, &payload, BPF_ANY);

	return 0;
}

/*
 * Defense Heuristic : Piped Core Dump Interception (Enforcement Phase)
 * Triggers asynchronously when the root `kworker` attempts to spawn the
 * handler. It locks the hardware watchlist and cross-references the
 * state-tracking map to intelligently differentiate between benign root
 * crashes and malicious unprivileged pipeline abuse.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(dump_restrict_bprm_check, struct linux_binprm *bprm) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	struct task_struct *task = bpf_get_current_task_btf();

	/*
	 * Ancestry Verification (The Usermodehelper Check)
	 * Usermode helpers are spawned by kernel workqueues. We rely on a
	 * fundamental architectural property: Kernel threads do not possess an
	 * mm_struct (memory descriptor). If the parent's mm is not NULL, this is
	 * a standard user application, and we exit early.
	 */
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	void *parent_mm = BPF_CORE_READ(parent, mm);

	if (parent_mm != NULL) {
		return 0;
	}

	/*
	 * Hardware-Backed Identity Verification
	 * Instead of vulnerable string parsing (d_name.name) which causes stack
	 * uninitialization bugs and allows hardlink spoofing, we extract the
	 * physical Inode and Device ID of the executable being launched.
	 */
	struct file *file = bprm->file;
	if (!file)
		return 0;

	struct inode *f_inode = BPF_CORE_READ(file, f_inode);
	if (!f_inode)
		return 0;

	struct dir_id bin_id = {};
	extract_dir_id_from_inode(f_inode, &bin_id);

	/*
	 * State Tracking Enforcement
	 * If the binary being executed matches the hardware footprint of the
	 * handler registered in `core_pattern`, we consult the lockbox.
	 */
	__u8 *is_handler = bpf_map_lookup_elem(&protected_files, &bin_id);
	if (is_handler && *is_handler == 1) {

		struct dump_alert payload = {};

		/*
		 * Temporal Lockbox: Atomic Pop & Consume
		 * `bpf_map_pop_elem` is inherently atomic. It extracts the oldest
		 * token and removes it from the queue simultaneously. If it returns 0
		 * (success), we are guaranteed that this kworker execution corresponds
		 * to a malicious unprivileged crash, and the token is safely destroyed
		 * to prevent double-counting.
		 */
		if (bpf_map_pop_elem(&pending_crash_blocks, &payload) == 0) {

			if (payload.pid != 0) {

				// Dispatch the pristine telemetry captured by the observer
				struct dump_alert *event =
					bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
				if (event) {
					__builtin_memcpy(event, &payload, sizeof(*event));
					bpf_ringbuf_submit(event, 0);
				}

				bpf_debug_printk(
					"Bouclier Bleu [BLOCK]: Unprivileged piped core "
					"handler execution blocked.\n");
				return -EPERM;
			}
		}

		/*
		 * If the pop fails (map is empty), the crash was initiated by an
		 * authorized root process which the Observer hook intentionally
		 * ignored.
		 */
		return 0;
	}

	return 0;
}
