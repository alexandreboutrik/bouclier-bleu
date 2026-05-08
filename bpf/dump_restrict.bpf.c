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

char LICENSE[] SEC("license") = "GPL";

/*
 * Kernel macros are stripped from the CO-RE vmlinux.h generation.
 * We manually redefine the necessary flags here.
 */
#ifndef PF_DUMPCORE
#define PF_DUMPCORE 0x00000200
#endif

#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif

/* Telemetry Action Identifiers */
#define ACTION_COREDUMP_FILE 1
#define ACTION_PRCTL_TAMPER 2

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

BOUCLIER_MODULE_ALERTS;
BOUCLIER_MODULE_STATE_MAP;

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

	/*
	 * Memory-Boundary Safe Extraction
	 * Use the dedicated helper for process names instead of a raw core read.
	 */
	if (bpf_get_current_comm(event->comm, sizeof(event->comm)) < 0) {
		char unknown_str[] = "<unknown>";
		__builtin_memcpy(event->comm, unknown_str, sizeof(unknown_str));
	}

	event->comm[sizeof(event->comm) - 1] = '\0';

	bpf_ringbuf_submit(event, 0);
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
