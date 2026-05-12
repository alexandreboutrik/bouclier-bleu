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

/* Telemetry Action Identifiers */
#define ACTION_IO_URING 1
#define ACTION_VMSPLICE 2
#define ACTION_SPLICE 3

/**
 * struct io_restrict_alert - Telemetry Payload Contract
 * @pid: The Process ID originating the restricted I/O attempt.
 * @action_type: Enum mapping to the specific I/O heuristic triggered.
 * @syscall: String literal identifying the originating syscall.
 *
 * Memory layout must strictly mirror the `IoRestrictAlert` struct in the Rust
 * userland to ensure safe zero-copy deserialization.
 */
struct io_restrict_alert {
	__u32 pid;
	__u32 action_type;
	char syscall[16];
};

/**
 * io_restrict_binaries - Hardware-Backed Opt-In Watchlist
 *
 * Stores the physical Inode and Device ID of compiled binaries explicitly
 * authorized by the administrator to initialize high-speed `io_uring` rings
 * (e.g., Nginx, PostgreSQL). Bypasses string path evasion entirely.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dir_id);
	__type(value, __u8);
	__uint(max_entries, 2048);
} io_restrict_binaries SEC(".maps");

BOUCLIER_MODULE_ALERTS;
BOUCLIER_MODULE_STATE_MAP;

/**
 * dispatch_io_alert() - Telemetry Payload Compilation
 * @action_type: The specific heuristic triggered.
 * @syscall_name: String literal identifying the blocked syscall.
 *
 * Centralizes the safe reservation and population of the ring buffer.
 */
static __always_inline void dispatch_io_alert(__u32 action_type,
											  const char *syscall_name) {
	struct io_restrict_alert *event =
		bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
	if (!event) {
		return;
	}

	BPF_SAFE_MEMSET(event, sizeof(*event));

	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->action_type = action_type;

	/*
	 * BPF String Read Overhead Removed
	 * syscall_name is a literal from .rodata. Using __builtin_strncpy
	 * relies on Clang's compiler built-ins, eliminating the expensive
	 * bpf_probe_read_kernel_str helper call.
	 */
	__builtin_strncpy(event->syscall, syscall_name, sizeof(event->syscall));
	event->syscall[sizeof(event->syscall) - 1] = '\0';

	bpf_ringbuf_submit(event, 0);
}

/*
 * Defense Heuristic : Asynchronous I/O Confinement
 * Advanced ransomware heavily leverages `io_uring` to maximize disk queue
 * depth and bypass synchronous I/O bottlenecks during the rapid encryption
 * phase. This heuristic enforces an aggressive default-deny posture: only
 * explicitly whitelisted, high-performance daemons are permitted to
 * instantiate an io_uring context. Dropped payloads are forced to use slow,
 * easily intercepted synchronous I/O.
 */
SEC("ksyscall/io_uring_setup")
int BPF_KSYSCALL(io_restrict_uring_setup) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	struct task_struct *task = bpf_get_current_task_btf();
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return 0;

	/*
	 * Hardware-backed validation
	 * Extract the hardware footprint of the executing process to verify
	 * against the administrator's authorized whitelist map.
	 */
	struct file *exe_file = BPF_CORE_READ(mm, exe_file);
	if (exe_file) {
		struct inode *inode = BPF_CORE_READ(exe_file, f_inode);
		if (inode) {
			struct dir_id bin_id = {};
			extract_dir_id_from_inode(inode, &bin_id);

			__u8 *is_whitelisted =
				bpf_map_lookup_elem(&io_restrict_binaries, &bin_id);
			if (is_whitelisted && *is_whitelisted == 1) {
				return 0; // Authorized High-Performance Daemon
			}
		}
	}

	/*
	 * Immediate Neutralization
	 * Because syscall entry tracepoints (ksyscalls) do not inherently support
	 * returning blocking error codes (like -EPERM) to userspace directly,
	 * we ensure robust and portable confinement by neutralizing the violating
	 * thread immediately via SIGKILL.
	 */
	bpf_send_signal(9);
	dispatch_io_alert(ACTION_IO_URING, "io_uring_setup");

	bpf_debug_printk(
		"Bouclier Bleu [BLOCK]: Unauthorized io_uring_setup intercepted.\n");

	return 0;
}

/*
 * Defense Heuristic : Dirty Pipe & Dirty Frag Mitigation
 * Advanced memory corruption vulnerabilities often exploit the zero-copy I/O
 * mechanisms of the kernel by manipulating pipeline buffer flags. Attackers
 * use `vmsplice` and `splice` to force the kernel to merge malicious
 * user-space pages into pipe buffers associated with read-only files.
 * `vmsplice` maps user pages directly into a pipe. It is powerful but
 * virtually never used by standard unprivileged user applications. We apply a
 * strict confinement: unprivileged use of `vmsplice` is blocked entirely.
 */
SEC("ksyscall/vmsplice")
int BPF_KSYSCALL(io_restrict_vmsplice) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	__u32 uid = get_global_uid();

	/* Unprivileged Confinement Fast-Path */
	if (uid != 0) {
		bpf_send_signal(9);
		dispatch_io_alert(ACTION_VMSPLICE, "vmsplice");

		bpf_debug_printk(
			"Bouclier Bleu [BLOCK]: Unprivileged vmsplice memory tampering "
			"blocked.\n");
	}

	return 0;
}

/*
 * Defense Heuristic : Zero-Copy Pipeline Auditor
 * While `vmsplice` can be strictly blocked for unprivileged users, standard
 * `splice` is heavily utilized by legitimate command-line utilities.
 * Monitoring `splice` provides a critical telemetry anchor for detecting the
 * final payload delivery mechanism of zero-copy exploits without breaking
 * system functionality.
 */
SEC("ksyscall/splice")
int BPF_KSYSCALL(io_restrict_splice) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	/*
	 * Pipeline Telemetry & Correlation
	 * Actively blocking `splice` operations risks disrupting standard system
	 * utilities. Instead, we enforce pipeline integrity via strict `vmsplice`
	 * isolation and emit high-fidelity telemetry here. This provides the SIEM
	 * layer the necessary context to cross-reference pipeline interactions and
	 * identify anomalies without compromising OS stability.
	 */

	__u32 uid = get_global_uid();

	/*
	 * We only log unprivileged splice events to avoid flooding the ring buffer
	 * with standard root daemon system I/O.
	 */
	if (uid != 0) {
		dispatch_io_alert(ACTION_SPLICE, "splice");
	}

	return 0;
}
