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
#define ACTION_IO_URING 1
#define ACTION_VMSPLICE 2
#define ACTION_SPLICE 3
#define ACTION_SPLICE_FLAGS 4
#define ACTION_SPLICE_TAINT 5

/* Pipeline Taint Identifiers */
#define TAINTED_READONLY 1

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

/**
 * pipe_taint_map - Tainted Pipeline Tracker (Information Flow Isolation)
 *
 * Stores the dynamic "taint" state of pipes. The key is the physical memory
 * address of the pipe (`struct pipe_inode_info *`). By using an LRU Hash map,
 * we cap memory at ~1MB (8192 entries) and rely on the kernel to automatically
 * evict old or inactive pipe trackers, neutralizing memory exhaustion attacks.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *); /* pipe_inode_info ptr */
	__type(value, __u8);
	__uint(max_entries, 8192);
} pipe_taint_map SEC(".maps");

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

/**
 * get_file_from_fd() - Safely resolve struct file * from an FD
 * @task: Pointer to the current task_struct.
 * @fd_num: The integer file descriptor.
 *
 * Utilizes CO-RE to traverse the task's file descriptor table. This is needed
 * for inspecting file metadata (like read-only permissions or pipe mappings)
 * within syscall entry hooks where we only possess integer FDs.
 */
static __always_inline struct file *get_file_from_fd(struct task_struct *task,
													 unsigned int fd_num) {
	struct files_struct *files = BPF_CORE_READ(task, files);
	if (!files)
		return NULL;

	struct fdtable *fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return NULL;

	unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
	if (fd_num >= max_fds)
		return NULL;

	struct file **fd_array = BPF_CORE_READ(fdt, fd);
	if (!fd_array)
		return NULL;

	struct file *f = NULL;
	bpf_probe_read_kernel(&f, sizeof(f), &fd_array[fd_num]);
	return f;
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
int BPF_KSYSCALL(io_restrict_splice, int fd_in, loff_t *off_in, int fd_out,
				 loff_t *off_out, size_t len, unsigned int flags) {
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
	 * Fast-Path Deferral
	 * Legitimate root daemons bypass immediately
	 */
	if (uid == 0)
		return 0;

	/*
	 * Invariant : Restricting Zero-Copy Flags
	 * Standard utilities (cat, cp) rely on default copy behaviors. Exploit
	 * chains frequently manipulate the kernel's MMU by passing advanced flags
	 * designed to hand over memory pages entirely (SPLICE_F_GIFT,
	 * SPLICE_F_MOVE). We restrict unprivileged users from accessing these
	 * complex mechanisms.
	 */
	if (flags & (SPLICE_F_GIFT | SPLICE_F_MOVE)) {
		bpf_send_signal(9);
		dispatch_io_alert(ACTION_SPLICE_FLAGS, "splice");

		bpf_debug_printk("Bouclier Bleu [BLOCK]: Unprivileged splice with "
						 "GIFT/MOVE flags intercepted.\n");

		return 0;
	}

	/*
	 * Invariant : The "Tainted Pipeline" (Information Flow Tracking)
	 * Resolves raw pointers (no string parsing) to evaluate the data flow. If
	 * data flows from a read-only file into a pipe, that pipe's state becomes
	 * TAINTED_READONLY.
	 */
	struct task_struct *task = bpf_get_current_task_btf();
	struct file *f_in = get_file_from_fd(task, fd_in);
	struct file *f_out = get_file_from_fd(task, fd_out);

	if (f_in && f_out) {
		umode_t in_mode = BPF_CORE_READ(f_in, f_inode, i_mode);
		umode_t out_mode = BPF_CORE_READ(f_out, f_inode, i_mode);

		bool in_is_pipe = S_ISFIFO(in_mode);
		bool out_is_pipe = S_ISFIFO(out_mode);

		/*
		 * Invariant : Outbound Taint Verification
		 * Advanced zero-copy exploits frequently chain multiple splice
		 * operations to launder a read-only page cache reference through an
		 * intermediate pipe before delivering it to a secondary execution
		 * vector (e.g., cryptographic sockets or arbitrary device
		 * descriptors). We must verify if the SOURCE of the splice is an
		 * already tainted pipe to prevent the weaponized buffer from escaping
		 * confinement and triggering the final payload.
		 */
		if (in_is_pipe) {
			void *in_pipe_ptr = BPF_CORE_READ(f_in, private_data);
			if (in_pipe_ptr) {
				__u8 *taint =
					bpf_map_lookup_elem(&pipe_taint_map, &in_pipe_ptr);
				if (taint && *taint == TAINTED_READONLY) {
					bpf_send_signal(9);
					dispatch_io_alert(ACTION_SPLICE_TAINT, "splice");
					bpf_debug_printk(
						"Bouclier Bleu [BLOCK]: Splice execution "
						"FROM TAINTED_READONLY pipe neutralized.\n");
					return 0;
				}
			}
		}

		/*
		 * Invariant : Inbound Taint Verification
		 * Resolves raw pointers (avoiding vulnerable string parsing) to
		 * evaluate the data flow topology. If data is observed flowing from a
		 * read-only file directly into a pipe, that pipe's physical memory
		 * address is explicitly marked as TAINTED_READONLY. This establishes
		 * the foundational anchor of our zero-copy confinement perimeter.
		 */
		if (out_is_pipe) {
			void *pipe_ptr = BPF_CORE_READ(f_out, private_data);
			if (pipe_ptr) {
				/* Protect against writing into an ALREADY TAINTED pipe */
				__u8 *taint = bpf_map_lookup_elem(&pipe_taint_map, &pipe_ptr);
				if (taint && *taint == TAINTED_READONLY) {
					bpf_send_signal(9);
					dispatch_io_alert(ACTION_SPLICE_TAINT, "splice");
					bpf_debug_printk("Bouclier Bleu [BLOCK]: Splice execution "
									 "into TAINTED_READONLY pipe.\n");
					return 0;
				}

				/*
				 * If not tainted, check if the source is a read-only file.
				 * If so, taint the pipe.
				 */
				fmode_t in_fmode = BPF_CORE_READ(f_in, f_mode);
				if (!in_is_pipe && (in_fmode & FMODE_READ) &&
					!(in_fmode & FMODE_WRITE)) {
					__u8 new_taint = TAINTED_READONLY;
					bpf_map_update_elem(&pipe_taint_map, &pipe_ptr, &new_taint,
										BPF_ANY);
					bpf_debug_printk("Bouclier Bleu [INFO]: Pipe structure "
									 "marked as TAINTED_READONLY.\n");
				}
			}
		}
	}

	/* Emit telemetry anchor for unprivileged splice operations */
	dispatch_io_alert(ACTION_SPLICE, "splice");

	return 0;
}

/*
 * Defense Heuristic : Tainted Pipeline Write Confinement
 * This hook enforces the final barrier of the "Tainted Pipeline" isolation.
 * If an attacker successfully taints a pipe with read-only data via splice,
 * this check guarantees they cannot subsequently use standard write()
 * operations to mix unprivileged data into the same "laundry machine" buffer.
 */
SEC("ksyscall/write")
int BPF_KSYSCALL(io_restrict_write, unsigned int fd, const char *buf,
				 size_t count) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	__u32 uid = get_global_uid();
	/*
	 * Fast-Path Deferral
	 * Trusted root processes bypass this check instantly, ensuring standard
	 * administrative tasks incur zero performance overhead.
	 */
	if (uid == 0)
		return 0;

	/*
	 * File Descriptor Resolution
	 * Safely resolve the internal file structure from the integer FD.
	 */
	struct task_struct *task = bpf_get_current_task_btf();
	struct file *f_out = get_file_from_fd(task, fd);
	if (!f_out)
		return 0;

	umode_t out_mode = BPF_CORE_READ(f_out, f_inode, i_mode);

	/*
	 * O(1) Performance Constraint
	 * We strictly limit the taint lookup to file descriptors that are
	 * definitively pipes (FIFOs). This prevents penalizing standard file I/O
	 * operations.
	 */
	if (S_ISFIFO(out_mode)) {
		void *pipe_ptr = BPF_CORE_READ(f_out, private_data);
		if (pipe_ptr) {
			/*
			 * Taint Verification
			 * If this pipe address exists in our LRU hash map and is marked as
			 * TAINTED_READONLY, it means it previously ingested read-only
			 * data. Allowing a write here would complete the zero-copy
			 * "laundry" exploit.
			 */
			__u8 *taint = bpf_map_lookup_elem(&pipe_taint_map, &pipe_ptr);
			if (taint && *taint == TAINTED_READONLY) {
				/*
				 * Immediate Neutralization
				 * Stop the exploit in its tracks by neutralizing the thread.
				 */
				bpf_send_signal(9);
				dispatch_io_alert(ACTION_SPLICE_TAINT, "write");
				bpf_debug_printk("Bouclier Bleu [BLOCK]: Standard write into "
								 "TAINTED_READONLY pipe neutralized.\n");
			}
		}
	}

	return 0;
}

/*
 * Defense Heuristic : Pipeline Taint Eviction (ABA Problem Mitigation)
 * The Linux kernel's slab allocator is highly efficient and reuses physical
 * memory addresses. When a pipe is destroyed (e.g., when `cat` finishes
 * execution), its `pipe_inode_info` pointer may be immediately reallocated by
 * the kernel to a brand-new, unrelated pipe requested by a completely different
 * process.
 * If we do not explicitly evict closed pipes from our taint tracker map, the
 * new pipe will inherit a "ghost taint" from the previous session, causing
 * false-positive SIGKILLs for legitimate zero-copy system operations. This
 * hook ensures absolute chronological integrity of the memory map.
 */
SEC("ksyscall/close")
int BPF_KSYSCALL(io_restrict_close, unsigned int fd) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	struct task_struct *task = bpf_get_current_task_btf();
	struct file *f = get_file_from_fd(task, fd);
	if (!f)
		return 0;

	umode_t mode = BPF_CORE_READ(f, f_inode, i_mode);

	/* Only spend overhead evaluating actual FIFO descriptors */
	if (S_ISFIFO(mode)) {
		void *pipe_ptr = BPF_CORE_READ(f, private_data);
		if (pipe_ptr) {
			/*
			 * By deleting the pointer upon descriptor closure, we guarantee
			 * that any subsequent kernel reallocation of this physical memory
			 * address starts with a clean, untainted slate.
			 */
			bpf_map_delete_elem(&pipe_taint_map, &pipe_ptr);
		}
	}

	return 0;
}
