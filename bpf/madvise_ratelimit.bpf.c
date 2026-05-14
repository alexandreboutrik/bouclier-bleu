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

char LICENSE[] SEC("license") = "GPL";

/*
 * Heuristic Constants
 * A legitimate application rarely invokes MADV_DONTNEED tens of thousands
 * of times per second. Dirty Cow (and similar Use-After-Free/Page-Fault
 * race conditions) relies on spamming this syscall millions of times in a
 * tight loop to consistently drop the memory page and confuse the kernel.
 */
#define RATELIMIT_WINDOW_NS 1000000000ULL // 1 second rolling window
#define RATELIMIT_THRESHOLD 10000		  // Max permitted calls per window

/* Telemetry Action Identifiers */
#define ACTION_MADVISE_SPAM 1

/**
 * struct madvise_alert - Telemetry Payload Contract
 * @pid: The Process ID (TGID) originating the exploit attempt.
 * @tid: The specific Thread ID spinning the malicious loop.
 * @count: The number of invocations recorded before neutralization.
 * @action_type: Enum mapping to the specific heuristic triggered.
 * @comm: The 16-byte short name of the targeted process.
 *
 * Memory layout must strictly mirror the `MadviseAlert` struct in the Rust
 * userland to ensure safe zero-copy deserialization over the ring buffer.
 */
struct madvise_alert {
	__u32 pid;
	__u32 tid;
	__u32 count;
	__u32 action_type;
	char comm[16];
};

/**
 * struct madvise_tracker - State Tracking Queue
 * @window_start: The nanosecond timestamp of the first invocation in the
 * window.
 * @count: The number of invocations within the current rolling window.
 */
struct madvise_tracker {
	__u64 window_start;
	__u32 count;
};

/**
 * madvise_tracking_map - Temporal Lockbox
 *
 * Uses an LRU (Least Recently Used) Hash Map to track madvise frequency per
 * user (Global UID). Shifting from per-process (TGID) to per-user tracking
 * completely neutralizes "Process Sharding" evasion techniques, where an
 * adversary spawns dozens of discrete processes to divide the syscall spam
 * and stay under the detection threshold. Old, inactive user entries are
 * automatically evicted.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct madvise_tracker);
	__uint(max_entries, 8192);
} madvise_tracking_map SEC(".maps");

BOUCLIER_MODULE_ALERTS;
BOUCLIER_MODULE_STATE_MAP;

/*
 * Defense Heuristic: Race Condition Mitigator
 * Intercepts the entry point of the `madvise` syscall via tracepoint. If a
 * specific thread is observed spamming `MADV_DONTNEED` at an inhuman rate, we
 * instantly neutralize the thread with SIGKILL before it can successfully
 * groom the heap or win the Copy-on-Write race condition.
 */
SEC("tracepoint/syscalls/sys_enter_madvise")
int madvise_ratelimit_sys_enter(struct trace_event_raw_sys_enter *tp_args) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	/*
	 * Extract the `behavior` argument via CO-RE.
	 * In standard `madvise(void *addr, size_t length, int advice)`, the
	 * advice/behavior parameter is the 3rd argument (args[2]).
	 */
	int behavior = (int)BPF_CORE_READ(tp_args, args[2]);

	/*
	 * Fast-Path Deferral
	 * We solely care about MADV_DONTNEED (and potentially MADV_FREE). Normal
	 * memory advisory hints like MADV_SEQUENTIAL or MADV_WILLNEED are safely
	 * ignored to preserve maximum native system I/O performance.
	 */
	if (behavior != MADV_DONTNEED) {
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid; // Lower 32 bits maps to the Kernel Thread ID
	__u32 pid = pid_tgid >> 32;	 // Upper 32 bits maps to the Process ID (TGID)
	__u32 uid = get_global_uid();

	__u64 now = bpf_ktime_get_ns();

	/*
	 * User-Wide Tracking (Global UID)
	 * Tracking by Global UID aggregates the rate limit across the user's
	 * entire session. If an attacker spins up 50 separate processes to
	 * execute the race condition, their aggregate `madvise` spam will still
	 * trigger the threshold, effectively defeating Process Sharding.
	 */
	struct madvise_tracker *state_ptr =
		bpf_map_lookup_elem(&madvise_tracking_map, &uid);

	struct madvise_tracker init_state = {};

	if (!state_ptr) {
		init_state.window_start = now;
		init_state.count = 1;

		bpf_map_update_elem(&madvise_tracking_map, &uid, &init_state, BPF_ANY);
		return 0;
	}

	/*
	 * Temporal Boundary Validation
	 * Read directly from the map pointer. If the window expired, reset the
	 * tracker block. Standard assignment is used over atomic swaps to prevent
	 * LLVM backend crashes on older eBPF targets. The micro-race condition is
	 * acceptable for a 10,000 threshold heuristic.
	 */
	if (now - state_ptr->window_start > RATELIMIT_WINDOW_NS) {
		state_ptr->window_start = now;
		state_ptr->count = 1;
		return 0;
	}

	/*
	 * Concurrency-Safe Increment
	 * Because multiple processes and threads share the same UID tracker, we
	 * must use an atomic increment directly on the map pointer to prevent lost
	 * updates during a multi-threaded or multi-process race condition attack.
	 */
	__sync_fetch_and_add(&state_ptr->count, 1);
	__u64 current_count = state_ptr->count;

	/*
	 * Enforcement & Telemetry
	 */
	if (current_count > RATELIMIT_THRESHOLD) {

		/*
		 * Immediate Neutralization
		 * Because this hook relies on a raw tracepoint (which cannot legally
		 * return a blocking denial code like -EPERM to userspace), we must
		 * rely on bpf_send_signal(9) to definitively break the race condition
		 * loop.
		 */
		long sig_result = bpf_send_signal(9);

		/*
		 * Telemetry Event Flooding Prevention
		 * Only reset the flood counter if we successfully neutralized the
		 * threat. If the kill failed, we want the telemetry to keep firing so
		 * the user-space daemon knows the threat is still active.
		 */
		if (sig_result == 0) {
			state_ptr->count = 0;
			bpf_debug_printk("Bouclier Bleu [BLOCK]: Thread %d neutralized for "
							 "MADV_DONTNEED spam.\n",
							 tid);
		} else {
			bpf_debug_printk("Bouclier Bleu [ERROR]: SIGKILL delivery failed "
							 "(%ld).\n",
							 sig_result);
		}

		struct madvise_alert *event =
			bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);

		if (event) {
			BPF_SAFE_MEMSET(event, sizeof(*event));

			event->pid = pid;
			event->tid = tid;
			event->count = (__u32)current_count;
			event->action_type = ACTION_MADVISE_SPAM;

			extract_safe_comm(event->comm, sizeof(event->comm));

			bpf_ringbuf_submit(event, 0);
		}
	}

	return 0;
}
