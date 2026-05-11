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
 * Memory Advisory Flags
 * Redefined here to avoid dependencies on host-specific user-space headers
 * during CO-RE compilation.
 */
#ifndef MADV_DONTNEED
#define MADV_DONTNEED 4
#endif

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
 * thread. Utilizing an LRU map natively prevents map exhaustion (fail-open)
 * attacks where an adversary might spawn thousands of dummy threads strictly
 * to fill the BPF map before executing the real exploit. Old, inactive thread
 * entries are automatically evicted.
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

	__u64 now = bpf_ktime_get_ns();

	/*
	 * Lock-Free Concurrency Optimization
	 * By explicitly tracking the Thread ID (TID) rather than the parent
	 * Process ID (TGID), we eliminate the need for expensive atomic
	 * `__sync_add_and_fetch` operations. A single thread can mathematically
	 * only execute one syscall at any given time, ensuring perfectly race-free
	 * map updates.
	 */
	struct madvise_tracker *state =
		bpf_map_lookup_elem(&madvise_tracking_map, &tid);

	if (!state) {
		struct madvise_tracker init_state = {};
		init_state.window_start = now;
		init_state.count = 1;

		bpf_map_update_elem(&madvise_tracking_map, &tid, &init_state, BPF_ANY);
		return 0;
	}

	/*
	 * Temporal Boundary Validation
	 * If the current timestamp has safely exceeded the rolling window limit,
	 * reset the tracker block for this thread.
	 */
	if (now - state->window_start > RATELIMIT_WINDOW_NS) {
		state->window_start = now;
		state->count = 1;
		return 0;
	}

	state->count++;

	/*
	 * Enforcement & Telemetry
	 * If the thread aggressively exceeds the statistical threshold, we isolate
	 * and terminate it instantly.
	 */
	if (state->count > RATELIMIT_THRESHOLD) {

		/*
		 * Immediate Neutralization
		 * Issuing SIGKILL (9) directly from kernel-space ensures the thread
		 * is terminated the exact microsecond it exits the syscall context,
		 * breaking the race condition cycle definitively.
		 */
		long sig_result = bpf_send_signal(9);
		if (sig_result < 0) {
			bpf_printk("Bouclier Bleu [ERROR]: SIGKILL delivery failed "
					   "(%ld).\n",
					   sig_result);
		} else {
			bpf_printk("Bouclier Bleu [BLOCK]: Race condition anomaly "
					   "detected. Killing PID %d.\n",
					   pid);
		}

		/*
		 * Telemetry Event Flooding Prevention
		 * Once the kill signal is successfully dispatched, we reset the
		 * counter back to 0. If the thread manages to execute a few lingering
		 * instructions before the kernel reaps it, this guarantees we don't
		 * blindly spam the userland ringbuffer with duplicate SIEM alerts.
		 */
		state->count = 0;

		struct madvise_alert *event =
			bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);

		if (event) {
			BPF_SAFE_MEMSET(event, sizeof(*event));

			event->pid = pid;
			event->tid = tid;
			event->count = RATELIMIT_THRESHOLD;
			event->action_type = ACTION_MADVISE_SPAM;

			/* Memory-Boundary Safe String Extraction */
			if (bpf_get_current_comm(event->comm, sizeof(event->comm)) < 0) {
				char unknown_str[] = "<unknown>";
				__builtin_memcpy(event->comm, unknown_str, sizeof(unknown_str));
			}
			event->comm[sizeof(event->comm) - 1] = '\0';

			bpf_ringbuf_submit(event, 0);
		}
	}

	return 0;
}
