#ifndef __MODULE_CORE_H
#define __MODULE_CORE_H

#include "../include/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/**
 * BOUCLIER_MODULE_ALERTS - Standardized Telemetry RingBuffer
 *
 * Injects a BPF_MAP_TYPE_RINGBUF into the module. This provides a lockless,
 * high-throughput memory queue for streaming telemetry directly to user-space.
 * Sized at 256KB to absorb sudden bursts of evasion events without dropping
 * packets during heavy system utilization.
 */
#define BOUCLIER_MODULE_ALERTS                                                 \
	struct {                                                                   \
		__uint(type, BPF_MAP_TYPE_RINGBUF);                                    \
		__uint(max_entries, 256 * 1024);                                       \
	} alerts SEC(".maps");

/**
 * BOUCLIER_MODULE_STATE_MAP - Administrative Control Plane Map
 *
 * Injects a single-element BPF_MAP_TYPE_ARRAY. Acts as an atomic, shared
 * memory flag between the Rust daemon and kernel.
 * - 0: Module is administratively disabled (Hook returns early).
 * - 1: Module is actively enforcing.
 */
#define BOUCLIER_MODULE_STATE_MAP                                              \
	struct {                                                                   \
		__uint(type, BPF_MAP_TYPE_ARRAY);                                      \
		__type(key, __u32);                                                    \
		__type(value, __u32);                                                  \
		__uint(max_entries, 1);                                                \
	} state_map SEC(".maps");

/**
 * BPF_SAFE_MEMSET() - Verifier-Safe Memory Initialization
 * @dest: Pointer to the struct/memory block.
 * @size: Size of the memory block (usually sizeof(*ptr)).
 *
 * Clang's BPF backend cannot safely inline standard `memset` for large structs
 * (>512 bytes), resulting in forbidden external function calls or
 * uninitialized memory rejections. This macro utilizes a volatile bounded loop
 * to force memory zeroing while defeating Clang's auto-memset optimization
 * passes.
 */
#define BPF_SAFE_MEMSET(dest, size)                                            \
	do {                                                                       \
		volatile __u8 *__ptr = (volatile __u8 *)(dest);                        \
		for (size_t __i = 0; __i < (size_t)(size); __i++) {                    \
			__ptr[__i] = 0;                                                    \
		}                                                                      \
	} while (0)

/**
 * is_module_active() - Evaluates the enforcement state of the calling module.
 * @map: Pointer to the module's state_map.
 *
 * If the map lookup fails (e.g., due to extreme memory exhaustion), we return
 * 0 (allow). In a kernel-space LSM, degrading visibility is preferable to
 * halting critical system operations and inducing a kernel panic.
 *
 * Return: 1 if active, 0 if disabled or error.
 */
static __always_inline int is_module_active(void *map) {
	__u32 key = 0;
	__u32 *active = bpf_map_lookup_elem(map, &key);

	if (!active) {
		/*
		 * State Map Exhaustion / Sabotage Defense
		 * If the control plane lookup fails, we default to fail-closed
		 * (active = 1). Degrading visibility is dangerous, but disabling
		 * protection entirely during a map exhaustion attack is fatal.
		 */
		bpf_printk("Bouclier Bleu [FATAL]: Control map lookup failed. Failing "
				   "closed.\n");
		return 1;
	}

	return (*active == 1);
}

/**
 * get_global_uid() - Safely resolve the true Global UID
 *
 * Standard `bpf_get_current_uid_gid()` evaluates the UID within the current
 * executing user namespace. This introduces a critical blind spot where an
 * unprivileged containerized process could map its local UID to 0, bypassing
 * LSM heuristics that rely on simple root checks.
 *
 * This helper utilizes CO-RE to safely traverse the kernel task structure and
 * extract the definitive, namespace-agnostic global UID.
 *
 * Return: The global __u32 UID of the current task.
 */
static __always_inline __u32 get_global_uid(void) {
	struct task_struct *task = bpf_get_current_task_btf();
	/*
	 * Traverse task_struct -> cred -> uid -> val
	 * Resolves the underlying kuid_t wrapper to extract the raw integer.
	 */
	return (__u32)BPF_CORE_READ(task, cred, uid.val);
}

#endif /* __MODULE_CORE_H */
