#ifndef __MODULE_CORE_H
#define __MODULE_CORE_H

#include "../include/vmlinux.h"
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
#define BOUCLIER_MODULE_ALERTS \
    struct { \
        __uint(type, BPF_MAP_TYPE_RINGBUF); \
        __uint(max_entries, 256 * 1024); \
    } alerts SEC(".maps"); \

/**
 * BOUCLIER_MODULE_STATE_MAP - Administrative Control Plane Map
 *
 * Injects a single-element BPF_MAP_TYPE_ARRAY. Acts as an atomic, shared
 * memory flag between the Rust daemon and kernel. 
 * - 0: Module is administratively disabled (Hook returns early).
 * - 1: Module is actively enforcing.
 */
#define BOUCLIER_MODULE_STATE_MAP \
    struct { \
        __uint(type, BPF_MAP_TYPE_ARRAY); \
        __type(key, __u32); \
        __type(value, __u32); \
        __uint(max_entries, 1); \
    } state_map SEC(".maps");

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
    return (active && *active == 1);
}

#endif /* __MODULE_CORE_H */
