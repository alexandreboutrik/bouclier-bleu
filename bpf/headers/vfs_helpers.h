#ifndef __VFS_HELPERS_H
#define __VFS_HELPERS_H

#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/**
 * struct dir_id - Cross-Device Unique Directory Identifier
 * @ino: The physical inode number.
 * @dev: The filesystem device ID (Superblock).
 * @_pad: Explicit padding to ensure stable 16-byte alignment.
 */
struct dir_id {
    __u64 ino;
    __u32 dev;
    __u32 _pad;
};

/**
 * BOUCLIER_PATH_BUFFER_MAP - Canonical Path Resolution Buffer
 *
 * eBPF programs are strictly constrained by a 512-byte stack limit. To
 * securely resolve absolute execution paths (PATH_MAX = 4096) without
 * triggering -ENAMETOOLONG fail-open vulnerabilities, we allocate a dedicated
 * memory segment. We utilize BPF_MAP_TYPE_PERCPU_ARRAY to provide a lock-free,
 * zero-contention memory region dedicated to each CPU core, maintaining O(1)
 * latency.
 */
#define BOUCLIER_PATH_BUFFER_MAP \
    struct { \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
        __type(key, __u32); \
        __type(value, char[PATH_MAX]); \
        __uint(max_entries, 1); \
    } path_buffer_map SEC(".maps");

/**
 * BOUCLIER_PROTECTED_DIRS_MAP - Hardware-Backed Directory Watchlist
 *
 * Relies on the physical Inode (`ino`) and Superblock Device ID (`dev`) rather
 * than vulnerable string paths. This architecture completely neutralizes mount
 * namespace evasion (`unshare -m`) and bind-mount spoofing techniques commonly
 * employed by advanced adversaries to bypass static path heuristics.
 *
 * Sized with a default fallback of 8,192 entries, meant to be dynamically
 * resized by the Rust userland daemon before kernel allocation.
 */
#define BOUCLIER_PROTECTED_DIRS_MAP \
    struct { \
        __uint(type, BPF_MAP_TYPE_LRU_HASH); \
        __type(key, struct dir_id); \
        __type(value, __u8); \
        __uint(max_entries, 8192); \
    } protected_dirs SEC(".maps");

/**
 * BOUCLIER_PROTECTED_FILES_MAP - Hardware-Backed File Watchlist
 *
 * Tracks the physical Inode and Superblock Device ID of critical EDR files.
 * This completely neutralizes string-based path evasion techniques like 
 * hardlink spoofing and mount namespace manipulation.
 */
#define BOUCLIER_PROTECTED_FILES_MAP \
	struct { \
    __uint(type, BPF_MAP_TYPE_HASH); \
    __type(key, struct dir_id); \
    __type(value, __u8); \
    __uint(max_entries, 2); \
} protected_files SEC(".maps");

/**
 * extract_dir_id_from_dentry() - Safely resolves dir_id from a dentry
 * @dentry: Pointer to the dentry cache object.
 * @out_id: Pointer to the struct dir_id to populate.
 *
 * Uses CO-RE (BPF_CORE_READ) to safely extract the physical Inode and
 * Superblock Device ID, bypassing namespace normalization vulnerabilities.
 */
static __always_inline void extract_dir_id_from_dentry(struct dentry *dentry, struct dir_id *out_id) {
    out_id->ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    out_id->dev = BPF_CORE_READ(dentry, d_sb, s_dev);
    out_id->_pad = 0;
}

/**
 * extract_dir_id_from_inode() - Safely resolves dir_id from an inode
 * @inode: Pointer to the VFS inode object.
 * @out_id: Pointer to the struct dir_id to populate.
 */
static __always_inline void extract_dir_id_from_inode(struct inode *inode, struct dir_id *out_id) {
    out_id->ino = BPF_CORE_READ(inode, i_ino);
    out_id->dev = BPF_CORE_READ(inode, i_sb, s_dev);
    out_id->_pad = 0;
}

/**
 * inherit_protection() - Dynamically cascades watchlist enforcement
 * @map: Pointer to the protected_dirs eBPF map.
 * @parent_id: The dir_id of the target/parent directory.
 * @child_id: The dir_id of the newly created or moved directory.
 * @module_name: String literal for BPF printk error context.
 *
 * Evaluates if the parent directory is protected. If true, atomically
 * updates the map to enforce protection on the child directory,
 * closing zero-day nested staging evasion loopholes.
 */
static __always_inline void inherit_protection(void *map, struct dir_id *parent_id, struct dir_id *child_id, const char *module_name) {
    __u8 *is_protected = bpf_map_lookup_elem(map, parent_id);

    if (is_protected && *is_protected == 1) {
        __u8 val = 1;
        int err = bpf_map_update_elem(map, child_id, &val, BPF_ANY);
        
        /*
         * BPF Map Exhaustion Handling
         * eBPF maps cannot be dynamically resized post-allocation. If an
         * attacker triggers a loop to create thousands of directories, the map
         * will fill up, and `bpf_map_update_elem` will return -E2BIG. We must
         * intercept this to prevent a fail-open scenario where subsequent
         * malicious directories go unmonitored.
         */
        if (err) {
            bpf_printk("Bouclier Bleu [CRITICAL]: protected_dirs map exhausted in %s! Fail-open state.\n", module_name);
        }
    }
}

#endif /* __VFS_HELPERS_H */
