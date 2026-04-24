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

/* Standard Linux Mount Flags (Legacy API) */
#define MS_NOSUID 2
#define MS_NODEV 4
#define MS_NOEXEC 8
#define SECURE_MOUNT_FLAGS (MS_NOSUID | MS_NODEV | MS_NOEXEC)

/*
 * Modern Mount API Flags (util-linux >= 2.39)
 * The new mount API detaches mount creation from attachment, tracking flags
 * within the vfsmount struct using a distinct bitwise layout.
 */
#ifndef MNT_NOSUID
#define MNT_NOSUID 0x01
#endif
#ifndef MNT_NODEV
#define MNT_NODEV 0x02
#endif
#ifndef MNT_NOEXEC
#define MNT_NOEXEC 0x04
#endif
#define SECURE_MOVE_MNT_FLAGS (MNT_NOSUID | MNT_NODEV | MNT_NOEXEC)

/**
 * struct mount_alert - Telemetry Payload Contract
 *
 * Memory layout must strictly mirror the `MountAlert` struct in the Rust
 * userland to ensure safe zero-copy deserialization.
 */
struct mount_alert {
	__u32 pid;
	char dev_name[256];
	char fs_type[64];
	char mount_point[512];
};

BOUCLIER_PATH_BUFFER_MAP;
BOUCLIER_MODULE_ALERTS;
BOUCLIER_MODULE_STATE_MAP;

/* =========================================================================
 * HEURISTIC EVALUATION HELPERS
 * ========================================================================= */

/**
 * is_removable_device() - Hardware Heuristic Evaluator
 * @dev_name: Extracted block device identifier string.
 *
 * Instead of relying on easily bypassed filesystem types (e.g., vfat), we
 * evaluate the originating block device to reliably identify physical USB or
 * SD card mounts (/dev/sd*, /dev/mmcblk*). This neutralizes arbitrary
 * filesystem evasions.
 */
static __always_inline bool is_removable_device(const char *dev_name) {
	if (!dev_name)
		return false;

	char prefix[8] = {};
	bpf_probe_read_kernel_str(prefix, sizeof(prefix), dev_name);

	if (prefix[0] == '/' && prefix[1] == 'd' && prefix[2] == 'e' &&
		prefix[3] == 'v' && prefix[4] == '/') {
		if (prefix[5] == 's' && prefix[6] == 'd')
			return true; // /dev/sd*
		if (prefix[5] == 'm' && prefix[6] == 'm' && prefix[7] == 'c')
			return true; // /dev/mmc*
	}
	return false;
}

/**
 * is_sensitive_path() - Universal Path Resolution
 * @path: Canonicalized destination path buffer.
 * @len: Length of the canonicalized path.
 *
 * Evaluates the destination directory to catch removable media mounts
 * regardless of the source device or filesystem format. We strictly enforce
 * length bounds before evaluating array indices to prevent garbage memory
 * reads (e.g., if a user mounts to `/m`).
 */
static __always_inline bool is_sensitive_path(const char *path, int len) {
	if (len < 4 || path[0] != '/')
		return false;

	if (path[1] == 'm' && path[2] == 'n' && path[3] == 't')
		return true; // /mnt

	if (len >= 6 && path[1] == 'm' && path[2] == 'e' && path[3] == 'd' &&
		path[4] == 'i' && path[5] == 'a')
		return true; // /media

	if (len >= 11 && path[1] == 'r' && path[2] == 'u' && path[3] == 'n' &&
		path[4] == '/' && path[5] == 'm' && path[6] == 'e' && path[7] == 'd' &&
		path[8] == 'i' && path[9] == 'a')
		return true; // /run/media

	return false;
}

/**
 * fallback_dentry_check() - Lock-Safe VFS Tree Traversal
 * @dst_path: Target destination path struct.
 *
 * bpf_d_path can fail with -EOPNOTSUPP or -EINVAL when called within certain
 * VFS namespace locks (like move_mount). If it fails, we manually traverse the
 * dentry parent pointers up the VFS tree to accurately determine if the target
 * resides within /mnt or /media.
 */
static __always_inline bool fallback_dentry_check(const struct path *dst_path) {
	struct dentry *d = BPF_CORE_READ(dst_path, dentry);

#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (!d)
			break;

		const unsigned char *name = BPF_CORE_READ(d, d_name.name);
		if (name) {
			char p_name[6] = {};
			bpf_probe_read_kernel_str(p_name, sizeof(p_name), name);

			if (p_name[0] == 'm' && p_name[1] == 'n' && p_name[2] == 't' &&
				p_name[3] == '\0')
				return true;
			if (p_name[0] == 'm' && p_name[1] == 'e' && p_name[2] == 'd' &&
				p_name[3] == 'i' && p_name[4] == 'a' && p_name[5] == '\0')
				return true;
		}
		d = BPF_CORE_READ(d, d_parent);
	}
	return false;
}

/**
 * dispatch_mount_alert() - Telemetry Payload Compilation
 * @dev_name: Block device identifier.
 * @fs_type: Filesystem type string.
 * @path_buf: Canonicalized mount destination path.
 *
 * Handles the reservation and safe population of the eBPF ring buffer.
 */
static __always_inline void dispatch_mount_alert(const char *dev_name,
												 const char *fs_type,
												 const char *path_buf) {
	struct mount_alert *event = bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
	if (!event)
		return;

	BPF_SAFE_MEMSET(event, sizeof(*event));
	event->pid = bpf_get_current_pid_tgid() >> 32;

	/*
	 * Invalid BPF Helper Memory Read Fix
	 * Read directly from the kernel-space pointer rather than copying from a
	 * local eBPF stack variable to prevent verifier/JIT issues.
	 */
	if (fs_type) {
		bpf_probe_read_kernel_str(event->fs_type, sizeof(event->fs_type),
								  fs_type);
	}

	if (dev_name) {
		bpf_probe_read_kernel_str(event->dev_name, sizeof(event->dev_name),
								  dev_name);
	} else {
		event->dev_name[0] = 'N';
		event->dev_name[1] = '/';
		event->dev_name[2] = 'A';
	}

	if (path_buf && path_buf[0] != '\0') {
		bpf_probe_read_kernel_str(event->mount_point,
								  sizeof(event->mount_point), path_buf);
	}

	bpf_ringbuf_submit(event, 0);
}

/**
 * evaluate_secure_mount() - Shared Heuristic Orchestrator
 * @dev_name: Extracted block device identifier string.
 * @fs_type: Extracted filesystem type string.
 * @dst_path: Target destination path struct.
 * @allow_d_path: Compile-time constant to strip bpf_d_path from restr. hooks.
 *
 * Consolidates the evaluation flow for both the legacy and modern mount APIs
 * to strictly adhere to the DRY principle while avoiding invalid cross-hook
 * calls restricted by the eBPF verifier.
 */
static __always_inline int evaluate_secure_mount(const char *dev_name,
												 const char *fs_type,
												 const struct path *dst_path,
												 bool allow_d_path) {
	/* Device Hardware Heuristic */
	bool is_target = is_removable_device(dev_name);

	/* Destination Directory Heuristics */
	__u32 key = 0;
	char *path_buf = bpf_map_lookup_elem(&path_buffer_map, &key);
	long len = 0;

	if (path_buf) {
		/*
		 * Compiler Optimization / Verifier Bypass:
		 * If `allow_d_path` is passed as `false` from the hook, Clang will
		 * optimize this block out entirely, removing the forbidden bpf_d_path
		 * instruction from the compiled bytecode for that specific hook.
		 */
		if (allow_d_path) {
			len = bpf_d_path((struct path *)dst_path, path_buf, PATH_MAX);

			if (len > 0) {
				if (!is_target)
					is_target = is_sensitive_path(path_buf, len);
			} else {
				/*
				 * Telemetry Data Leak & Log Spoofing Mitigation
				 * bpf_d_path can fail (e.g., -ENAMETOOLONG). We must
				 * explicitly null-terminate the buffer on failure to prevent
				 * stale path strings from previous CPU executions leaking into
				 * the EDR telemetry.
				 */
				path_buf[0] = '\0';
			}
		} else {
			path_buf[0] = '\0';
		}
	}

	/* Lock-Safe VFS Fallback (if bpf_d_path failed or was disabled) */
	if (!is_target && len <= 0) {
		is_target = fallback_dentry_check(dst_path);
	}

	/* Enforcement & Telemetry */
	if (is_target) {
		dispatch_mount_alert(dev_name, fs_type, path_buf);
		bpf_printk("Bouclier Bleu [BLOCK]: Insecure removable media mount "
				   "prevented.\n");
		return -EPERM;
	}

	return 0;
}

/*
 * Legacy Mount API Interception
 * Intercepts traditional mount(2) syscalls commonly used on pre-2023 kernels
 * or manually invoked via legacy userspace tools.
 */
SEC("lsm/sb_mount")
int BPF_PROG(mount_secure_sb_mount, const char *dev_name,
			 const struct path *path, const char *type, unsigned long flags,
			 void *data) {

	if (!is_module_active(&state_map))
		return 0;

	/*
	 * Fast-path Deferral
	 * If the sysadmin or automounter explicitly set all 3 required security
	 * flags, we allow the mount to proceed without string evaluation.
	 */
	if ((flags & SECURE_MOUNT_FLAGS) == SECURE_MOUNT_FLAGS)
		return 0;

	// bpf_d_path is allowlisted for sb_mount. Pass `true`.
	return evaluate_secure_mount(dev_name, type, path, true);
}

/*
 * Modern Mount API Interception (util-linux >= 2.39)
 * Captures `move_mount` attachments utilized by modern Linux distributions
 * (e.g., Fedora 43). This acts as the gatekeeper since the new API completely
 * detaches mount creation from its attachment to the VFS tree.
 */
SEC("lsm/move_mount")
int BPF_PROG(mount_secure_move_mount, const struct path *from_path,
			 const struct path *to_path) {

	if (!is_module_active(&state_map))
		return 0;

	/*
	 * In the new API, mount properties are bound to the vfsmount struct
	 * instead of being passed as raw syscall integers.
	 */
	int mnt_flags = BPF_CORE_READ(from_path, mnt, mnt_flags);
	if ((mnt_flags & SECURE_MOVE_MNT_FLAGS) == SECURE_MOVE_MNT_FLAGS)
		return 0;

	const char *dev_name = NULL;
	const char *fs_type = NULL;

	/*
	 * Safely extract backing device and filesystem type via CO-RE.
	 * Because `move_mount` only provides path pointers, we must manually walk
	 * the superblock structures to extract telemetry strings.
	 */
	struct super_block *sb = BPF_CORE_READ(from_path, mnt, mnt_sb);
	if (sb) {
		struct file_system_type *type = BPF_CORE_READ(sb, s_type);
		if (type) {
			fs_type = BPF_CORE_READ(type, name);
		}
	}

	/*
	 * Container-Of Extrapolation (CO-RE)
	 * The new VFS API discards spoofed pseudo-filesystem source strings from
	 * the superblock's s_id. To perfectly mirror the legacy sb_mount behavior,
	 * we must calculate the offset of the embedded vfsmount to access the
	 * internal 'struct mount', which perfectly preserves the original
	 * mnt_devname.
	 */
	size_t mnt_offset =
		__builtin_preserve_field_info(((struct mount *)0)->mnt, 0);
	struct mount *real_mount =
		(struct mount *)((void *)from_path->mnt - mnt_offset);
	dev_name = BPF_CORE_READ(real_mount, mnt_devname);

	// bpf_d_path is NOT allowlisted for move_mount. Pass `false` to compile it
	// out.
	return evaluate_secure_mount(dev_name, fs_type, to_path, false);
}
