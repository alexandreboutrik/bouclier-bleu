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

/* Standard Linux Mount Flags */
#define MS_NOSUID 2
#define MS_NODEV 4
#define MS_NOEXEC 8
#define SECURE_MOUNT_FLAGS (MS_NOSUID | MS_NODEV | MS_NOEXEC)

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

SEC("lsm/sb_mount")
int BPF_PROG(mount_secure_sb_mount, const char *dev_name,
			 const struct path *path, const char *type, unsigned long flags,
			 void *data) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	/*
	 * Fast-path Deferral
	 * If the sysadmin or automounter explicitly set all 3 required security
	 * flags, we allow the mount to proceed without string evaluation.
	 */
	if ((flags & SECURE_MOUNT_FLAGS) == SECURE_MOUNT_FLAGS) {
		return 0;
	}

	bool is_target = false;

	/*
	 * Heuristic 1: Removable Block Device Prefixes
	 * Instead of relying on easily bypassed filesystem types (e.g., vfat), we
	 * evaluate the originating block device to reliably identify physical USB
	 * or SD card mounts (/dev/sd*, /dev/mmcblk*). This neutralizes arbitrary
	 * filesystem evasions.
	 */
	if (dev_name) {
		char dev_prefix[8] = {};
		bpf_probe_read_kernel_str(dev_prefix, sizeof(dev_prefix), dev_name);

		if (dev_prefix[0] == '/' && dev_prefix[1] == 'd' &&
			dev_prefix[2] == 'e' && dev_prefix[3] == 'v' &&
			dev_prefix[4] == '/') {
			if (dev_prefix[5] == 's' && dev_prefix[6] == 'd') {
				is_target = true; // /dev/sd*
			} else if (dev_prefix[5] == 'm' && dev_prefix[6] == 'm' &&
					   dev_prefix[7] == 'c') {
				is_target = true; // /dev/mmc*
			}
		}
	}

	/*
	 * Heuristic 2: Destination Directory (Universal Path Resolution)
	 * Evaluates the destination directory to catch removable media mounts
	 * regardless of the source device or filesystem format.
	 */
	__u32 key = 0;
	char *path_buf = bpf_map_lookup_elem(&path_buffer_map, &key);

	if (path_buf) {
		long len = bpf_d_path((struct path *)path, path_buf, PATH_MAX);

		/*
		 * Telemetry Data Leak & Log Spoofing Mitigation
		 * bpf_d_path can fail (e.g., -ENAMETOOLONG). We must explicitly
		 * null-terminate the buffer on failure to prevent stale path strings
		 * from previous CPU executions leaking into the EDR telemetry.
		 */
		if (len <= 0) {
			path_buf[0] = '\0';
		} else {
			/*
			 * Out-of-Bounds Read Prevention
			 * We strictly enforce length bounds before evaluating array
			 * indices to prevent garbage memory reads if a user mounts to
			 * `/m`.
			 */
			if (len >= 6 && path_buf[0] == '/' && path_buf[1] == 'm' &&
				path_buf[2] == 'e' && path_buf[3] == 'd' &&
				path_buf[4] == 'i' && path_buf[5] == 'a') {
				is_target = true;
			} else if (len >= 4 && path_buf[0] == '/' && path_buf[1] == 'm' &&
					   path_buf[2] == 'n' && path_buf[3] == 't') {
				is_target = true;
			} else if (len >= 6 && path_buf[0] == '/' && path_buf[1] == 'r' &&
					   path_buf[2] == 'u' && path_buf[3] == 'n' &&
					   path_buf[4] == '/' && path_buf[5] == 'm') {
				is_target = true;
			}
		}
	}

	if (is_target) {
		struct mount_alert *event =
			bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);

		if (event) {
			BPF_SAFE_MEMSET(event, sizeof(*event));
			event->pid = bpf_get_current_pid_tgid() >> 32;

			/*
			 * Invalid BPF Helper Memory Read Fix
			 * Read directly from the kernel-space 'type' pointer rather than
			 * copying from a local eBPF stack variable to prevent
			 * verifier/JIT issues.
			 */
			if (type) {
				bpf_probe_read_kernel_str(event->fs_type,
										  sizeof(event->fs_type), type);
			} else {
				event->fs_type[0] = '\0';
			}

			if (dev_name) {
				bpf_probe_read_kernel_str(event->dev_name,
										  sizeof(event->dev_name), dev_name);
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

		bpf_printk("Bouclier Bleu [BLOCK]: Insecure removable media mount "
				   "prevented.\n");
		return -EPERM;
	}

	return 0;
}
