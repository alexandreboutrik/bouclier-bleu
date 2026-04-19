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
	char mount_point[PATH_MAX];
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
	 * Fast-path Deferral:
	 * If the sysadmin or automounter explicitly set all 3 required security
	 * flags, we allow the mount to proceed without string evaluation.
	 */
	if ((flags & SECURE_MOUNT_FLAGS) == SECURE_MOUNT_FLAGS) {
		return 0;
	}

	/*
	 * eBPF string extraction and stack limitations (512 bytes)
	 * We carefully extract the filesystem type into a small stack buffer.
	 */
	char fs_type[64] = {};
	bpf_probe_read_kernel_str(fs_type, sizeof(fs_type), type);

	bool is_target = false;

	/* Heuristic 1: Removable Filesystem Types */
	if (fs_type[0] == 'v' && fs_type[1] == 'f' && fs_type[2] == 'a' &&
		fs_type[3] == 't')
		is_target = true;
	else if (fs_type[0] == 'e' && fs_type[1] == 'x' && fs_type[2] == 'f' &&
			 fs_type[3] == 'a' && fs_type[4] == 't')
		is_target = true;
	else if (fs_type[0] == 'n' && fs_type[1] == 't' && fs_type[2] == 'f' &&
			 fs_type[3] == 's')
		is_target = true;
	else if (fs_type[0] == 'i' && fs_type[1] == 's' && fs_type[2] == 'o' &&
			 fs_type[3] == '9')
		is_target = true;

	/*
	 * Heuristic 2: Destination Directory (Path Resolution)
	 * If the fs_type is generic, we check if it's being mounted into standard
	 * removable media directories.
	 */
	__u32 key = 0;
	char *path_buf = NULL;

	if (!is_target) {
		path_buf = bpf_map_lookup_elem(&path_buffer_map, &key);
		if (path_buf) {
			long len = bpf_d_path((struct path *)path, path_buf, PATH_MAX);
			if (len > 0 && len != -ENAMETOOLONG) {
				if (path_buf[0] == '/' && path_buf[1] == 'm' &&
					path_buf[2] == 'e' && path_buf[3] == 'd' &&
					path_buf[4] == 'i' && path_buf[5] == 'a')
					is_target = true;
				else if (path_buf[0] == '/' && path_buf[1] == 'm' &&
						 path_buf[2] == 'n' && path_buf[3] == 't')
					is_target = true;
				else if (path_buf[0] == '/' && path_buf[1] == 'r' &&
						 path_buf[2] == 'u' && path_buf[3] == 'n' &&
						 path_buf[4] == '/' && path_buf[5] == 'm')
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

			bpf_probe_read_kernel_str(event->fs_type, sizeof(event->fs_type),
									  fs_type);

			if (dev_name) {
				bpf_probe_read_kernel_str(event->dev_name,
										  sizeof(event->dev_name), dev_name);
			} else {
				event->dev_name[0] = 'N';
				event->dev_name[1] = '/';
				event->dev_name[2] = 'A';
			}

			/*
			 * If we haven't already resolved the path in Heuristic 2, do it
			 * now for telemetry.
			 */
			if (!path_buf) {
				path_buf = bpf_map_lookup_elem(&path_buffer_map, &key);
				if (path_buf) {
					bpf_d_path((struct path *)path, path_buf, PATH_MAX);
				}
			}

			if (path_buf) {
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
