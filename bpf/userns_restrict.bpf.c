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

#ifndef CAP_SYS_ADMIN
#define CAP_SYS_ADMIN 21
#endif

/* Telemetry Action Identifiers */
#define ACTION_USERNS_CREATE 1
#define ACTION_CAP_SYS_ADMIN 2
#define ACTION_MOUNT_DEV 3

/**
 * struct userns_alert - Telemetry Payload Contract
 * @pid: The Process ID originating the restricted action.
 * @action_type: Enum mapping to the specific namespace heuristic triggered.
 * @target: Contextual string detailing the blocked resource or action.
 *
 * Memory layout must strictly mirror the `UsernsAlert` struct in the Rust
 * userland to ensure safe zero-copy deserialization.
 */
struct userns_alert {
	__u32 pid;
	__u32 action_type;
	char target[64];
};

BOUCLIER_MODULE_ALERTS;
BOUCLIER_MODULE_STATE_MAP;

/**
 * dispatch_userns_alert() - Telemetry Payload Compilation
 * @action_type: The specific heuristic triggered.
 * @target_str: String literal providing context for the block.
 *
 * Centralizes the safe reservation and population of the ring buffer, avoiding
 * inline repetition and reducing verifier complexity.
 */
static __always_inline void dispatch_userns_alert(__u32 action_type,
												  const char *target_str) {
	struct userns_alert *event =
		bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
	if (!event) {
		return;
	}

	BPF_SAFE_MEMSET(event, sizeof(*event));

	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->action_type = action_type;

	__builtin_strncpy(event->target, target_str, sizeof(event->target));
	event->target[sizeof(event->target) - 1] = '\0';

	bpf_ringbuf_submit(event, 0);

	bpf_debug_printk(
		"Bouclier Bleu [BLOCK]: Namespace restriction triggered: %s\n",
		target_str);
}

/*
 * Defense Heuristic : Unprivileged Namespace Creation
 * Attackers exploit unprivileged user namespace creation as the crucial first
 * step for exploiting kernel vulnerabilities. We block
 * `unshare(CLONE_NEWUSER)` by evaluating both the effective UID and the
 * immutable process ancestry to prevent SUID proxying and double-fork evasion.
 */
SEC("lsm/userns_create")
int BPF_PROG(userns_restrict_create, const struct cred *cred) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	struct task_struct *task = bpf_get_current_task_btf();
	__u32 current_uid = get_global_uid();

	/*
	 * Immutable Audit Anchor (Defeats SUID & Double-Fork)
	 * The loginuid is set during the initial authentication phase (SSH/TTY)
	 * and is irrevocably inherited by all children. It cannot be altered by
	 * SUID binaries (su/sudo) or scrubbed via double-forking to PID 1.
	 * System daemons spawned by systemd inherently hold AUDIT_UID_UNSET
	 * (0xFFFFFFFF). By validating against this, we permit legitimate container
	 * runtimes while blocking interactive human adversaries.
	 */
	__u32 login_uid = BPF_CORE_READ(task, loginuid.val);

	/*
	 * Immediate Parent Validation
	 * Captures the real_parent creds. This serves as a secondary defense layer
	 * for environments where the Audit subsystem might be disabled, ensuring
	 * simple SUID proxies are still caught.
	 */
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	__u32 parent_uid = BPF_CORE_READ(parent, cred, uid.val);

	if (current_uid != 0) {
		dispatch_userns_alert(ACTION_USERNS_CREATE,
							  "unshare() - Direct Unprivileged");
		return -EPERM;
	}

	/*
	 * Ancestry Spoofing (SUID / Double-Fork)
	 * The effective UID is 0, but the origin session belongs to a standard
	 * user (e.g., UID 1000).
	 */
	if (login_uid != 0 && login_uid != 0xFFFFFFFF) {
		dispatch_userns_alert(ACTION_USERNS_CREATE,
							  "unshare() - SUID/Ancestry Evasion");
		return -EPERM;
	}

	/*
	 * SUID Proxy Fallback
	 * The immediate parent was unprivileged. This acts as a fallback if
	 * loginuid is unset due to host misconfiguration.
	 */
	if (parent_uid != 0 && parent_uid != 0xFFFFFFFF) {
		dispatch_userns_alert(ACTION_USERNS_CREATE,
							  "unshare() - SUID Proxy Fallback");
		return -EPERM;
	}

	return 0;
}

/*
 * Defense Heuristic: Restricted Capability Abuse (Container Escape)
 * Even if an attacker compromises a process inside a legitimate Docker or
 * Flatpak container, gaining CAP_SYS_ADMIN inside that nested namespace allows
 * mounting and transitioning to full host compromise. We monitor capability
 * checks and block CAP_SYS_ADMIN strictly if the task is inside a child
 * namespace.
 */
SEC("lsm/capable")
int BPF_PROG(userns_restrict_capable, const struct cred *cred,
			 struct user_namespace *ns, int cap, int opts) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	/* Fast-Path Deferral for non-critical capabilities */
	if (cap != CAP_SYS_ADMIN) {
		return 0;
	}

	/*
	 * Namespace Level Evaluation
	 * The `init_user_ns` has a level of 0. Nested namespaces (e.g., Docker,
	 * LXC, Flatpak sandboxes) inherently have a level > 0.
	 */
	unsigned int level = BPF_CORE_READ(ns, level);
	if (level > 0) {
		dispatch_userns_alert(ACTION_CAP_SYS_ADMIN,
							  "CAP_SYS_ADMIN in container");
		return -EPERM;
	}

	return 0;
}

/*
 * Defense Heuristic: Host /dev Mounting (runc/Dirty Pipe Mitigation)
 * If an attacker gains limited execution in a container, attempting to mount
 * the host's physical `/dev` or establishing a `devtmpfs` block device is a
 * primary vector to directly tamper with the host kernel's physical disks or
 * memory blocks.
 */
SEC("lsm/sb_mount")
int BPF_PROG(userns_restrict_sb_mount, const char *dev_name,
			 const struct path *path, const char *type, unsigned long flags,
			 void *data) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	struct task_struct *task = bpf_get_current_task_btf();
	if (!task)
		return 0;

	struct user_namespace *ns = BPF_CORE_READ(task, cred, user_ns);

	unsigned int level = 0;
	if (ns) {
		level = BPF_CORE_READ(ns, level);
	}

	/* Only enforce restrictions on processes within nested namespaces */
	if (level > 0) {
		bool is_dev_mount = false;
		char dev_buf[16] = {};
		char type_buf[16] = {};

		/* Check if mapping physical device blocks (e.g. /dev/sda1) */
		if (dev_name) {
			if (bpf_probe_read_kernel_str(dev_buf, sizeof(dev_buf), dev_name) >
				0) {
				if (dev_buf[0] == '/' && dev_buf[1] == 'd' &&
					dev_buf[2] == 'e' && dev_buf[3] == 'v') {
					is_dev_mount = true;
				}
			}
		}

		/* Check if dynamically provisioning a device tmpfs */
		if (!is_dev_mount && type) {
			if (bpf_probe_read_kernel_str(type_buf, sizeof(type_buf), type) >
				0) {
				if (type_buf[0] == 'd' && type_buf[1] == 'e' &&
					type_buf[2] == 'v' && type_buf[3] == 't') {
					is_dev_mount = true;
				}
			}
		}

		if (is_dev_mount) {
			dispatch_userns_alert(ACTION_MOUNT_DEV, "Host /dev mount attempt");
			return -EPERM;
		}
	}

	return 0;
}
