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

#ifndef O_WRONLY
#define O_WRONLY 00000001
#endif
#ifndef O_RDWR
#define O_RDWR 00000002
#endif
#ifndef O_TRUNC
#define O_TRUNC 00001000
#endif

#ifndef S_IFMT
#define S_IFMT 00170000
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif
#ifndef S_ISREG
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

#define ACTION_FILE_TAMPER 1
#define ACTION_BPF_TAMPER 2
#define ACTION_SYSLOG_LEAK 3

/**
 * struct shield_alert - Telemetry Payload Contract
 * @pid: The Process ID originating the tampering attempt.
 * @action_type: Enum mapping to the type of shield violation.
 * @target: The path or resource targeted by the attacker.
 *
 * Memory layout must strictly mirror the `ShieldAlert` struct in the Rust
 * userland to ensure safe zero-copy deserialization.
 */
struct shield_alert {
	__u32 pid;
	__u32 action_type;
	char target[PATH_MAX];
};

BOUCLIER_PATH_BUFFER_MAP;
BOUCLIER_MODULE_ALERTS;
BOUCLIER_MODULE_STATE_MAP;
BOUCLIER_PROTECTED_FILES_MAP;

/*
 * Privilege Enforcement
 * Standardizes the execution lifecycle for access-control hooks.
 * Handles fast-path root deferral, securely reserves and zero-initializes
 * the ring buffer payload (preventing verifier state leaks), and dispatches
 * the telemetry event.
 */
#define BOUCLIER_ENFORCE_PRIVILEGE(action, target_str, log_msg)                \
	if (!is_module_active(&state_map)) {                                       \
		return 0;                                                              \
	}                                                                          \
                                                                               \
	if (get_global_uid() != 0) {                                               \
		struct shield_alert *event =                                           \
			bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);                   \
		if (event) {                                                           \
			BPF_SAFE_MEMSET(event, sizeof(*event));                            \
                                                                               \
			event->pid = bpf_get_current_pid_tgid() >> 32;                     \
			event->action_type = (action);                                     \
			/*                                                                 \
			 * Memory-Boundary Safe Extraction                                 \
			 * target_str is inherently a static kernel string literal.        \
			 * We read it directly rather than copying to the BPF stack first. \
			 */                                                                \
			bpf_probe_read_kernel_str(event->target, sizeof(event->target),    \
									  target_str);                             \
			bpf_ringbuf_submit(event, 0);                                      \
		}                                                                      \
		bpf_printk(log_msg);                                                   \
		return -EPERM;                                                         \
	}                                                                          \
	return 0;

/*
 * Defense Heuristic : Architecture Tampering (Config & Binary)
 * Hooks into the file opening lifecycle to enforce an immutable O_RDONLY
 * policy for critical EDR files for all unprivileged users. This acts as a
 * mandatory access control fail-safe even if a sysadmin accidentally executes
 * `chmod 777 /etc/bouclier-bleu/config.toml`.
 */
SEC("lsm/file_open")
int BPF_PROG(shield_file_open, struct file *file) {
	if (!is_module_active(&state_map)) {
		return 0;
	}

	unsigned int f_flags = file->f_flags;

	/*
	 * Fast-Path Deferral
	 * If the file is only being opened for reading without truncation, it's
	 * safe. We allow the operation to proceed without incurring string
	 * resolution overhead.
	 */
	if (!((f_flags & O_WRONLY) || (f_flags & O_RDWR) || (f_flags & O_TRUNC))) {
		return 0;
	}

	/*
	 * UID Fast-Path
	 * System daemons (root) are permitted to modify files. Returning early
	 * here saves us from executing expensive BPF_CORE_READs and Map Lookups
	 * for legitimate, high-frequency system I/O.
	 */
	if (get_global_uid() == 0) {
		return 0;
	}

	umode_t i_mode = BPF_CORE_READ(file, f_inode, i_mode);
	if (!S_ISREG(i_mode)) {
		return 0;
	}

	/*
	 * Hardware Validation
	 * Extract the composite hardware IDs directly from the target file's
	 * inode. This bypasses all naming and namespace layers, providing
	 * unevadable identity verification.
	 */
	struct dir_id f_id = {};
	extract_dir_id_from_inode(BPF_CORE_READ(file, f_inode), &f_id);

	__u8 *is_protected = bpf_map_lookup_elem(&protected_files, &f_id);
	if (is_protected && *is_protected == 1) {
		struct shield_alert *event =
			bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
		if (event) {
			BPF_SAFE_MEMSET(event, sizeof(*event));

			event->pid = bpf_get_current_pid_tgid() >> 32;
			event->action_type = ACTION_FILE_TAMPER;

			/*
			 * Telemetry Fallback: Best-effort path resolution for the
			 * alert log. If the path exceeds 4096 bytes (-ENAMETOOLONG),
			 * we skip resolution but still block the event and send the
			 * alert, eliminating the fail-open truncation vulnerability.
			 */
			__u32 key = 0;
			char *path_buf = bpf_map_lookup_elem(&path_buffer_map, &key);
			if (path_buf) {
				long len = bpf_d_path(&file->f_path, path_buf, PATH_MAX);
				if (len > 0 && len != -ENAMETOOLONG) {
					bpf_probe_read_kernel_str(event->target, PATH_MAX,
											  path_buf);
				}
			}
			bpf_ringbuf_submit(event, 0);
		}
		bpf_printk("Bouclier Bleu [BLOCK]: Unauthorized modification of core "
				   "EDR file.\n");
		return -EACCES; // Fail-closed execution block
	}

	return 0;
}

/*
 * Defense Heuristic : EDR Unloading Prevention
 * Advanced malware routinely attempts to unload eBPF programs or detach hooks
 * using the `bpf()` syscall. We strictly gate this syscall to root.
 */
SEC("lsm/bpf")
int BPF_PROG(shield_bpf, int cmd, union bpf_attr *attr, unsigned int size) {
	BOUCLIER_ENFORCE_PRIVILEGE(
		ACTION_BPF_TAMPER, "bpf() syscall invocation",
		"Bouclier Bleu [BLOCK]: Unprivileged bpf() tampering prevented.\n");
}

/*
 * Defense heuristic : KASLR Bypass Prevention
 * The kernel ring buffer (dmesg) contains highly sensitive information,
 * including crash dumps, hardware faults, and kernel pointer addresses.
 * Attackers parse this to bypass Kernel Address Space Layout Randomization
 * (KASLR) to build ROP chains. This enforces `kernel.dmesg_restrict=1`
 * directly at the LSM layer.
 */
SEC("lsm/syslog")
int BPF_PROG(shield_syslog, int type) {
	BOUCLIER_ENFORCE_PRIVILEGE(ACTION_SYSLOG_LEAK, "kernel syslog/dmesg read",
							   "Bouclier Bleu [BLOCK]: Unprivileged dmesg "
							   "kernel info leak prevented.\n");
}
