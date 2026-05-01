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

#define NAME_MAX 255

/* Scaled Entropy Threshold (4.2 * 1024 = 4300)
 * Legitimate files rarely exceed 3.8 Shannon entropy. Ransomware payloads
 * typically generate highly randomized extensions and names, hitting 4.5+.
 */
#define ENTROPY_THRESHOLD_SCALED 4300

/**
 * struct rename_alert - Telemetry Payload Contract for Entropy Anomalies
 * @pid: The Process ID originating the malicious rename attempt.
 * @dir_path: The canonicalized destination directory path.
 * @file_name: The destination filename resulting from the rename operation.
 *
 * Memory layout must strictly mirror the `RenameAlert` struct in the Rust
 * userland to ensure safe zero-copy deserialization over the ring buffer.
 */
struct rename_alert {
	__u32 pid;
	__u32 ppid;
	char dir_path[PATH_MAX];
	char file_name[256];
};

BOUCLIER_PATH_BUFFER_MAP;
BOUCLIER_PROTECTED_DIRS_MAP;
BOUCLIER_MODULE_ALERTS;
BOUCLIER_MODULE_STATE_MAP;

/**
 * struct entropy_scratch - Entropy Calculation Workspace
 * @name: Buffer to hold the extracted target filename.
 * @counts: Byte-frequency array for Shannon entropy calculations.
 *
 * Allocating arrays for string extraction and byte frequency counting directly
 * would immediately exceed the eBPF stack limit. This structure represents the
 * off-stack workspace.
 */
struct entropy_scratch {
	char name[256];
	__u8 counts[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct entropy_scratch);
	__uint(max_entries, 1);
} scratch_map SEC(".maps");

/**
 * scaled_log2 - Pre-computed Logarithm Lookup Table
 *
 * The eBPF virtual machine lacks native floating-point support and standard
 * math libraries. To calculate Shannon Entropy in kernel-space, we use a
 * pre-computed lookup table representing `floor(log2(x) * 1024)`. This
 * eliminates complex branching logic and loop unrolling, completely bypassing
 * the verifier's strict instruction complexity and backward-edge limits.
 */
static const __u32 scaled_log2[256] = {
	0,	  0,	1024, 1623, 2048, 2377, 2647, 2874, 3072, 3246, 3401, 3542,
	3671, 3790, 3900, 4004, 4100, 4191, 4276, 4356, 4432, 4504, 4572, 4638,
	4700, 4760, 4817, 4872, 4925, 4976, 5026, 5074, 5120, 5164, 5208, 5250,
	5291, 5332, 5371, 5410, 5448, 5485, 5521, 5557, 5592, 5626, 5660, 5693,
	5726, 5758, 5789, 5820, 5851, 5881, 5910, 5939, 5968, 5996, 6024, 6052,
	6079, 6106, 6132, 6158, 6184, 6209, 6234, 6259, 6283, 6307, 6331, 6355,
	6378, 6401, 6424, 6446, 6468, 6490, 6512, 6533, 6555, 6576, 6596, 6617,
	6638, 6658, 6678, 6698, 6718, 6737, 6757, 6776, 6795, 6814, 6833, 6851,
	6870, 6888, 6906, 6924, 6942, 6960, 6977, 6995, 7012, 7029, 7046, 7063,
	7080, 7096, 7113, 7129, 7145, 7161, 7177, 7193, 7209, 7224, 7240, 7255,
	7270, 7285, 7300, 7315, 7330, 7345, 7359, 7374, 7388, 7402, 7416, 7430,
	7444, 7458, 7472, 7486, 7499, 7513, 7526, 7540, 7553, 7566, 7579, 7592,
	7605, 7618, 7631, 7643, 7656, 7668, 7681, 7693, 7705, 7718, 7730, 7742,
	7754, 7766, 7778, 7789, 7801, 7813, 7824, 7836, 7847, 7859, 7870, 7881,
	7892, 7903, 7914, 7925, 7936, 7947, 7958, 7969, 7979, 7990, 8000, 8011,
	8021, 8032, 8042, 8052, 8062, 8072, 8083, 8093, 8103, 8113, 8123, 8132,
	8142, 8152, 8162, 8171, 8181, 8191, 8200, 8210, 8219, 8229, 8238, 8247,
	8257, 8266, 8275, 8284, 8294, 8303, 8312, 8321, 8330, 8339, 8348, 8356,
	8365, 8374, 8383, 8392, 8400, 8409, 8418, 8426, 8435, 8443, 8452, 8460,
	8469, 8477, 8485, 8494, 8502, 8510, 8518, 8527, 8535, 8543, 8551, 8559,
	8567, 8575, 8583, 8591, 8599, 8607, 8615, 8622, 8630, 8638, 8646, 8653,
	8661, 8669, 8676, 8684};

/*
 * Byte Frequency Aggregation
 * Iterate over the filename to populate the frequency array.
 * __noinline prevents verifier state explosion by verifying this exactly once.
 */
static __noinline void
calculate_character_counts(struct entropy_scratch *scratch) {
	for (int i = 0; i < NAME_MAX; i++) {
		__u8 c = scratch->name[i];
		if (c == '\0')
			break; // stop counting if we hit the end of the filename
		scratch->counts[c]++;
	}
}

/*
 * Integer-Math Shannon Entropy
 * Calculates the entropy using our precomputed lookup table.
 * The bitwise mask on `c` (`c & 0xFF`) guarantees to the verifier that
 * the lookup into the `scaled_log2` array remains within the 0-255 bounds.
 * __noinline prevents verifier state explosion by verifying this exactly once.
 */
static __noinline __u32 compute_entropy(struct entropy_scratch *scratch) {
	__u32 sum_c_log_c = 0;

	for (int i = 0; i < 256; i++) {
		__u32 c = scratch->counts[i] & 0xFF;
		if (c == 0)
			continue; // skip math for chars not present in the fname
		sum_c_log_c += c * scaled_log2[c];
	}

	return sum_c_log_c;
}

SEC("lsm/path_rename")
int BPF_PROG(rename_entropy_path_rename, const struct path *old_dir,
			 struct dentry *old_dentry, const struct path *new_dir,
			 struct dentry *new_dentry, unsigned int flags) {
	__u32 key = 0;
	char *dir_buf;
	struct entropy_scratch *scratch;
	long len;
	struct rename_alert *event;

	if (!is_module_active(&state_map)) {
		return 0;
	}

	scratch = bpf_map_lookup_elem(&scratch_map, &key);
	if (!scratch) {
		return 0;
	}

	/*
	 * State Initialization
	 * We must manually zero-out the scratch memory to prevent
	 * cross-pollination from previous hook executions, which would
	 * artificially inflate entropy scores for subsequent, shorter filenames.
	 */
	__builtin_memset(scratch->name, 0, sizeof(scratch->name));
	__builtin_memset(scratch->counts, 0, sizeof(scratch->counts));

	/*
	 * Cross-Directory Migration Evasion Prevention
	 * Ransomware may attempt to evade detection by moving a target file out
	 * of a protected directory into a temporary, unmonitored staging area
	 * (e.g., /tmp) during the rename syscall. We validate the composite IDs
	 * of both the source and destination directories. If either resides within
	 * the protected watchlist, the operation is subjected to entropy analysis.
	 */
	struct dir_id old_id = {};
	struct dir_id new_id = {};

	extract_dir_id_from_dentry(BPF_CORE_READ(old_dir, dentry), &old_id);
	extract_dir_id_from_dentry(BPF_CORE_READ(new_dir, dentry), &new_id);

	__u8 *old_protected = bpf_map_lookup_elem(&protected_dirs, &old_id);
	__u8 *new_protected = bpf_map_lookup_elem(&protected_dirs, &new_id);

	if ((!old_protected || *old_protected == 0) &&
		(!new_protected || *new_protected == 0)) {
		return 0; // Neither boundary is protected, safely ignore the event
	}

	/* Target Filename Extraction */
	__u32 original_nlen = BPF_CORE_READ(new_dentry, d_name.len);
	__u32 nlen = original_nlen;

	/*
	 * Secure bounds clamping to satisfy the verifier without wrap-around
	 * vulnerabilities (&= 0xFF).
	 */
	if (nlen > 255) {
		nlen = 255;
	}

	// Entropy math is irrelevant for very short names
	if (nlen < 8 || nlen > NAME_MAX) {
		return 0;
	}

	const unsigned char *name_ptr = BPF_CORE_READ(new_dentry, d_name.name);

	/*
	 * Memory-Boundary Safe Extraction
	 * Utilizing `bpf_probe_read_kernel_str` instead of a fixed-size block copy
	 * instructs the VM to halt at the null terminator or physical page
	 * boundary. This prevents fatal `-EFAULT` drops caused by attempting to
	 * traverse unmapped memory regions when a filename resides at the very
	 * edge of a kernel memory page.
	 */
	bpf_probe_read_kernel_str(scratch->name, sizeof(scratch->name), name_ptr);

	/*
	 * False-Positive Mitigation: Extension Whitelisting
	 * Benign operations (e.g., git objects, temporary swap files) often
	 * generate highly randomized filenames that inherently trip entropy
	 * heuristics. We inspect the suffix directly in memory to bypass
	 * calculation for known safe extensions, reducing false positives in
	 * critical system paths. Use original_nlen instead of nlen to prevent
	 * truncation bugs.
	 */
	if (original_nlen >= 4 && original_nlen <= 255) {
		int dot_pos = -1;

/*
 * Traverse from the end of the string to find the true extension
 * boundary, preventing bypasses where attackers append benign
 * extensions to malicious ones (e.g., malware.locked.log)
 */
#pragma unroll
		for (int i = 0; i < 8; i++) {
			int idx = nlen - 1 - i;
			if (idx < 0)
				break;

			if (scratch->name[idx & 0xFF] == '.') {
				dot_pos = idx;
				break; // True extension boundary found
			}
		}

		if (dot_pos > 0 && (original_nlen - dot_pos) <= 5) {
			/*
			 * eBPF Verifier Bounds Guarantee (& 0xFF)
			 * The eBPF verifier tracks the maximum possible value of all
			 * variables to prevent out-of-bounds memory access. When doing
			 * pointer arithmetic or array indexing (like `scratch->name[i1]`),
			 * the verifier must be mathematically certain the index won't
			 * exceed the array size (256 bytes).
			 * 0xFF in binary is 11111111 (255). By applying a bitwise AND
			 * (& 0xFF) to our calculated index, we truncate any higher bits.
			 * This mathematically proves to the Verifier that the resulting
			 * integer can NEVER be larger than 255.
			 */
			__u32 i1 = (dot_pos + 1) & 0xFF;
			__u32 i2 = (dot_pos + 2) & 0xFF;
			__u32 i3 = (dot_pos + 3) & 0xFF;

			if (scratch->name[i1] == 'l' && scratch->name[i2] == 'o' &&
				scratch->name[i3] == 'g')
				return 0;
			if (scratch->name[i1] == 'g' && scratch->name[i2] == 'i' &&
				scratch->name[i3] == 't')
				return 0;
			if (scratch->name[i1] == 't' && scratch->name[i2] == 'm' &&
				scratch->name[i3] == 'p')
				return 0;
			if (scratch->name[i1] == 's' && scratch->name[i2] == 'w' &&
				scratch->name[i3] == 'p')
				return 0;
		}
	}

	calculate_character_counts(scratch);
	__u32 sum_c_log_c = compute_entropy(scratch);

	/*
	 * Safeguard nlen with a mask to prove to the verifier it won't exceed the
	 * array size, and prevent division-by-zero panics in the virtual machine.
	 */
	__u32 safe_nlen = (nlen > 0) ? nlen : 1;
	__u32 h_scaled = scaled_log2[safe_nlen & 0xFF] - (sum_c_log_c / safe_nlen);

	/*
	 * Enforcement & Telemetry
	 */
	if (h_scaled > ENTROPY_THRESHOLD_SCALED) {
		event = bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
		if (event) {
			/*
			 * CO-RE Process Lineage Extraction
			 * Use BPF_CORE_READ to safely walk the task_struct hierarchy.
			 * Extracting the real_parent allows the userland daemon to map
			 * isolated worker threads back to the orchestrator.
			 */
			struct task_struct *task = bpf_get_current_task_btf();
			event->ppid = BPF_CORE_READ(task, real_parent, tgid);

			event->pid = bpf_get_current_pid_tgid() >> 32;

			dir_buf = bpf_map_lookup_elem(&path_buffer_map, &key);
			if (dir_buf) {
				len = bpf_d_path((struct path *)new_dir, dir_buf, PATH_MAX);
				if (len > 0 && len != -ENAMETOOLONG) {
					bpf_probe_read_kernel_str(event->dir_path,
											  sizeof(event->dir_path), dir_buf);
				}
			}

			bpf_probe_read_kernel_str(event->file_name,
									  sizeof(event->file_name), scratch->name);

			/*
			 * Immediate Neutralization
			 * Now that telemetry is securely buffered, issue SIGKILL (9)
			 * directly from kernel-space to eliminate TOCTOU race conditions.
			 */
			bpf_send_signal(9);
			bpf_ringbuf_submit(event, 0);
		} else {
			/*
			 * Map Exhaustion Fallback
			 * If the ring buffer is full, the system is under extreme load.
			 * We still issue the kill to prevent ransomware encryption, but
			 * this represents a degraded, silent kill.
			 */
			bpf_send_signal(9);
		}
		return -EPERM; // Block the rename atomically in the kernel
	}

	return 0;
}

/*
 * Dynamic Watchlist Inheritance
 * Hooks into the exit of vfs_mkdir. If a new directory is created inside a
 * currently protected directory, we automatically add the new child's inode to
 * the protected_dirs map.
 */
BOUCLIER_GENERATE_MKDIR_HOOKS(rename_entropy, "rename_entropy")

/*
 * Dynamic Watchlist Inheritance (rename)
 * An attacker stages a malicious payload in an unmonitored directory (e.g.
 * /tmp/staging) and moves the entire directory into a protected path like
 * /home/user/. Because moving a directory does not change its inode or trigger
 * `vfs_mkdir`, the system remains blind. This hook monitors directory moves.
 * If an unprotected directory is moved into a currently protected directory,
 * it immediately inherits the parent's protection status.
 */
BOUCLIER_GENERATE_RENAME_HOOK(rename_entropy, "rename_entropy")
