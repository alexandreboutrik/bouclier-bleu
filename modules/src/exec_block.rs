// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 The Bouclier Bleu Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{BpfReader, define_security_module};
use walkdir::WalkDir;

/// Telemetry payload yielded by the `exec_block` BPF hook.
///
/// Represents an attempt to execute a binary from a world-writable directory.
/// Uses safe, natively-owned Rust types to prevent lifecycle management
/// issues.
#[derive(Debug)]
pub struct ExecAlert {
	pub pid: u32,
	pub path: String,
}

impl ExecAlert {
	/// Safe Deserialization Engine.
	///
	/// Extracts structured fields from the contiguous memory slice provided by
	/// the kernel. Utilizing `try_into()` and `from_utf8_lossy()` entirely
	/// eliminates the need for C-FFI or `unsafe` blocks, neutralizing the risk
	/// of buffer overflows or panics from malformed kernel strings.
	pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
		// Enforce structural boundaries: 4 (u32 PID) + 4096 (PATH_MAX)
		if data.len() < 4100 {
			return Err("Telemetry payload violates minimum size constraints.");
		}

		let mut reader = BpfReader::new(data);

		let pid = reader.read_u32()?;
		let path = reader.read_string(4096)?;

		Ok(Self { pid, path })
	}
}

/*
 * DEFENSE HEURISTIC: WORLD-WRITABLE EXECUTION BLOCK
 * Memory corruption exploits and web-shell droppers frequently lack the
 * privileges required to write to protected directories (/usr/bin). They rely
 * on world-writable paths (/tmp, /dev/shm) to stage secondary payloads.
 * This module blocks those executions using a hardware-backed directory
 * watchlist to remain resilient against mount namespace spoofing.
 */
define_security_module!(
	struct: ExecBlock,
	name: "Untrusted Path Execution Prevention",
	slug: "exec_block",
	parser: ExecAlert::try_from_bytes,
	handler: |alert: ExecAlert| {
		println!(
			"Bouclier Bleu [BLOCK]: PID {} attempted execution from protected path: {}",
			alert.pid, alert.path
		);
	},
	capacities: || -> std::collections::HashMap<String, u32> {
		/*
		 * JUST-IN-TIME (JIT) PROTECTED_DIRS MAP SIZING HEURISTIC
		 * To maintain a lightweight EDR footprint, we perform a rapid pre-scan
		 * of the target world-writable directories before instructing the
		 * kernel to allocate memory. We apply a 1.25x scaling factor (25%
		 * safety buffer) to accommodate future directory creations during the
		 * system's uptime.
		 */
		let mut count = 0;
		let target_paths = ["/tmp", "/var/tmp", "/dev/shm", "/var/crash", "/dev/mqueue", "/run/user"];

		for path in target_paths {
			for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
				if entry.file_type().is_dir() {
					count += 1;
				}
			}
		}

		// Apply a 25% safety buffer for new directories, with an absolute
		// minimum of 8192
		let safe_capacity = ((count as f64 * 1.25) as u32).max(8192);

		let mut caps = std::collections::HashMap::new();
		caps.insert("protected_dirs".to_string(), safe_capacity);
		caps
	},
	init: |provider: &dyn crate::MapProvider| -> Result<(), String> {
		let bpf_map = provider.get_map("protected_dirs")?;

		let target_paths = ["/tmp", "/var/tmp", "/dev/shm", "/var/crash", "/dev/mqueue", "/run/user"];
		let is_protected: [u8; 1] = [1];

		/*
		 * HARDWARE-BACKED DIRECTORY WATCHLIST INITIALIZATION
		 * Threat Model: Advanced adversaries routinely use mount namespaces
		 * (`unshare -m`) or bind-mounts to obfuscate paths and bypass
		 * string-matching security heuristics. To neutralize this, the
		 * userland daemon resolves the exact physical `inode` of
		 * world-writable directories at boot. These hardware-level identifiers
		 * are passed to the kernel via the `protected_dirs` eBPF Map.
		 */
		for path in target_paths {
			println!("Bouclier Bleu [Setup]: Recursively indexing volatile path {}...", path);

			for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
				// System-level Inode Extraction
				if entry.file_type().is_dir() {
					if let Ok(key_bytes) = crate::get_secure_hardware_key(entry.path()) {
			bpf_map.update(&key_bytes, &is_protected, libbpf_rs::MapFlags::ANY)
				.map_err(|e| format!("CRITICAL: Map update failed for {}: {}", entry.path().display(), e))?;
		}
				}
			}
		}
		Ok(())
	}
);
