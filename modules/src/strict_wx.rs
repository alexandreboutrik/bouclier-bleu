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

use crate::{define_security_module, BpfReader};
use xattr::FileExt;

/// Telemetry payload yielded by the `strict_wx` BPF hook.
#[derive(Debug, serde::Serialize)]
pub struct StrictWxAlert {
	pub pid: u32,
	pub syscall: String,
}

impl StrictWxAlert {
	/// Safe Deserialization Engine.
	pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
		/*
		 * Enforce structural boundaries:
		 * 4 (PID) + 16 (syscall_name) = 20 bytes
		 */
		if data.len() < 20 {
			return Err("Telemetry payload violates minimum size constraints.");
		}

		let mut reader = BpfReader::new(data);

		let pid = reader.read_u32()?;
		let syscall = reader.read_string(16)?;

		Ok(Self { pid, syscall })
	}
}

/*
 * Defense Heuristic : Strict Write XOR Execute (W^X)
 * Mitigates shellcode injection and advanced in-memory staging (like hollow
 * process injection or dynamic reflective DLL loading). Because enforcing
 * strict W^X system-wide breaks JIT compilers (e.g., Python, Node.js, JVM),
 * this module is purely OPT-IN. It pre-scans system paths at boot for the
 * `user.bouclier.strict_wx` extended attribute.
 */
define_security_module!(
	struct: StrictWx,
	name: "Strict Write XOR Execute (W^X)",
	slug: "strict_wx",
	parser: StrictWxAlert::try_from_bytes,
	handler: |alert: StrictWxAlert| {
		println!(
			"Bouclier Bleu [BLOCK]: PID {} attempted shellcode injection via PROT_WRITE | PROT_EXEC on {}.",
			alert.pid, alert.syscall
		);
	},
	capacities: || -> std::collections::HashMap<String, u32> {
		let mut count = 0;
		let target_paths = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/opt"];

		for path in target_paths {
			for entry in crate::build_secure_walker(path).filter_map(|e| e.ok()) {
				if entry.file_type().is_file() {
					count += 1;
				}
			}
		}

		// Apply a 25% safety buffer for future installations, with a fallback
		// floor of 2048
		let safe_capacity = ((count as f64 * 1.25) as u32).max(2048);

		let mut caps = std::collections::HashMap::new();
		caps.insert("strict_wx_binaries".to_string(), safe_capacity);
		caps
	},
	init: |provider: &dyn crate::MapProvider| -> Result<(), String> {
		let bpf_map = provider.get_map("strict_wx_binaries")?;

		// Standard system binary staging directories
		let target_paths = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/opt"];
		let is_protected: [u8; 1] = [1];

		/*
		 * Hardware-backed Extended Attribute Watchlist
		 * To eliminate the massive overhead of reading extended attributes
		 * inside the eBPF fast-path during every memory allocation, we index
		 * opted-in binaries during daemon startup.
		 */
		for path in target_paths {
			println!("Bouclier Bleu [Setup]: Scanning {} for strict_wx opt-in attributes...", path);

			for entry in crate::build_secure_walker(path).filter_map(|e| e.ok()) {
				if entry.file_type().is_file() {
					/*
					 * TOCTOU Race Condition Mitigation
					 * By avoiding the path-based xattr::get entirely and
					 * opening the file descriptor directly with O_NOFOLLOW, we
					 * completely neutralize the window where an attacker could
					 * swap the target binary for a malicious symlink.
					 */
					if let Ok(fd) = rustix::fs::openat(
						rustix::fs::CWD,
						entry.path(),
						rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
						rustix::fs::Mode::empty(),
					) {
						let file = std::fs::File::from(fd);
						if let Ok(Some(fd_xattr)) = file.get_xattr("user.bouclier.strict_wx") {
							if fd_xattr == b"1" {
								if let Ok(metadata) = file.metadata() {
									let key_bytes = crate::generate_hardware_key(&metadata);

									/*
									 * Strict Map Exhaustion Handling
									 * Catch and crash early if the BPF
									 * map runs out of bounds rather
									 * than silently failing open.
									 */
									if let Err(e) = bpf_map.update(&key_bytes, &is_protected, libbpf_rs::MapFlags::ANY) {
										return Err(format!("CRITICAL: strict_wx_binaries map failed to update: {}", e));
									}

									println!("Bouclier Bleu [Setup]: W^X strict enforcement activated for {:?}", entry.path());
								}
							}
						}
					}
				}
			}
		}
		Ok(())
	}
);
