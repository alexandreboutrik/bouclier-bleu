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

use crate::common::fs_utils::{build_secure_walker, generate_hardware_key};
use crate::common::traits::{BpfReader, MapProvider};
use crate::define_security_module;
use libbpf_rs::MapCore;
use xattr::FileExt;

/// Telemetry payload yielded by the `io_restrict` BPF hooks.
///
/// Captures unauthorized attempts to instantiate high-speed asynchronous I/O
/// rings (io_uring) or manipulate zero-copy pipelines (splice/vmsplice) often
/// leveraged by modern ransomware and privilege escalation exploits.
#[derive(Debug, serde::Serialize)]
pub struct IoRestrictAlert {
	pub pid: u32,
	pub action_type: u32,
	pub syscall: String,
}

impl IoRestrictAlert {
	/// Safe Deserialization Engine.
	///
	/// Extracts structured fields from the contiguous memory slice provided by
	/// the kernel. Utilizing the `BpfReader` utility eliminates the need for
	/// C-FFI or `unsafe` blocks, neutralizing the risk of buffer overflows or
	/// panics from malformed or maliciously tampered kernel strings.
	pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
		/*
		 * Enforce structural boundaries:
		 * 4 (PID) + 4 (Action Type) + 16 (Syscall Name) = 24 bytes
		 */
		if data.len() < 24 {
			return Err("Telemetry payload violates minimum size constraints.");
		}

		let mut reader = BpfReader::new(data);

		let pid = reader.read_u32()?;
		let action_type = reader.read_u32()?;
		// The kernel pads strings with null bytes. We must trim these to
		// ensure clean downstream telemetry logging and string matching.
		let raw_syscall = reader.read_string(16)?;
		let syscall = raw_syscall.trim_matches('\0').to_string();

		Ok(Self {
			pid,
			action_type,
			syscall,
		})
	}
}

// Telemetry action identifiers bridging the kernel BPF definitions.
const ACTION_IO_URING: u32 = 1;
const ACTION_VMSPLICE: u32 = 2;
const ACTION_SPLICE: u32 = 3;

/*
 * Defense Heuristic : I/O Confinement Monitor
 * Hardens the kernel's advanced I/O pathways against exploitation. Limits
 * `io_uring_setup` to explicitly authorized high-performance binaries,
 * stripping ransomware of the ability to encrypt disks asynchronously at
 * maximum queue depth. Simultaneously blocks unprivileged use of `vmsplice`
 * to neutralize zero-copy memory corruption exploits (e.g., Dirty Pipe and
 * Dirty Frag).
 */
define_security_module!(
	struct: IoRestrict,
	name: "I/O Confinement Monitor",
	slug: "io_restrict",
	/*
	 * T1486 - Data Encrypted for Impact
	 * By blocking unauthorized io_uring_setup calls, the module prevents
	 * ransomware from utilizing kernel-level asynchronous I/O to maximize
	 * storage throughput during the encryption phase.
	 *
	 * T1068 - Exploitation for Privilege Escalation
	 * Confining splice and blocking vmsplice neutralizes critical primitives
	 * required by adversaries to execute zero-copy pipe buffer overwrites
	 * (e.g., CVE-2022-0847).
	 */
	mitre: ["T1486", "T1068"],
	parser: IoRestrictAlert::try_from_bytes,
	handler: |alert: IoRestrictAlert| {
		let action_str = match alert.action_type {
			ACTION_IO_URING => "ASYNC_IO_SETUP",
			ACTION_VMSPLICE => "ZERO_COPY_VMSPLICE",
			ACTION_SPLICE => "ZERO_COPY_SPLICE",
			_ => "UNKNOWN_IO_VIOLATION",
		};

		println!(
			"Bouclier Bleu [BLOCK]: PID {} attempted restricted I/O primitive [{}] via {}.",
			alert.pid, action_str, alert.syscall
		);
	},
	capacities: || -> std::collections::HashMap<String, u32> {
		/*
		 * JIT Map Sizing Heuristic
		 * We traverse the filesystem exactly as we do for `strict_wx` to
		 * establish a precise upper bound for the BPF Map allocation before
		 * loading the eBPF program, avoiding severe memory lock overheads.
		 */
		let mut count = 0;
		let target_paths = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/opt"];

		for path in target_paths {
			for entry in build_secure_walker(path).filter_map(|e| e.ok()) {
				if entry.file_type().is_file() {
					count += 1;
				}
			}
		}

		// Apply a 25% safety buffer for future installations, with a fallback
		// floor of 2048
		let safe_capacity = ((count as f64 * 1.25) as u32).max(2048);

		let mut caps = std::collections::HashMap::new();
		caps.insert("io_restrict_binaries".to_string(), safe_capacity);
		caps
	},
	init: |provider: &dyn MapProvider| -> Result<(), String> {
		let bpf_map = provider.get_map("io_restrict_binaries")?;

		// Standard system binary staging directories
		let target_paths = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/opt"];
		let is_whitelisted: [u8; 1] = [1];

		/*
		 * Hardware-backed Extended Attribute Watchlist
		 * We utilize the `user.bouclier.io_restrict` extended attribute
		 * mechanism to authorize specific system binaries for high-performance
		 * `io_uring` capabilities. This unified opt-in model simplifies system
		 * administration while maintaining hardware-backed TOCTOU resilience.
		 */
		for path in target_paths {
			println!("Bouclier Bleu [Setup]: Scanning {} for io_restrict authorized I/O daemons...", path);

			for entry in build_secure_walker(path).filter_map(|e| e.ok()) {
				if entry.file_type().is_file() {
					/*
					 * TOCTOU Race Condition Mitigation
					 * By avoiding the path-based xattr::get entirely and
					 * opening the file descriptor directly with O_NOFOLLOW, we
					 * neutralize the window where an attacker could swap the
					 * target binary for a malicious symlink.
					 */
					if let Ok(fd) = rustix::fs::openat(
						rustix::fs::CWD,
						entry.path(),
						rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
						rustix::fs::Mode::empty(),
					) {
						let file = std::fs::File::from(fd);
						match file.get_xattr("user.bouclier.io_restrict") {
							Ok(Some(fd_xattr)) if fd_xattr == b"1" => {
								if let Ok(metadata) = file.metadata() {
									let key_bytes = generate_hardware_key(&metadata);

									/*
									 * Strict Map Exhaustion Handling
									 */
									if let Err(e) = bpf_map.update(&key_bytes, &is_whitelisted, libbpf_rs::MapFlags::ANY) {
										return Err(format!("CRITICAL: io_restrict_binaries map failed to update: {}", e));
									}

									println!("Bouclier Bleu [Setup]: High-speed asynchronous I/O (io_uring) authorized for {:?}", entry.path());
								}
							}
							_ => {}
						}
					}
				}
			}
		}
		Ok(())
	}
);
