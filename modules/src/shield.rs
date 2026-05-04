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

use crate::common::fs_utils::get_secure_hardware_key;
use crate::common::traits::{BpfReader, MapProvider};
use crate::define_security_module;
use libbpf_rs::MapCore;

/// Telemetry payload yielded by the `core_shield` BPF hooks.
///
/// Captures unprivileged attempts to modify the EDR configuration, tamper
/// with eBPF subsystem links, or read sensitive kernel ring buffer logs.
#[derive(Debug, serde::Serialize)]
pub struct ShieldAlert {
	pub pid: u32,
	pub action_type: u32,
	pub target: String,
}

impl ShieldAlert {
	/// Safe Deserialization Engine.
	///
	/// Extracts structured fields from the contiguous memory slice provided by
	/// the kernel. Utilizing `try_into()` and `from_utf8_lossy()` entirely
	/// eliminates the need for C-FFI or `unsafe` blocks, neutralizing the risk
	/// of buffer overflows or panics from malformed kernel strings.
	pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
		// Enforce structural boundaries: 4 (u32 PID) + 4 (u32 ACTION) + 4096
		// (PATH_MAX) = 4104 bytes
		if data.len() < 4104 {
			return Err("Telemetry payload violates minimum size constraints.");
		}

		let mut reader = BpfReader::new(data);

		let pid = reader.read_u32()?;
		let action_type = reader.read_u32()?;
		let target = reader.read_string(4096)?;

		Ok(Self {
			pid,
			action_type,
			target,
		})
	}
}

/*
 * Defense Heuristic : Self-Defense Shield
 * Hardens the Bouclier Bleu architecture against direct tampering and LPE
 * (Local Privilege Escalation) primitives. It strictly enforces immutable
 * access controls on critical configuration files via hardware invariants,
 * blocks unprivileged bpf() syscalls to prevent EDR unloading, and locks
 * down dmesg to neutralize KASLR bypasses.
 */
define_security_module!(
	struct: Shield,
	name: "Self-Defense Architecture",
	slug: "shield",
	parser: ShieldAlert::try_from_bytes,
	handler: |alert: ShieldAlert| {
		let action_str = match alert.action_type {
			1 => "FILE_TAMPER",
			2 => "BPF_TAMPER",
			3 => "SYSLOG_LEAK",
			_ => "UNKNOWN_VIOLATION",
		};

		println!(
			"Bouclier Bleu [SHIELD]: Blocked unauthorized action [{}] by PID {} on target: {}",
			action_str, alert.pid, alert.target
		);
	},
	capacities: || -> std::collections::HashMap<String, u32> {
		/*
		 * Map Sizing Heuristic
		 * The shield module currently only protects a statically defined set
		 * of core EDR files. We explicitly allocate exactly what is needed
		 * to minimize the locked memory footprint in the kernel.
		 */
		let mut caps = std::collections::HashMap::new();
		caps.insert("protected_files".to_string(), 2);
		caps
	},
	init: |provider: &dyn MapProvider| -> Result<(), String> {
		let bpf_map = provider.get_map("protected_files")?;

		let target_files = ["/etc/bouclier-bleu/config.toml", "/usr/bin/bouclier-bleu-core"];
		let is_protected: [u8; 1] = [1];

		/*
		 * Hardware-backed File Watchlist Initialization
		 * Threat Model: Static string path matching is inherently vulnerable
		 * to mount namespace evasion (`unshare -m`) and hardlink abuse. By
		 * resolving the physical `inode` and `device ID` of our critical
		 * files at boot, we establish an immutable tracking mechanism that
		 * the kernel hook can validate regardless of how the file is named
		 * or mapped in user-space.
		 */
		for path in target_files {
			let Ok(key_bytes) = get_secure_hardware_key(path) else { continue; };
			if let Err(e) = bpf_map.update(&key_bytes, &is_protected, libbpf_rs::MapFlags::ANY) {
					eprintln!("Bouclier Bleu [WARNING]: Could not protect {}: {}", path, e);
			}
		}
		Ok(())
	}
);
