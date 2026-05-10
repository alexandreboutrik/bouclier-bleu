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

/// Telemetry payload yielded by the `dump_restrict` BPF hooks.
///
/// Captures unprivileged attempts to write a core dump file or alter the
/// dumpable state via prctl(). Uses safe, natively-owned Rust types to prevent
/// lifecycle management issues across the user/kernel boundary.
#[derive(Debug, serde::Serialize)]
pub struct DumpAlert {
	pub pid: u32,
	pub uid: u32,
	pub action_type: u32,
	pub comm: String,
}

impl DumpAlert {
	/// Safe Deserialization Engine.
	///
	/// Extracts structured fields from the contiguous memory slice provided by
	/// the kernel. Utilizing the `BpfReader` utility eliminates the need for
	/// C-FFI or `unsafe` blocks, neutralizing the risk of buffer overflows or
	/// panics from malformed or maliciously tampered kernel strings.
	pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
		/*
		 * Enforce structural boundaries:
		 * 4 (PID) + 4 (UID) + 4 (Action Type) + 16 (Comm) = 28 bytes
		 */
		if data.len() < 28 {
			return Err("Telemetry payload violates minimum size constraints.");
		}

		let mut reader = BpfReader::new(data);

		let pid = reader.read_u32()?;
		let uid = reader.read_u32()?;
		let action_type = reader.read_u32()?;
		// The kernel pads strings with null bytes. We must trim these to
		// ensure clean downstream telemetry logging and string matching.
		let raw_comm = reader.read_string(16)?;
		let comm = raw_comm.trim_matches('\0').to_string();

		Ok(Self {
			pid,
			uid,
			action_type,
			comm,
		})
	}
}

// Telemetry action identifiers bridging the kernel BPF definitions.
const ACTION_COREDUMP_FILE: u32 = 1;
const ACTION_PRCTL_TAMPER: u32 = 2;
const ACTION_PIPED_HANDLER: u32 = 3;

/*
 * Defense Heuristic : Core Dump Disabling (ASLR Bypass Mitigator)
 * Hardens the system against advanced memory corruption exploits. Attackers
 * routinely intentionally crash worker threads to force the kernel to write
 * a core dump, leaking memory layouts to bypass ASLR and construct ROP chains.
 * This module universally denies core dump generation and dumpable-state
 * tampering for all unprivileged processes.
 */
define_security_module!(
	struct: DumpRestrict,
	name: "Unprivileged Dump Restriction",
	slug: "dump_restrict",
	/*
	 * T1003 - OS Credential Dumping
	 * Core dumps routinely contain plaintext credentials, session tokens, and
	 * encryption keys left in the memory space of the crashed process.
	 *
	 * T1068 - Exploitation for Privilege Escalation
	 * Preventing memory layout leaks disrupts the exploit development
	 * lifecycle, specifically the construction of reliable Return-Oriented
	 * Programming (ROP) chains required for local privilege escalation.
	 */
	mitre: ["T1003", "T1068"],
	parser: DumpAlert::try_from_bytes,
	handler: |alert: DumpAlert| {
		let action_str = match alert.action_type {
			ACTION_COREDUMP_FILE => "COREDUMP_GENERATION",
			ACTION_PRCTL_TAMPER => "PRCTL_DUMPABLE_TAMPER",
			ACTION_PIPED_HANDLER => "PIPED_COREDUMP_HANDLER",
			_ => "UNKNOWN_VIOLATION",
		};

		println!(
			"Bouclier Bleu [BLOCK]: PID {} (UID {}) attempted [{}] via process '{}'.",
			alert.pid, alert.uid, action_str, alert.comm
		);
	},
	capacities: || -> std::collections::HashMap<String, u32> {
		/*
		 * Map Sizing Heuristic
		 * We only need to store the singular hardware footprint of the
		 * registered `core_pattern` handler. A capacity of 16 is plenty to
		 * avoid verifier rejection while maintaining a microscopic memory
		 * footprint.
		 */
		let mut caps = std::collections::HashMap::new();
		caps.insert("protected_files".to_string(), 16);
		caps
	},
	init: |provider: &dyn MapProvider| -> Result<(), String> {
		// Initialize the module state to active
		// This guarantees `is_module_active` returns true during the initial
		// boot.
		let state_map = provider.get_map("state_map")?;
		let key = 0u32.to_ne_bytes();
		let val = 1u32.to_ne_bytes();
		state_map.update(&key, &val, libbpf_rs::MapFlags::ANY)
			.map_err(|e| format!("Failed to initialize state_map: {}", e))?;

		// Hardware-backed indexing of the piped core dump handler
		let protected_files = provider.get_map("protected_files")?;

		/*
		 * Temporal Context Resolution
		 * The Rust userland acts as the Control Plane, dynamically evaluating
		 * the host's `/proc/sys/kernel/core_pattern` at boot. If the pattern
		 * dictates a piped usermode helper (e.g., `systemd-coredump` or
		 * `apport`), we calculate its physical Inode + DevID and inject it
		 * into the eBPF map. This allows the kernel hooks to neutralize
		 * hardlink spoofing entirely.
		 */
		let Ok(core_pattern) = std::fs::read_to_string("/proc/sys/kernel/core_pattern") else {
			return Ok(());
		};

		let Some(stripped) = core_pattern.trim().strip_prefix('|') else {
			return Ok(());
		};

		// Extract the absolute binary path (ignoring trailing arguments like
		// %P %u)
		let path_str = stripped.split_whitespace().next().unwrap_or("");
		if path_str.is_empty() {
			return Ok(());
		}

		if let Ok(key_bytes) = get_secure_hardware_key(path_str) {
			let is_protected: [u8; 1] = [1];

			protected_files.update(&key_bytes, &is_protected, libbpf_rs::MapFlags::ANY)
				.map_err(|e| format!("Failed to update protected_files map: {}", e))?;

			println!("Bouclier Bleu [Setup]: Core dump piped handler '{}' indexed.", path_str);
		} else {
			println!("Bouclier Bleu [Warning]: Could not resolve hardware key for piped handler '{}'.", path_str);
		}

		Ok(())
	}
);
