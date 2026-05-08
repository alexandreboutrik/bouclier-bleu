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

use crate::common::traits::BpfReader;
use crate::define_security_module;

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
			_ => "UNKNOWN_VIOLATION",
		};

		println!(
			"Bouclier Bleu [BLOCK]: PID {} (UID {}) attempted [{}] via process '{}'.",
			alert.pid, alert.uid, action_str, alert.comm
		);
	}
	// Note: We omit the `capacities` and `init` closures here because this
	// module relies entirely on the global `state_map` and the standard
	// RingBuffer. It does not require any hardware-backed watchlists or
	// dynamic eBPF Hash maps.
);
