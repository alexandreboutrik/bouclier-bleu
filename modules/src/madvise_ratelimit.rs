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

/// Telemetry payload yielded by the `madvise_ratelimit` BPF tracepoint.
///
/// Captures race condition exploitation attempts (e.g., Dirty Cow or UAF heap
/// grooming) where a thread rapidly spams memory advisory syscalls to
/// confuse the kernel. Uses safe, natively-owned Rust types to prevent
/// lifecycle management issues across the user/kernel boundary.
#[derive(Debug, serde::Serialize)]
pub struct MadviseAlert {
	pub pid: u32,
	pub tid: u32,
	pub count: u32,
	pub action_type: u32,
	pub comm: String,
}

impl MadviseAlert {
	/// Safe Deserialization Engine.
	///
	/// Extracts structured fields from the contiguous memory slice provided by
	/// the kernel. Utilizing the `BpfReader` utility eliminates the need for
	/// C-FFI or `unsafe` blocks, neutralizing the risk of buffer overflows or
	/// panics from malformed or maliciously tampered kernel strings.
	pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
		/*
		 * Enforce structural boundaries:
		 * 4 (PID) + 4 (TID) + 4 (Count) + 4 (Action Type) + 16 (Comm) = 32
		 * bytes
		 */
		if data.len() < 32 {
			return Err("Telemetry payload violates minimum size constraints.");
		}

		let mut reader = BpfReader::new(data);

		let pid = reader.read_u32()?;
		let tid = reader.read_u32()?;
		let count = reader.read_u32()?;
		let action_type = reader.read_u32()?;
		// The kernel pads strings with null bytes. We must trim these to
		// ensure clean downstream telemetry logging and string matching.
		let raw_comm = reader.read_string(16)?;
		let comm = raw_comm.trim_matches('\0').to_string();

		Ok(Self {
			pid,
			tid,
			count,
			action_type,
			comm,
		})
	}
}

// Telemetry action identifiers bridging the kernel BPF definitions.
const ACTION_MADVISE_SPAM: u32 = 1;

/*
 * Defense Heuristic : Race Condition Mitigator (Dirty Cow / UAF)
 * Hardens the system against advanced memory corruption and page-fault race
 * conditions. Exploits like Dirty Cow rely on rapidly invoking
 * `madvise(MADV_DONTNEED)` millions of times in a tight loop to force the
 * kernel to drop page references at the exact wrong moment. This module
 * evaluates the frequency of these calls per-thread, instantly terminating
 * the attacker if they exceed human or benign application limits.
 */
define_security_module!(
	struct: MadviseRatelimit,
	name: "Race Condition Mitigator",
	slug: "madvise_ratelimit",
	/*
	 * T1068 - Exploitation for Privilege Escalation
	 * By neutralizing the prerequisite race condition loop necessary for
	 * Copy-on-Write (COW) or Use-After-Free (UAF) exploits, we disrupt the
	 * core mechanism attackers use to elevate privileges from a local user to
	 * root.
	 */
	mitre: ["T1068"],
	parser: MadviseAlert::try_from_bytes,
	handler: |alert: MadviseAlert| {
		let action_str = match alert.action_type {
			ACTION_MADVISE_SPAM => "MADVISE_RACE_CONDITION",
			_ => "UNKNOWN_VIOLATION",
		};

		println!(
			"Bouclier Bleu [BLOCK]: Process '{}' (PID {}, TID {}) neutralized for attempting [{}] with {} loop iterations.",
			alert.comm, alert.pid, alert.tid, action_str, alert.count
		);
	}
	// Note: We omit `capacities` and `init` closures here. The BPF map
	// `madvise_tracking_map` is an LRU Hash managed entirely inside the kernel
	// for lock-free performance, requiring no pre-population of hardware IDs
	// or targets from userland.
);
