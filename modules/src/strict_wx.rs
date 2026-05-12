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
	/*
	 * T1055 - Process Injection
	 * Preventing memory allocations from requesting PROT_WRITE | PROT_EXEC
	 * (and blocking sequential transitions) neutralizes almost all forms of
	 * shellcode injection, hollow process injection, and dynamic payload
	 * execution.
	 *
	 * T1620 - Reflective Code Loading
	 * W^X enforcement also severely limits an attacker's ability to map
	 * malicious shared libraries (.so) into memory dynamically without
	 * touching the disk.
	 *
	 * T1027.002 - Obfuscated Files or Information: Software Packing
	 * Packers must decompress or decrypt their payload dynamically in memory.
	 * Denying PROT_WRITE | PROT_EXEC allocations directly starves packers of
	 * the memory states required to unwrap and execute their obfuscated code.
	 */
	mitre: ["T1055", "T1620", "T1027.002"],
	parser: StrictWxAlert::try_from_bytes,
	handler: |alert: StrictWxAlert| {
		println!(
			"Bouclier Bleu [BLOCK]: PID {} attempted shellcode injection via PROT_WRITE | PROT_EXEC on {}.",
			alert.pid, alert.syscall
		);
	},
	/*
	 * Declarative Hardware-Backed Watchlist
	 * Automatically compiles the strict W^X policy allowed-list at daemon
	 * startup, eliminating the massive overhead of reading extended attributes
	 * inside the eBPF fast-path.
	 */
	xattr_watchlist: {
		map_name: "strict_wx_binaries",
		attribute: "user.bouclier.strict_wx",
		target_paths: ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/opt"]
	}
);
