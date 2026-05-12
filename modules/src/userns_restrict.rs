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

/// Telemetry payload yielded by the `userns_restrict` BPF hooks.
///
/// Captures unauthorized container escape primitives, including unprivileged
/// user namespace creation, suspicious capability acquisitions, and physical
/// device mounting attempts inside sandboxes.
#[derive(Debug, serde::Serialize)]
pub struct UsernsAlert {
	pub pid: u32,
	pub action_type: u32,
	pub target: String,
}

impl UsernsAlert {
	/// Safe Deserialization Engine.
	///
	/// Extracts structured fields from the contiguous memory slice provided by
	/// the kernel. Utilizing the `BpfReader` utility eliminates the need for
	/// C-FFI or `unsafe` blocks, neutralizing the risk of buffer overflows or
	/// panics from malformed or maliciously tampered kernel strings.
	pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
		/*
		 * Enforce structural boundaries:
		 * 4 (PID) + 4 (Action Type) + 64 (Target String) = 72 bytes
		 */
		if data.len() < 72 {
			return Err("Telemetry payload violates minimum size constraints.");
		}

		let mut reader = BpfReader::new(data);

		let pid = reader.read_u32()?;
		let action_type = reader.read_u32()?;
		// The kernel pads strings with null bytes. We must trim these to
		// ensure clean downstream telemetry logging and string matching.
		let raw_target = reader.read_string(64)?;
		let target = raw_target.trim_matches('\0').to_string();

		Ok(Self {
			pid,
			action_type,
			target,
		})
	}
}

// Telemetry action identifiers bridging the kernel BPF definitions.
const ACTION_USERNS_CREATE: u32 = 1;
const ACTION_CAP_SYS_ADMIN: u32 = 2;
const ACTION_MOUNT_DEV: u32 = 3;

/*
 * Defense Heuristic : Namespace Escape Monitor
 * Hardens the system against container escape vulnerabilities (e.g., Dirty
 * Pipe, runc exploits). Instantly neutralizes processes inside restricted
 * namespaces (Docker, Flatpak) that attempt to request CAP_SYS_ADMIN, create
 * new isolated user namespaces, or mount the host's physical disks.
 */
define_security_module!(
	struct: UsernsRestrict,
	name: "Namespace Escape Monitor",
	slug: "userns_restrict",
	/*
	 * T1611 - Escape to Host
	 * Blocking unprivileged user namespace creation and restricted operations
	 * inside nested namespaces mitigates advanced container escape techniques
	 * used to transition from a restricted sandbox to root execution on the
	 * host.
	 *
	 * T1068 - Exploitation for Privilege Escalation
	 * Neutralizes privilege escalation vectors by strictly gating capability
	 * grants and sensitive filesystem mounts that attackers use to tamper with
	 * underlying physical constraints.
	 *
	 * T1610 - Deploy Container
	 * T1612 - Build Image on Host
	 * By restricting unprivileged user namespace creation (CLONE_NEWUSER),
	 * the module neutralizes an adversary's ability to utilize daemonless
	 * container engines (e.g., Podman, Buildah) to build malicious images or
	 * deploy rogue containers locally to bypass system-level auditing.
	 */
	mitre: ["T1611", "T1068", "T1610", "T1612"],
	parser: UsernsAlert::try_from_bytes,
	handler: |alert: UsernsAlert| {
		let action_str = match alert.action_type {
			ACTION_USERNS_CREATE => "USER_NAMESPACE_CREATION",
			ACTION_CAP_SYS_ADMIN => "CAP_SYS_ADMIN_ACQUISITION",
			ACTION_MOUNT_DEV => "PHYSICAL_DEVICE_MOUNT",
			_ => "UNKNOWN_VIOLATION",
		};

		println!(
			"Bouclier Bleu [BLOCK]: PID {} attempted container escape primitive [{}] targeting: {}.",
			alert.pid, action_str, alert.target
		);
	}
	// Note: We omit the `capacities` and `init` closures here because this
	// module relies entirely on the global `state_map` and the standard
	// RingBuffer. It does not require any hardware-backed watchlists or
	// dynamic eBPF Hash maps setup.
);
