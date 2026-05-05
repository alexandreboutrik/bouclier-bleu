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

/// Telemetry payload yielded by the `mount_secure` BPF hook.
#[derive(Debug, serde::Serialize)]
pub struct MountAlert {
	pub pid: u32,
	pub dev_name: String,
	pub fs_type: String,
	pub mount_point: String,
}

impl MountAlert {
	/// Safe Deserialization Engine.
	pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
		/*
		 * Enforce structural boundaries:
		 * 4 (PID) + 256 (dev_name) + 64 (fs_type) + 512 (mount_point) = 836
		 */
		if data.len() < 836 {
			return Err("Telemetry payload violates minimum size constraints.");
		}

		let mut reader = BpfReader::new(data);

		let pid = reader.read_u32()?;
		let dev_name = reader.read_string(256)?;
		let fs_type = reader.read_string(64)?;
		let mount_point = reader.read_string(512)?;

		Ok(Self {
			pid,
			dev_name,
			fs_type,
			mount_point,
		})
	}
}

/*
 * Defense Heuristic : Removable Media Neutralizer
 * Strips physical USB drops of their ability to execute binaries or escalate
 * privileges. Hooks into the VFS mount layer to guarantee that removable media
 * strictly enforces MS_NOEXEC, MS_NOSUID, and MS_NODEV flags.
 * To prevent arbitrary filesystem evasions (e.g., ext4 on USB), this module
 * enforces checks on both standard hardware prefixes (/dev/sd*, /dev/mmc*)
 * and universal removable mount paths (/media, /mnt, /run/media).
 */
define_security_module!(
	struct: MountSecure,
	name: "Removable Media Neutralizer",
	slug: "mount_secure",
	/*
	 * T1200 - Hardware Additions
	 * Intercepting mounts from /dev/sd* and /dev/mmcblk*.
	 *
	 * T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid
	 * Enforcing the MS_NOSUID / MNT_NOSUID flags to block privilege escalation
	 * via pre-compiled binaries on the USB.
	 *
	 * T1204.002 - User Execution: Malicious File
	 * Enforcing MS_NOEXEC / MNT_NOEXEC to prevent payload execution from the
	 * mounted device.
	 */
	mitre: ["T1200", "T1548.001", "T1204.002"],
	parser: MountAlert::try_from_bytes,
	handler: |alert: MountAlert| {
		println!(
			"Bouclier Bleu [BLOCK]: PID {} attempted insecure mount of {} ({}) at '{}'. Enforcing MS_NOEXEC, MS_NOSUID, MS_NODEV.",
			alert.pid, alert.dev_name, alert.fs_type, alert.mount_point
		);
	}
);
