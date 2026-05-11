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

/// Telemetry payload yielded by the `ptrace_block` BPF hook.
///
/// Captures unauthorized cross-process memory tampering, hollow process
/// injection, or credential dumping attempts. Uses safe, natively-owned Rust
/// types to prevent lifecycle management issues across the user/kernel
/// boundary.
#[derive(Debug, serde::Serialize)]
pub struct PtraceAlert {
	pub pid: u32,
	pub target_pid: u32,
	pub action_type: u32,
	pub target_comm: String,
}

impl PtraceAlert {
	/// Safe Deserialization Engine.
	///
	/// Extracts structured fields from the contiguous memory slice provided by
	/// the kernel. Utilizing the `BpfReader` utility eliminates the need for
	/// C-FFI or `unsafe` blocks, neutralizing the risk of buffer overflows or
	/// panics from malformed or maliciously tampered kernel strings.
	pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
		/*
		 * Enforce structural boundaries:
		 * 4 (PID) + 4 (Target PID) + 4 (Action Type) + 16 (Target Comm) = 28
		 * bytes
		 */
		if data.len() < 28 {
			return Err("Telemetry payload violates minimum size constraints.");
		}

		let mut reader = BpfReader::new(data);

		let pid = reader.read_u32()?;
		let target_pid = reader.read_u32()?;
		let action_type = reader.read_u32()?;
		// The kernel pads strings with null bytes. We must trim these to
		// ensure clean downstream telemetry logging and string matching.
		let raw_comm = reader.read_string(16)?;
		let target_comm = raw_comm.trim_matches('\0').to_string();

		Ok(Self {
			pid,
			target_pid,
			action_type,
			target_comm,
		})
	}
}

// Telemetry action identifiers bridging the kernel BPF definitions.
const ACTION_CRED_DUMP: u32 = 1;
const ACTION_INJECTION: u32 = 2;
const ACTION_PROC_MEM: u32 = 3;

/*
 * Defense Heuristic : Process Injection & Credential Dumping Prevention
 * Hardens the Linux ptrace capability boundary. It restricts unprivileged
 * processes from attaching to foreign processes to execute hollow process
 * injection (via PTRACE_TRACEME manipulation) and enforces a strict,
 * hardware-backed ring-fence around critical system daemons to prevent memory
 * scraping (credential dumping).
 */
define_security_module!(
	struct: PtraceBlock,
	name: "Process Injection Prevention",
	slug: "ptrace_block",
	/*
	 * T1055 - Process Injection
	 * Blocking unauthorized PTRACE_MODE_ATTACH and unprivileged PTRACE_TRACEME
	 * neutralizes dynamic shellcode staging into remote processes and hollow
	 * process injection.
	 *
	 * T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow (Memory)
	 * Memory scraping of password managers or authentication daemons (like
	 * sshd) via PTRACE_MODE_READ is blocked via the hardware invariant
	 * watchlist, mimicking Windows LSASS protection on Linux.
	 *
	 * T1068 - Exploitation for Privilege Escalation
	 * Neutralizes direct VFS-based memory writes to /proc/**/mem, stopping
	 * exploits and advanced stealth injectors that bypass standard ptrace
	 * hooks.
	 */
	mitre: ["T1055", "T1003.008", "T1068"],
	parser: PtraceAlert::try_from_bytes,
	handler: |alert: PtraceAlert| {
		let action_str = match alert.action_type {
			ACTION_CRED_DUMP => "CREDENTIAL_DUMP",
			ACTION_INJECTION => "PROCESS_INJECTION",
			ACTION_PROC_MEM => "PROC_MEM_TAMPER",
			_ => "UNKNOWN_VIOLATION",
		};

		println!(
			"Bouclier Bleu [BLOCK]: PID {} attempted [{}] against target '{}' (PID {}).",
			alert.pid, action_str, alert.target_comm, alert.target_pid
		);
	},
	capacities: || -> std::collections::HashMap<String, u32> {
		/*
		 * Map Sizing Heuristic
		 * We lock the credential target watchlist to 256 entries. This
		 * provides ample room for custom enterprise daemons while maintaining
		 * a tiny, predictable locked-memory footprint in the kernel.
		 */
		let mut caps = std::collections::HashMap::new();
		caps.insert("protected_processes".to_string(), 256);
		caps
	},
	init: |provider: &dyn MapProvider| -> Result<(), String> {
		let bpf_map = provider.get_map("protected_processes")?;

		// Standard system daemons that handle plaintext credentials, keys, or
		// tokens
		let target_binaries = [
			"/usr/sbin/sshd",
			"/usr/bin/sshd",
			"/usr/sbin/sshd-session",
			"/usr/bin/sshd-session",
			"/usr/bin/passwd",
			"/usr/bin/su",
			"/usr/bin/sudo",

			"/sbin/pam_timestamp_check",
			"/usr/sbin/pam_timestamp_check",
			"/sbin/unix_chkpwd",
			"/usr/sbin/unix_chkpwd",

			"/usr/sbin/sssd",
			"/usr/bin/sssd",
			"/usr/lib/systemd/systemd-logind",
			"/usr/lib/polkit-1/polkitd",
			"/usr/libexec/polkit-1/polkitd",

			"/usr/bin/gnome-keyring-daemon",
			"/usr/bin/kwalletd5",
			"/usr/bin/gpg-agent",

			"/usr/sbin/gdm3",
			"/usr/sbin/gdm",
			"/usr/bin/gdm",
			"/usr/sbin/lightdm",
			"/usr/bin/lightdm",
			"/usr/bin/sddm",
		];
		let is_protected: [u8; 1] = [1];

		/*
		 * Hardware-backed Credential Watchlist Initialization
		 * Threat Model: Static string path matching is inherently vulnerable
		 * to mount namespace evasion (`unshare -m`) and hardlink abuse. By
		 * resolving the physical `inode` and `device ID` of critical
		 * credential-handling binaries at boot, we establish an immutable
		 * tracking mechanism that the kernel hook can validate regardless of
		 * how the file is mapped in user-space memory.
		 */
		let mut protection_count = 0;

		for path in target_binaries {
			match get_secure_hardware_key(path) {
				Ok(key_bytes) => {
					if let Err(e) = bpf_map.update(&key_bytes, &is_protected, libbpf_rs::MapFlags::ANY) {
						eprintln!("Bouclier Bleu [WARNING]: Could not protect credential process {}: {}", path, e);
					} else {
						println!("Bouclier Bleu [Setup]: Anti-dumping memory protection activated for {}", path);
						protection_count += 1;
					}
				}
				Err(_) => {
					// Silently skip if the binary isn't installed on this
					// specific OS, but we will validate the total count at the
					// end.
					continue;
				}
			}
		}

		if protection_count == 0 {
			eprintln!("Bouclier Bleu [CRITICAL]: No credential processes could be protected!");
			return Err("Credential protection initialization failed: Watchlist empty".to_string());
		}

		Ok(())
	}
);
