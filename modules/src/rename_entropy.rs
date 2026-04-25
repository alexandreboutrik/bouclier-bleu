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
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use sysinfo::{Pid, Signal, System};
use walkdir::WalkDir;

/// Telemetry payload yielded by the `rename_entropy` BPF hook.
///
/// Represents a detected filesystem operation where a process attempted
/// to rename a file resulting in a highly entropic (randomized) filename,
/// a primary indicator of ransomware encryption phases.
/// Uses safe, natively-owned Rust types to prevent lifecycle management
/// issues.
#[derive(Debug, serde::Serialize)]
pub struct RenameAlert {
	pub pid: u32,
	pub ppid: u32,
	pub full_path: String,
}

impl RenameAlert {
	/// Safe Deserialization Engine.
	///
	/// Extracts structured fields from the contiguous memory slice provided by
	/// the kernel via the RingBuffer. By abstracting the byte-slice parsing
	/// through `BpfReader`, this engine entirely eliminates the need for C-FFI
	/// or `unsafe` blocks, neutralizing the risk of buffer overflows,
	/// out-of-bounds access, or panics from truncated kernel strings.
	pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
		/*
		 * Enforce strict structural boundaries:
		 * 4 bytes (u32 PID) + 4 bytes (u32 PPID) + 4096 bytes (dir_path) + 256
		 * bytes (file_name) = 4356 bytes. This validates the payload integrity
		 * before any memory reads occur.
		 */
		if data.len() < 4360 {
			return Err("Telemetry payload violates minimum size constraints.");
		}

		let mut reader = BpfReader::new(data);

		let pid = reader.read_u32()?;
		let ppid = reader.read_u32()?;
		let dir_path = reader.read_string(4096)?;
		let file_name = reader.read_string(256)?;

		let clean_dir = dir_path.trim_end_matches('/');
		let full_path = format!("{}/{}", clean_dir, file_name);

		Ok(Self {
			pid,
			ppid,
			full_path,
		})
	}
}

/// Temporal Heuristic State
///
/// Tracks occurrences of high-entropy renaming operations mapped to their
/// parent orchestrator. Utilizing a sliding time window ensures transient,
/// benign spikes do not result in catastrophic false-positive terminations.
struct PpidStrike {
	count: u32,
	first_strike: Instant,
}

/*
 * Decoupled State Registry
 * As `SecurityModule` implementations are instantiated via macros and shared
 * immutably via `Arc` across worker threads, we utilize a global OnceLock to
 * maintain the heuristic state matrix without violating safe concurrency bounds.
 */
static STRIKE_TRACKER: OnceLock<Mutex<HashMap<u32, PpidStrike>>> = OnceLock::new();

fn get_tracker() -> &'static Mutex<HashMap<u32, PpidStrike>> {
	STRIKE_TRACKER.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Asynchronous Threat Remediation (Process Tree Eradication)
///
/// Neutralizes an identified orchestrator process and all active child workers.
/// While the eBPF hook isolates and kills the offending thread instantly to
/// prevent disk corruption (TOCTOU), this routine cleans up the surrounding
/// malicious infrastructure to prevent re-spawning.
fn neutralize_threat_tree(target_ppid: u32) {
	let mut sys = System::new_all();
	sys.refresh_processes();

	let target = Pid::from_u32(target_ppid);

	/*
	 * Eradicate Sibling/Child Workers FIRST
	 * On Linux, when a parent process dies, its orphaned children are
	 * immediately reparented to PID 1 (init/systemd) or a designated
	 * subreaper. Because the loop looks for processes where process.parent()
	 * == target, the reparented children would no longer match this condition
	 * if we kill the parent orchestrator first.
	 */
	for (pid, process) in sys.processes() {
		if let Some(parent_pid) = process.parent() {
			if parent_pid == target {
				process.kill_with(Signal::Kill);
				println!(
					"Bouclier Bleu [REMEDIATION]: Collateral worker terminated -> PID: {}",
					pid
				);
			}
		}
	}

	if let Some(parent) = sys.process(target) {
		parent.kill_with(Signal::Kill);
	}
}

/*
 * DEFENSE HEURISTIC: HIGH-ENTROPY RANSOMWARE RENAMING
 * Ransomware families dynamically rename files with high-entropy, randomized
 * extensions (e.g., `.locked_xyz123`) or pure base-64 strings post-encryption.
 * * While the eBPF kernel hook atomically blocks the operation (`-EPERM`) and
 * directly issues a SIGKILL to prevent Time-of-Check to Time-of-Use (TOCTOU)
 * loops,  this userland module serves as the Control Plane and Telemetry Sink.
 * It consumes the forensic artifacts from the `alerts` RingBuffer for logging,
 * SIEM forwarding, and secondary remediation actions.
 */
define_security_module!(
	struct: RenameEntropy,
	name: "Ransomware Rename Entropy Monitor",
	slug: "rename_entropy",
	parser: RenameAlert::try_from_bytes,
	handler: |alert: RenameAlert| {
		let mut tracker = match get_tracker().lock() {
			Ok(guard) => guard,
			Err(poisoned) => {
				eprintln!("Bouclier Bleu [Warning]: Strike tracker mutex was poisoned. Recovering state.");
		poisoned.into_inner()
			}
		};

		/*
		 * Dynamic State Pruning (Memory Leak Prevention)
		 * Advanced evasion techniques might drip-feed low-entropy renames over
		 * long durations. To prevent the `STRIKE_TRACKER` map from
		 * experiencing unbounded growth and starving daemon memory, we execute
		 * an O(n) prune of stale entries older than 5 seconds. Since this
		 * handler fires strictly on heuristic violations, the amortized cost
		 * of this cleanup is negligible.
		 */
		tracker.retain(|_, strike| {
			Instant::now().duration_since(strike.first_strike) < Duration::from_secs(5)
		});

		let now = Instant::now();

		/*
		 * FIXME: Forwarding to standard output for PoC.
		 * Production iterations should forward this object to a SIEM
		 * connector or trigger automated host-isolation protocols.
		 */
		println!(
			"Bouclier Bleu [FATAL]: PID {} triggered ransomware entropy heuristic on target: {}",
			alert.pid, alert.full_path
		);

		let strike = tracker.entry(alert.ppid).or_insert(PpidStrike {
			count: 0,
			first_strike: now,
		});

		/*
		 * Temporal Correlation Matrix (2-Second Sliding Window)
		 * Modern ransomware operates asynchronously, spawning multiple threads
		 * rapidly. If an orchestrator triggers 3 high-entropy violations within
		 * a strict 2-second window, statistical confidence of malicious intent
		 * approaches 100%, warranting an automated tree termination.
		 */
		if now.duration_since(strike.first_strike) > Duration::from_secs(2) {
			// Window expired. Demote risk score and reset baseline.
			strike.count = 1;
			strike.first_strike = now;
		} else {
			strike.count += 1;
		}

		if strike.count >= 3 {
			println!(
				"Bouclier Bleu [FATAL]: PPID {} crossed heuristic threshold (3 strikes/2s). Executing tree eradication.",
				alert.ppid
			);

			neutralize_threat_tree(alert.ppid);

			/*
			 * Flush localized state to prevent ghost-strikes if the OS recycles
			 * the PID for a future, benign process.
			 */
			tracker.remove(&alert.ppid);
		}
	},
	capacities: || -> std::collections::HashMap<String, u32> {
		/*
		 * JUST-IN-TIME (JIT) PROTECTED_DIRS MAP SIZING HEURISTIC
		 * To maintain a lightweight EDR footprint, we perform a rapid pre-scan
		 * of the filesystem before instructing the kernel to allocate memory.
		 * We apply a 1.25x scaling factor (25% safety buffer) to accommodate
		 * future directory creations during the system's uptime. Because the
		 * Linux VFS layer heavily caches dentries, this initial pass pulls the
		 * directory metadata from disk to RAM, dramatically accelerating the
		 * subsequent `init` population pass and practically nullifying any
		 * perceived performance penalty of the double-loop.
		 */
		let mut count = 0;
		let target_paths = ["/home", "/var", "/etc", "/opt"];
		let critical_hidden = [".ssh", ".gnupg", ".aws", ".kube", ".docker", ".config"];

		for path in target_paths {
			let walker = WalkDir::new(path).into_iter().filter_entry(|e| {
				let fname = e.file_name().to_string_lossy();
				if !fname.starts_with('.') { return true; }
				critical_hidden.contains(&fname.as_ref())
			});

			for entry in walker.filter_map(|e| e.ok()) {
				if entry.file_type().is_dir() {
					count += 1;
				}
			}
		}

		// Apply a 25% safety buffer for new directories, with an absolute
		// minimum of 8192
		let safe_capacity = ((count as f64 * 1.25) as u32).max(8192);

		let mut caps = std::collections::HashMap::new();
		caps.insert("protected_dirs".to_string(), safe_capacity);
		caps
	},
	init: |provider: &dyn crate::MapProvider| -> Result<(), String> {
		let bpf_map = provider.get_map("protected_dirs")?;

		let target_paths = ["/home", "/var", "/etc", "/opt"];
		let is_protected: [u8; 1] = [1];

		/*
		 * HARDWARE-BACKED DIRECTORY WATCHLIST INITIALIZATION
		 * Advanced adversaries routinely use mount namespaces (`unshare -m`)
		 * or bind-mounts to obfuscate paths and bypass string-matching
		 * security heuristics. To neutralize this, the userland daemon
		 * resolves the exact physical `inode` of target directories at boot.
		 * These hardware-level identifiers are passed to the kernel via the
		 * `protected_dirs` eBPF Map. The kernel hook then performs validation
		 * against the inode that is entirely immune to namespace manipulation.
		 */
		for path in target_paths {
			println!("Bouclier Bleu [Setup]: Recursively indexing {}...", path);

			// Optimization & Constraint Management
			// The eBPF hash map has a strict maximum entry limit (1,048,576).
			// To prevent capacity exhaustion and optimize lookup latency, we
			// proactively filter out hidden directories (e.g., `~/.cache`,
			// `~/.mozilla`) which generally contain high-churn, benign files
			// that do not require strict ransomware entropy monitoring.
			let critical_hidden = [".ssh", ".gnupg", ".aws", ".kube", ".docker", ".config"];
			let walker = WalkDir::new(path)
				.into_iter()
				.filter_entry(move |e| {
					let file_name = e.file_name().to_string_lossy();

					if !file_name.starts_with('.') {
						return true;
					}

					critical_hidden.contains(&file_name.as_ref())
				});

			for entry in walker.filter_map(|e| e.ok()) {
				// System-level Inode Extraction
				// We strictly index directories because the `rename` syscall's
				// `new_dir` parameter provided to the LSM hook points to the
				// destination directory's inode structure, not the individual
				// file itself.
				if entry.file_type().is_dir() {
					if let Ok(key_bytes) = crate::get_secure_hardware_key(entry.path()) {
		bpf_map.update(&key_bytes, &is_protected, libbpf_rs::MapFlags::ANY)
			.map_err(|e| format!("Failed to update map for {}: {}", entry.path().display(), e))?;
	}
				}
			}

			println!("Bouclier Bleu [Setup]: Protected {} and all subdirectories.", path);
		}
		Ok(())
	}
);
