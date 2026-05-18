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

use std::fs::{self, File};
use std::io::{BufRead, BufReader, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

const SOCKET_PATH: &str = "/var/run/bouclier-bleu/control.sock";
const TELEMETRY_PATH: &str = "/var/log/bouclier-bleu/alerts.json";

/// RAII guard ensuring deterministic lifecycle management of the core daemon.
/// Prevents orphaned background processes and socket file lock contentions
/// across subsequent integration test executions.
struct DaemonGuard {
	process: Child,
}

impl DaemonGuard {
	fn spawn() -> Self {
		// Purge dangling socket descriptors and previous telemetry to
		// guarantee a clean test state without cross-contamination.
		let _ = fs::remove_file(SOCKET_PATH);
		let _ = fs::remove_file(TELEMETRY_PATH);

		let core_bin = env!("CARGO_BIN_EXE_core");

		let process = Command::new(core_bin)
			.spawn()
			.expect("Failed to execute core daemon binary. Verify build prerequisites.");

		let guard = Self { process };
		guard.await_socket_readiness();
		guard
	}

	/// Actively polls the VFS layer to resolve race conditions between the
	/// daemon's initialization phase and the test runner's execution loop.
	fn await_socket_readiness(&self) {
		let start = Instant::now();
		let timeout = Duration::from_secs(5);

		while start.elapsed() < timeout {
			if Path::new(SOCKET_PATH).exists() && UnixStream::connect(SOCKET_PATH).is_ok() {
				// Give the daemon a brief moment to finish mounting the eBPF
				// hooks after the IPC socket binds.
				thread::sleep(Duration::from_millis(200));
				return;
			}
			thread::sleep(Duration::from_millis(100));
		}
		panic!(
			"Core daemon failed to bind IPC socket at {} within timeout limit.",
			SOCKET_PATH
		);
	}
}

impl Drop for DaemonGuard {
	fn drop(&mut self) {
		let _ = self.process.kill();
		let _ = self.process.wait();
	}
}

#[test]
fn test_telemetry_siem_pipeline_e2e() {
	let _daemon = DaemonGuard::spawn();

	let test_payload = "/tmp/bb_telemetry_test_bin";

	// Provision the malicious payload
	fs::copy("/bin/true", test_payload).expect("Failed to stage test payload to /tmp");

	let mut perms = fs::metadata(test_payload).unwrap().permissions();
	perms.set_mode(0o755);
	fs::set_permissions(test_payload, perms).expect("Failed to set execution permissions");

	println!("Phase 1: Triggering the 'exec_block' LSM hook...");

	// Execute the payload. We use `spawn()` to capture the exact PID generated
	// by the Rust fork/exec process before the kernel intercepts and kills it.
	let execute_attempt = Command::new(test_payload).spawn();

	let target_pid = match execute_attempt {
		Ok(mut child) => {
			let pid = child.id();
			let output = child.wait().expect("Failed to wait on child process");
			assert!(
				!output.success(),
				"CRITICAL: Payload executed successfully. The eBPF module failed to block it."
			);
			pid
		}
		Err(e) if e.kind() == ErrorKind::PermissionDenied => {
			// Depending on exactly how fast the LSM hook drops the execve
			// call, standard library `Command` might catch the EPERM before
			// yielding the Child. In this edge case, we can't reliably assert
			// against the PID, but the block succeeded.
			println!("Notice: eBPF blocked execution fast enough to yield EPERM to the parent.");
			0 // Sentinel value, we will skip the strict PID assertion below.
		}
		Err(e) => panic!("Execution failed with an unexpected system error: {}", e),
	};

	println!("Phase 2: Awaiting telemetry pipeline flush...");

	// Poll the SIEM log file.
	// Reading from the ring buffer and serializing to disk is asynchronous.
	let start = Instant::now();
	let timeout = Duration::from_secs(5);
	let mut found_telemetry_line = None;

	while start.elapsed() < timeout {
		if let Ok(file) = File::open(TELEMETRY_PATH) {
			let reader = BufReader::new(file);
			for line in reader.lines().flatten() {
				// Search for the specific line corresponding to our payload run
				if line.contains(test_payload) {
					found_telemetry_line = Some(line);
					break;
				}
			}
		}

		if found_telemetry_line.is_some() {
			break;
		}

		thread::sleep(Duration::from_millis(100));
	}

	let json_str = found_telemetry_line.expect(
		"Failed to locate the SIEM alert in /var/log/bouclier-bleu/alerts.json. The pipeline dropped the event."
	);

	println!("Phase 3: Validating NDJSON schema integrity...");

	// Validate the structured JSON
	let siem_event: Value =
		serde_json::from_str(&json_str).expect("SIEM File contains malformed, non-compliant JSON.");

	// Convert the JSON payload back to a string for robust searching,
	// this allows the test to pass regardless of how the userland engine
	// specifically wraps the core event (e.g., {"data": {...}} vs flat
	// struct).
	let event_dump = siem_event.to_string();

	// Assert String truncation didn't occur (validating the C-FFI / null
	// termination boundary)
	assert!(
		event_dump.contains(test_payload),
		"Telemetry string truncation detected! The canonical path was corrupted during zero-copy deserialization."
	);

	// Assert PID accuracy (only if the standard library yielded the child PID
	// successfully)
	if target_pid != 0 {
		assert!(
			event_dump.contains(&target_pid.to_string()),
			"Telemetry PID mismatch! Expected PID {} to be present in the SIEM payload.",
			target_pid
		);
	}

	// Cleanup
	let _ = fs::remove_file(test_payload);
	println!("Telemetry & SIEM Pipeline E2E verified successfully.");
}
