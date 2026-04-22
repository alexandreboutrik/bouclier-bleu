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

// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

const SOCKET_PATH: &str = "/var/run/bouclier-bleu/control.sock";

struct DaemonGuard {
	process: Child,
}

impl DaemonGuard {
	fn spawn() -> Self {
		let _ = std::fs::remove_file(SOCKET_PATH);
		let core_bin = env!("CARGO_BIN_EXE_core");

		let process = Command::new(core_bin)
			.spawn()
			.expect("Failed to execute core daemon binary.");

		let guard = Self { process };
		guard.await_socket_readiness();
		guard
	}

	fn await_socket_readiness(&self) {
		let start = Instant::now();
		let timeout = Duration::from_secs(5);

		while start.elapsed() < timeout {
			if Path::new(SOCKET_PATH).exists() && UnixStream::connect(SOCKET_PATH).is_ok() {
				thread::sleep(Duration::from_millis(200));
				return;
			}
			thread::sleep(Duration::from_millis(100));
		}
		panic!("Core daemon failed to bind IPC socket within timeout limit.");
	}
}

impl Drop for DaemonGuard {
	fn drop(&mut self) {
		let _ = self.process.kill();
		let _ = self.process.wait();
	}
}

fn execute_cli(args: &[&str]) -> String {
	let core_bin = PathBuf::from(env!("CARGO_BIN_EXE_core"));
	let cli_bin = core_bin.with_file_name("cli");

	let output = Command::new(cli_bin)
		.args(args)
		.output()
		.expect("Failed to execute CLI binary.");

	String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn test_true_enforcement_toggling() {
	let _daemon = DaemonGuard::spawn();

	// exec_block module
	let test_payload = "/tmp/bouclier_malware_sim";
	fs::copy("/bin/true", test_payload).expect("Failed to stage test payload");

	let mut perms = fs::metadata(test_payload).unwrap().permissions();
	perms.set_mode(0o755);
	fs::set_permissions(test_payload, perms).unwrap();

	println!("Phase 1: Testing default active enforcement...");

	let execute_attempt_1 = Command::new(test_payload).output();

	// If the BPF LSM hook catches this, it prevents the execve syscall.
	// Rust translates this kernel EPERM into an ErrorKind::PermissionDenied.
	let is_blocked = match execute_attempt_1 {
		Err(e) if e.kind() == ErrorKind::PermissionDenied => true,
		Ok(out) if !out.status.success() => true,
		_ => false,
	};

	assert!(
		is_blocked,
		"CRITICAL SECURITY FAILURE: eBPF module did not block execution upon startup."
	);

	println!("Phase 2: Disabling module and verifying kernel state...");
	let disable_out = execute_cli(&["disable", "exec_block"]);
	assert!(
		disable_out.contains("SUCCESS"),
		"CLI failed to disable module"
	);

	let execute_attempt_2 = Command::new(test_payload).output();

	match execute_attempt_2 {
		Ok(out) => assert!(
			out.status.success(),
			"Payload should have executed successfully when module is disabled."
		),
		Err(e) => panic!(
			"Execution failed unexpectedly while module was disabled: {}",
			e
		),
	}

	println!("Phase 3: Re-enabling module and verifying kernel state...");
	let enable_out = execute_cli(&["enable", "exec_block"]);
	assert!(
		enable_out.contains("SUCCESS"),
		"CLI failed to re-enable module"
	);

	let execute_attempt_3 = Command::new(test_payload).output();

	let is_blocked_again = match execute_attempt_3 {
		Err(e) if e.kind() == ErrorKind::PermissionDenied => true,
		Ok(out) if !out.status.success() => true,
		_ => false,
	};

	assert!(
		is_blocked_again,
		"CRITICAL SECURITY FAILURE: eBPF module failed to resume blocking after re-enable."
	);

	let _ = fs::remove_file(test_payload);
	println!("True enforcement lifecycle verified successfully.");
}
