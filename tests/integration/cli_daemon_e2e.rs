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

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

const SOCKET_PATH: &str = "/var/run/bouclier-bleu/control.sock";

/// RAII guard ensuring deterministic lifecycle management of the core daemon.
/// Prevents orphaned background processes and socket file lock contentions
/// across subsequent integration test executions.
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

	/// Actively polls the virtual filesystem to resolve race conditions between
	/// the daemon's asynchronous initialization phase and the test runner.
	fn await_socket_readiness(&self) {
		let start = Instant::now();
		let timeout = Duration::from_secs(5);

		while start.elapsed() < timeout {
			if Path::new(SOCKET_PATH).exists() && UnixStream::connect(SOCKET_PATH).is_ok() {
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

/// Utility function to execute the CLI binary with arbitrary arguments
/// and return the standard output as a parsed string.
fn execute_cli(args: &[&str]) -> String {
	let core_bin = PathBuf::from(env!("CARGO_BIN_EXE_core"));
	let cli_bin = core_bin.with_file_name("cli");

	let output = Command::new(cli_bin)
		.args(args)
		.output()
		.expect("Failed to execute CLI binary.");

	assert!(
		output.status.success(),
		"CLI command execution failed. Stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);

	String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn test_cli_daemon_integration_lifecycle() {
	let _daemon = DaemonGuard::spawn();

	let status_output = execute_cli(&["status"]);
	assert!(
		!status_output.is_empty(),
		"Daemon returned empty status payload."
	);

	let disable_output = execute_cli(&["disable", "exec_block"]);
	assert!(
		disable_output.contains("DISABLED"),
		"CLI failed to correctly broker the DISABLE command. Output: {}",
		disable_output
	);

	let enable_output = execute_cli(&["enable", "exec_block"]);
	assert!(
		enable_output.contains("ENABLE") || enable_output.contains("active"),
		"CLI failed to correctly broker the ENABLE command. Output: {}",
		enable_output
	);

	let list_output = execute_cli(&["list"]);
	assert!(
		list_output.contains("exec_block"),
		"Module list failed to reflect active registry. Output: {}",
		list_output
	);
}
