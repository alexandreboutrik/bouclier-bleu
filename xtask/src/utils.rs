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

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

pub const VM_NAME: &str = "bb-test-runner";
pub const SNAPSHOT_NAME: &str = "clean-state";

pub type TaskResult<T> = Result<T, String>;

/// Path Resolution Engine
///
/// Navigates the Cargo workspace to locate the absolute root directory.
/// Centralizing this prevents hardcoded relative paths that would break
/// depending on where the `cargo xtask` command is invoked.
pub fn project_root() -> PathBuf {
	Path::new(&env!("CARGO_MANIFEST_DIR"))
		.ancestors()
		.nth(1)
		.unwrap()
		.to_path_buf()
}

/// Robust System Execution Wrapper
///
/// Executes host-level OS commands, capturing standard error streams.
/// Standardizes failure context, ensuring that upstream pipeline panics are
/// highly descriptive rather than opaque exit codes.
pub fn execute_cmd(cmd: &mut Command, error_msg: &str) -> TaskResult<()> {
	let output = cmd.output().map_err(|e| format!("{}: {}", error_msg, e))?;
	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		return Err(format!(
			"{} (Exit code: {})\n\n--- STDERR ---\n{}",
			error_msg,
			output.status.code().unwrap_or(-1),
			stderr.trim()
		));
	}
	Ok(())
}

/// Secure Boundary Translator (Host-to-Guest)
///
/// Tunnels execution into the isolated Incus instance. Automatically sources
/// the Rust environment and pins execution to the synchronized workspace.
pub fn incus_exec(command: &str) -> TaskResult<()> {
	let full_cmd = format!("source ~/.cargo/env && cd /workspace && {}", command);
	let output = Command::new("incus")
		.args(["exec", VM_NAME, "--", "bash", "-c", &full_cmd])
		.output()
		.map_err(|e| format!("Incus translation execution failure: {}", e))?;

	/*
	 * Execution State Validation
	 * If the guest command fails, we dump both stdout and stderr to standard
	 * output. This prevents blind failures during CI/CD execution where
	 * debugging interactively is impossible.
	 */
	if output.status.success() {
		Ok(())
	} else {
		Err(format!(
			"Guest command failed (Exit code: {:?})\n\n--- STDOUT ---\n{}\n--- STDERR ---\n{}",
			output.status.code(),
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		))
	}
}

/// Asynchronous Boot Synchronization
///
/// Cold-booting the testing kernel introduces race conditions if the runner
/// attempts injection before the guest agent is fully initialized. This
/// implements an exponential backoff-like polling mechanism to ensure API
/// readiness.
pub fn await_guest_agent() -> TaskResult<()> {
	for _ in 0..120 {
		if Command::new("incus")
			.args(["exec", VM_NAME, "--", "echo", "ready"])
			.output()
			.is_ok_and(|o| o.status.success())
		{
			return Ok(());
		}
		thread::sleep(Duration::from_secs(2));
	}
	Err("VM communication agent exceeded response timeout limit.".to_string())
}
