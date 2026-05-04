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

use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::UnixListener;

pub const SOCKET_DIR: &str = "/var/run/bouclier-bleu";
pub const SOCKET_PATH: &str = "/var/run/bouclier-bleu/control.sock";

/// Bootstraps the secure directory with strict TOCTOU mitigations.
pub fn setup_secure_dir() -> Result<(), String> {
	/*
	 * TOCTOU (Time-of-Check to Time-of-Use) Mitigation
	 * We atomically create the directory with root-only permissions (0o700).
	 * This eliminates the microsecond world-readable window that occurs if
	 * permissions are locked down *after* creation.
	 */
	if let Err(e) = DirBuilder::new()
		.recursive(true)
		.mode(0o700)
		.create(SOCKET_DIR)
	{
		return Err(format!(
			"FATAL: Failed to construct secure IPC directory: {}",
			e
		));
	}

	if let Ok(meta) = fs::symlink_metadata(SOCKET_DIR) {
		if meta.is_symlink() || meta.uid() != 0 || (meta.mode() & 0o777) != 0o700 {
			eprintln!(
                "Bouclier Bleu [WARNING]: IPC directory {} has insecure permissions (Potential Pre-Staging Attack). Auto-remediating...",
                SOCKET_DIR
            );

			/*
			 * NUKE AND PAVE
			 * If the path is a symlink, we simply remove the file/link.
			 * If it is an actual directory, we can safely wipe it.
			 */
			if meta.is_symlink() || meta.is_file() {
				if let Err(e) = fs::remove_file(SOCKET_DIR) {
					return Err(format!(
						"FATAL: Failed to remove compromised symlink/file: {}",
						e
					));
				}
			} else if let Err(e) = fs::remove_dir_all(SOCKET_DIR) {
				return Err(format!(
					"FATAL: Failed to wipe compromised IPC directory: {}",
					e
				));
			}

			// Rebuild the directory cleanly
			if let Err(e) = DirBuilder::new()
				.recursive(true)
				.mode(0o700)
				.create(SOCKET_DIR)
			{
				return Err(format!(
					"FATAL: Failed to recreate secure IPC directory post-remediation: {}",
					e
				));
			}

			eprintln!("Bouclier Bleu [INFO]: IPC directory securely rebuilt.");
		}
	} else {
		return Err("FATAL: Failed to verify IPC directory metadata.".to_string());
	}

	Ok(())
}

/// Safely manipulates the umask to bind the Unix Socket.
pub fn bind_socket() -> Result<UnixListener, String> {
	let _ = fs::remove_file(SOCKET_PATH);

	// Temporarily tighten the umask before creating the socket file
	let old_umask = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o177));

	let listener = UnixListener::bind(SOCKET_PATH)
		.map_err(|e| format!("FATAL: Failed to bind to Unix socket: {}", e))?;

	// Restore the original umask
	rustix::process::umask(old_umask);

	/*
	 * Socket Validation (Post-Bind)
	 * Detects if an attacker managed to pre-create the socket or replace
	 * it in the microsecond window between remove_file and bind.
	 */
	if fs::symlink_metadata(SOCKET_PATH).is_ok_and(|meta| meta.uid() != 0 || meta.is_symlink()) {
		let _ = fs::remove_file(SOCKET_PATH);
		return Err("FATAL: IPC socket ownership validation failed (Possible TOCTOU).".to_string());
	}

	Ok(listener)
}
