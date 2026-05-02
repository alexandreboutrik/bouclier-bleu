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
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use rustix::net::sockopt;

const SOCKET_DIR: &str = "/var/run/bouclier-bleu";
const SOCKET_PATH: &str = "/var/run/bouclier-bleu/control.sock";

/// Strongly typed RPC commands strictly parsed from raw socket payloads.
///
/// This enum acts as the serialization boundary, ensuring only syntactically
/// valid directives propagate to the core execution engine.
pub enum DaemonCmd {
	Status,
	List,
	Enable(String),
	Disable(String),
}

/// Represents an encapsulated transaction across the IPC boundary.
///
/// Includes a single-use transmission channel (`mpsc::Sender`) allowing the
/// asynchronous core engine to route execution results back to the synchronous
/// socket thread.
pub struct IpcMessage {
	pub cmd: DaemonCmd,
	pub reply: mpsc::Sender<String>,
}

/// Spawns the CLI Control Plane listener on an isolated background thread.
///
/// Exclusively handles socket connections and command parsing, delegating
/// actual state mutation to the main execution engine via `mpsc`.
pub fn start_ipc_server(tx: mpsc::SyncSender<IpcMessage>) {
	/*
	 * SECURITY: TOCTOU (Time-of-Check to Time-of-Use) Mitigation
	 * We atomically create the directory with root-only permissions (0o700).
	 * This eliminates the microsecond world-readable window that occurs if
	 * permissions are locked down *after* creation.
	 */
	if let Err(e) = DirBuilder::new()
		.recursive(true)
		.mode(0o700)
		.create(SOCKET_DIR)
	{
		eprintln!("FATAL: Failed to construct secure IPC directory: {}", e);
		return;
	}

	if let Ok(meta) = fs::metadata(SOCKET_DIR) {
		if meta.uid() != 0 || (meta.mode() & 0o777) != 0o700 {
			eprintln!(
				"Bouclier Bleu [WARNING]: IPC directory {} has insecure permissions (Potential Pre-Staging Attack). Auto-remediating...",
				SOCKET_DIR
			);

			/*
			 * NUKE AND PAVE
			 * Wipe the tainted directory to destroy any pre-staged sockets,
			 * symlinks, or open file descriptors.
			 */
			if let Err(e) = fs::remove_dir_all(SOCKET_DIR) {
				eprintln!(
					"FATAL: Failed to wipe compromised IPC directory during remediation: {}",
					e
				);
				return;
			}

			// Rebuild the directory cleanly
			if let Err(e) = DirBuilder::new()
				.recursive(true)
				.mode(0o700)
				.create(SOCKET_DIR)
			{
				eprintln!(
					"FATAL: Failed to recreate secure IPC directory post-remediation: {}",
					e
				);
				return;
			}

			eprintln!("Bouclier Bleu [INFO]: IPC directory securely rebuilt.");
		}
	} else {
		eprintln!("FATAL: Failed to verify IPC directory metadata.");
		return;
	}

	let _ = fs::remove_file(SOCKET_PATH);
	let old_umask = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o177));

	let listener = UnixListener::bind(SOCKET_PATH).expect("FATAL: Failed to bind to Unix socket");

	rustix::process::umask(old_umask);

	thread::spawn(move || {
		println!("· IPC Control Plane listening securely on {}", SOCKET_PATH);

		for stream in listener.incoming() {
			match stream {
				Ok(mut stream) => {
					/*
					 * DEFENSE IN DEPTH: SO_PEERCRED Identity Verification
					 * We query the kernel directly via the socket file
					 * descriptor to ascertain the authentic UID of the
					 * connecting process.
					 * This cryptographic verification completely bypasses
					 * user-space spoofing attempts. If the caller is not
					 * strictly UID 0 (root), the connection is terminated.
					 */
					match sockopt::socket_peercred(&stream) {
						Ok(cred) => {
							if cred.uid.as_raw() != 0 {
								eprintln!(
									"SECURITY ALERT: Non-root process (UID: {}) attempted IPC connection.",
									cred.uid.as_raw()
								);
								let _ = stream.write_all(
									b"ERROR: Permission denied. Root access required.\n",
								);
								continue;
							}
						}
						Err(e) => {
							eprintln!(
								"SECURITY ERROR: Kernel failed to yield peer credentials: {}. Dropping connection.",
								e
							);
							continue;
						}
					}

					/*
					 * RESOURCE EXHAUSTION MITIGATION (Anti-DoS)
					 * Since the listener processes connections sequentially to
					 * avoid thread-spawning overhead, a malicious root client
					 * could connect and refuse to send data, hanging the
					 * entire control plane. We enforce a strict read timeout
					 * to sever stalled connections and maintain daemon
					 * availability.
					 */
					if let Err(e) = stream.set_read_timeout(Some(Duration::from_millis(100))) {
						eprintln!("WARNING: Failed to apply read timeout to stream: {}", e);
						continue;
					}

					/* Apply timeout to prevent Slowloris-style blocking */
					if let Err(e) = stream.set_write_timeout(Some(Duration::from_millis(100))) {
						eprintln!("WARNING: Failed to apply write timeout to stream: {}", e);
						continue;
					}

					let mut buffer = Vec::new();

					/*
					 * STREAM TRUNCATION & Anti-OOM MITIGATION
					 * Sockets are streams; data can arrive fragmented. We read
					 * until the client signals EOF, but strictly cap the read
					 * at 1024 bytes using `.take()` to prevent memory
					 * exhaustion attacks from malicious clients attempting to
					 * send infinite data.
					 */
					if let Ok(bytes_read) = (&mut stream).take(1024).read_to_end(&mut buffer) {
						if bytes_read == 0 {
							continue;
						}

						let command_str = String::from_utf8_lossy(&buffer).trim().to_string();
						let parts: Vec<&str> = command_str.split_whitespace().collect();
						if parts.is_empty() {
							continue;
						}

						let cmd = match parts[0].to_uppercase().as_str() {
							"STATUS" => DaemonCmd::Status,
							"LIST" => DaemonCmd::List,
							"ENABLE" if parts.len() > 1 => DaemonCmd::Enable(parts[1].to_string()),
							"DISABLE" if parts.len() > 1 => {
								DaemonCmd::Disable(parts[1].to_string())
							}
							_ => {
								let _ = stream.write_all(b"ERROR: Unknown command received.\n");
								continue;
							}
						};

						let (reply_tx, reply_rx) = mpsc::channel();

						match tx.try_send(IpcMessage {
							cmd,
							reply: reply_tx,
						}) {
							Ok(_) => {
								/*
								 * THREAD DEADLOCK PREVENTION
								 * We bound the wait time for the main engine's
								 * response. If a kernel eBPF map toggle stalls
								 * or the engine panics, this timeout ensures
								 * the IPC thread recovers gracefully and
								 * signals the failure back to the CLI user.
								 */
								if let Ok(response) = reply_rx.recv_timeout(Duration::from_secs(5))
								{
									let _ = stream.write_all(response.as_bytes());
								} else {
									let _ = stream.write_all(
										b"ERROR: Engine operation timed out or panicked.\n",
									);
								}
							}
							Err(mpsc::TrySendError::Full(_)) => {
								let _ = stream.write_all(
									b"ERROR: Daemon is busy or overwhelmed. Try again later.\n",
								);
							}
							Err(mpsc::TrySendError::Disconnected(_)) => {
								let _ = stream.write_all(
									b"FATAL: Core engine has crashed. Channel disconnected.\n",
								);
							}
						}
					}
				}
				Err(e) => eprintln!("IPC connection error: {}", e),
			}
		}
	});
}
