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

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::Duration;

use rustix::net::sockopt;

use super::types::{DaemonCmd, IpcMessage};

/// Processes an individual socket connection from start to finish.
pub fn handle_connection(mut stream: UnixStream, tx: &mpsc::SyncSender<IpcMessage>) {
	if let Err(e) = verify_peercred(&stream) {
		eprintln!("{}", e);
		let _ = stream.write_all(b"ERROR: Permission denied. Root access required.\n");
		return;
	}

	/*
	 * Resource Exhaustion Mitigation (Anti-DoS)
	 * Since the listener processes connections sequentially to avoid
	 * thread-spawning overhead, a malicious root client could connect and
	 * refuse to send data, hanging the entire control plane. We enforce a
	 * strict read timeout to sever stalled connections and maintain daemon
	 * availability.
	 */
	if let Err(e) = stream.set_read_timeout(Some(Duration::from_millis(1000))) {
		eprintln!("WARNING: Failed to apply read timeout to stream: {}", e);
		return;
	}

	/* Apply timeout to prevent Slowloris-style blocking */
	if let Err(e) = stream.set_write_timeout(Some(Duration::from_millis(1000))) {
		eprintln!("WARNING: Failed to apply write timeout to stream: {}", e);
		return;
	}

	let cmd = match parse_command(&mut stream) {
		Ok(Some(c)) => c,
		Ok(None) => return, // Empty command / dropped connection
		Err(_e) => {
			let _ = stream.write_all(b"ERROR: Unknown command received.\n");
			return;
		}
	};

	if let Err(e) = dispatch_command(cmd, tx, &mut stream) {
		let _ = stream.write_all(e.as_bytes());
	}
}

/// Validates the kernel-level cryptographic identity of the peer.
fn verify_peercred(stream: &UnixStream) -> Result<(), String> {
	/*
	 * Defense in Depth: SO_PEERCRED Identity Verification
	 * We query the kernel directly via the socket file descriptor to ascertain
	 * the authentic UID of the connecting process. This cryptographic
	 * verification completely bypasses user-space spoofing attempts. If the
	 * caller is not strictly UID 0 (root), the connection is terminated.
	 */
	match sockopt::socket_peercred(stream) {
		Ok(cred) => {
			if cred.uid.as_raw() != 0 {
				Err(format!(
					"SECURITY ALERT: Non-root process (UID: {}) attempted IPC connection.",
					cred.uid.as_raw()
				))
			} else {
				Ok(())
			}
		}
		Err(e) => Err(format!(
			"SECURITY ERROR: Kernel failed to yield peer credentials: {}. Dropping connection.",
			e
		)),
	}
}

/// Reads from the stream securely and parses the raw bytes into a DaemonCmd.
fn parse_command(stream: &mut UnixStream) -> Result<Option<DaemonCmd>, String> {
	let mut buffer = Vec::new();

	/*
	 * Stream Truncation & Anti-OOM Mitigation
	 * Sockets are streams; data can arrive fragmented. We read until the
	 * client signals EOF, but strictly cap the read at 1024 bytes using
	 * `.take()` to prevent memory exhaustion attacks from malicious clients
	 * attempting to send infinite data.
	 */
	match stream.take(1024).read_to_end(&mut buffer) {
		Ok(bytes_read) => {
			if bytes_read == 0 {
				return Ok(None);
			}

			let command_str = String::from_utf8_lossy(&buffer).trim().to_string();
			let parts: Vec<&str> = command_str.split_whitespace().collect();
			if parts.is_empty() {
				return Ok(None);
			}

			match parts[0].to_uppercase().as_str() {
				"STATUS" => Ok(Some(DaemonCmd::Status)),
				"LIST" => Ok(Some(DaemonCmd::List)),
				"ENABLE" if parts.len() > 1 => Ok(Some(DaemonCmd::Enable(parts[1].to_string()))),
				"DISABLE" if parts.len() > 1 => Ok(Some(DaemonCmd::Disable(parts[1].to_string()))),
				_ => Err("Unknown command".to_string()),
			}
		}
		Err(e) => Err(format!("Read error: {}", e)),
	}
}

/// Routes the command to the main actor and awaits the response.
fn dispatch_command(
	cmd: DaemonCmd,
	tx: &mpsc::SyncSender<IpcMessage>,
	_stream: &mut UnixStream,
) -> Result<(), String> {
	let (reply_tx, reply_rx) = mpsc::channel();

	match tx.try_send(IpcMessage {
		cmd,
		reply: reply_tx,
	}) {
		Ok(_) => {
			/*
			 * Thread Deadlock Prevention
			 * We bound the wait time for the main engine's response. If a
			 * kernel eBPF map toggle stalls or the engine panics, this timeout
			 * ensures the IPC thread recovers gracefully and signals the
			 * failure back to the CLI user.
			 */
			if let Ok(response) = reply_rx.recv_timeout(Duration::from_secs(5)) {
				// Return Ok containing the raw response string to write back
				// to stream
				Err(response) // Wrapped in Err simply for unified string
			      // propagation in handler
			} else {
				Err("ERROR: Engine operation timed out or panicked.\n".to_string())
			}
		}
		Err(mpsc::TrySendError::Full(_)) => {
			Err("ERROR: Daemon is busy or overwhelmed. Try again later.\n".to_string())
		}
		Err(mpsc::TrySendError::Disconnected(_)) => {
			Err("FATAL: Core engine has crashed. Channel disconnected.\n".to_string())
		}
	}
}
