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

use std::fs::{self, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::thread;

use rustix::net::sockopt;

const SOCKET_PATH: &str = "/var/run/bouclier-bleu.sock";

/// Strongly typed RPC commands strictly parsed from raw socket payloads.
pub enum DaemonCmd {
    Status,
    List,
    Enable(String),
    Disable(String),
}

/// Represents an encapsulated transaction across the IPC boundary.
/// Includes an mpsc Sender for the Main thread to asynchronouslly reply to
/// the socket.
pub struct IpcMessage {
    pub cmd: DaemonCmd,
    pub reply: mpsc::Sender<String>,
}

/// Spawns the CLI Control Plane listener on an isolated background thread.
/// Exclusively handles socket connections and command parsing, delegating 
/// actual state mutation to the main execution engine via `mpsc`.
pub fn start_ipc_server(tx: mpsc::Sender<IpcMessage>) {
    // Clean up lingering socket files from previous ungraceful shutdowns
    let _ = fs::remove_file(SOCKET_PATH);

    let listener = UnixListener::bind(SOCKET_PATH)
        .expect("Failed to bind to Unix socket");

    /*
     * DEFENSE IN DEPTH: Stage 1 (Filesystem Restrictions)
     * We strictly set the socket file permissions to 0600 (rw-------).
     * This ensures the Linux kernel will block any non-root user from even 
     * attempting to open a connection to the socket.
     */
    let perms = Permissions::from_mode(0o600);
    fs::set_permissions(SOCKET_PATH, perms)
        .expect("Failed to set strict permissions on IPC socket");

    thread::spawn(move || {
        println!("· IPC Control Plane listening securely on {}", SOCKET_PATH);

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    /*
                     * DEFENSE IN DEPTH: Stage 2 (SO_PEERCRED Validation)
                     * We query the kernel to cryptographically verify the
                     * identity of the process on the other end of the socket.
                     * If it is not explicitly UID 0 (root), we drop the
                     * connection immediately.
                     */
                    match sockopt::get_socket_peercred(&stream) {
                        Ok(cred) => {
                            if cred.uid.as_raw() != 0 {
                                eprintln!("SECURITY ALERT: Non-root process (UID: {}) attempted IPC connection.", cred.uid.as_raw());
                                let _ = stream.write_all(b"ERROR: Permission denied. Root access required.\n");
                                continue;
                            }
                        }
                        Err(e) => {
                            eprintln!("SECURITY ERROR: Failed to get peer credentials: {}. Dropping connection.", e);
                            continue;
                        }
                    }

                    let mut buffer = [0; 1024];
                    if let Ok(bytes_read) = stream.read(&mut buffer) {
                        let command_str = String::from_utf8_lossy(&buffer[..bytes_read]).trim().to_string();
                        let parts: Vec<&str> = command_str.split_whitespace().collect();
                        if parts.is_empty() { continue; }

                        let cmd = match parts[0].to_uppercase().as_str() {
                            "STATUS" => DaemonCmd::Status,
                            "LIST" => DaemonCmd::List,
                            "ENABLE" if parts.len() > 1 => DaemonCmd::Enable(parts[1].to_string()),
                            "DISABLE" if parts.len() > 1 => DaemonCmd::Disable(parts[1].to_string()),
                            _ => {
                                let _ = stream.write_all(format!("ERROR: Unknown command '{}'\n", parts[0]).as_bytes());
                                continue;
                            }
                        };

                        let (reply_tx, reply_rx) = mpsc::channel();

                        // Dispatch validated command to the Main Engine and
                        // await sync response.
                        if tx.send(IpcMessage { cmd, reply: reply_tx }).is_ok() {
                            if let Ok(response) = reply_rx.recv() {
                                let _ = stream.write_all(response.as_bytes());
                            }
                        }
                    }
                }
                Err(e) => eprintln!("IPC connection error: {}", e),
            }
        }
    });
}
