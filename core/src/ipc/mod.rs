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

use std::sync::mpsc;
use std::thread;

pub mod handler;
pub mod setup;
pub mod types;

// Re-export core types so `actor.rs` and `main.rs` do not break
pub use types::{DaemonCmd, IpcMessage};

/// Spawns the CLI Control Plane listener on an isolated background thread.
///
/// Exclusively handles socket connections and command parsing, delegating
/// actual state mutation to the main execution engine via `mpsc`.
pub fn start_ipc_server(tx: mpsc::SyncSender<IpcMessage>) {
	if let Err(e) = setup::setup_secure_dir() {
		eprintln!("{}", e);
		return;
	}

	let listener = match setup::bind_socket() {
		Ok(l) => l,
		Err(e) => {
			eprintln!("{}", e);
			return;
		}
	};

	thread::spawn(move || {
		println!(
			"· IPC Control Plane listening securely on {}",
			setup::SOCKET_PATH
		);

		for stream in listener.incoming() {
			match stream {
				Ok(stream) => {
					handler::handle_connection(stream, &tx);
				}
				Err(e) => eprintln!("IPC connection error: {}", e),
			}
		}
	});
}
