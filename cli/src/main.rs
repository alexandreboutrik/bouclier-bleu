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

use clap::{Parser, Subcommand};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process;

const SOCKET_PATH: &str = "/var/run/bouclier-bleu.sock";

#[derive(Parser)]
#[command(name = "bouclier", about = "Bouclier Bleu Control Plane", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check the status of the EDR daemon
    Status,
    /// List all available defense modules and their operational states
    List,
    /// Enable a specific defense module
    Enable { module: String },
    /// Disable a specific defense module
    Disable { module: String },
}

/*
 * IPC CLIENT IMPLEMENTATION
 * Architecture Note:
 * The CLI is intentionally designed to be completely stateless. It acts
 * purely as a message proxy between the system administrator and the
 * long-lived `core` daemon.
 * Security Context:
 * Because the `core` daemon's Unix Socket enforces 0600 permissions and
 * SO_PEERCRED, this CLI must be executed with root privileges (`sudo`).
 * Standard user execution will fail at the Linux Virtual File System (VFS)
 * layer before a connection is even negotiated.
 */
fn send_command_to_daemon(cmd: &str) {
    match UnixStream::connect(SOCKET_PATH) {
        Ok(mut stream) => {
            // Transmit the serialized command payload
            if let Err(e) = stream.write_all(cmd.as_bytes()) {
                eprintln!("Failed to send command over IPC: {}", e);
                return;
            }

            // Await synchronous confirmation from the core daemon's Actor loop
            let mut response = String::new();
            if let Err(e) = stream.read_to_string(&mut response) {
                eprintln!("Failed to read daemon response: {}", e);
                return;
            }

            println!("{}", response.trim_end());
        }
        Err(e) => {
            eprintln!("Failed to connect to Bouclier Bleu daemon.");
            eprintln!("Error: {}", e);
            eprintln!("Make sure the core engine is running and you are executing this CLI as root (sudo).");
            process::exit(1);
        }
    }
}

fn main() {
    let cli = Cli::parse();

    // Translate strongly-typed Rust enums into standard string payloads.
    // This decouples the CLI's argument parsing from the daemon's internal
    // RPC protocol.
    let payload = match &cli.command {
        Commands::Status => "STATUS".to_string(),
        Commands::List => "LIST".to_string(),
        Commands::Enable { module } => format!("ENABLE {}", module),
        Commands::Disable { module } => format!("DISABLE {}", module),
    };

    send_command_to_daemon(&payload);
}
