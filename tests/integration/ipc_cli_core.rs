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
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

const SOCKET_PATH: &str = "/var/run/bouclier-bleu/control.sock";

/// RAII guard ensuring deterministic lifecycle management of the core daemon
/// during integration testing. Guarantees process termination and resource
/// cleanup even upon test assertion panics.
struct DaemonGuard {
    process: Child,
}

impl DaemonGuard {
    fn spawn() -> Self {
        // Purge dangling socket descriptors from prior ungraceful terminations
        // to prevent AddressInUse errors.
        let _ = std::fs::remove_file(SOCKET_PATH);

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
            if Path::new(SOCKET_PATH).exists() {
                if UnixStream::connect(SOCKET_PATH).is_ok() {
                    return;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("Core daemon failed to bind IPC socket at {} within timeout limit.", SOCKET_PATH);
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

#[test]
fn test_ipc_disable_command() {
    let _daemon = DaemonGuard::spawn();

    let mut stream = UnixStream::connect(SOCKET_PATH)
        .expect("Failed to establish IPC channel to core daemon.");

    // Dispatch state mutation RPC directly to the control plane, intentionally
    // circumventing the CLI abstraction layer to test the socket's raw payload
    // parsing.
    stream.write_all(b"DISABLE exec_block")
        .expect("Failed to transmit IPC payload.");

    let _ = stream.shutdown(Shutdown::Write);

    let mut response = String::new();
    stream.read_to_string(&mut response).expect("Failed to read IPC response stream.");

    assert!(
        response.contains("SUCCESS: Defense module 'exec_block' has been DISABLED via state_map synchronization"),
        "Unexpected IPC response payload: {}",
        response
    );
}
