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

use crate::define_security_module;

/// Telemetry payload yielded by the `exec_block` BPF hook.
///
/// Represents an attempt to execute a binary from a world-writable directory.
/// Uses safe, natively-owned Rust types to prevent lifecycle management
/// issues.
#[derive(Debug)]
pub struct ExecAlert {
    pub pid: u32,
    pub path: String, 
}

impl ExecAlert {
    /// Safe Deserialization Engine.
    ///
    /// Extracts structured fields from the contiguous memory slice provided by 
    /// the kernel. Utilizing `try_into()` and `from_utf8_lossy()` entirely 
    /// eliminates the need for C-FFI or `unsafe` blocks, neutralizing the risk 
    /// of buffer overflows or panics from malformed kernel strings.
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        // Enforce structural boundaries: 4 (u32 PID) + 4096 (PATH_MAX)
        if data.len() < 4100 {
            return Err("Telemetry payload violates minimum size constraints.");
        }

        let pid_bytes: [u8; 4] = data[0..4]
            .try_into()
            .map_err(|_| "Memory layout mismatch: Failed to isolate PID block.")?;
        /*
         * Native endianness is enforced to match the host architecture of the
         * kernel.
         */
        let pid = u32::from_ne_bytes(pid_bytes);

        let path_buffer = &data[4..4104];
        let null_index = path_buffer
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_buffer.len());

        /*
         * `from_utf8_lossy` sanitizes any invalid byte sequences seamlessly, 
         * preventing application crashes from malformed kernel strings.
         */
        let path = String::from_utf8_lossy(&path_buffer[0..null_index]).into_owned();

        Ok(Self { pid, path })
    }
}

/*
 * DEFENSE HEURISTIC: WORLD-WRITABLE EXECUTION BLOCK
 * Memory corruption exploits and web-shell droppers frequently lack the
 * privileges required to write to protected directories (/usr/bin). They rely
 * on world-writable paths (/tmp, /dev/shm) to stage secondary payloads.
 * This module consumes events from the `alerts` RingBuffer, triggered 
 * dynamically whenever the kernel vetoes an execution attempt from these paths.
 */
define_security_module!(
    struct: ExecBlock,
    name: "Exec Block (/tmp, /dev/shm)",
    slug: "exec_block",
    parser: ExecAlert::try_from_bytes,
    handler: |alert: ExecAlert| {
        /*
         * FIXME: Forwarding to standard output for PoC. 
         * Production iterations should forward this object to a SIEM
         * connector.
         */
        println!(
            "Bouclier Bleu [BLOCK]: PID {} attempted execution from protected path: {}",
            alert.pid, alert.path
        );
    }
);
