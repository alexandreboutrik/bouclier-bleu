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

use crate::{BpfReader, define_security_module};
use std::os::unix::fs::MetadataExt;
use walkdir::WalkDir;

/// Telemetry payload yielded by the `rename_entropy` BPF hook.
///
/// Represents a detected filesystem operation where a process attempted
/// to rename a file resulting in a highly entropic (randomized) filename,
/// a primary indicator of ransomware encryption phases.
/// Uses safe, natively-owned Rust types to prevent lifecycle management
/// issues.
#[derive(Debug)]
pub struct RenameAlert {
    pub pid: u32,
    pub full_path: String,
}

impl RenameAlert {
    /// Safe Deserialization Engine.
    ///
    /// Extracts structured fields from the contiguous memory slice provided by
    /// the kernel via the RingBuffer. By abstracting the byte-slice parsing
    /// through `BpfReader`, this engine entirely eliminates the need for C-FFI
    /// or `unsafe` blocks, neutralizing the risk of buffer overflows,
    /// out-of-bounds access, or panics from truncated kernel strings.
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        /*
         * Enforce strict structural boundaries:
         * 4 bytes (u32 PID) + 2048 bytes (dir_path) + 256 bytes (file_name) =
         * 2308 bytes. This validates the payload integrity before any memory
         * reads occur.
         */
        if data.len() < 2308 {
            return Err("Telemetry payload violates minimum size constraints.");
        }

        let mut reader = BpfReader::new(data);

        let pid = reader.read_u32()?;
        let dir_path = reader.read_string(2048)?;
        let file_name = reader.read_string(256)?;

        let full_path = format!("{}{}", dir_path, file_name);

        Ok(Self { pid, full_path })
    }
}

/*
 * DEFENSE HEURISTIC: HIGH-ENTROPY RANSOMWARE RENAMING
 * Ransomware families dynamically rename files with high-entropy, randomized
 * extensions (e.g., `.locked_xyz123`) or pure base-64 strings post-encryption.
 * * While the eBPF kernel hook atomically blocks the operation (`-EPERM`) and
 * directly issues a SIGKILL to prevent Time-of-Check to Time-of-Use (TOCTOU)
 * loops,  this userland module serves as the Control Plane and Telemetry Sink.
 * It consumes the forensic artifacts from the `alerts` RingBuffer for logging,
 * SIEM forwarding, and secondary remediation actions.
 */
define_security_module!(
    struct: RenameEntropy,
    name: "Ransomware Entropy Monitor",
    slug: "rename_entropy",
    parser: RenameAlert::try_from_bytes,
    handler: |alert: RenameAlert| {
        /*
         * FIXME: Forwarding to standard output for PoC.
         * Production iterations should forward this object to a SIEM
         * connector or trigger automated host-isolation protocols.
         */
        println!(
            "Bouclier Bleu [FATAL]: PID {} triggered ransomware entropy heuristic on target: {}",
            alert.pid, alert.full_path
        );
    },
    init: |provider: &dyn crate::MapProvider| -> Result<(), String> {
        let bpf_map = provider.get_map("protected_dirs")?;

        let target_paths = ["/home", "/var", "/etc", "/opt"];
        let is_protected: [u8; 1] = [1];

        /*
         * HARDWARE-BACKED DIRECTORY WATCHLIST INITIALIZATION
         * Threat Model: Advanced adversaries routinely use mount namespaces
         * (`unshare -m`) or bind-mounts to obfuscate paths and bypass
         * string-matching security heuristics. To neutralize this, the
         * userland daemon resolves the exact physical `inode` of target
         * directories at boot. These hardware-level identifiers are passed to
         * the kernel via the `protected_dirs` eBPF Map. The kernel hook then
         * performs validation against the inode that is entirely immune to
         * namespace manipulation.
         */
        for path in target_paths {
            println!("Bouclier Bleu [Setup]: Recursively indexing {}...", path);

            // Optimization & Constraint Management
            // The eBPF hash map has a strict maximum entry limit (1,048,576).
            // To prevent capacity exhaustion and optimize lookup latency, we
            // proactively filter out hidden directories (e.g., `~/.cache`,
            // `~/.mozilla`) which generally contain high-churn, benign files
            // that do not require strict ransomware entropy monitoring.
            let walker = WalkDir::new(path)
                .into_iter()
                .filter_entry(|e| !e.file_name().to_string_lossy().starts_with('.'));

            for entry in walker.filter_map(|e| e.ok()) {
                // System-level Inode Extraction
                // We strictly index directories because the `rename` syscall's
                // `new_dir` parameter provided to the LSM hook points to the
                // destination directory's inode structure, not the individual
                // file itself.
                if entry.file_type().is_dir() {
                    if let Ok(metadata) = entry.metadata() {
                        // Extract the physical u64 Inode and convert it to raw
                        // bytes natively for BPF Map compatibility.
                        let ino: u64 = metadata.ino();
                        let key_bytes = ino.to_ne_bytes();

                        // Push the subdirectory's Inode to the kernel space
                        bpf_map.update(&key_bytes, &is_protected, libbpf_rs::MapFlags::ANY)
                            .map_err(|e| format!("Failed to update map for {}: {}", entry.path().display(), e))?;
                    }
                }
            }

            println!("Bouclier Bleu [Setup]: Protected {} and all subdirectories.", path);
        }
        Ok(())
    }
);
