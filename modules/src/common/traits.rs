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

//! Core Abstractions for Bouclier Bleu Security Modules.
//!
//! This module provides the `SecurityModule` contract and the dependency
//! injection registry, decoupling specific defensive heuristics from the core
//! eBPF routing engine.

use std::collections::HashMap;

/// BPF Map Dependency Injection Contract
///
/// Decouples the heuristic modules from the core routing engine's concrete
/// `libbpf-rs` skeleton implementations. By providing an interface to request
/// maps dynamically by their C-defined names, modules can securely manipulate
/// kernel state (e.g., updating hardware-backed watchlists or toggling flags)
/// without introducing tightly-coupled, circular dependencies between the
/// `core` and `modules` crates.
pub trait MapProvider {
	fn get_map(&self, name: &str) -> Result<libbpf_rs::Map<'_>, String>;
}

/// A zero-copy utility for safely extracting native Rust types from contiguous
/// eBPF telemetry buffers. Prevents buffer underruns and isolates
/// byte-shifting boilerplate from the heuristic modules.
pub struct BpfReader<'a> {
	data: &'a [u8],
	offset: usize,
}

impl<'a> BpfReader<'a> {
	pub fn new(data: &'a [u8]) -> Self {
		Self { data, offset: 0 }
	}

	/// Safely extracts a 32-bit unsigned integer using native endianness.
	pub fn read_u32(&mut self) -> Result<u32, &'static str> {
		if self.offset + 4 > self.data.len() {
			return Err("Buffer underrun: Failed to isolate u32 block.");
		}
		let bytes: [u8; 4] = self.data[self.offset..self.offset + 4]
			.try_into()
			.map_err(|_| "Memory layout mismatch for u32")?;
		self.offset += 4;
		Ok(u32::from_ne_bytes(bytes))
	}

	/// Safely extracts a C-style null-terminated string up to a maximum
	/// length.
	pub fn read_string(&mut self, max_len: usize) -> Result<String, &'static str> {
		if self.offset + max_len > self.data.len() {
			return Err("Buffer underrun: String boundary exceeds payload size.");
		}

		let path_buffer = &self.data[self.offset..self.offset + max_len];
		let null_index = path_buffer.iter().position(|&b| b == 0).unwrap_or(max_len);

		// `from_utf8_lossy` sanitizes invalid byte sequences seamlessly
		let raw_string = String::from_utf8_lossy(&path_buffer[0..null_index]).into_owned();
		self.offset += max_len;

		// Automatically sanitize all kernel strings to prevent log injection
		// system-wide
		let sanitized = raw_string.replace(|c: char| !c.is_ascii_graphic() && c != ' ', "?");

		// Forensic Preservation Heuristic
		// If non-printable characters were stripped, we alert the SIEM stream
		// so operators know the original filename was mangled (e.g. evasive
		// malware).
		if sanitized.len() != raw_string.len() {
			eprintln!(
				"Bouclier Bleu [Warning]: Sanitized {} non-printable chars from kernel string",
				raw_string.len() - sanitized.len()
			);
		}

		Ok(sanitized)
	}
}

/// Defines the architectural boundary between the generalized eBPF event
/// router and specialized defensive heuristics.
///
/// Modules are instantiated once at boot and shared across asynchronous worker
/// threads (the Main Actor loop and the IPC loop) via `Arc`. Implementors
/// must guarantee thread-safe interior mutability.
pub trait SecurityModule: Send + Sync {
	/// The human-readable operational name for UI/CLI presentation.
	fn name(&self) -> &'static str;

	/// The unique system identifier used by the IPC router for mapping
	/// incoming daemon commands to the correct instance.
	fn slug(&self) -> &'static str;

	/// Returns the real-time operational state.
	/// `false` indicates the module should silently drop routed kernel events.
	fn status(&self) -> bool;

	/// Instructs the module to alter its active state.
	fn toggle(&self, state: bool);

	/// Ingestion pipeline for kernel telemetry.
	///
	/// Receives raw byte slices directly from the BPF RingBuffer.
	/// Implementations are strictly responsible for safe deserialization to
	/// uphold memory safety across the kernel/user boundary.
	fn process_event(&self, event_data: &[u8]);

	/// Pre-Load Map Sizing Heuristic
	///
	/// Returns a declarative mapping of BPF Map names to their required
	/// capacities. This is evaluated strictly during the 'Open' phase of the
	/// eBPF lifecycle (before kernel-space memory allocation). It allows
	/// modules to dynamically shrink or expand their Hash/Array maps based on
	/// real-time system state (e.g., active directory counts), avoiding the
	/// massive `RLIMIT_MEMLOCK` overhead of hardcoded worst-case scenarios.
	fn map_capacities(&self) -> HashMap<String, u32> {
		HashMap::new()
	}

	/// Post-Attach Lifecycle Hook
	///
	/// Executed synchronously immediately after the eBPF skeleton is loaded
	/// and attached to the kernel, but strictly before the asynchronous
	/// RingBuffer polling loop begins.
	///
	/// This provides a guaranteed-safe window for modules to perform
	/// initialization logic - such as pre-populating eBPF Hash maps with
	/// target Inodes or configuring baseline telemetry thresholds-via the
	/// injected `MapProvider` context, eliminating race conditions during
	/// startup.
	fn init(&self, _provider: &dyn MapProvider) -> Result<(), String> {
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_bpf_reader_u32_success() {
		/*
		 * Native Endianness Extraction Validation
		 * Ensures that a valid 4-byte slice is correctly converted into a u32
		 * without advancing the offset out of bounds.
		 */
		let data = 42u32.to_ne_bytes();
		let mut reader = BpfReader::new(&data);

		assert_eq!(reader.read_u32(), Ok(42));
		assert_eq!(reader.offset, 4);
	}

	#[test]
	fn test_bpf_reader_u32_underrun() {
		/*
		 * Buffer Underrun Mitigation
		 * Validates that malformed eBPF payloads (e.g., truncated packets)
		 * fail safely rather than causing a kernel/user boundary panic.
		 */
		let data = [0u8; 3]; // Intentionally 1 byte short
		let mut reader = BpfReader::new(&data);

		assert!(reader.read_u32().is_err());
	}

	#[test]
	fn test_bpf_reader_string_success() {
		/*
		 * C-Style String Parsing
		 * Verifies null-byte termination handling. The reader must stop
		 * exactly at the null byte while advancing the offset by the full
		 * `max_len`.
		 */
		let mut data = b"secret.txt\0".to_vec();
		data.extend_from_slice(&[0u8; 5]); // Add padding

		let mut reader = BpfReader::new(&data);
		let result = reader.read_string(15);

		assert_eq!(result, Ok("secret.txt".to_string()));
		assert_eq!(reader.offset, 15);
	}

	#[test]
	fn test_bpf_reader_string_sanitization() {
		/*
		 * Evasive Malware Sanitization
		 * Ensures that non-printable ASCII characters (often used by rootkits
		 * for log injection or terminal manipulation) are replaced with `?`.
		 */
		let payload = b"malware\x1B[31m.sh\0";
		let mut reader = BpfReader::new(payload);

		let result = reader.read_string(payload.len());
		// \x1B is the ESC character, [ is printable, so it becomes
		// malware?[31m.sh
		assert_eq!(result.unwrap(), "malware?[31m.sh");
	}

	#[test]
	fn test_bpf_reader_string_underrun() {
		let data = b"short\0";
		let mut reader = BpfReader::new(data);

		// Attempting to read 10 bytes from a 6-byte buffer
		assert!(reader.read_string(10).is_err());
	}
}
