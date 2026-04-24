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
//! This module provides the `SecurityModule` contract and the IoC registry,
//! decoupling specific defensive heuristics from the core eBPF routing engine.

use rustix::fs::{openat, Mode, OFlags, CWD};
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

pub mod exec_block;
pub mod mount_secure;
pub mod rename_entropy;
pub mod shield;
pub mod strict_wx;

/// BPF Map Dependency Injection Contract
///
/// Decouples the heuristic modules from the core routing engine's concrete
/// `libbpf-rs` skeleton implementations. By providing an interface to request
/// maps dynamically by their C-defined names, modules can securely manipulate
/// kernel state (e.g., updating hardware-backed watchlists or toggling flags)
/// without introducing tightly-coupled, circular dependencies between the
/// `core` and `modules` crates.
pub trait MapProvider {
	fn get_map(&self, name: &str) -> Result<&libbpf_rs::Map, String>;
}

/// A zero-copy utility for safely extracting native Rust types from contiguous
/// eBPF telemetry buffers. Prevents buffer underruns and isolates byte-shifting
/// boilerplate from the heuristic modules.
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

	/// Safely extracts a C-style null-terminated string up to a maximum length.
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

	/// The unique system identifier used by the IPC router for mapping incoming
	/// daemon commands to the correct instance.
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
	fn map_capacities(&self) -> std::collections::HashMap<String, u32> {
		std::collections::HashMap::new()
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

/// Inversion of Control (IoC) Registry Builder.
///
/// Constructs the active defense matrix. The core engine remains agnostic to
/// specific threat heuristics, iterating purely over this dynamic trait object
/// matrix.
pub fn build_registry() -> Vec<Arc<dyn SecurityModule + Send + Sync>> {
	vec![
		Arc::new(exec_block::ExecBlock::new()),
		Arc::new(rename_entropy::RenameEntropy::new()),
		Arc::new(shield::Shield::new()),
		Arc::new(mount_secure::MountSecure::new()),
		Arc::new(strict_wx::StrictWx::new()),
		// Future expansions: e.g. Arc::new(ransomware_heur::CanaryDrop::new()),
	]
}

/// Declarative factory macro for generating `SecurityModule` boilerplate.
///
/// Enforces a strict "No Unsafe" boundary. Callers must inject a purely safe
/// parsing function (`$parser`) to validate raw kernel bytes before the
/// payload reaches the heuristic engine.
#[macro_export]
macro_rules! define_security_module {
    (
        struct: $struct_name:ident,
        name: $name:expr,
        slug: $slug:expr,
        parser: $parser:path,
        handler: $handler:expr
        $(, capacities: $capacities_closure:expr)?
        $(, init: $init_closure:expr)?
    ) => {
        pub struct $struct_name {
            is_active: std::sync::atomic::AtomicBool,
        }

        impl $struct_name {
            pub fn new() -> Self {
                Self {
                    is_active: std::sync::atomic::AtomicBool::new(true),
                }
            }
        }

        impl Default for $struct_name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl crate::SecurityModule for $struct_name {
            fn name(&self) -> &'static str {
                $name
            }
            fn slug(&self) -> &'static str {
                $slug
            }

            fn status(&self) -> bool {
                /*
                 * Ordering::Relaxed is sufficient for the high-frequency read
                 * loop. We prioritize CPU cache-coherency performance over
                 * strict synchronization for a simple boolean flag.
                 */
                self.is_active.load(std::sync::atomic::Ordering::Relaxed)
            }

            fn toggle(&self, state: bool) {
                /*
                 * Ordering::SeqCst ensures the state change from the IPC
                 * thread  is immediately visible to the RingBuffer polling
                 * thread.
                 */
                self.is_active
                    .store(state, std::sync::atomic::Ordering::SeqCst);
                println!(
                    "Bouclier Bleu [Control]: {} active state -> {}",
                    self.slug(),
                    state
                );
            }

            fn process_event(&self, event_data: &[u8]) {
                if !self.status() {
                    return;
                }

                /*
                 * Utilize the strictly safe, module-specific parsing logic.
                 * If the kernel payload is malformed or maliciously tampered
                 * with, it is caught here before entering the heuristic
                 * engine.
                 */
                match $parser(event_data) {
                    Ok(alert) => {
                        // Pass the validated, purely safe Rust struct to the
                        // logic block
                        $handler(alert);
                    }
                    Err(e) => {
                        eprintln!(
                            "Bouclier Bleu [Error]: {} failed to parse kernel event: {}",
                            self.slug(),
                            e
                        );
                    }
                }
            }

            fn map_capacities(&self) -> std::collections::HashMap<String, u32> {
                let mut _caps = std::collections::HashMap::new();
                $(
                    _caps = $capacities_closure();
                )?
                _caps
            }

            /*
             * Declarative Lifecycle Execution
             * Encapsulates the module-specific setup closure defined during
             * macro invocation. It safely passes the map resolution context
             * down to the heuristic logic while maintaining the strict
             * safe-Rust boundary enforced by the IoC registry.
             */
            fn init(&self, _provider: &dyn crate::MapProvider) -> Result<(), String> {
                $(
                    $init_closure(_provider)?;
                )?
                Ok(())
            }
        }
    };
}

/// Centralized Hardware Key Generator
///
/// Translates user-space filesystem metadata into the strict 16-byte
/// composite key (Inode + Kernel Device ID) required by the eBPF `dir_id`
/// C-struct. Centralizing this prevents bitwise math duplication and
/// ensures uniform padding alignment across all security modules.
pub fn generate_hardware_key(metadata: &Metadata) -> [u8; 16] {
	let ino = metadata.ino();
	let user_dev = metadata.dev();

	/*
	 * User-to-Kernel dev_t Translation
	 * glibc uses a 64-bit encoded device ID. The kernel uses a 32-bit
	 * internal format ((major << 20) | minor). We must reconstruct it.
	 */
	let major = ((user_dev & 0x00000000000fff00) >> 8) | ((user_dev & 0xfffff00000000000) >> 32);
	let minor = (user_dev & 0x00000000000000ff) | ((user_dev & 0x00000ffffff00000) >> 12);
	let kernel_dev = ((major as u32) << 20) | (minor as u32);

	// Construct the 16-byte struct dir_id memory layout
	let mut key_bytes = [0u8; 16];
	key_bytes[0..8].copy_from_slice(&ino.to_ne_bytes());
	key_bytes[8..12].copy_from_slice(&kernel_dev.to_ne_bytes());
	// Bytes 12..16 inherently remain 0 as padding for C-struct alignment

	key_bytes
}

/// Securely extracts a hardware key, neutralizing TOCTOU symlink races.
///
/// Opens a file descriptor enforcing `O_NOFOLLOW` to prevent symlink swapping
/// during path resolution, then extracts the hardware-backed Inode and Device
/// ID.
pub fn get_secure_hardware_key<P: AsRef<Path>>(path: P) -> std::io::Result<[u8; 16]> {
	/*
	 * Open the file descriptor safely
	 * OFlags::NOFOLLOW prevents symlink evaluation. OFlags::CLOEXEC prevents
	 * file descriptor leaks to child processes.
	 */
	let fd = openat(
		CWD,
		path.as_ref(),
		OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::PATH | OFlags::CLOEXEC,
		Mode::empty(),
	)
	.map_err(Into::<std::io::Error>::into)?;

	let file = File::from(fd);

	let metadata = file.metadata()?;
	Ok(generate_hardware_key(&metadata))
}
