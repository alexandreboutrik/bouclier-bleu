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

use libbpf_rs::MapCore;
use rustix::fs::{openat, Mode, OFlags, CWD};
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use xattr::FileExt;

/// Abstraction for declarative target filtering.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
	File,
	Directory,
}

/// Secure Filesystem Traversal Builder
///
/// Standardizes directory scanning across all security modules. Enforces a
/// strict maximum recursion depth of 20 and explicitly disables symlink
/// following. This neutralizes infinite loops, I/O exhaustion, and extreme
/// startup latency caused by malicious filesystem nesting or recursive
/// bind-mounts.
pub fn build_secure_walker<P: AsRef<Path>>(path: P) -> walkdir::IntoIter {
	walkdir::WalkDir::new(path)
		.max_depth(20)
		.follow_links(false)
		.into_iter()
}

/// Centralized Hardware Key Generator
///
/// Translates user-space filesystem metadata into the strict 16-byte composite
/// key (Inode + Kernel Device ID) required by the eBPF `dir_id` C-struct.
/// Centralizing this prevents bitwise math duplication and ensures uniform
/// padding alignment across all security modules.
pub fn generate_hardware_key(metadata: &Metadata) -> [u8; 16] {
	let ino = metadata.ino();
	let user_dev = metadata.dev();

	/*
	 * Pure-Rust dev_t Translation (Linux ABI)
	 * Strict internal policy forbids unsafe FFI to libc. Therefore, we
	 * manually replicate the <sys/sysmacros.h> gnu_dev_major/minor bitwise
	 * shifts to decode the 64-bit userland `dev_t` into major and minor
	 * numbers, then repack them into the kernel's 32-bit eBPF format.
	 */
	let major = ((user_dev >> 8) & 0xfff) | ((user_dev >> 32) & !0xfff);
	let minor = (user_dev & 0xff) | ((user_dev >> 12) & !0xff);

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

/// Declarative Helper: Generalized Map Sizing Heuristic
///
/// Traverses the provided system paths to establish a precise upper bound
/// for the BPF Map allocation before loading the eBPF program, avoiding
/// severe `RLIMIT_MEMLOCK` overheads from hardcoded worst-case scenarios.
/// Applies a 1.25x (25%) safety buffer for future allocations. Because the
/// Linux VFS layer heavily caches dentries, this initial pass pulls the
/// metadata from disk to RAM, dramatically accelerating the subsequent
/// `init` population pass.
pub fn calculate_dynamic_capacity(
	target_paths: &[&str],
	entry_type: EntryType,
	min_capacity: u32,
	ignore_hidden: bool,
	allow_hidden: &[&str],
) -> u32 {
	let mut count = 0;
	for path in target_paths {
		let walker = build_secure_walker(path).filter_entry(|e| {
			if !ignore_hidden {
				return true;
			}
			let fname = e.file_name().to_string_lossy();
			if !fname.starts_with('.') {
				return true;
			}
			allow_hidden.contains(&fname.as_ref())
		});

		for entry in walker.filter_map(|e| e.ok()) {
			let is_match = match entry_type {
				EntryType::File => entry.file_type().is_file(),
				EntryType::Directory => entry.file_type().is_dir(),
			};
			if is_match {
				count += 1;
			}
		}
	}
	((count as f64 * 1.25) as u32).max(min_capacity)
}

/// Declarative Helper: Generalized Hardware-backed Watchlist Setup
///
/// Scans system paths and populates a BPF map. Advanced adversaries routinely
/// use mount namespaces (`unshare -m`) or bind-mounts to obfuscate paths and
/// bypass string-matching security heuristics. To neutralize this, this engine
/// resolves the exact physical `inode` of target paths at boot.
pub fn populate_map_from_paths(
	bpf_map: &libbpf_rs::Map<'_>,
	target_paths: &[&str],
	entry_type: EntryType,
	ignore_hidden: bool,
	allow_hidden: &[&str],
	module_slug: &str,
) -> Result<(), String> {
	let is_protected: [u8; 1] = [1];

	for path in target_paths {
		println!(
			"Bouclier Bleu [Setup]: Recursively indexing path {} for {}...",
			path, module_slug
		);

		/*
		 * Optimization & Constraint Management
		 * The eBPF hash map has strict capacity limits. By optionally
		 * filtering hidden directories (e.g., `~/.cache`), we prevent capacity
		 * exhaustion and optimize lookup latency for paths that contain
		 * high-churn, benign files that do not require strict monitoring.
		 */
		let walker = build_secure_walker(path).filter_entry(|e| {
			if !ignore_hidden {
				return true;
			}
			let file_name = e.file_name().to_string_lossy();
			if !file_name.starts_with('.') {
				return true;
			}
			allow_hidden.contains(&file_name.as_ref())
		});

		for entry in walker.filter_map(|e| e.ok()) {
			let is_match = match entry_type {
				EntryType::File => entry.file_type().is_file(),
				EntryType::Directory => entry.file_type().is_dir(),
			};

			if !is_match {
				continue;
			}

			if let Ok(key_bytes) = get_secure_hardware_key(entry.path()) {
				bpf_map
					.update(&key_bytes, &is_protected, libbpf_rs::MapFlags::ANY)
					.map_err(|e| {
						format!(
							"CRITICAL: Map update failed for {}: {}",
							entry.path().display(),
							e
						)
					})?;
			}
		}
	}
	Ok(())
}

/// Declarative Helper: JIT Map Sizing Heuristic
///
/// Traverses the provided system paths to establish a precise upper bound
/// for the BPF Map allocation before loading the eBPF program, avoiding
/// severe `RLIMIT_MEMLOCK` overheads from hardcoded worst-case scenarios.
/// Applies a 25% safety buffer for future installations, with a fallback floor of 2048.
pub fn calculate_watchlist_capacity(target_paths: &[&str]) -> u32 {
	let mut count = 0;
	for path in target_paths {
		for entry in build_secure_walker(path).filter_map(|e| e.ok()) {
			if entry.file_type().is_file() {
				count += 1;
			}
		}
	}
	((count as f64 * 1.25) as u32).max(2048)
}

/// Declarative Helper: Hardware-backed Extended Attribute Watchlist Setup
///
/// Scans system paths and populates a BPF map based on extended attributes.
/// It utilizes a strict "No Symlink" policy to prevent TOCTOU race conditions
/// while indexing opted-in binaries during daemon startup.
pub fn populate_map_from_xattr(
	bpf_map: &libbpf_rs::Map<'_>,
	target_paths: &[&str],
	xattr_name: &str,
	module_slug: &str,
) -> Result<(), String> {
	let is_whitelisted: [u8; 1] = [1];

	for path in target_paths {
		println!(
			"Bouclier Bleu [Setup]: Scanning {} for {} opt-in attributes...",
			path, module_slug
		);

		for entry in build_secure_walker(path).filter_map(|e| e.ok()) {
			if entry.file_type().is_file() {
				/*
				 * TOCTOU Race Condition Mitigation
				 * By avoiding the path-based `xattr::get` entirely and
				 * opening the file descriptor directly with O_NOFOLLOW, we
				 * completely neutralize the window where an attacker could
				 * swap the target binary for a malicious symlink right before
				 * we extract the hardware key.
				 */
				if let Ok(fd) = rustix::fs::openat(
					rustix::fs::CWD,
					entry.path(),
					rustix::fs::OFlags::RDONLY
						| rustix::fs::OFlags::NOFOLLOW
						| rustix::fs::OFlags::CLOEXEC,
					rustix::fs::Mode::empty(),
				) {
					let file = std::fs::File::from(fd);
					match file.get_xattr(xattr_name) {
						Ok(Some(fd_xattr)) if fd_xattr == b"1" => {
							if let Ok(metadata) = file.metadata() {
								let key_bytes = generate_hardware_key(&metadata);

								/*
								 * Strict Map Exhaustion Handling
								 * We explicitly catch and bubble up errors if
								 * the BPF map runs out of bounds, preferring
								 * to crash the daemon rather than silently
								 * failing open.
								 */
								if let Err(e) = bpf_map.update(
									&key_bytes,
									&is_whitelisted,
									libbpf_rs::MapFlags::ANY,
								) {
									return Err(format!(
										"CRITICAL: {} map failed to update: {}",
										bpf_map.name().to_string_lossy(),
										e
									));
								}

								println!("Bouclier Bleu [Setup]: {} strict enforcement activated for {:?}", module_slug, entry.path());
							}
						}
						_ => {} // Attribute not present or invalid; silently ignore
					}
				}
			}
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::env;
	use std::fs::File;

	#[test]
	fn test_build_secure_walker_constraints() {
		/*
		 * Defensive Recursion Validation
		 * Ensures the walker is initialized with our strict anti-exhaustion
		 * parameters (max_depth=20, follow_links=false). While we can't easily
		 * assert the internal state of `walkdir`, we can verify it doesn't
		 * panic upon instantiation with valid paths.
		 */
		let temp_dir = env::temp_dir();
		let walker = build_secure_walker(&temp_dir);

		// Ensure it produces an iterator
		assert!(walker.into_iter().next().is_some());
	}

	#[test]
	fn test_generate_hardware_key_alignment() {
		/*
		 * eBPF dir_id Memory Layout Assertion
		 * We create a temporary file to extract real kernel metadata,
		 * then validate that our pure-Rust bitwise translation maps correctly
		 * to a 16-byte array, with the final 4 bytes acting as C-struct
		 * padding (0s).
		 */
		let temp_dir = env::temp_dir();
		let temp_file_path = temp_dir.join("bouclier_test_hw_key.tmp");

		// Create a dummy file to generate valid OS metadata
		File::create(&temp_file_path).expect("Failed to create temp test file");

		let meta = std::fs::metadata(&temp_file_path).expect("Failed to read metadata");

		let key = generate_hardware_key(&meta);

		// 1. Length must be exactly 16 bytes for eBPF map alignment
		assert_eq!(key.len(), 16);

		// 2. The padding bytes (12..16) must remain strictly 0
		assert_eq!(&key[12..16], &[0, 0, 0, 0]);

		// Cleanup
		let _ = std::fs::remove_file(temp_file_path);
	}
}
