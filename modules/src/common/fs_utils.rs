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

use rustix::fs::{openat, Mode, OFlags, CWD};
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

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
