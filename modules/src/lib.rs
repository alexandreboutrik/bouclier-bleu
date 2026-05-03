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
use std::fs::{File, Metadata, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

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
	fn get_map(&self, name: &str) -> Result<libbpf_rs::Map<'_>, String>;
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

		// Forensic Preservation Heuristic
		// If non-printable characters were stripped, we alert the SIEM stream
		// so operators know the original filename was mangled (e.g. evasive malware).
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

        impl $crate::SecurityModule for $struct_name {
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
                        /*
                         * NDJSON Pipeline
                         * Automatically intercept the parsed, safe Rust struct
                         * and forward it to the standardized SIEM JSON log
                         * before executing localized remediation closures.
                         * This guarantees zero-code integration for all
                         * modules.
                         */
                        $crate::emit_siem_event($slug, &alert);

                        // Pass the validated payload to the localized logic
                        // block
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
            fn init(&self, _provider: &dyn $crate::MapProvider) -> Result<(), String> {
                $(
                    $init_closure(_provider)?;
                )?
                Ok(())
            }
        }
    };
}

/*
 * Decoupled Telemetry Sink
 * Global lock for the NDJSON log file. Utilizing OnceLock ensures the file
 * descriptor is lazily initialized exactly once across all asynchronous worker
 * threads, while the Mutex prevents interleaved JSON objects during concurrent
 * high-frequency attack bursts.
 */
static SIEM_LOG_SINK: OnceLock<Mutex<Option<File>>> = OnceLock::new();

/// NDJSON Forwarding Engine
///
/// Wraps the module-specific struct in a standardized envelope containing
/// SIEM-critical metadata (ISO-like timestamps, source identifiers) and
/// flushes it to disk.
pub fn emit_siem_event<T: serde::Serialize>(module_slug: &str, alert: &T) {
	let file_mutex = SIEM_LOG_SINK.get_or_init(|| {
        let log_dir = "/var/log/bouclier-bleu";

        /*
         * Graceful Telemetry Degradation
         * Instead of panicking with unwrap() if the fallback file is missing,
         * we safely iterate through a list of fallback devices to keep the EDR
         * daemon alive.
         */
        let get_fallback = || {
            let fallback_file = ["/tmp/bouclier_fallback.log"]
                .iter()
                .find_map(|path| OpenOptions::new().write(true).open(path).ok());
            if fallback_file.is_none() {
                eprintln!("Bouclier Bleu [FATAL]: No writable device available. Telemetry dropped.");
            }

            Mutex::new(fallback_file)
        };

        /*
         * TOCTOU & Privilege Escalation Mitigation
         * We atomically create the directory with root-only permissions
         * (0o700) to prevent unprivileged users from staging symlink attacks
         * within thelog directory.
         */
        if let Err(e) = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(log_dir)
        {
            eprintln!("Bouclier Bleu [Warning]: Failed to securely create log directory: {}", e);
        }

        /*
         * Pre-Existing Directory Validation & Auto-Remediation
         * Validates that the directory wasn't pre-staged by an attacker with 
         * wide-open permissions. Instead of panicking (which allows a trivial 
         * Denial of Service), we auto-remediate by wiping the tainted
         * workspace.
         */
        if let Ok(meta) = std::fs::metadata(log_dir) {
            if !meta.is_dir() || meta.uid() != 0 || (meta.mode() & 0o777) != 0o700 {
                eprintln!(
                    "Bouclier Bleu [WARNING]: Log directory {} has insecure permissions (Potential Pre-Staging Attack). Auto-remediating...",
                    log_dir
                );

                /*
                 * "Nuke and Pave"
                 * We do not just `chmod` the directory, because the attacker 
                 * might have already created `alerts.json` and kept an open 
                 * file descriptor to it to siphon logs. We destroy the entire 
                 * directory tree to guarantee state purity.
                 * Graceful Degradation : Instead of crashing the daemon and
                 * disabling all protection modules via a panic, we fall back
                 * to /dev/null if remediation fails.
                 */
                let removal_result = if !meta.is_dir() {
                    std::fs::remove_file(log_dir)
                } else {
                    std::fs::remove_dir_all(log_dir)
                };

                if let Err(e) = removal_result {
                    eprintln!("Bouclier Bleu [CRITICAL]: Failed to wipe compromised log directory: {}. Sinking telemetry to fallback.", e);
                    return get_fallback();
                }

                // Rebuild the directory cleanly
                if let Err(e) = std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(log_dir)
                {
                    eprintln!("Bouclier Bleu [CRITICAL]: Failed to recreate secure log directory: {}. Sinking telemetry to fallback.", e);
                    return get_fallback();
                }

                eprintln!("Bouclier Bleu [INFO]: Log directory securely rebuilt.");
            }
        } else {
            eprintln!("Bouclier Bleu [CRITICAL]: Failed to verify log directory metadata. Sinking telemetry to fallback.");
            return get_fallback();
        }

        /*
         * Strict Open Controls
         * .mode(0o600): Ensures only root can read the telemetry data.
         * .custom_flags(O_NOFOLLOW): Completely neutralizes symlink swapping 
         * attacks by forcing the kernel to fail the open() syscall if
         * alerts.json is a symbolic link.
         */
        let file_opt = match OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(format!("{}/alerts.json", log_dir))
        {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("Bouclier Bleu [CRITICAL]: Failed to open SIEM sink: {}. Using /dev/null fallback.", e);
                return get_fallback();
            }
        };

        Mutex::new(file_opt)
    });

	/*
	 * Standardized SIEM Envelope
	 * We use a flattened schema so the resulting JSON is a single, clean layer
	 * without nested `alert: { ... }` blocks, which makes indexing in Splunk
	 * or Elasticsearch significantly cheaper and faster.
	 */
	#[derive(serde::Serialize)]
	struct EnvelopedAlert<'a, A: serde::Serialize> {
		#[serde(rename = "@timestamp")]
		timestamp_ms: u128,
		event_source: &'a str,
		#[serde(flatten)]
		payload: &'a A,
	}

	let timestamp_ms = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis();

	let envelope = EnvelopedAlert {
		timestamp_ms,
		event_source: module_slug,
		payload: alert,
	};

	// Serialize and write to disk
	let Ok(json_string) = serde_json::to_string(&envelope) else {
		return;
	};
	let Ok(mut file_guard) = file_mutex.lock() else {
		return;
	};
	let Some(file) = file_guard.as_mut() else {
		return;
	};

	/*
	 * Telemetry Sink Validation
	 * explicitly catch and log write failures to alert operators
	 * of potential disk exhaustion or SIEM ingestion issues.
	 */
	if let Err(e) = writeln!(file, "{}", json_string) {
		eprintln!("Bouclier Bleu [ERROR]: Failed to write SIEM event: {}", e);
	}
}

///
/// Secure Filesystem Traversal Builder
///
/// Standardizes directory scanning across all security modules. Enforces a
/// strict maximum recursion depth of 20 and explicitly disables symlink
/// following. This neutralizes infinite loops, I/O exhaustion, and extreme
/// startup latency caused by malicious filesystem nesting or recursive
/// bind-mounts.
///
pub fn build_secure_walker<P: AsRef<Path>>(path: P) -> walkdir::IntoIter {
	walkdir::WalkDir::new(path)
		.max_depth(20)
		.follow_links(false)
		.into_iter()
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
