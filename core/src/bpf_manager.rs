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

use anyhow::Result;
use std::any::Any;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use crate::config::DaemonConfig;
use modules::common::traits::{MapProvider, SecurityModule};

#[allow(clippy::all)]
pub mod bpf_loader {
	include!(concat!(env!("OUT_DIR"), "/bpf_loader.rs"));
}

/// Concrete BPF Map Resolver
///
/// Implements the `MapProvider` dependency injection contract for the core
/// daemon. It acts as the secure bridge between the type-erased eBPF skeletons
/// (`dyn Any`) stored in the active registry and the strongly-typed
/// `libbpf_rs::Map` handles. It delegates the unsafe downcasting to the
/// dynamically generated `bpf_loader` bindings.
pub struct CoreMapProvider<'a> {
	pub skel: &'a dyn Any,
}

impl<'a> MapProvider for CoreMapProvider<'a> {
	fn get_map(&self, name: &str) -> Result<libbpf_rs::Map<'_>, String> {
		bpf_loader::get_map(self.skel, name).map_err(|e| e.to_string())
	}
}

/// Determines if the host kernel is running version 6.12 or newer.
/// This boundary signifies the major VFS refactor where `vfs_mkdir`
/// transitioned to returning a `struct dentry *` instead of an `int`.
fn is_post_2025_vfs() -> bool {
	// Attempt to read the release string (e.g., "6.12.0-azure\n")
	let release = match fs::read_to_string("/proc/sys/kernel/osrelease") {
		Ok(s) => s.trim().to_string(),
		Err(_) => {
			// Fallback to true (newer) if procfs is completely unavailable,
			// erring on the side of modern kernel layouts.
			return true;
		}
	};

	// Parse the major and minor versions
	let parts: Vec<&str> = release.split('.').collect();
	if parts.len() < 2 {
		return true; // malformed
	}

	if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
		return major > 6 || (major == 6 && minor >= 12);
	}

	true // Fallback if parsing fails
}

/// The Kernel Broker
/// Responsible for handling all eBPF lifecycle events, kernel boundary checks,
/// and keeping the active skeletons safely in memory.
#[derive(Default)]
pub struct BpfEngine {
	/*
	 * Kernel Memory Lifecycle
	 * We maintain active eBPF skeletons strictly in memory. Dropping these
	 * file descriptors would instruct the kernel to abruptly detach the BPF
	 * hooks.
	 * For real-time state manipulation (toggling on/off), we now synchronize
	 * state directly into the kernel's maps to avoid performance bottlenecks
	 * and fail-open race conditions associated with rapid attach/detach
	 * cycles.
	 */
	pub active_skeletons: HashMap<String, Box<dyn Any>>,
}

impl BpfEngine {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn load_modules(
		&mut self,
		shared_registry: &Arc<Vec<Arc<dyn SecurityModule + Send + Sync>>>,
		daemon_config: &DaemonConfig,
	) {
		// Evaluate the kernel boundary once before loading modules
		let post_2025 = is_post_2025_vfs();

		for mod_name in bpf_loader::available_modules() {
			let capacities = Self::get_capacities(mod_name, shared_registry);

			if let Ok(skel) = bpf_loader::load_module(mod_name, &capacities, |obj| {
				/*
				 * Kernel Btf Signature Validation
				 * If the module contains multi-version fexit hooks (like
				 * vfs_mkdir), we must disable the one that does not match the
				 * host kernel's exact signature, otherwise the verifier will
				 * reject the entire object during the load phase with -EINVAL.
				 *
				 * vfs_rename has taken `struct renamedata *` since Linux 5.12.
				 * The CO-RE logic inside the _new hook already dynamically
				 * handles the layout changes.
				 */
				let old_hook = format!("{}_vfs_mkdir_exit_old", mod_name);
				let new_hook = format!("{}_vfs_mkdir_exit_new", mod_name);
				let old_rename = format!("{}_vfs_rename_exit_old", mod_name);
				let new_rename = format!("{}_vfs_rename_exit_new", mod_name);

				// Iterate securely over mutable programs to bypass
				// deeply nested optionals and match arms.
				for mut prog in obj.progs_mut() {
					let name = prog.name().to_string_lossy();
					if name == new_hook {
						prog.set_autoload(post_2025);
					} else if name == old_hook {
						prog.set_autoload(!post_2025);
					} else if name == new_rename {
						prog.set_autoload(true);
					} else if name == old_rename {
						prog.set_autoload(false);
					}
				}

				Ok(())
			}) {
				println!("· Loaded and Attached eBPF module: {}", mod_name);
				self.active_skeletons.insert(mod_name.to_string(), skel);
			} else {
				eprintln!("· [Fatal] Failed to load module {}", mod_name);
			}
		}

		self.initialize_active_modules(shared_registry, daemon_config);
	}

	pub fn get_skeleton(&self, target: &str) -> Option<&dyn Any> {
		self.active_skeletons.get(target).map(|b| &**b)
	}

	/// Extracts dynamic memory constraints from the userland module.
	/// This bridges the architectural gap between the module's domain-specific
	/// sizing logic and the generic BPF loader.
	fn get_capacities(
		mod_name: &str,
		shared_registry: &Arc<Vec<Arc<dyn SecurityModule + Send + Sync>>>,
	) -> HashMap<String, u32> {
		if let Some(user_mod) = shared_registry.iter().find(|m| m.slug() == mod_name) {
			user_mod.map_capacities()
		} else {
			HashMap::new()
		}
	}

	/// The Modular Init Dispatcher
	/// Lifecycle Synchronization Boundary handled iteratively post-load.
	fn initialize_active_modules(
		&self,
		shared_registry: &Arc<Vec<Arc<dyn SecurityModule + Send + Sync>>>,
		daemon_config: &DaemonConfig,
	) {
		for (mod_name, stored_skel) in self.active_skeletons.iter() {
			let is_active = daemon_config
				.modules
				.get(mod_name)
				.copied()
				.unwrap_or(false);

			if let Err(e) = bpf_loader::set_module_state(&**stored_skel, mod_name, is_active) {
				println!(
					"· [Warning] Failed to initialize kernel state map for {}: {}",
					mod_name, e
				);
			}

			/*
			 * At this specific execution phase, the eBPF program is
			 * successfully loaded and actively enforcing in the kernel, but
			 * the userland RingBuffer consumer thread has not yet been bound.
			 * We invoke the module's optional `init` routine, injecting the
			 * `CoreMapProvider` context to securely configure kernel state
			 * before high-frequency telemetry begins flowing.
			 */
			if let Some(user_mod) = shared_registry.iter().find(|m| m.slug() == mod_name) {
				let provider = CoreMapProvider {
					skel: &**stored_skel,
				};
				if let Err(e) = user_mod.init(&provider) {
					eprintln!("· [Fatal] Module {} initialization failed: {}", mod_name, e);
				}
				user_mod.toggle(is_active);
			}
		}
	}
}
