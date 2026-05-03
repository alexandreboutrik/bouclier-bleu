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

use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use libbpf_rs::RingBuffer;
use modules::SecurityModule;

use crate::bpf_manager::{bpf_loader, BpfEngine};
use crate::ipc;

/// The Event Dispatcher
/// Manages the infinite execution loop, non-blocking IPC interactions, and
/// routing commands into the bpf_manager.
pub struct DaemonActor<'a> {
	pub rx: mpsc::Receiver<ipc::IpcMessage>,
	pub engine: &'a BpfEngine,
	pub ring_buffer: Option<RingBuffer<'a>>,
	pub shared_registry: Arc<Vec<Arc<dyn SecurityModule + Send + Sync>>>,
}

impl<'a> DaemonActor<'a> {
	pub fn run(self) {
		println!("· [Success] Engine is running securely.");
		println!("Press Ctrl+C to exit.");

		// MAIN ACTOR LOOP
		loop {
			/*
			 * Process non-blocking IPC commands from the Control Plane
			 * Bound the channel drain to a maximum of 10 messages per tick.
			 */
			for msg in self.rx.try_iter().take(10) {
				let response = self.handle_command(msg.cmd);
				let _ = msg.reply.send(response);
			}

			// Service the Kernel Telemetry Queues
			if let Some(rb) = &self.ring_buffer {
				if let Err(e) = rb.poll(Duration::from_millis(50)) {
					eprintln!("Bouclier Bleu [Warning]: Telemetry poll interrupted: {}", e);
				}
			} else {
				/*
				 * If no telemetry maps are loaded, fallback to a standard
				 * sleep so we don't accidentally pin the CPU to 100% in a
				 * busy-wait loop.
				 */
				thread::sleep(Duration::from_millis(50));
			}
		}
	}

	/// Extracted IPC command handler to isolate routing logic and lower
	/// the cognitive complexity of the main event loop.
	fn handle_command(&self, cmd: ipc::DaemonCmd) -> String {
		match cmd {
			ipc::DaemonCmd::Status => {
				"Bouclier Bleu EDR Status: Kernel Engine Running\n".to_string()
			}

			ipc::DaemonCmd::List => {
				let mut out = String::from("MODULE REGISTRY:\n");
				for module in self.shared_registry.iter() {
					let state = if module.status() {
						"[ACTIVE]  "
					} else {
						"[INACTIVE]"
					};
					out.push_str(&format!(
						" {} {} ({})\n",
						state,
						module.slug(),
						module.name()
					));
				}
				out
			}

			ipc::DaemonCmd::Enable(target) => self.toggle_module(target, true),
			ipc::DaemonCmd::Disable(target) => self.toggle_module(target, false),
		}
	}

	/// Unified handler for state synchronization.
	/// Consolidates Enable/Disable logic to prevent code duplication.
	fn toggle_module(&self, target: String, enable: bool) -> String {
		let state_str = if enable { "ENABLED" } else { "DISABLED" };

		if let Some(skel) = self.engine.get_skeleton(&target) {
			// FAST PATH
			// Seamlessly toggle enforcement logic via `state_map` while
			// retaining the BPF file descriptor to avoid latency spikes and
			// kernel reallocation.
			match bpf_loader::set_module_state(skel, &target, enable) {
				Ok(_) => {
					if let Some(user_mod) = self.shared_registry.iter().find(|m| m.slug() == target)
					{
						user_mod.toggle(enable);
					}
					format!(
						"SUCCESS: Defense module '{}' {} via state synchronization\n",
						target, state_str
					)
				}
				Err(e) => format!(
					"ERROR: Failed to update kernel state for '{}': {}\n",
					target, e
				),
			}
		} else {
			if enable {
				// SLOW PATH
				// We do not attempt dangerous mid-flight eBPF
				// compilations/loads. If it's not in memory, reject it.
				format!(
					"ERROR: Module '{}' is not loaded in kernel memory. Check daemon boot logs or restart the service to load new modules.\n",
					target
				)
			} else {
				format!("ERROR: Module '{}' is not currently active\n", target)
			}
		}
	}
}
