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
use std::time::Duration;

use libbpf_rs::RingBuffer;
use modules::common::traits::SecurityModule;

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
			 * Inverted Yielding (Anti-DoS)
			 * We block on the IPC channel instead of the kernel RingBuffer.
			 * This instantly wakes the thread when a CLI command arrives (0ms
			 * latency), eliminating the timeout vulnerabilities while still
			 * capping idle CPU usage.
			 */
			match self.rx.recv_timeout(Duration::from_millis(50)) {
				Ok(msg) => {
					let response = self.handle_command(msg.cmd);
					let _ = msg.reply.send(response);

					/*
					 * Bounded Queue Draining (Anti-Starvation)
					 * We process up to 10 backlogged messages per tick. If a
					 * flood of IPC commands occurs, this forces the thread to
					 * break out and yield CPU to `rb.poll`, ensuring zero
					 * telemetry loss.
					 */
					for pending_msg in self.rx.try_iter().take(10) {
						let response = self.handle_command(pending_msg.cmd);
						let _ = pending_msg.reply.send(response);
					}
				}
				Err(mpsc::RecvTimeoutError::Timeout) => {
					// Expected timeout every 50ms; proceed to telemetry
					// polling
				}
				Err(mpsc::RecvTimeoutError::Disconnected) => {
					eprintln!("Bouclier Bleu [Fatal]: IPC Control Plane disconnected.");
					break;
				}
			}

			// Service the Kernel Telemetry Queues
			if let Some(rb) = &self.ring_buffer {
				/*
				 * Non-Blocking Poll
				 * We pass a 0ms duration because we already yielded time
				 * during the IPC recv_timeout phase. This simply flushes any
				 * pending  kernel events and immediately returns.
				 */
				if let Err(e) = rb.poll(Duration::from_millis(0)) {
					eprintln!("Bouclier Bleu [Warning]: Telemetry poll interrupted: {}", e);
				}
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::bpf_manager::BpfEngine;
	use crate::ipc::DaemonCmd;
	use std::sync::mpsc;

	/*
	 * Actor State Verification
	 * These tests validate the synchronous command routing and string
	 * formatting logic of the DaemonActor. We inject an empty BpfEngine and
	 * Registry to simulate a pristine, unloaded state, bypassing complex
	 * kernel dependencies.
	 */

	fn setup_mock_actor<'a>(engine: &'a BpfEngine) -> DaemonActor<'a> {
		let (_, rx) = mpsc::channel();
		let shared_registry = Arc::new(vec![]);

		DaemonActor {
			rx,
			engine,
			ring_buffer: None,
			shared_registry,
		}
	}

	#[test]
	fn test_handle_command_status() {
		let engine = BpfEngine::default();
		let actor = setup_mock_actor(&engine);

		let response = actor.handle_command(DaemonCmd::Status);
		assert_eq!(
			response,
			"Bouclier Bleu EDR Status: Kernel Engine Running\n"
		);
	}

	#[test]
	fn test_handle_command_list_empty() {
		let engine = BpfEngine::default();
		let actor = setup_mock_actor(&engine);

		let response = actor.handle_command(DaemonCmd::List);
		assert_eq!(response, "MODULE REGISTRY:\n");
	}

	#[test]
	fn test_toggle_module_not_loaded() {
		let engine = BpfEngine::default();
		let actor = setup_mock_actor(&engine);

		/*
		 * Slow Path Rejection Test
		 * Attempting to enable a module that has not been mapped into kernel
		 * memory should safely fail and return an instructional error string.
		 */
		let response = actor.handle_command(DaemonCmd::Enable("exec_block".to_string()));

		assert!(response.contains("ERROR: Module 'exec_block' is not loaded in kernel memory."));
	}

	#[test]
	fn test_toggle_module_disable_not_active() {
		let engine = BpfEngine::default();
		let actor = setup_mock_actor(&engine);

		let response = actor.handle_command(DaemonCmd::Disable("shield".to_string()));

		assert!(response.contains("ERROR: Module 'shield' is not currently active\n"));
	}
}
