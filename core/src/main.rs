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

//! Bouclier Bleu Core Daemon
//!
//! Orchestrates the lifecycle of eBPF kernel hooks, manages the asynchronous
//! telemetry ingestion pipeline, and brokers IPC commands from the Control
//! Plane.

use anyhow::{Context, Result};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use libbpf_rs::RingBufferBuilder;
use modules::SecurityModule;

pub mod config;
pub mod ipc;

#[allow(clippy::all)]
pub mod bpf_loader {
    include!(concat!(env!("OUT_DIR"), "/bpf_loader.rs"));
}

/// Concrete BPF Map Resolver
///
/// Implements the `MapProvider` dependency injection contract for the core
/// daemon. It acts as the secure bridge between the type-erased eBPF skeletons
/// (`dyn Any`) stored in the active registry and the strongly-typed
/// `libbpf_rs::Map` references. It delegates the unsafe downcasting to the
/// dynamically generated `bpf_loader` bindings.
struct CoreMapProvider<'a> {
    skel: &'a dyn Any,
}

impl<'a> modules::MapProvider for CoreMapProvider<'a> {
    fn get_map(&self, name: &str) -> Result<&libbpf_rs::Map, String> {
        bpf_loader::get_map(self.skel, name).map_err(|e| e.to_string())
    }
}

fn main() -> Result<()> {
    println!("🛡️ Starting Bouclier Bleu Core Engine...");

    let daemon_config = config::DaemonConfig::load();

    /*
     * REGISTRY INITIALIZATION
     * The userland registry acts as the logical abstraction layer for defense
     * rules.
     * Wrapping these in Arc ensures safe, read-only concurrent access across
     * our asynchronous worker threads, adhering strictly to Rust's memory
     * safety guarantees.
     */
    let registry: Vec<Arc<dyn SecurityModule + Send + Sync>> = modules::build_registry();
    let shared_registry = Arc::new(registry);

    /*
     * KERNEL MEMORY LIFECYCLE
     * We maintain active eBPF skeletons strictly in memory. Dropping these
     * file descriptors would instruct the kernel to abruptly detach the BPF
     * hooks.
     * For real-time state manipulation (toggling on/off), we now synchronize
     * state directly into the kernel's maps to avoid performance bottlenecks
     * and fail-open race conditions associated with rapid attach/detach
     * cycles.
     */
    let mut active_skeletons: HashMap<String, Box<dyn Any>> = HashMap::new();
    let mut ringbuf_builder = RingBufferBuilder::new();

    for mod_name in bpf_loader::available_modules() {
        /*
         * Extract dynamic memory constraints from the userland module.
         * This bridges the architectural gap between the module's
         * domain-specific sizing logic and the generic BPF loader, ensuring
         * the kernel only locks exactly the amount of RAM needed for the
         * current system state.
         */
        let capacities =
            if let Some(user_mod) = shared_registry.iter().find(|m| m.slug() == mod_name) {
                user_mod.map_capacities()
            } else {
                std::collections::HashMap::new()
            };

        if let Ok(skel) = bpf_loader::load_module(mod_name, &capacities) {
            println!("· Loaded and Attached eBPF module: {}", mod_name);
            active_skeletons.insert(mod_name.to_string(), skel);
        }
    }

    let mut has_ringbuf = false;

    for (mod_name, stored_skel) in active_skeletons.iter() {
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

        let registry_clone = Arc::clone(&shared_registry);
        let module_slug = mod_name.to_string();

        /*
         * THE MODULAR INIT DISPATCHER
         * Lifecycle Synchronization Boundary
         * At this specific execution phase, the eBPF program is successfully
         * loaded and actively enforcing in the kernel, but the userland
         * RingBuffer consumer thread has not yet been bound. We invoke the
         * module's optional `init` routine, injecting the `CoreMapProvider`
         * context. This allows the defense heuristic to securely and
         * synchronously configure kernel state (e.g., pushing protected
         * directory hardware IDs) before high-frequency telemetry begins
         * flowing.
         */
        if let Some(user_mod) = shared_registry.iter().find(|m| m.slug() == mod_name) {
            let provider = CoreMapProvider {
                skel: &**stored_skel,
            };
            if let Err(e) = user_mod.init(&provider) {
                eprintln!("· [Fatal] Module {} initialization failed: {}", mod_name, e);
            }
        }

        if let Ok(alerts_map) = bpf_loader::get_map(&**stored_skel, "alerts") {
            ringbuf_builder
                .add(alerts_map, move |data| {
                    if let Some(user_mod) = registry_clone.iter().find(|m| m.slug() == module_slug)
                    {
                        user_mod.process_event(data);
                    }
                    0 // continue polling
                })
                .context("Failed to bind RingBuffer callback")?;

            has_ringbuf = true;
        } else {
            println!(
                "· [Warning] Standard 'alerts' map not found in module: {}",
                mod_name
            );
        }

        if let Some(user_mod) = shared_registry.iter().find(|m| m.slug() == mod_name) {
            user_mod.toggle(is_active);
        }
    }

    let ring_buffer = if has_ringbuf {
        Some(
            ringbuf_builder
                .build()
                .context("Failed to build unified BPF RingBuffer")?,
        )
    } else {
        println!("· [Info] No telemetry maps found. Operating in silent enforcement mode.");
        None
    };

    /*
     * IPC CONTROL PLANE
     * Establishes a Multi-Producer, Single-Consumer (mpsc) channel following
     * the Actor Model. The main thread retains exclusive mutation rights over
     * kernel skeletons and BPF maps, thereby preventing data races.
     */
    let (tx, rx) = mpsc::sync_channel(128);
    ipc::start_ipc_server(tx);

    println!("· [Success] Engine is running securely.");
    println!("Press Ctrl+C to exit.");

    // MAIN ACTOR LOOP
    loop {
        // 1. Process non-blocking IPC commands from the Control Plane
        while let Ok(msg) = rx.try_recv() {
            let response = match msg.cmd {
                ipc::DaemonCmd::Status => {
                    "Bouclier Bleu EDR Status: Kernel Engine Running\n".to_string()
                }

                ipc::DaemonCmd::List => {
                    let mut out = String::from("MODULE REGISTRY:\n");
                    for module in shared_registry.iter() {
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

                ipc::DaemonCmd::Enable(target) => {
                    if let Some(skel) = active_skeletons.get(&target) {
                        // FAST PATH
                        // Sync the `state_map` directly. No kernel
                        // reallocation needed.
                        match bpf_loader::set_module_state(&**skel, &target, true) {
                            Ok(_) => {
                                if let Some(user_mod) =
                                    shared_registry.iter().find(|m| m.slug() == target)
                                {
                                    user_mod.toggle(true);
                                }
                                format!(
                                    "SUCCESS: Defense module '{}' ENABLED via state synchronization\n",
                                    target
                                )
                            }
                            Err(e) => format!(
                                "ERROR: Failed to update kernel state for '{}': {}\n",
                                target, e
                            ),
                        }
                    } else {
                        // SLOW PATH
                        // Complete reload of the BPF program into the kernel.
                        let capacities = if let Some(user_mod) =
                            shared_registry.iter().find(|m| m.slug() == target)
                        {
                            user_mod.map_capacities()
                        } else {
                            std::collections::HashMap::new()
                        };

                        match bpf_loader::load_module(&target, &capacities) {
                            Ok(skel) => {
                                if let Err(e) = bpf_loader::set_module_state(&*skel, &target, true)
                                {
                                    format!(
                                        "ERROR: Failed to set kernel state for {}. Aborting: {}\n",
                                        target, e
                                    )
                                } else {
                                    active_skeletons.insert(target.clone(), skel);
                                    if let Some(user_mod) =
                                        shared_registry.iter().find(|m| m.slug() == target)
                                    {
                                        user_mod.toggle(true);
                                    }
                                    format!(
                                        "SUCCESS: Defense module '{}' ENABLED and ATTACHED\n",
                                        target
                                    )
                                }
                            }
                            Err(e) => format!("ERROR: Failed to load module '{}': {}\n", target, e),
                        }
                    }
                }

                ipc::DaemonCmd::Disable(target) => {
                    // FAST PATH
                    // Seamlessly toggle enforcement logic via `state_map`
                    // while retaining the BPF file descriptor to avoid latency
                    // spikes.
                    if let Some(skel) = active_skeletons.get(&target) {
                        match bpf_loader::set_module_state(&**skel, &target, false) {
                            Ok(_) => {
                                if let Some(user_mod) =
                                    shared_registry.iter().find(|m| m.slug() == target)
                                {
                                    user_mod.toggle(false);
                                }
                                format!(
                                    "SUCCESS: Defense module '{}' DISABLED via state synchronization\n",
                                    target
                                )
                            }
                            Err(e) => format!(
                                "ERROR: Failed to update kernel state for '{}': {}\n",
                                target, e
                            ),
                        }
                    } else {
                        format!("ERROR: Module '{}' is not currently active\n", target)
                    }
                }
            };

            let _ = msg.reply.send(response);
        }

        // 2. Service the Kernel Telemetry Queues
        if let Some(rb) = &ring_buffer {
            if let Err(e) = rb.poll(Duration::from_millis(50)) {
                eprintln!("Bouclier Bleu [Warning]: Telemetry poll interrupted: {}", e);
            }
        } else {
            /*
             * If no telemetry maps are loaded, fallback to a standard sleep
             * so we don't accidentally pin the CPU to 100% in a busy-wait
             * loop.
             */
            thread::sleep(Duration::from_millis(50));
        }
    }
}
