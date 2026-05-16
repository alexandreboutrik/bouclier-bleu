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

use anyhow::Result;
use rustix::process::geteuid;
use std::sync::{mpsc, Arc};
use std::{fs, process};

use modules::common::macros::build_registry;
use modules::common::traits::SecurityModule;

pub mod actor;
pub mod bpf_manager;
pub mod config;
pub mod ipc;
pub mod telemetry;

use actor::DaemonActor;
use bpf_manager::BpfEngine;
use telemetry::TelemetryPipeline;

fn main() -> Result<()> {
	println!("* Starting Bouclier Bleu Core Engine...");

	/*
	 * Root Privilege Validation
	 * eBPF map allocations, LSM hook attachments, and secure IPC socket
	 * binding require elevated capabilities (CAP_SYS_ADMIN / CAP_BPF). We
	 * evaluate the Effective UID here to fail fast and prevent a cascade of
	 * libbpf -EPERM errors if executed by an unprivileged user.
	 */
	if !geteuid().is_root() {
		eprintln!("Bouclier Bleu [Fatal]: The core daemon must be executed as root (UID 0).");
		process::exit(1);
	}

	/*
	 * Kernel eBPF LSM Validation
	 * Even if the daemon is running as root, the kernel must actively support
	 * and enforce BPF Security Modules. If it doesn't, libbpf will fail to
	 * attach our heuristics. We check this natively to fail gracefully.
	 */
	match fs::read_to_string("/sys/kernel/security/lsm") {
		Ok(lsms) => {
			if !lsms.contains("bpf") {
				eprintln!("Bouclier Bleu [Fatal]: eBPF LSM is not active on this host.");
				eprintln!("      Ensure your kernel supports CONFIG_BPF_LSM=y and append:");
				eprintln!(
					"      'lsm=landlock,lockdown,yama,apparmor,bpf' to your GRUB boot parameters."
				);
				process::exit(1);
			}
		}
		Err(e) => {
			// If we can't read the file (e.g., highly restricted container),
			// we log a warning but attempt to proceed rather than failing
			// closed.
			eprintln!(
				"Bouclier Bleu [Warning]: Could not verify active Security Modules ({}).",
				e
			);
		}
	}

	let daemon_config = config::DaemonConfig::load();

	/*
	 * Registry Initialization
	 * The userland registry acts as the logical abstraction layer for defense
	 * rules. Wrapping these in Arc ensures safe, read-only concurrent access
	 * across our asynchronous worker threads, adhering strictly to Rust's
	 * memory safety guarantees.
	 */
	let registry: Vec<Arc<dyn SecurityModule + Send + Sync>> = build_registry();
	let shared_registry = Arc::new(registry);

	// Initialize Kernel Broker & Load modules into memory
	let mut engine = BpfEngine::new();
	engine.load_modules(&shared_registry, &daemon_config);

	// Stage Telemetry & Bind BPF RingBuffers safely
	let ring_buffer = TelemetryPipeline::build(&engine, &shared_registry)?;

	/*
	 * Ipc Control Plane
	 * Establishes a Multi-Producer, Single-Consumer (mpsc) channel following
	 * the Actor Model. The main thread retains exclusive mutation rights over
	 * kernel skeletons and BPF maps, thereby preventing data races.
	 */
	let (tx, rx) = mpsc::sync_channel(128);
	ipc::start_ipc_server(tx);

	// Delegate to the Daemon Actor dispatcher to process the infinite event
	// loop
	let actor = DaemonActor {
		rx,
		engine: &engine,
		ring_buffer,
		shared_registry,
	};

	actor.run();

	Ok(())
}
