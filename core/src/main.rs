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
use std::sync::{mpsc, Arc};

use modules::SecurityModule;

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

	let daemon_config = config::DaemonConfig::load();

	/*
	 * Registry Initialization
	 * The userland registry acts as the logical abstraction layer for defense
	 * rules. Wrapping these in Arc ensures safe, read-only concurrent access
	 * across our asynchronous worker threads, adhering strictly to Rust's
	 * memory safety guarantees.
	 */
	let registry: Vec<Arc<dyn SecurityModule + Send + Sync>> = modules::build_registry();
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
