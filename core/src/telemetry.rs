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

use anyhow::{Context, Result};
use libbpf_rs::{RingBuffer, RingBufferBuilder};
use std::panic;
use std::sync::Arc;

use crate::bpf_manager::{bpf_loader, BpfEngine};
use modules::common::traits::SecurityModule;

// Type aliases
pub type SharedRegistry = Arc<Vec<Arc<dyn SecurityModule + Send + Sync>>>;
type StagedTelemetryMap<'a> = (libbpf_rs::Map<'a>, String, SharedRegistry);

/// The Pipeline
/// Manages the high-frequency asynchronous telemetry pipeline between
/// kernel-space and user-space.
pub struct TelemetryPipeline;

impl TelemetryPipeline {
	pub fn build<'a>(
		engine: &'a BpfEngine,
		shared_registry: &SharedRegistry,
	) -> Result<Option<RingBuffer<'a>>> {
		let telemetry_maps = Self::stage_maps(engine, shared_registry);
		Self::bind_ringbuffer(telemetry_maps)
	}

	/// Phase 1: Telemetry Staging
	/// Extract the 'alerts' map handle and stage it alongside its contextual
	/// variables. We do not bind to the RingBuffer here to avoid
	/// mutable/immutable borrow conflicts on the staging vector.
	fn stage_maps<'a>(
		engine: &'a BpfEngine,
		shared_registry: &SharedRegistry,
	) -> Vec<StagedTelemetryMap<'a>> {
		let mut telemetry_maps = Vec::new();

		for (mod_name, stored_skel) in engine.active_skeletons.iter() {
			let module_slug = mod_name.to_string();
			let registry_clone = Arc::clone(shared_registry);

			if let Ok(alerts_map) = bpf_loader::get_map(&**stored_skel, "alerts") {
				telemetry_maps.push((alerts_map, module_slug, registry_clone));
			} else {
				println!(
					"· [Warning] Standard 'alerts' map not found in module: {}",
					mod_name
				);
			}
		}

		telemetry_maps
	}

	/// Phase 2: Ringbuffer Binding
	/// With the staging vector fully populated and locked from further
	/// mutation, we safely iterate and borrow the map handles to construct
	/// the unified, high-frequency telemetry pipeline.
	fn bind_ringbuffer<'a>(
		telemetry_maps: Vec<StagedTelemetryMap<'a>>,
	) -> Result<Option<RingBuffer<'a>>> {
		let mut ringbuf_builder = RingBufferBuilder::new();
		let mut has_ringbuf = false;

		for (alerts_map, module_slug, registry_clone) in &telemetry_maps {
			let slug = module_slug.clone();
			let reg = Arc::clone(registry_clone);

			ringbuf_builder
				.add(alerts_map, move |data| {
					if let Some(user_mod) = reg.iter().find(|m| m.slug() == slug) {
						/*
						 * Fault Isolation Boundary
						 * Wraps the user module invocation in a catch_unwind
						 * boundary. This prevents a panicking module from
						 * unwinding across the FFI boundary into libbpf C
						 * code, which is Undefined Behavior and would fatally
						 * crash the telemetry consumer thread.
						 */
						let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
							user_mod.process_event(data);
						}));

						if let Err(err) = result {
							eprintln!(
								"· [Fatal] Module '{}' panicked during event processing: {:?}",
								slug, err
							);
						}
					}
					0 // continue polling
				})
				.context("Failed to bind RingBuffer callback")?;

			has_ringbuf = true;
		}

		if has_ringbuf {
			Ok(Some(
				ringbuf_builder
					.build()
					.context("Failed to build unified BPF RingBuffer")?,
			))
		} else {
			println!("· [Info] No telemetry maps found. Operating in silent enforcement mode.");
			Ok(None)
		}
	}
}
