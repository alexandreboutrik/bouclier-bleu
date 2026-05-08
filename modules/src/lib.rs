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

//! Bouclier Bleu Defense Modules
//!
//! This crate contains the specific heuristics and the common framework
//! required to interface with the core eBPF engine.

// Declare the common framework (which houses our traits, telemetry, etc.)
pub mod common;

// Declare the individual heuristic modules
pub mod dump_restrict;
pub mod exec_block;
pub mod mount_secure;
pub mod ptrace_block;
pub mod rename_entropy;
pub mod shield;
pub mod strict_wx;
pub mod userns_restrict;

#[cfg(test)]
mod tests {
	use super::*;
	use crate::common::macros::build_registry;
	use crate::common::traits::SecurityModule;

	// Dummy alert struct for testing the payload pipeline
	#[derive(serde::Serialize)]
	struct DummyAlert {
		severity: u8,
	}

	// Dummy safe parser
	fn dummy_parser(data: &[u8]) -> Result<DummyAlert, &'static str> {
		if data.is_empty() {
			Err("Empty payload")
		} else {
			Ok(DummyAlert { severity: data[0] })
		}
	}

	/*
	 * Declarative Macro Invocation
	 * We synthesize a transient security module exactly as the production
	 * heuristics do, ensuring the generated boilerplate satisfies all IoC
	 * traits.
	 */
	define_security_module!(
		struct: DummyHeuristic,
		name: "Dummy Heuristic Engine",
		slug: "dummy_heur",
		mitre: [],
		parser: dummy_parser,
		handler: |_alert: DummyAlert| {
			// Localized logic block (No-op for test)
		}
	);

	#[test]
	fn test_macro_generated_module_state() {
		let module = DummyHeuristic::new();

		// 1. Assert metadata mapping
		assert_eq!(module.name(), "Dummy Heuristic Engine");
		assert_eq!(module.slug(), "dummy_heur");

		// 2. Assert initial AtomicBool status (should default to true)
		assert!(module.status());

		// 3. Thread-safe toggling
		module.toggle(false);
		assert!(
			!module.status(),
			"Module failed to toggle offline via SeqCst ordering"
		);

		module.toggle(true);
		assert!(
			module.status(),
			"Module failed to toggle online via SeqCst ordering"
		);
	}

	#[test]
	fn test_build_registry_instantiation() {
		/*
		 * IoC Registry Validation
		 * Ensures the central builder successfully maps all production
		 * heuristics into the dynamic trait object vector without panicking.
		 */
		let registry = build_registry();
		assert!(
			!registry.is_empty(),
			"Registry failed to build the defense matrix"
		);
	}
}
