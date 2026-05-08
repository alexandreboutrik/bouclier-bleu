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

mod report;
mod runner;
mod utils;
mod vm;

use std::env;
use std::process::exit;

use crate::runner::run_tests;
use crate::vm::prepare_test_image;

/// Control Plane Command Router
///
/// Acts exclusively as the pipeline entry boundary. Validates incoming CLI
/// parameters, routes execution dynamically, and ensures critical execution
/// failures properly reflect system exit codes.
fn main() {
	let mut args: Vec<String> = env::args().skip(1).collect();

	// Default image if no flag is provided
	let mut target_image = String::from("bouclier-bleu-test-base");

	// Extract `-img <name>` or `--img <name>` if present
	if let Some(idx) = args.iter().position(|a| a == "-img" || a == "--img") {
		if idx + 1 < args.len() {
			target_image = args[idx + 1].clone();
			args.remove(idx + 1);
			args.remove(idx);
		} else {
			eprintln!("Error: -img flag requires an image name argument.");
			exit(1);
		}
	}

	let mut args_iter = args.into_iter();

	let result = match args_iter.next().as_deref() {
		Some("prepare-image") => prepare_test_image(&target_image),
		Some("test") => run_tests(
			args_iter.next().as_deref(),
			args_iter.next().as_deref(),
			&target_image,
		),
		_ => {
			eprintln!("Bouclier Bleu Build & Test Pipeline");
			eprintln!("Usage:");
			eprintln!("  cargo xtask [-img <image>] prepare-image           - Builds the base testing VM image");
			eprintln!("  cargo xtask [-img <image>] test                    - Runs all public test suites in VM");
			eprintln!("  cargo xtask [-img <image>] test unit               - Runs all inline Rust unit tests in VM");
			eprintln!("  cargo xtask [-img <image>] test component          - Runs all module component tests in VM");
			eprintln!("  cargo xtask [-img <image>] test integration        - Runs all integration tests in VM");
			eprintln!(
				"  cargo xtask [-img <image>] test benchmark          - Runs all benchmarks in VM"
			);
			eprintln!("  cargo xtask [-img <image>] test <category> [test]  - Runs a specific test file within a category");
			eprintln!(
				"  cargo xtask [-img <image>] test <fuzz/threat>      - Restricted Private Suites"
			);
			exit(1);
		}
	};

	if let Err(err) = result {
		eprintln!("\n[FATAL] Pipeline terminated: {}", err);
		exit(1);
	}
}
