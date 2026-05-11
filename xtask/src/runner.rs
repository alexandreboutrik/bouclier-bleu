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

use std::fs;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::report::{generate_markdown_report, TestRecord};
use crate::utils::{incus_exec, project_root, TaskResult, VM_NAME};
use crate::vm::{prepare_test_image, restore_vm_snapshot, setup_and_snapshot_vm};

/// Ephemeral Environment Destructor
///
/// Utilizes the RAII (Resource Acquisition Is Initialization) pattern to
/// strictly guarantee the termination of the Incus sandbox. Even if a
/// destructive test triggers an unrecoverable Rust panic within the pipeline,
/// this Drop implementation ensures no lingering VM resources or state escapes
/// occur.
struct VmGuard;
impl Drop for VmGuard {
	fn drop(&mut self) {
		println!(
			"\n[INFO] Terminating ephemeral test environment ({})...",
			VM_NAME
		);
		let _ = Command::new("incus")
			.args(["delete", VM_NAME, "--force"])
			.output();
	}
}

/// Execution Orchestrator
///
/// Connects the VM lifecycle management with the dynamic test runner. Manages
/// cumulative execution states and handles graceful failure degradation.
pub fn run_tests(
	category: Option<&str>,
	target_test: Option<&str>,
	image_alias: &str,
) -> TaskResult<()> {
	prepare_test_image(image_alias)?;
	let _guard = VmGuard; // Bind VM lifecycle strictly to this scope
	let setup_time = setup_and_snapshot_vm(image_alias)?;

	let mut all_results = Vec::new();
	let mut cumulative_restore_time = Duration::ZERO;

	let mut execute_suite = |cat: &str, target: Option<&str>| -> TaskResult<()> {
		let (res, time) = match cat {
			"unit" => {
				/*
				 * Inline Unit Test Execution
				 * Unlike component/integration tests, Rust unit tests live inline
				 * within the `src/` directories. We bypass `run_test_suite`'s
				 * directory iteration and invoke a singular, workspace-wide cargo
				 * test command.
				 */
				println!("\n[INFO] Executing Inline Unit Tests...");
				println!("[INFO] Reverting environment to clean state for Unit Tests...");
				let restore_time = restore_vm_snapshot()?;

				let target_filter = target.unwrap_or("");
				let cmd = format!(
					"cargo test -q --release --workspace --lib {}",
					target_filter
				);

				let start_time = Instant::now();
				let result = incus_exec(&cmd);
				let passed = result.is_ok();
				let elapsed = start_time.elapsed();

				let display_name = if target_filter.is_empty() {
					"Workspace Unit Tests".to_string()
				} else {
					format!("Unit Filter: {}", target_filter)
				};

				if let Err(err) = result {
					eprintln!("\n[ERROR] Unit test suite failed.");
					eprintln!("{}", err);
				} else {
					println!("[SUCCESS] Passed: {}", display_name);
				}

				(
					vec![TestRecord {
						name: display_name,
						category: "unit".to_string(),
						duration: elapsed,
						passed,
					}],
					restore_time,
				)
			}
			"component" => run_test_suite(
				"Component (eBPF Defenses)",
				"component",
				"sh",
				target,
				|_, full| format!("bash tests/component/{}", full),
			)?,
			"integration" => {
				run_test_suite("Integration", "integration", "rs", target, |stem, _| {
					format!("cargo test -q --release --test {}", stem)
				})?
			}
			"benchmark" => {
				let (res, time) =
					run_test_suite("Benchmark", "benchmark", "rs", target, |stem, _| {
						format!("cargo test -q --release --test {} -- --nocapture", stem)
					})?;
				(res, time)
			}
			"fuzzing" | "threat" => {
				println!(
					"[WARN] The '{}' test suite requires strict network air-gapping and is restricted.",
					cat
				);
				(Vec::new(), Duration::ZERO)
			}
			_ => return Err(format!("Unknown test category: {}", cat)),
		};
		all_results.extend(res);
		cumulative_restore_time += time;
		Ok(())
	};

	match category {
		None | Some("all") => {
			println!("\n[INFO] Initiating public Bouclier Bleu test suites...");
			execute_suite("unit", None)?;
			execute_suite("component", None)?;
			execute_suite("integration", None)?;
		}
		Some(cat) => execute_suite(cat, target_test)?,
	}

	if let Err(e) = generate_markdown_report(&all_results, setup_time, cumulative_restore_time) {
		eprintln!("[ERROR] Failed to generate markdown report: {}", e);
	}

	if all_results.iter().all(|r| r.passed) {
		println!("\n[SUCCESS] Test suite execution completed with zero failures.");
		Ok(())
	} else {
		Err("One or more test suites failed validation.".to_string())
	}
}

/// Generic Test Execution Engine
///
/// Dynamically evaluates test directories, filters targets via closures,
/// strictly reverts to the immutable clean snapshot before execution, and
/// handles benchmark data side-loading capabilities.
fn run_test_suite<F>(
	title: &str,
	dir_name: &str,
	ext: &str,
	target_test: Option<&str>,
	build_cmd: F,
) -> TaskResult<(Vec<TestRecord>, Duration)>
where
	F: Fn(&str, &str) -> String,
{
	let suite_dir = project_root().join("tests").join(dir_name);
	let mut results = Vec::new();
	let mut total_restore_time = Duration::ZERO;

	if !suite_dir.exists() {
		println!(
			"[INFO] No {} test artifacts located. Bypassing phase.",
			dir_name
		);
		return Ok((results, total_restore_time));
	}

	println!("\n[INFO] Executing {} Tests...", title);

	for entry in
		fs::read_dir(&suite_dir).map_err(|e| format!("IO Error reading {} dir: {}", dir_name, e))?
	{
		let path = entry.unwrap().path();

		if path.is_file() && path.extension().unwrap_or_default() == ext {
			let stem = path.file_stem().unwrap().to_string_lossy();
			let full_name = path.file_name().unwrap().to_string_lossy();

			/*
			 * Execution Filtering
			 * Support targeting by either exact filename (e.g. exec_block.sh)
			 * or stem (e.g. exec_block) to optimize targeted local debugging.
			 */
			if target_test.is_some_and(|target| target != stem && target != full_name) {
				continue;
			}

			let display_name = if ext == "sh" {
				full_name.to_string()
			} else {
				stem.to_string()
			};

			println!(
				"\n[INFO] Reverting environment to clean state for {}...",
				display_name
			);
			total_restore_time += restore_vm_snapshot()?;

			println!("[INFO] Executing {}...", display_name);
			let cmd = build_cmd(&stem, &full_name);

			let start_time = Instant::now();
			let result = incus_exec(&cmd);
			let passed = result.is_ok();
			let elapsed = start_time.elapsed();

			/*
			 * Side-Channel Data Extraction
			 * For benchmarks, the test framework natively emits markdown to
			 * the guest workspace. We extract and append this transparently
			 * if the underlying evaluation completes without crashing.
			 */
			if dir_name == "benchmark" && passed {
				match Command::new("incus")
					.args([
						"exec",
						VM_NAME,
						"--",
						"cat",
						"/workspace/benchmark_results.md",
					])
					.output()
				{
					Ok(output) if output.status.success() => {
						let metrics = String::from_utf8_lossy(&output.stdout).to_string();
						let bench_path = project_root().join("tests").join("benchmark_results.md");

						if let Ok(mut file) = std::fs::OpenOptions::new()
							.create(true)
							.append(true)
							.open(&bench_path)
						{
							use std::io::Write;
							let _ = file.write_all(metrics.as_bytes());
						}
					}
					_ => {}
				}
			}

			if let Err(err) = result {
				eprintln!("\n[ERROR] {} test failed: {}", dir_name, display_name);
				eprintln!("{}", err);
			} else {
				println!("[SUCCESS] Passed: {}", display_name);
			}

			results.push(TestRecord {
				name: display_name,
				category: dir_name.to_string(),
				duration: elapsed,
				passed,
			});
		}
	}

	Ok((results, total_restore_time))
}
