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

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};
use std::thread;
use std::time::{Duration, Instant};

const VM_NAME: &str = "bb-test-runner";
const SNAPSHOT_NAME: &str = "clean-state";

type TaskResult<T> = Result<T, String>;

/// Telemetry payload for aggregating test suite results across execution boundaries.
struct TestRecord {
	name: String,
	category: String,
	duration: Duration,
	passed: bool,
}

fn main() {
	let mut args: Vec<String> = env::args().skip(1).collect();

	// Default image if no flag is provided
	let mut target_image = String::from("bouclier-bleu-test-base");

	// Extract `-img <name>` or `--img <name>` if present
	if let Some(idx) = args.iter().position(|a| a == "-img" || a == "--img") {
		if idx + 1 < args.len() {
			target_image = args[idx + 1].clone();
			args.remove(idx + 1); // Remove the value
			args.remove(idx); // Remove the flag
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

/// RAII guard guaranteeing the destruction of the ephemeral Incus environment.
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

/// Primary orchestration sequence for test execution.
fn run_tests(
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

// --- Generic Test Runner Engine ---

/// Generic execution engine that dynamically evaluates test directories, filters
/// targets, restores snapshots, and evaluates outcomes using a provided command builder.
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

			// Support targeting by either exact filename (exec_block.sh) or stem
			// (exec_block)
			if let Some(target) = target_test {
				if target != stem && target != full_name {
					continue;
				}
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

			if dir_name == "benchmark" && passed {
				if let Ok(output) = Command::new("incus")
					.args([
						"exec",
						VM_NAME,
						"--",
						"cat",
						"/workspace/benchmark_results.md",
					])
					.output()
				{
					if output.status.success() {
						let metrics = String::from_utf8_lossy(&output.stdout).to_string();
						let bench_path = project_root().join("tests").join("benchmark_results.md");

						// Append to the host-side file
						if let Ok(mut file) = std::fs::OpenOptions::new()
							.create(true)
							.append(true)
							.open(&bench_path)
						{
							use std::io::Write;
							let _ = file.write_all(metrics.as_bytes());
						}
					}
				}
			}

			if result.is_ok() {
				println!("[SUCCESS] Passed: {}", display_name);
			} else {
				eprintln!("\n[ERROR] {} test failed: {}", dir_name, display_name);
				eprintln!("{}", result.unwrap_err());
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

// --- Incus VM Orchestration Subsystem ---

fn setup_and_snapshot_vm(image_alias: &str) -> TaskResult<Duration> {
	println!(
		"\n[INFO] Provisioning Base Incus VM Environment (Image: {})...",
		image_alias
	);
	let start = Instant::now();

	ensure_base_image(image_alias)?;
	let _ = Command::new("incus")
		.args(["delete", VM_NAME, "--force"])
		.output();
	launch_instance(image_alias)?;
	await_guest_agent()?;

	transfer_workspace()?;
	provision_default_config()?;
	compile_workspace()?;

	enforce_airgap()?;

	inject_kernel_parameters()?;
	assert_no_network()?;
	create_snapshot()?;

	println!("[SUCCESS] VM Environment provisioned and snapshotted.");
	Ok(start.elapsed())
}

fn ensure_base_image(image_alias: &str) -> TaskResult<()> {
	if Command::new("incus")
		.args(["image", "info", image_alias])
		.output()
		.map_or(false, |o| o.status.success())
	{
		return Ok(());
	}

	println!(
		"[INFO] Synchronizing base image '{}' to Incus database...",
		image_alias
	);
	let img = fs::read_dir(project_root().join("tests"))
		.ok()
		.into_iter()
		.flatten()
		.filter_map(Result::ok)
		.find(|e| {
			e.file_name()
				.to_string_lossy()
				.starts_with(&format!("{}.tar", image_alias))
		})
		.map(|e| e.path())
		.ok_or_else(|| {
			format!(
				"Pre-compiled test image '{}' missing. Run `scripts/build_image.sh -out {}`.",
				image_alias, image_alias
			)
		})?;

	let import_out = Command::new("incus")
		.args([
			"image",
			"import",
			img.to_str().unwrap(),
			"--alias",
			image_alias,
		])
		.output()
		.map_err(|e| format!("Incus import failed: {}", e))?;

	if !import_out.status.success() {
		let stderr = String::from_utf8_lossy(&import_out.stderr);
		if stderr.contains("already exists") {
			println!("[INFO] Abstracting existing fingerprint constraint via direct alias...");
			let sha_out = Command::new("sha256sum")
				.arg(&img)
				.output()
				.map_err(|e| e.to_string())?;
			let fingerprint = String::from_utf8_lossy(&sha_out.stdout)
				.split_whitespace()
				.next()
				.unwrap_or("")
				.to_string();
			execute_cmd(
				Command::new("incus").args(["image", "alias", "create", image_alias, &fingerprint]),
				"Failed to bypass alias lock",
			)?;
		} else {
			return Err(format!("Image synchronization error:\n{}", stderr));
		}
	}
	Ok(())
}

fn ensure_no_network_profile() -> TaskResult<()> {
	println!("[INFO] Ensuring 'bb-no-network' profile is correctly configured...");

	let exists = Command::new("incus")
		.args(["profile", "show", "bb-no-network"])
		.output()
		.map_or(false, |o| o.status.success());

	if !exists {
		println!("[INFO] Creating 'bb-no-network' profile from default...");

		execute_cmd(
			Command::new("incus").args(["profile", "copy", "default", "bb-no-network"]),
			"Failed to copy default profile",
		)?;
	} else {
		println!("[INFO] 'bb-no-network' profile already exists.");
	}

	let remove = Command::new("incus")
		.args(["profile", "device", "remove", "bb-no-network", "eth0"])
		.output();

	match remove {
		Ok(output) => {
			if output.status.success() {
				println!("[INFO] Removed eth0 from 'bb-no-network' profile.");
			} else {
				let stderr = String::from_utf8_lossy(&output.stderr);
				if stderr.contains("doesn't exist") {
					println!("[INFO] No eth0 device present (already air-gapped).");
				} else {
					return Err(format!("Failed to remove eth0 from profile:\n{}", stderr));
				}
			}
		}
		Err(e) => {
			return Err(format!(
				"Failed to execute incus profile device remove: {}",
				e
			));
		}
	}

	Ok(())
}

fn assert_no_network() -> TaskResult<()> {
	let output = Command::new("incus")
		.args(["exec", VM_NAME, "--", "ip", "-o", "link", "show"])
		.output()
		.map_err(|e| format!("Failed to inspect VM network: {}", e))?;

	let stdout = String::from_utf8_lossy(&output.stdout);

	if stdout.contains("eth0") {
		return Err("Air-gap violation: eth0 interface detected".into());
	}

	println!("[SECURITY] Verified: no network interfaces present.");
	Ok(())
}

fn enforce_airgap() -> TaskResult<()> {
	println!("[INFO] Severing network connection for test isolation...");
	ensure_no_network_profile()?;

	execute_cmd(
		Command::new("incus").args(["profile", "assign", VM_NAME, "bb-no-network"]),
		"Failed to assign air-gapped profile",
	)
}

fn launch_instance(image_alias: &str) -> TaskResult<()> {
	println!(
		"[INFO] Spawning isolated guest environment ({})...",
		VM_NAME
	);

	execute_cmd(
		Command::new("incus").args([
			"launch",
			image_alias,
			VM_NAME,
			"--vm",
			"-c",
			"security.secureboot=false",
			"-c",
			"limits.cpu=4",
			"-c",
			"limits.memory=8GB",
		]),
		"Guest initialization failed",
	)
}

fn transfer_workspace() -> TaskResult<()> {
	println!("[INFO] Packaging and injecting source workspace...");
	let root = project_root();
	let tarball_path = env::temp_dir().join("bb-src-bundle.tar.gz");

	execute_cmd(
		Command::new("tar")
			.args([
				"--exclude=target",
				"--exclude=.git",
				"--exclude=*.tar.*",
				"-czf",
				tarball_path.to_str().unwrap(),
				".",
			])
			.current_dir(&root),
		"Failed to archive host workspace",
	)?;

	execute_cmd(
		Command::new("incus").args([
			"file",
			"push",
			tarball_path.to_str().unwrap(),
			&format!("{}/root/src-bundle.tar.gz", VM_NAME),
		]),
		"Host-to-Guest file injection failed",
	)?;

	let _ = fs::remove_file(tarball_path);
	execute_cmd(
		Command::new("incus").args([
			"exec",
			VM_NAME,
			"--",
			"bash",
			"-c",
			"mkdir -p /workspace && tar -xzf /root/src-bundle.tar.gz -C /workspace",
		]),
		"Guest extraction phase failed",
	)
}

fn compile_workspace() -> TaskResult<()> {
	println!("[INFO] Executing cross-environment compilation phase...");
	let inject_cmd = r#"
        find tests -mindepth 2 -type f -name "*.rs" | while read -r f; do
            name=$(basename "$f" .rs)
            [ "$name" = "main" ] && continue
            printf "\n[[test]]\nname = \"%s\"\npath = \"../%s\"\n" "$name" "$f" >> core/Cargo.toml
        done
    "#;
	incus_exec(inject_cmd)?;
	incus_exec("cargo clean -q && cargo build -q --release --workspace --all-targets")?;

	println!("[INFO] Committing VFS page cache to persistent storage...");
	incus_exec("sync")?;
	thread::sleep(Duration::from_secs(3));
	Ok(())
}

fn inject_kernel_parameters() -> TaskResult<()> {
	println!("[INFO] Activating eBPF LSM subsystem in guest kernel...");

	let enable_lsm_script = r#"
    export PATH="$PATH:/usr/sbin:/sbin"

    if command -v grubby >/dev/null 2>&1; then
        # Fedora / RHEL Family
        grubby --update-kernel=ALL --args="lsm=bpf"
    elif command -v update-grub >/dev/null 2>&1; then
        # Ubuntu / Debian Family
        mkdir -p /etc/default/grub.d
        echo 'GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} lsm=bpf"' > /etc/default/grub.d/99-bpf-lsm.cfg
        update-grub
    else
        echo "Error: Neither grubby nor update-grub found. Cannot configure LSM." >&2
        exit 1
    fi
"#;

	let status = Command::new("incus")
		.args(&["exec", VM_NAME, "--", "bash", "-c", enable_lsm_script])
		.status()
		.expect("Failed to execute VM process");

	if !status.success() {
		eprintln!("[FATAL] Pipeline terminated: Guest command failed to update GRUB.");
		std::process::exit(1);
	}

	println!(
		"[INFO] Masking network-wait and cloud services to prevent airgap boot/shutdown hangs..."
	);
	let _ = incus_exec(
    "systemctl mask systemd-networkd-wait-online.service NetworkManager-wait-online.service cloud-init.service cloud-config.service cloud-final.service cloud-init-local.service"
);

	println!("[INFO] Re-initializing kernel via cold boot...");
	execute_cmd(
		Command::new("incus").args(["restart", VM_NAME]),
		"VM reboot procedure failed",
	)?;
	await_guest_agent()
}

fn create_snapshot() -> TaskResult<()> {
	println!("[INFO] Capturing immutable state vector for test resets...");
	execute_cmd(
		Command::new("incus").args(["stop", VM_NAME]),
		"Failed to gracefully halt VM",
	)?;
	execute_cmd(
		Command::new("incus").args(["snapshot", "create", VM_NAME, SNAPSHOT_NAME]),
		"Snapshot generation aborted",
	)
}

fn provision_default_config() -> TaskResult<()> {
	println!("[INFO] Provisioning default daemon configuration for test environment...");
	incus_exec(
		"mkdir -p /etc/bouclier-bleu && \
         cp /workspace/config.toml /etc/bouclier-bleu/config.toml && \
         chown root:root /etc/bouclier-bleu/config.toml && \
         chmod 600 /etc/bouclier-bleu/config.toml",
	)
}

fn restore_vm_snapshot() -> TaskResult<Duration> {
	let start = Instant::now();
	let _ = Command::new("incus")
		.args(["stop", VM_NAME, "--force"])
		.output();
	execute_cmd(
		Command::new("incus").args(["snapshot", "restore", VM_NAME, SNAPSHOT_NAME]),
		"VM state reversion failed",
	)?;
	execute_cmd(
		Command::new("incus").args(["start", VM_NAME]),
		"Failed to resurrect VM from snapshot",
	)?;
	await_guest_agent()?;
	Ok(start.elapsed())
}

// --- System Utilities ---

fn await_guest_agent() -> TaskResult<()> {
	for _ in 0..120 {
		if Command::new("incus")
			.args(["exec", VM_NAME, "--", "echo", "ready"])
			.output()
			.map_or(false, |o| o.status.success())
		{
			return Ok(());
		}
		thread::sleep(Duration::from_secs(2));
	}
	Err("VM communication agent exceeded response timeout limit.".to_string())
}

fn incus_exec(command: &str) -> TaskResult<()> {
	let full_cmd = format!("source ~/.cargo/env && cd /workspace && {}", command);
	let output = Command::new("incus")
		.args(["exec", VM_NAME, "--", "bash", "-c", &full_cmd])
		.output()
		.map_err(|e| format!("Incus translation execution failure: {}", e))?;

	if output.status.success() {
		Ok(())
	} else {
		Err(format!(
			"Guest command failed (Exit code: {:?})\n\n--- STDOUT ---\n{}\n--- STDERR ---\n{}",
			output.status.code(),
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		))
	}
}

fn execute_cmd(cmd: &mut Command, error_msg: &str) -> TaskResult<()> {
	let output = cmd.output().map_err(|e| format!("{}: {}", error_msg, e))?;
	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		return Err(format!(
			"{} (Exit code: {})\n\n--- STDERR ---\n{}",
			error_msg,
			output.status.code().unwrap_or(-1),
			stderr.trim()
		));
	}
	Ok(())
}

fn prepare_test_image(image_alias: &str) -> TaskResult<()> {
	let root = project_root();

	if root.join(format!("tests/{}.tar.gz", image_alias)).exists()
		|| root.join(format!("tests/{}.tar.xz", image_alias)).exists()
	{
		return Ok(());
	}

	println!(
		"[INFO] Pre-compiled testing artifact '{}' missing. Initiating build sequence...",
		image_alias
	);
	execute_cmd(
		Command::new("bash")
			.args([
				root.join("scripts/build_image.sh").to_str().unwrap(),
				"-os",
				"ubuntu",
				"-out",
				image_alias,
			])
			.current_dir(&root),
		"Upstream base-image compilation script failed",
	)
}

fn generate_markdown_report(
	results: &[TestRecord],
	setup_time: Duration,
	restore_time: Duration,
) -> Result<(), std::io::Error> {
	if results.is_empty() {
		println!("[INFO] No tests were executed. Skipping report generation.");
		return Ok(());
	}

	let mut report = String::from(
		"# Bouclier Bleu Test Results\n\n| Test Name | Category | Duration | Status |\n|-----------|----------|----------|--------|\n",
	);
	for res in results {
		report.push_str(&format!(
			"| `{}` | {} | {:.2}s | {} |\n",
			res.name,
			res.category,
			res.duration.as_secs_f64(),
			if res.passed { "PASS" } else { "FAIL" }
		));
	}

	report.push_str(&format!("\n## Pipeline Environment Metrics\n\n* **Initial VM Setup & Snapshot:** `{:.2}s`\n* **Cumulative Snapshot Restorations:** `{:.2}s`\n", setup_time.as_secs_f64(), restore_time.as_secs_f64()));

	let bench_path = project_root().join("tests").join("benchmark_results.md");
	if bench_path.exists() {
		if let Ok(bench_data) = fs::read_to_string(&bench_path) {
			report.push_str("\n");
			report.push_str(&bench_data);
		}
		let _ = fs::remove_file(&bench_path);
	}

	let report_path = project_root().join("tests").join("Results.md");
	fs::write(&report_path, report)?;
	println!(
		"\n[INFO] Test report successfully generated at {}",
		report_path.display()
	);
	Ok(())
}

fn project_root() -> PathBuf {
	Path::new(&env!("CARGO_MANIFEST_DIR"))
		.ancestors()
		.nth(1)
		.unwrap()
		.to_path_buf()
}
