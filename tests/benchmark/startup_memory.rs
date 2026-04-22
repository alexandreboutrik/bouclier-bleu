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

use std::collections::HashSet;
use std::fs::{self, File};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SOCKET_PATH: &str = "/var/run/bouclier-bleu/control.sock";
const BENCH_ENV_PATH: &str = "/home/bb_bench_env";

/// Provisions a massive dummy filesystem to stress-test the `WalkDir`
fn provision_dummy_filesystem() {
	let _ = fs::remove_dir_all(BENCH_ENV_PATH);
	fs::create_dir_all(BENCH_ENV_PATH).expect("Failed to create base benchmark directory");
	println!(
		"[INFO] Provisioning 20,000 directories and 60,000 files in {}...",
		BENCH_ENV_PATH
	);

	for d in 0..20_000 {
		let dir_path = format!("{}/dir_{}", BENCH_ENV_PATH, d);
		fs::create_dir(&dir_path).expect("Failed to create dummy dir");
		for f in 0..3 {
			let _ = File::create(format!("{}/file_{}.txt", dir_path, f));
		}
	}
	let _ = Command::new("sync").status();
	println!("[INFO] Filesystem provisioning complete.");
}

/// Dynamically extracts module slugs from the CLI list output using structural parsing.
fn get_modules_from_cli(cli_bin: &Path) -> Vec<String> {
	let output = Command::new(cli_bin)
		.arg("list")
		.output()
		.expect("Failed to run CLI list");
	let stdout = String::from_utf8_lossy(&output.stdout);

	let mut modules = Vec::new();

	for line in stdout.lines() {
		let trimmed = line.trim();

		// Only process lines that contain our known status brackets
		if trimmed.starts_with('[')
			&& (trimmed.contains("[ACTIVE]") || trimmed.contains("[INACTIVE]"))
		{
			// Split the line by spaces.
			// Example: ["[ACTIVE]", "exec_block", "(Untrusted", ...]
			let parts: Vec<&str> = trimmed.split_whitespace().collect();

			// The module slug is always the second word (index 1)
			if parts.len() >= 2 {
				modules.push(parts[1].to_string());
			}
		}
	}

	modules.sort();
	modules.dedup();
	modules
}

/// Correlates a module slug to its loaded eBPF programs, extracts their
/// unique Map IDs, and aggregates the locked kernel memory for those specific
/// maps.
fn get_module_memory(slug: &str, prog_json: &str, map_json: &str) -> usize {
	let mut map_ids = HashSet::new();

	// Find Map IDs belonging to programs prefixed with our module slug
	let mut search_idx = 0;
	let name_key = "\"name\":\"";
	while let Some(idx) = prog_json[search_idx..].find(name_key) {
		let start = search_idx + idx + name_key.len();
		if let Some(end) = prog_json[start..].find('"') {
			let prog_name = &prog_json[start..start + end];

			if prog_name.starts_with(slug) {
				// Extract the map_ids array for this specific program
				if let Some(map_ids_start) = prog_json[start + end..].find("\"map_ids\":[") {
					let array_start = start + end + map_ids_start + 11;
					if let Some(array_end) = prog_json[array_start..].find(']') {
						let ids_str = &prog_json[array_start..array_start + array_end];
						for id_str in ids_str.split(',') {
							if let Ok(id) = id_str.trim().parse::<u32>() {
								map_ids.insert(id); // HashSet deduplicates
								 // shared maps
								 // automatically
							}
						}
					}
				}
			}
		}
		search_idx = start;
	}

	// Sum the bytes_memlock for those unique Map IDs
	let mut total_bytes = 0;
	for id in map_ids {
		let id_key = format!("\"id\":{},", id);
		if let Some(idx) = map_json.find(&id_key) {
			if let Some(memlock_idx) = map_json[idx..].find("\"bytes_memlock\":") {
				let val_start = idx + memlock_idx + 16;
				if let Some(val_end) = map_json[val_start..].find(|c: char| c == ',' || c == '}') {
					let num_str = &map_json[val_start..val_start + val_end];
					if let Ok(bytes) = num_str.trim().parse::<usize>() {
						total_bytes += bytes;
					}
				}
			}
		}
	}

	total_bytes
}

#[test]
fn benchmark_startup_and_memory() {
	provision_dummy_filesystem();
	let _ = std::fs::remove_file(SOCKET_PATH);

	let core_bin = env!("CARGO_BIN_EXE_core");
	let cli_bin = PathBuf::from(core_bin).with_file_name("cli");

	let start_time = Instant::now();

	let mut child = Command::new(core_bin)
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.spawn()
		.expect("Failed to start Bouclier Bleu core daemon");

	let mut startup_duration = Duration::ZERO;
	let timeout = Duration::from_secs(30);

	// Await Socket Readiness
	while start_time.elapsed() < timeout {
		if Path::new(SOCKET_PATH).exists() && UnixStream::connect(SOCKET_PATH).is_ok() {
			startup_duration = start_time.elapsed();
			break;
		}
		thread::sleep(Duration::from_millis(50));
	}

	if startup_duration == Duration::ZERO {
		let status = child.try_wait().unwrap_or(None);
		let _ = child.kill();
		panic!(
			"Daemon failed to bind socket within timeout. Did it crash? Status: {:?}",
			status
		);
	}

	thread::sleep(Duration::from_millis(500));

	// Measure User-Space Memory
	let pid = child.id();
	let status_file = fs::read_to_string(format!("/proc/{}/status", pid))
		.unwrap_or_else(|_| String::from("VmRSS: 0 kB"));

	let mut vm_rss = String::from("Unknown");
	for line in status_file.lines() {
		if line.starts_with("VmRSS:") {
			vm_rss = line.replace("VmRSS:", "").trim().to_string();
			break;
		}
	}

	// Capture the state of the kernel while the daemon is actively running
	let prog_output = Command::new("bpftool")
		.args(["prog", "show", "-j"])
		.output()
		.expect("bpftool prog failed");
	let map_output = Command::new("bpftool")
		.args(["map", "show", "-j"])
		.output()
		.expect("bpftool map failed");

	let prog_json = String::from_utf8_lossy(&prog_output.stdout);
	let map_json = String::from_utf8_lossy(&map_output.stdout);

	let active_modules = get_modules_from_cli(&cli_bin);

	// Terminate daemon safely
	let _ = child.kill();
	let _ = child.wait();
	let _ = fs::remove_dir_all(BENCH_ENV_PATH);

	// Build the dynamic report
	let mut report = format!(
		"### Benchmark Results\n\n\
        * **Startup Time (80k files):** `{:.2}ms`\n\
        * **User-Space Memory (VmRSS):** `{}`\n\n\
        #### Kernel-Space Memory (eBPF Maps)\n\n",
		startup_duration.as_secs_f64() * 1000.0,
		vm_rss
	);

	if active_modules.is_empty() {
		report.push_str("* *No active modules detected by CLI.*\n");
	} else {
		for slug in active_modules {
			let mem_bytes = get_module_memory(&slug, &prog_json, &map_json);
			report.push_str(&format!(
				"* **`{}`:** `{:.2} KB`\n",
				slug,
				mem_bytes as f64 / 1024.0
			));
		}
	}

	fs::write("/workspace/benchmark_results.md", report)
		.expect("Failed to write benchmark results file");
}
