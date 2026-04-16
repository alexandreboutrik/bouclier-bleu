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

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SOCKET_PATH: &str = "/var/run/bouclier-bleu/control.sock";

// Benchmark execution constants
const ITERATIONS: usize = 50_000;
const WARMUP_ITERATIONS: usize = 10_000;
const BATCH_SIZE: usize = 500;

const BENCH_DIR: &str = "/tmp/bb_bench_shield";

/// Provisions the dummy files required for the file_open benchmark.
fn provision_test_files(dir: &str, count: usize) {
    let _ = fs::remove_dir_all(dir);
    fs::create_dir_all(dir).expect("Failed to create benchmark directory");
    
    for i in 0..count {
        let file_path = format!("{}/dummy_{}.txt", dir, i);
        File::create(&file_path).expect("Failed to create dummy file");
        
        // Grant world-write access (0o666) so the unprivileged 'nobody' worker 
        // can pass kernel DAC checks and successfully trigger the LSM hook.
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o666))
            .expect("Failed to set permissions");
    }
    
    // Force the VFS to flush metadata to disk before we start the timer
    let _ = Command::new("sync").status();
}

/// Executes a tight loop of file openings to warm up the VFS dentry cache.
fn execute_warmup(dir: &str, count: usize) {
    for i in 0..count {
        let path = format!("{}/dummy_{}.txt", dir, i);
        let _ = OpenOptions::new().write(true).open(&path);
    }
}

/// Dynamically extracts module slugs from the CLI list output.
fn get_modules_from_cli(cli_bin: &Path) -> Vec<String> {
    let output = Command::new(cli_bin).arg("list").output().expect("Failed to run CLI list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    let mut modules = Vec::new();
    for word in stdout.split_whitespace() {
        let clean_word = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
        if clean_word.contains('_') {
            modules.push(clean_word.to_string());
        }
    }
    modules.sort();
    modules.dedup();
    modules
}

#[test]
fn benchmark_shield_overhead() {
    /*
     * WORKER SUBPROCESS TRAP
     * Catches re-invocations of this binary for Phase 3. This allows us to run 
     * the file_open loop as an unprivileged user (nobody) while measuring the 
     * exact duration *internally* to completely bypass process spawn overhead.
     */
    if let Ok(batch_str) = std::env::var("PHASE3_BATCH") {
        let b: usize = batch_str.parse().unwrap();
        let start = Instant::now();
        for i in 0..BATCH_SIZE {
            let idx = (b * BATCH_SIZE) + i;
            let path = format!("{}/dummy_{}.txt", BENCH_DIR, idx);
            let _ = OpenOptions::new().write(true).open(&path);
        }
        // Print purely the elapsed nanoseconds to stdout for the orchestrator
        println!("bb_nanos:{}", start.elapsed().as_nanos());
        std::process::exit(0);
    }

    println!("[INFO] Provisioning files for shield benchmark phases...");
    provision_test_files(BENCH_DIR, std::cmp::max(ITERATIONS, WARMUP_ITERATIONS));

    let core_bin = env!("CARGO_BIN_EXE_core");
    let cli_bin = PathBuf::from(core_bin).with_file_name("cli");

    /*
     * DAEMON INITIALIZATION
     */
    let _ = std::fs::remove_file(SOCKET_PATH);
    let mut child = Command::new(core_bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start Bouclier Bleu core daemon");

    let start_time = Instant::now();
    let timeout = Duration::from_secs(30);
    let mut ready = false;

    // Await Socket Readiness
    while start_time.elapsed() < timeout {
        if Path::new(SOCKET_PATH).exists() && UnixStream::connect(SOCKET_PATH).is_ok() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    if !ready {
        let _ = child.kill();
        panic!("Daemon failed to initialize within timeout limit.");
    }

    /*
     * PHASE 1: TRUE BASELINE (Daemon Online, Modules Disabled)
     */
    println!("[INFO] Establishing True Baseline (Daemon Online, Modules Disabled)");
    let active_modules = get_modules_from_cli(&cli_bin);
    for mod_slug in active_modules {
        let _ = Command::new(&cli_bin).args(["disable", &mod_slug]).output();
    }
    thread::sleep(Duration::from_millis(500)); 

    println!("  -> Running {} warmup operations...", WARMUP_ITERATIONS);
    execute_warmup(BENCH_DIR, WARMUP_ITERATIONS);
    
    let mut baseline_durations = Vec::new();
    let batches = ITERATIONS / BATCH_SIZE;

    for b in 0..batches {
        let start = Instant::now();
        for i in 0..BATCH_SIZE {
            let idx = (b * BATCH_SIZE) + i;
            let path = format!("{}/dummy_{}.txt", BENCH_DIR, idx);
            let _ = OpenOptions::new().write(true).open(&path);
        }
        baseline_durations.push(start.elapsed());
    }

    baseline_durations.sort_unstable();
    let baseline_duration = baseline_durations[baseline_durations.len() / 2] * (batches as u32);

    /*
     * PHASE 2 & 3: INTERLEAVED EXECUTION (shield ENABLED)
     */
    println!("[INFO] Enabling shield module via IPC...");
    let _ = Command::new(&cli_bin).args(["enable", "shield"]).output();
    thread::sleep(Duration::from_millis(500)); 

    println!("[INFO] Executing Phase 2 & 3: Fast-Path vs Hardware Lookup Measurement");
    
    // Reprovision and run warmup to ensure CPU is spooled up again
    provision_test_files(BENCH_DIR, std::cmp::max(ITERATIONS, WARMUP_ITERATIONS));
    println!("  -> Running {} post-activation warmup operations...", WARMUP_ITERATIONS);
    execute_warmup(BENCH_DIR, WARMUP_ITERATIONS);

    let mut fast_path_durations = Vec::new();
    let mut lookup_durations = Vec::new();
    let current_exe = std::env::current_exe().expect("Failed to get current executable");

    for b in 0..batches {
        // Phase 2: Fast-Path Deferral (O_RDONLY as Root)
        let start_fp = Instant::now();
        for i in 0..BATCH_SIZE {
            let idx = (b * BATCH_SIZE) + i;
            let path = format!("{}/dummy_{}.txt", BENCH_DIR, idx);
            let _ = OpenOptions::new().read(true).open(&path);
        }
        fast_path_durations.push(start_fp.elapsed());

        // Phase 3: Hardware Map Lookup (O_WRONLY as Unprivileged User)
        // Re-invoke the test binary as UID 65534 (nobody).
        let output = Command::new(&current_exe)
            .arg("benchmark_shield_overhead")
            .arg("--exact")
            .arg("--nocapture")
            .env("PHASE3_BATCH", b.to_string())
            .uid(65534) 
            .output()
            .expect("Failed to execute phase 3 worker");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut parsed_nanos = None;

        for line in stdout.lines() {
            if line.starts_with("bb_nanos:") {
                parsed_nanos = line.replace("bb_nanos:", "").trim().parse::<u64>().ok();
            }
        }

        if let Some(nanos) = parsed_nanos {
            lookup_durations.push(Duration::from_nanos(nanos));
        } else {
            panic!("Phase 3 worker failed. Stdout: {}, Stderr: {}", stdout, String::from_utf8_lossy(&output.stderr));
        }
    }

    // Teardown
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(BENCH_DIR);

    /*
     * METRICS CALCULATION
     */
    fast_path_durations.sort_unstable();
    lookup_durations.sort_unstable();

    let fast_path_duration = fast_path_durations[fast_path_durations.len() / 2] * (batches as u32);
    let lookup_duration = lookup_durations[lookup_durations.len() / 2] * (batches as u32);

    let calc_ops = |dur: Duration| -> f64 {
        ITERATIONS as f64 / dur.as_secs_f64()
    };
    
    let calc_ns_op = |dur: Duration| -> f64 {
        dur.as_nanos() as f64 / ITERATIONS as f64
    };

    let base_ns = calc_ns_op(baseline_duration);
    let fast_path_ns = calc_ns_op(fast_path_duration);
    let lookup_ns = calc_ns_op(lookup_duration);

    let fast_path_overhead = fast_path_ns - base_ns;
    let lookup_overhead = lookup_ns - base_ns;

    /*
     * REPORT GENERATION
     */
    let report = format!(
        "\n### Syscall Overhead: `shield` module (Median)\n\n\
        | Phase | Cleaned Time | Throughput | Latency / Op | Overhead |\n\
        |-------|--------------|------------|--------------|----------|\n\
        | **1. Baseline (Modules Disabled)** | `{:.2}ms` | `{:.0} ops/sec` | `{:.0} ns` | `-` |\n\
        | **2. Fast-Path (O_RDONLY)** | `{:.2}ms` | `{:.0} ops/sec` | `{:.0} ns` | `+{:.0} ns` |\n\
        | **3. Hardware Lookup (O_WRONLY)** | `{:.2}ms` | `{:.0} ops/sec` | `{:.0} ns` | `+{:.0} ns` |\n\n",
        baseline_duration.as_secs_f64() * 1000.0, calc_ops(baseline_duration), base_ns,
        fast_path_duration.as_secs_f64() * 1000.0, calc_ops(fast_path_duration), fast_path_ns, fast_path_overhead,
        lookup_duration.as_secs_f64() * 1000.0, calc_ops(lookup_duration), lookup_ns, lookup_overhead
    );

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/workspace/benchmark_results.md")
        .expect("Failed to open benchmark results file for appending");

    file.write_all(report.as_bytes())
        .expect("Failed to append shield benchmark results");
}
