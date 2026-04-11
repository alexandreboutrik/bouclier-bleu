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
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SOCKET_PATH: &str = "/var/run/bouclier-bleu/control.sock";

// Benchmark execution constants
const ITERATIONS: usize = 20_000;
const WARMUP_ITERATIONS: usize = 5_000;
const BATCH_SIZE: usize = 100;

// Benchmarking directories
const WARMUP_DIR: &str = "/tmp/bb_bench_warmup";
const BASELINE_DIR: &str = "/opt/bb_bench_baseline";
const UNMONITORED_DIR: &str = "/tmp/bb_bench_unmonitored";
const MONITORED_DIR: &str = "/var/bb_bench_monitored";

/// Provisions the dummy files required for the rename benchmark.
fn provision_test_files(dir: &str, count: usize) {
    let _ = fs::remove_dir_all(dir);
    fs::create_dir_all(dir).expect("Failed to create benchmark directory");
    
    for i in 0..count {
        let file_path = format!("{}/low_entropy_dummy_data_{}.txt", dir, i);
        File::create(&file_path).expect("Failed to create dummy file");
    }
    
    // Force the VFS to flush metadata to disk before we start the timer
    let _ = Command::new("sync").status();
}

/// Discards timings and simply spools the CPU up to Turbo and warms VFS
/// caches.
fn execute_warmup(dir: &str, count: usize) {
    for i in 0..count {
        let old_path = format!("{}/low_entropy_dummy_data_{}.txt", dir, i);
        let new_path = format!("{}/low_entropy_dummy_data_{}_renamed.txt", dir, i);
        let _ = fs::rename(&old_path, &new_path);
    }
}

/// Executes the rename loop in small chunks to filter out OS/Hypervisor
/// jitter, returning the median batch duration extrapolated to the total
/// iterations.
fn execute_baseline_batches(dir: &str, count: usize) -> Duration {
    let mut batch_durations = Vec::new();
    let batches = count / BATCH_SIZE;

    for b in 0..batches {
        let start = Instant::now();
        for i in 0..BATCH_SIZE {
            let idx = (b * BATCH_SIZE) + i;
            let old_path = format!("{}/low_entropy_dummy_data_{}.txt", dir, idx);
            let new_path = format!("{}/low_entropy_dummy_data_{}_renamed.txt", dir, idx);
            let _ = fs::rename(&old_path, &new_path);
        }
        batch_durations.push(start.elapsed());
    }

    batch_durations.sort_unstable();
    let median_batch = batch_durations[batch_durations.len() / 2];
    median_batch * (batches as u32)
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
fn benchmark_rename_entropy_overhead() {
    println!("[INFO] Provisioning files for all benchmark phases...");
    provision_test_files(WARMUP_DIR, WARMUP_ITERATIONS);
    provision_test_files(BASELINE_DIR, ITERATIONS);
    provision_test_files(UNMONITORED_DIR, ITERATIONS);
    provision_test_files(MONITORED_DIR, ITERATIONS);

    let core_bin = env!("CARGO_BIN_EXE_core");
    let cli_bin = PathBuf::from(core_bin).with_file_name("cli");

    /*
     * DAEMON INITIALIZATION
     * We start the daemon *before* Phase 1 to completely eliminate the OS
     * idle penalty and VFS wakeup jitter between the baseline and active
     * phases.
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
     * We dynamically list all modules and disable them via the CLI.
     * The LSM hook fires, reads the `state_map` as 0, and immediately returns,
     * giving us a perfectly clean baseline.
     */
    println!("[INFO] Establishing True Baseline (Daemon Online, Modules Disabled)");
    let active_modules = get_modules_from_cli(&cli_bin);
    for mod_slug in active_modules {
        let _ = Command::new(&cli_bin).args(["disable", &mod_slug]).output();
    }
    thread::sleep(Duration::from_millis(500)); // Allow IPC state to sync to kernel

    println!("  -> Running {} warmup operations...", WARMUP_ITERATIONS);
    execute_warmup(WARMUP_DIR, WARMUP_ITERATIONS);
    
    let baseline_duration = execute_baseline_batches(BASELINE_DIR, ITERATIONS);

    /*
     * PHASE 2 & 3: INTERLEAVED EXECUTION (rename_entropy ENABLED)
     * We re-enable the target module and interleave the batches.
     */
    println!("[INFO] Enabling rename_entropy module via IPC...");
    let _ = Command::new(&cli_bin).args(["enable", "rename_entropy"]).output();
    thread::sleep(Duration::from_millis(500)); // Allow IPC state to sync

    println!("[INFO] Executing Phase 2 & 3: Interleaved Overhead Measurement");
    
    // Reprovision and run warmup to ensure CPU is spooled up again
    provision_test_files(WARMUP_DIR, WARMUP_ITERATIONS);
    println!("  -> Running {} post-activation warmup operations...", WARMUP_ITERATIONS);
    execute_warmup(WARMUP_DIR, WARMUP_ITERATIONS);

    let mut unmonitored_durations = Vec::new();
    let mut monitored_durations = Vec::new();
    let batches = ITERATIONS / BATCH_SIZE;

    for b in 0..batches {
        // Unmonitored Batch (Early-Exit)
        let start_u = Instant::now();
        for i in 0..BATCH_SIZE {
            let idx = (b * BATCH_SIZE) + i;
            let old_path = format!("{}/low_entropy_dummy_data_{}.txt", UNMONITORED_DIR, idx);
            let new_path = format!("{}/low_entropy_dummy_data_{}_renamed.txt", UNMONITORED_DIR, idx);
            let _ = fs::rename(&old_path, &new_path);
        }
        unmonitored_durations.push(start_u.elapsed());

        // Monitored Batch (Full eBPF Math)
        let start_m = Instant::now();
        for i in 0..BATCH_SIZE {
            let idx = (b * BATCH_SIZE) + i;
            let old_path = format!("{}/low_entropy_dummy_data_{}.txt", MONITORED_DIR, idx);
            let new_path = format!("{}/low_entropy_dummy_data_{}_renamed.txt", MONITORED_DIR, idx);
            let _ = fs::rename(&old_path, &new_path);
        }
        monitored_durations.push(start_m.elapsed());
    }

    // Teardown
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(WARMUP_DIR);
    let _ = fs::remove_dir_all(BASELINE_DIR);
    let _ = fs::remove_dir_all(UNMONITORED_DIR);
    let _ = fs::remove_dir_all(MONITORED_DIR);

    /*
     * METRICS CALCULATION
     * Resolve the median batch duration and extrapolate to the full dataset.
     */
    unmonitored_durations.sort_unstable();
    monitored_durations.sort_unstable();

    let unmonitored_duration = unmonitored_durations[unmonitored_durations.len() / 2] * (batches as u32);
    let monitored_duration = monitored_durations[monitored_durations.len() / 2] * (batches as u32);

    let calc_ops = |dur: Duration| -> f64 {
        ITERATIONS as f64 / dur.as_secs_f64()
    };
    
    let calc_ns_op = |dur: Duration| -> f64 {
        dur.as_nanos() as f64 / ITERATIONS as f64
    };

    let base_ns = calc_ns_op(baseline_duration);
    let early_exit_ns = calc_ns_op(unmonitored_duration);
    let full_math_ns = calc_ns_op(monitored_duration);

    let early_exit_overhead = early_exit_ns - base_ns;
    let full_math_overhead = full_math_ns - base_ns;

    /*
     * REPORT GENERATION
     */
    let report = format!(
        "\n### Syscall Overhead: `rename_entropy` module (Median)\n\n\
        | Phase | Cleaned Time | Throughput | Latency / Op | Overhead |\n\
        |-------|--------------|------------|--------------|----------|\n\
        | **1. Baseline (Modules Disabled)** | `{:.2}ms` | `{:.0} ops/sec` | `{:.0} ns` | `-` |\n\
        | **2. Unmonitored (Early Exit)** | `{:.2}ms` | `{:.0} ops/sec` | `{:.0} ns` | `+{:.0} ns` |\n\
        | **3. Monitored (Full Math)** | `{:.2}ms` | `{:.0} ops/sec` | `{:.0} ns` | `+{:.0} ns` |\n\n",
        baseline_duration.as_secs_f64() * 1000.0, calc_ops(baseline_duration), base_ns,
        unmonitored_duration.as_secs_f64() * 1000.0, calc_ops(unmonitored_duration), early_exit_ns, early_exit_overhead,
        monitored_duration.as_secs_f64() * 1000.0, calc_ops(monitored_duration), full_math_ns, full_math_overhead
    );

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/workspace/benchmark_results.md")
        .expect("Failed to open benchmark results file for appending");

    file.write_all(report.as_bytes())
        .expect("Failed to append rename benchmark results");
}
