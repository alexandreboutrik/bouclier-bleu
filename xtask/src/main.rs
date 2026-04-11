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
use std::process::{Command, exit};
use std::thread;
use std::time::{Duration, Instant};

const VM_NAME: &str = "bb-test-runner";
const IMAGE_ALIAS: &str = "bouclier-bleu-test-base";
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
    let mut args = env::args().skip(1);

    let result = match args.next().as_deref() {
        Some("prepare-image") => prepare_test_image(),
        Some("test") => run_tests(args.next().as_deref(), args.next().as_deref()),
        _ => {
            eprintln!("Bouclier Bleu Build & Test Pipeline");
            eprintln!("Usage:");
            eprintln!("  cargo xtask prepare-image           - Builds the base testing VM image");
            eprintln!("  cargo xtask test                    - Runs all public test suites in VM");
            eprintln!(
                "  cargo xtask test component          - Runs all module component tests in VM"
            );
            eprintln!("  cargo xtask test integration        - Runs all integration tests in VM");
            eprintln!("  cargo xtask test benchmark          - Runs all benchmarks in VM (TODO)");
            eprintln!(
                "  cargo xtask test <category> [test]  - Runs a specific test file within a category"
            );
            eprintln!("  cargo xtask test <fuzz/threat>      - Restricted Private Suites");
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
fn run_tests(category: Option<&str>, target_test: Option<&str>) -> TaskResult<()> {
    prepare_test_image()?;
    let _guard = VmGuard; // Bind VM lifecycle strictly to this scope
    let setup_time = setup_and_snapshot_vm()?;

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
                        let _ = fs::write(
                            project_root().join("tests").join("benchmark_results.md"),
                            metrics,
                        );
                    }
                }
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

fn setup_and_snapshot_vm() -> TaskResult<Duration> {
    println!("\n[INFO] Provisioning Base Incus VM Environment...");
    let start = Instant::now();

    ensure_base_image()?;
    let _ = Command::new("incus")
        .args(["delete", VM_NAME, "--force"])
        .output();
    launch_instance()?;
    await_guest_agent()?;
    transfer_workspace()?;
    provision_default_config()?;
    compile_workspace()?;
    inject_kernel_parameters()?;
    create_snapshot()?;

    println!("[SUCCESS] VM Environment provisioned and snapshotted.");
    Ok(start.elapsed())
}

fn ensure_base_image() -> TaskResult<()> {
    if Command::new("incus")
        .args(["image", "info", IMAGE_ALIAS])
        .output()
        .map_or(false, |o| o.status.success())
    {
        return Ok(());
    }

    println!("[INFO] Synchronizing base image to Incus database...");
    let img = fs::read_dir(project_root().join("tests"))
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .find(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("bouclier-bleu-test-base.tar")
        })
        .map(|e| e.path())
        .ok_or("Pre-compiled test image missing. Run `cargo xtask prepare-image`.")?;

    let import_out = Command::new("incus")
        .args([
            "image",
            "import",
            img.to_str().unwrap(),
            "--alias",
            IMAGE_ALIAS,
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
                Command::new("incus").args(["image", "alias", "create", IMAGE_ALIAS, &fingerprint]),
                "Failed to bypass alias lock",
            )?;
        } else {
            return Err(format!("Image synchronization error:\n{}", stderr));
        }
    }
    Ok(())
}

fn launch_instance() -> TaskResult<()> {
    println!(
        "[INFO] Spawning isolated guest environment ({})...",
        VM_NAME
    );
    execute_cmd(
        Command::new("incus").args([
            "launch",
            IMAGE_ALIAS,
            VM_NAME,
            "--vm",
            "-c",
            "security.secureboot=false",
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
    incus_exec(
        "echo 'GRUB_CMDLINE_LINUX_DEFAULT=\"${GRUB_CMDLINE_LINUX_DEFAULT} lsm=landlock,lockdown,yama,integrity,apparmor,bpf\"' > /etc/default/grub.d/99-bpf-lsm.cfg && update-grub",
    )?;

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
    for _ in 0..40 {
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

fn prepare_test_image() -> TaskResult<()> {
    let root = project_root();
    if root.join("tests/bouclier-bleu-test-base.tar.gz").exists()
        || root.join("tests/bouclier-bleu-test-base.tar.xz").exists()
    {
        return Ok(());
    }

    println!("[INFO] Pre-compiled testing artifact missing. Initiating build sequence...");
    execute_cmd(
        Command::new("bash")
            .arg(root.join("scripts/build_image.sh"))
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
