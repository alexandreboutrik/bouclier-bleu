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
use std::time::Duration;

const VM_NAME: &str = "bb-test-runner";
const IMAGE_ALIAS: &str = "bouclier-bleu-test-base";
const SNAPSHOT_NAME: &str = "clean-state";

type TaskResult<T> = Result<T, String>;

/// Telemetry payload for aggregating test suite results across execution
/// boundaries.
struct TestRecord {
    name: String,
    category: String,
    passed: bool,
}

fn main() {
    let mut args = env::args().skip(1);
    let task = args.next();

    let result = match task.as_deref() {
        Some("prepare-image") => prepare_test_image(),
        Some("test") => run_tests(args.next().as_deref()),
        _ => {
            eprintln!("Bouclier Bleu Build & Test Pipeline");
            eprintln!("Usage:");
            eprintln!("  cargo xtask prepare-image           - Builds the base testing VM image");
            eprintln!("  cargo xtask test                    - Runs all public test suites in VM");
            eprintln!("  cargo xtask test component          - Runs all module component tests in VM");
            eprintln!("  cargo xtask test integration        - Runs all integration tests in VM");
            eprintln!("  cargo xtask test performance        - Runs all performance benchmarks in VM (TODO)");
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
/// This ensures host resources are freed even if the test runner panics or
/// exits prematurely during execution.
struct VmGuard;
impl Drop for VmGuard {
    fn drop(&mut self) {
        println!("\n[INFO] Terminating ephemeral test environment ({})...", VM_NAME);
        let _ = Command::new("incus")
            .args(["delete", VM_NAME, "--force"])
            .output();
    }
}

/// Primary orchestration sequence for test execution.
fn run_tests(category: Option<&str>) -> TaskResult<()> {
    prepare_test_image()?;

    // Bind the VM lifecycle strictly to this function's scope.
    let _guard = VmGuard; 

    setup_and_snapshot_vm()?;

    let mut all_results: Vec<TestRecord> = Vec::new();

    match category {
        Some("component") => all_results.extend(run_component_tests()?),
        Some("integration") => all_results.extend(run_integration_tests()?),
        Some("performance") => all_results.extend(run_performance_tests()?),
        Some("fuzzing") | Some("threat") => {
            println!("[WARN] The '{}' test suite is private and restricted.", category.unwrap());
        }
        None | Some("all") => {
            println!("\n[INFO] Initiating public Bouclier Bleu test suites...");
            all_results.extend(run_component_tests()?);
            all_results.extend(run_integration_tests()?);
        }
        Some(other) => {
            return Err(format!("Unknown test category requested: {}", other));
        }
    }

    // Ensure artifact generation occurs before evaluating exit status to
    // preserve telemetry in CI environments.
    if let Err(e) = generate_markdown_report(&all_results) {
        eprintln!("[ERROR] Failed to generate markdown report: {}", e);
    }

    let success = all_results.iter().all(|r| r.passed);
    if success {
        println!("\n[SUCCESS] Test suite execution completed with zero failures.");
        Ok(())
    } else {
        Err("One or more test suites failed validation.".to_string())
    }
}

// --- Test Suite Runners ---

fn run_component_tests() -> TaskResult<Vec<TestRecord>> {
    let comp_dir = project_root().join("tests/component");
    let mut results = Vec::new();

    if !comp_dir.exists() {
        println!("[INFO] No component test artifacts located. Bypassing phase.");
        return Ok(results);
    }

    println!("\n[INFO] Executing Component Tests (eBPF Defenses)...");

    for entry in fs::read_dir(comp_dir).map_err(|e| format!("IO Error reading component directory: {}", e))? {
        let path = entry.unwrap().path();

        if path.is_file() && path.extension().unwrap_or_default() == "sh" {
            let test_name = path.file_name().unwrap().to_string_lossy();
            
            println!("\n[INFO] Reverting environment to clean state for {}...", test_name);
            restore_vm_snapshot()?;

            println!("[INFO] Executing {}...", test_name);
            let cmd = format!("bash tests/component/{}", test_name);
            
            let passed = incus_exec(&cmd).is_ok();
            if passed {
                println!("[SUCCESS] Passed: {}", test_name);
            } else {
                eprintln!("[ERROR] Component test failed: {}", test_name);
            }

            results.push(TestRecord {
                name: test_name.to_string(),
                category: "component".to_string(),
                passed,
            });
        }
    }

    Ok(results)
}

fn run_integration_tests() -> TaskResult<Vec<TestRecord>> {
    let int_dir = project_root().join("tests/integration");
    let mut results = Vec::new();

    if !int_dir.exists() {
        println!("[INFO] No integration test artifacts located. Bypassing phase.");
        return Ok(results);
    }

    println!("\n[INFO] Executing Integration Tests...");

    for entry in fs::read_dir(int_dir).map_err(|e| format!("IO Error reading integration directory: {}", e))? {
        let path = entry.unwrap().path();

        if path.is_file() && path.extension().unwrap_or_default() == "rs" {
            let test_name = path.file_stem().unwrap().to_string_lossy();
            
            println!("\n[INFO] Reverting environment to clean state for {}...", test_name);
            restore_vm_snapshot()?;

            println!("[INFO] Executing {}...", test_name);
            let cmd = format!("cargo test --release --test {}", test_name);
            
            let passed = incus_exec(&cmd).is_ok();
            if passed {
                println!("[SUCCESS] Passed: {}", test_name);
            } else {
                eprintln!("[ERROR] Integration test failed: {}", test_name);
            }

            results.push(TestRecord {
                name: test_name.to_string(),
                category: "integration".to_string(),
                passed,
            });
        }
    }

    Ok(results)
}

fn run_performance_tests() -> TaskResult<Vec<TestRecord>> {
    println!("\n[INFO] Executing Performance Benchmarks (System Overhead Analysis)...");
    
    // TODO: Implement standardized system overhead and latency benchmarks.
    println!("[TODO] Performance suite is currently pending implementation. Bypassing.");
    
    Ok(Vec::new())
}

// --- Incus VM Orchestration Subsystem ---

fn setup_and_snapshot_vm() -> TaskResult<()> {
    println!("\n[INFO] Provisioning Base Incus VM Environment...");

    ensure_base_image()?;
    purge_stale_instance();
    launch_instance()?;
    await_guest_agent()?;
    transfer_workspace()?;
    compile_workspace()?;
    inject_kernel_parameters()?;
    create_snapshot()?;

    println!("[SUCCESS] VM Environment provisioned and snapshotted.");
    Ok(())
}

fn ensure_base_image() -> TaskResult<()> {
    if Command::new("incus").args(["image", "info", IMAGE_ALIAS]).output().map_or(false, |o| o.status.success()) {
        return Ok(());
    }

    println!("[INFO] Synchronizing base image to Incus database...");
    
    let root = project_root();
    let mut image_path = None;
    
    if let Ok(entries) = fs::read_dir(root.join("tests")) {
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.starts_with("bouclier-bleu-test-base.tar") {
                image_path = Some(entry.path());
                break;
            }
        }
    }

    let img = image_path.ok_or("Pre-compiled test image missing. Run `cargo xtask prepare-image`.")?;
    
    let import_out = Command::new("incus")
        .args(["image", "import", img.to_str().unwrap(), "--alias", IMAGE_ALIAS])
        .output()
        .map_err(|e| format!("Incus import failed: {}", e))?;

    if !import_out.status.success() {
        let stderr = String::from_utf8_lossy(&import_out.stderr);
        
        // Mitigates persistent fingerprint locks caused by Incus state
        // desynchronization by abstracting the constraint via a direct alias.
        if stderr.contains("already exists") {
            println!("[INFO] Abstracting existing fingerprint constraint via direct alias...");
            let sha_out = Command::new("sha256sum").arg(&img).output().map_err(|e| e.to_string())?;
            let fingerprint = String::from_utf8_lossy(&sha_out.stdout).split_whitespace().next().unwrap_or("").to_string();
            
            execute_cmd(
                Command::new("incus").args(["image", "alias", "create", IMAGE_ALIAS, &fingerprint]),
                "Failed to bypass alias lock"
            )?;
        } else {
            return Err(format!("Image synchronization error:\n{}", stderr));
        }
    }

    Ok(())
}

fn purge_stale_instance() {
    let _ = Command::new("incus").args(["delete", VM_NAME, "--force"]).output();
}

fn launch_instance() -> TaskResult<()> {
    println!("[INFO] Spawning isolated guest environment ({})...", VM_NAME);
    execute_cmd(
        Command::new("incus").args(["launch", IMAGE_ALIAS, VM_NAME, "--vm", "-c", "security.secureboot=false"]),
        "Guest initialization failed"
    )
}

fn transfer_workspace() -> TaskResult<()> {
    println!("[INFO] Packaging and injecting source workspace...");
    let root = project_root();
    let tarball_path = env::temp_dir().join("bb-src-bundle.tar.gz");

    // Standardizes codebase pathing without transferring host-specific
    // metadata. Excludes heavy VM image artifacts to prevent race conditions
    // during archival.
    execute_cmd(
        Command::new("tar")
            .args([
                "--exclude=target", 
                "--exclude=.git", 
                "--exclude=*.tar.gz",
                "--exclude=*.tar.xz",
                "-czf", 
                tarball_path.to_str().unwrap(), 
                "."
            ])
            .current_dir(&root),
        "Failed to archive host workspace"
    )?;

    execute_cmd(
        Command::new("incus").args(["file", "push", tarball_path.to_str().unwrap(), &format!("{}/root/src-bundle.tar.gz", VM_NAME)]),
        "Host-to-Guest file injection failed"
    )?;

    let _ = fs::remove_file(tarball_path);

    execute_cmd(
        Command::new("incus").args(["exec", VM_NAME, "--", "bash", "-c", "mkdir -p /workspace && tar -xzf /root/src-bundle.tar.gz -C /workspace"]),
        "Guest extraction phase failed"
    )
}

fn compile_workspace() -> TaskResult<()> {
    println!("[INFO] Executing cross-environment compilation phase...");

    // Bypasses Cargo's workspace constraints by dynamically injecting
    // discovered test targets directly into the guest's crate manifest. Skips
    // root 'main.rs' to prevent duplicate target collisions.
    let inject_cmd = r#"
        find tests -mindepth 2 -type f -name "*.rs" | while read -r f; do
            name=$(basename "$f" .rs)
            
            # Skip main.rs as Cargo auto-registers tests/<dir>/main.rs
            [ "$name" = "main" ] && continue
            
            echo "" >> core/Cargo.toml
            echo "[[test]]" >> core/Cargo.toml
            echo "name = \"$name\"" >> core/Cargo.toml
            echo "path = \"../$f\"" >> core/Cargo.toml
        done
    "#;
    incus_exec(inject_cmd)?;
    
    // Purging target/ mitigates edge cases where the host's immutable path
    // configs inadvertently override the Ubuntu guest's linker paths.
    incus_exec("cargo clean && cargo build --release --workspace --all-targets")?;

    // Ensures object files residing in the kernel's volatile memory cache are
    // committed to the persistent disk, preventing structural corruption
    // during forceful snapshots.
    println!("[INFO] Committing VFS page cache to persistent storage...");
    incus_exec("sync")?;
    thread::sleep(Duration::from_secs(3)); 

    Ok(())
}

fn inject_kernel_parameters() -> TaskResult<()> {
    println!("[INFO] Activating eBPF LSM subsystem in guest kernel...");
    
    let grub_cmd = "echo 'GRUB_CMDLINE_LINUX_DEFAULT=\"${GRUB_CMDLINE_LINUX_DEFAULT} lsm=landlock,lockdown,yama,integrity,apparmor,bpf\"' > /etc/default/grub.d/99-bpf-lsm.cfg && update-grub";
    incus_exec(grub_cmd)?;

    println!("[INFO] Re-initializing kernel via cold boot...");
    execute_cmd(Command::new("incus").args(["restart", VM_NAME]), "VM reboot procedure failed")?;
    
    await_guest_agent()
}

fn create_snapshot() -> TaskResult<()> {
    println!("[INFO] Capturing immutable state vector for test resets...");
    execute_cmd(Command::new("incus").args(["stop", VM_NAME]), "Failed to gracefully halt VM")?;
    execute_cmd(Command::new("incus").args(["snapshot", "create", VM_NAME, SNAPSHOT_NAME]), "Snapshot generation aborted")
}

fn restore_vm_snapshot() -> TaskResult<()> {
    let _ = Command::new("incus").args(["stop", VM_NAME, "--force"]).output();
    
    execute_cmd(
        Command::new("incus").args(["snapshot", "restore", VM_NAME, SNAPSHOT_NAME]),
        "VM state reversion failed"
    )?;

    execute_cmd(Command::new("incus").args(["start", VM_NAME]), "Failed to resurrect VM from snapshot")?;
    await_guest_agent()
}

// --- System Utilities ---

fn await_guest_agent() -> TaskResult<()> {
    for _ in 0..40 {
        if Command::new("incus").args(["exec", VM_NAME, "--", "echo", "ready"]).output().map_or(false, |o| o.status.success()) {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(2));
    }
    Err("VM communication agent exceeded response timeout limit.".to_string())
}

fn incus_exec(command: &str) -> TaskResult<()> {
    let full_cmd = format!("source ~/.cargo/env && cd /workspace && {}", command);
    
    let status = Command::new("incus")
        .args(["exec", VM_NAME, "--", "bash", "-c", &full_cmd])
        .status()
        .map_err(|e| format!("Incus translation execution failure: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("Guest operation '{}' returned a non-zero exit status.", command))
    }
}

fn execute_cmd(cmd: &mut Command, error_msg: &str) -> TaskResult<()> {
    let status = cmd.status().map_err(|e| format!("{}: {}", error_msg, e))?;
    if !status.success() {
        return Err(format!("{} (Exit code: {})", error_msg, status.code().unwrap_or(-1)));
    }
    Ok(())
}

fn prepare_test_image() -> TaskResult<()> {
    let project_root = project_root();
    
    let has_tar_gz = project_root.join("tests/bouclier-bleu-test-base.tar.gz").exists();
    let has_tar_xz = project_root.join("tests/bouclier-bleu-test-base.tar.xz").exists();

    if has_tar_gz || has_tar_xz {
        return Ok(());
    }

    println!("[INFO] Pre-compiled testing artifact missing. Initiating build sequence...");
    
    let script_path = project_root.join("scripts/build_image.sh");
    execute_cmd(
        Command::new("bash").arg(&script_path).current_dir(&project_root),
        "Upstream base-image compilation script failed"
    )
}

fn generate_markdown_report(results: &[TestRecord]) -> Result<(), std::io::Error> {
    if results.is_empty() {
        println!("[INFO] No tests were executed. Skipping report generation.");
        return Ok(());
    }

    let mut report = String::from("# Bouclier Bleu Test Results\n\n");
    report.push_str("| Test Name | Category | Status |\n");
    report.push_str("|-----------|----------|--------|\n");

    for res in results {
        let status = if res.passed { "PASS" } else { "FAIL" };
        report.push_str(&format!("| `{}` | {} | {} |\n", res.name, res.category, status));
    }

    let report_path = project_root().join("tests").join("Results.md");
    fs::write(&report_path, report)?;
    
    println!("\n[INFO] Test report successfully generated at {}", report_path.display());
    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
}
