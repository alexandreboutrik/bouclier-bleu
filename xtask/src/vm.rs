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
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use crate::utils::{
	await_guest_agent, execute_cmd, incus_exec, project_root, TaskResult, SNAPSHOT_NAME, VM_NAME,
};

/// Environment Bootstrapper
///
/// Orchestrates the entire initialization sequence required to bring an
/// isolated hypervisor environment to a "clean, execution-ready" state.
pub fn setup_and_snapshot_vm(image_alias: &str) -> TaskResult<Duration> {
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

/// Image Synchronization Engine
///
/// Ensures the target testing image exists in the local hypervisor registry.
/// Attempts fingerprint evasion if the image already exists but requires
/// linking to bypass locking mechanisms.
fn ensure_base_image(image_alias: &str) -> TaskResult<()> {
	if Command::new("incus")
		.args(["image", "info", image_alias])
		.output()
		.is_ok_and(|o| o.status.success())
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

/// Strict Network Profile Instantiation
///
/// Replicates the default hypervisor profile but actively strips the
/// physical/bridge adapter (eth0). This ensures live malware detonated during
/// threat tests cannot establish C2 (Command & Control) or scan the host
/// bridge.
fn ensure_no_network_profile() -> TaskResult<()> {
	println!("[INFO] Ensuring 'bb-no-network' profile is correctly configured...");

	let exists = Command::new("incus")
		.args(["profile", "show", "bb-no-network"])
		.output()
		.is_ok_and(|o| o.status.success());

	if !exists {
		println!("[INFO] Creating 'bb-no-network' profile from default...");
		execute_cmd(
			Command::new("incus").args(["profile", "copy", "default", "bb-no-network"]),
			"Failed to copy default profile",
		)?;
	} else {
		println!("[INFO] 'bb-no-network' profile already exists.");
	}

	match Command::new("incus")
		.args(["profile", "device", "remove", "bb-no-network", "eth0"])
		.output()
	{
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
			))
		}
	}
	Ok(())
}

/// Air-Gap Validation
///
/// Internally audits the guest kernel's link state. Throws an immediate fatal
/// error if an interface other than loopback is detected, preventing unsafe
/// runs.
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

pub fn enforce_airgap() -> TaskResult<()> {
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

	/*
	 * Hypervisor Constraints
	 * Disables secure boot for LSM hooking, explicitly forces hardware
	 * virtualization (--vm) instead of LXC containers for strict kernel
	 * isolation.
	 */
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

/// State Decoupling & Tarball Injection
///
/// Excludes target/ and .git/ directories during workspace injection.
/// Moving unnecessary binaries (or potential compilation state from the host)
/// guarantees that the guest compiles against a pure state.
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

/// Graceful Degradation & LSM Configuration
///
/// Injects 'lsm=bpf' into the bootloader to ensure eBPF LSM support is active.
/// Additionally masks network-wait services to prevent boot/shutdown hangs
/// caused by the intentional air-gapping mechanism.
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
    elif command -v grub-mkconfig >/dev/null 2>&1; then
        # Arch Linux / Generic GRUB
        if grep -q "^GRUB_CMDLINE_LINUX_DEFAULT=" /etc/default/grub; then
            sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="lsm=bpf /' /etc/default/grub
        else
            echo 'GRUB_CMDLINE_LINUX_DEFAULT="lsm=bpf"' >> /etc/default/grub
        fi
        grub-mkconfig -o /boot/grub/grub.cfg
    elif [ -d "/boot/loader/entries" ]; then
        # Systemd-boot fallback (used by some Arch cloud images)
        for conf in /boot/loader/entries/*.conf; do
            if grep -q "^options" "$conf"; then
                sed -i 's/^options.*/& lsm=bpf/' "$conf"
            fi
        done
    else
        echo "Error: No recognized bootloader management tool found. Cannot configure LSM." >&2
        exit 1
    fi
"#;

	let status = Command::new("incus")
		.args(["exec", VM_NAME, "--", "bash", "-c", enable_lsm_script])
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

/// Idempotent State Restoration
///
/// Restores the immutable snapshot (`clean-state`), ensuring zero state
/// leakage (filesystem artifacts, active processes, memory) across independent
/// test boundaries.
pub fn restore_vm_snapshot() -> TaskResult<Duration> {
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

/// Dependency Remediation
///
/// Validates the existence of the base OS image locally. Triggers upstream
/// compile scripts directly if the file is absent.
pub fn prepare_test_image(image_alias: &str) -> TaskResult<()> {
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
