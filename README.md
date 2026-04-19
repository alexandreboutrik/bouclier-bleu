<div align="center">
<img align="center" width="128px" src="./assets/BB-Logo.png">
</div>

<h1 align="center">Bouclier Bleu</h1>

<div align="center">
<img src="https://img.shields.io/badge/version-v0.3.1--alpha-blue">
<img src="https://img.shields.io/badge/license-GPL--2.0--only-424242">
<img src="https://img.shields.io/badge/license-Apache--2.0-a8afb3">
</div>

<p align="center">
  <a href="#architecture-overview">Architecture Overview</a> •
  <a href="#compilation-usage">Compilation & Usage</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#testing-pipeline">Testing Pipeline</a> •
  <a href="#security">Security</a>
</p>

---

Created as a modular Next-Generation Antivirus (NGAV) and Endpoint Detection and Response (EDR) system for Linux, `Bouclier Bleu` leverages eBPF (BPF LSM) in kernel-space and memory safety in user-space via Rust. 

Its primary goals are to: 1.) prevent ransomware and 2.) stop memory corruption (overflows) before they compromise the system.

## Architecture Overview

`Bouclier Bleu` is designed to be modular and it is divided into four main directories:

- **`core/`**: The Rust userland daemon. It loads the eBPF programs into the kernel and routes asynchronous events to the decoupled defense mechanisms.
- **`bpf/`**: The kernel-space eBPF code. It hooks into Linux Security Modules (LSM) to monitor and/or pause execution.
- **`modules/`**: The userland modules. Defensive mechanisms (e.g. canary files). 
- **`cli/`**: The Control Plane. Allows users to toggle specific protections and interact with the core daemon on the fly.

### Modularity

Each "defense capability" is implemented as a standalone module. A complete module consists of a kernel-space eBPF program (`bpf/<module>.bpf.c`) and a user-space Rust component (`modules/src/<module>.rs`).

### Current Modules (Features)

The NGAV/EDR currently has the following defense heuristics:

* **Ransomware Entropy Monitor (`rename_entropy`)** : Detects and neutralizes ransomware encryption phases in real-time. It intercepts `rename` operations (e.g., appending `.locked_xyz123`) and calculates Shannon entropy using a custom, pre-computed logarithm lookup table for O(1) integer-math execution within the eBPF virtual machine. 

* **World-Writable Execution Block (`exec_block`)** : Mitigates memory corruption exploits and web-shell droppers from staging secondary payloads. It hooks into `bprm_check_security` to intercept process execution, blocking executions originating from historically insecure world-writable directories (e.g., `/tmp`, `/dev/shm`, `/var/crash`, `/run/user`).

* **Self-Defense Shield (`shield`)** : Hardens the NGAV/EDR architecture against direct tampering and LPE primitives. It strictly enforces `O_RDONLY` on critical configuration files, restricts the `bpf()` syscall to prevent EDR unloading, and locks down `dmesg` reads to prevent unprivileged kernel info leaks and KASLR bypasses.

* **Removable Media Neutralizer (`mount_secure`)** : Stripping physical USB drops of their ability to execute binaries or escalate privileges. It will hook `lsm/sb_mount` to guarantee that any removable media mount operation strictly enforces `MS_NOEXEC`, `MS_NOSUID`, and `MS_NODEV` flags, acting as a fail-safe against unsafe sysadmin defaults.

`Bouclier Bleu` is actively being developed. Upcoming modules (TODO SOON) include:

* **Strict Write XOR Execute (`strict_wx`)** : [OPT-IN] Mitigating shellcode injection and in-memory staging. It will check for a specific extended attribute (e.g. `user.bouclier.strict_wx`) on compiled binaries, mercilessly blocking any `mmap` or `mprotect` calls requesting `PROT_WRITE | PROT_EXEC` memory allocations.

* **Process Injection Prevention (`ptrace_access_check` / `ptrace_traceme`):** Monitoring and restricting `ptrace` capabilities to block cross-process memory tampering, hollow process injection, and credential dumping.

## Compilation & Usage

> [!IMPORTANT]  
> You must be running Linux kernel version **5.12 or higher** to support the `renamedata` structure and `bpf_d_path` execution paths. Additionally, your kernel must support BPF Security Modules (`CONFIG_BPF_LSM=y`), which may require enabling it at boot by appending `lsm=landlock,lockdown,yama,apparmor,bpf` to your GRUB boot parameters.

> [!NOTE]
> Pre-compiled packages `.deb` (Ubuntu/Debian) and `.rpm` (Fedora/RHEL) are available on the [GitHub Releases](https://github.com/alexandreboutrik/bouclier-bleu/releases) page. If you just want to install and use the NGAV/EDR, you do not need to build it from source.

```bash
# If using NixOS, load the declarative dev environment first
nix-shell

# Compile the eBPF C code and Rust userland binaries
cargo build --release

# The core daemon requires root to load BPF programs
sudo ./target/release/core
```

We also include an automated release pipeline (`scripts/release.sh`) for cross-distribution packaging (`via fpm`), GitHub Releases, and package manager repository updates.

```bash
./scripts/release.sh -h
```

## Configuration

`Bouclier Bleu` can be configured via a TOML file located at `/etc/bouclier-bleu/config.toml`:

```bash
[modules]
# Enable world-writable execution blocking
exec_block = true

# Enable ransomware entropy heuristics
rename_entropy = true

# Future modules can be toggled here
# file_mprotect = false
```

> [!NOTE]
> While this file dictates the default boot state, you can dynamically override these configurations at runtime without restarting the daemon by using the cli Control Plane (e.g., `sudo cli disable rename_entropy`).

## Testing Pipeline

`Bouclier Bleu` uses an isolated testing infrastructure powered by `incus` to virtualize an Ubuntu 24.04 environment. This ensures that potentially destructive tests (like malware execution) do not harm the host system.

> [!WARNING]
> Risk of VM Escape : While the Incus test environment utilizes a hardware-virtualized sandbox (`--vm`) and is strictly air-gapped from the host network (`--network none`), executing live, weaponized malwarae/ransomware (e.g. within the `threat` suite) always carries inherent risk. Advanced threats may attempt to exploit hypervisor vulnerabilities or guest-to-host communication channels to escape the virtual machine. Please ensure your host system is fully patched, updated, and ideally isolated from sensitive environments when executing live malware.

We manage the testing lifecycle using a custom `xtask` runner. Upon completion, it automatically generates a markdown report at `tests/Results.md` mapping out test statuses, durations, and environment metrics.

### Running the Tests

We manage the testing lifecycle using a custom `xtask` runner:

```bash
# Run all test suites
cargo xtask test

# Run a specific suite
cargo xtask test component
cargo xtask test integration
cargo xtask test benchmark
```

> [!Note]
> The test runner requires a base testing image (`bouclier-bleu-test-base.tar.gz/xz`). If this image is not found in the `tests/` directory (it is `.gitignore`d by default), `xtask` will automatically execute `scripts/build_image.sh` to provision, build, and export a fresh Ubuntu 24.04 image before running the tests. Therefore, for the first time you run `cargo xtask test`, it will take longer.

## Security

If you discover a security vulnerability, please check out our [Security Policy](SECURITY.md) for more details. All security vulnerabilities will be promptly addressed.

## LICENSE

This project is dual-licensed. The userland engine (`core`, `cli`, `modules`) is licensed under the [Apache](LICENSE) License. The kernel-space eBPF code (`bpf/`) is strictly [GPL-2.0](bpf/LICENSE) compliant due to Linux kernel API requirements. Feel free to use, modify, and distribute the code as needed. See the [LICENSE](LICENSE) file for more information.
