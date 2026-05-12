<div align="center">
<img align="center" width="128px" src="./assets/BB-Logo.png">
</div>

<h1 align="center">Bouclier Bleu</h1>

<div align="center">
<img src="https://img.shields.io/badge/version-v0.10.1--alpha-blue">
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

`Bouclier Bleu` implements numerous modules such as `rename_entropy`, `strict_wx`, and `shield`. For documentation on active heuristics, their specific eBPF hooks, and technical implementation details, please refer to [docs/MODULES.md](docs/MODULES.md).

## Installation

> [!IMPORTANT]  
> You must be running Linux kernel version **5.12 or higher** to support the `renamedata` structure and `bpf_d_path` execution paths. Additionally, your kernel must support BPF Security Modules (`CONFIG_BPF_LSM=y`), which may require enabling it at boot by appending `lsm=landlock,lockdown,yama,apparmor,bpf` to your GRUB boot parameters.

> [!NOTE]
> Pre-compiled packages `.deb` (Ubuntu/Debian) and `.rpm` (Fedora/RHEL) are available on the [GitHub Releases](https://github.com/alexandreboutrik/bouclier-bleu/releases) page. If you just want to install and use the NGAV/EDR, you do not need to build it from source.

If you prefer to compile the EDR from source, or are using a distribution outside of the Debian/RedHat families, we provide an automated installation script. This script compiles the Rust and eBPF binaries, provisions the `/etc/` directories, and natively registers the daemon with either `systemd` or `OpenRC`.

```bash
# If using NixOS, load the declarative dev environment first
nix-shell

# The core daemon requires root to load BPF programs
./scripts/install.sh
```

> [!NOTE]
> For maintainers : We also include an automated release pipeline (`scripts/release.sh`) for cross-distribution packaging (`via fpm`), GitHub Releases, and package manager repository updates. Run `./scripts/release.sh -h` for more information.

## Configuration

`Bouclier Bleu` can be configured via a TOML file located at `/etc/bouclier-bleu/config.toml`:

```bash
[modules]
# Untrusted Path Execution Prevention (Blocks execution from /tmp, /dev/shm)
exec_block = true

# Ransomware Rename Entropy Monitor (Analyzes filesystem encryption patterns)
rename_entropy = true
```

> [!NOTE]
> While this file dictates the default boot state, you can dynamically override these configurations at runtime without restarting the daemon by using the cli Control Plane (e.g., `sudo cli disable rename_entropy`).

## Telemetry & SIEM Integration

`Bouclier Bleu` is built with a "zero-code" enterprise integration philosophy. Instead of requiring a custom log shipper or complex networking configurations, the core daemon automatically formats all security events as structured NDJSON (Newline Delimited JSON) and streams them securely to a local file : `/var/log/bouclier-bleu/alerts.json`.

This decoupled architecture allows you to natively ingest Bouclier Bleu's telemetry into any existing enterprise SIEM or observability stack (e.g., Splunk Universal Forwarder, Datadog Agent, Elastic Filebeat, Promtail) simply by pointing your existing agent at this file.

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
