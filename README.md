<div align="center">
<img align="center" width="128px" src="./assets/BB-Logo.png">
</div>

<h1 align="center">Bouclier Bleu</h1>

<div align="center">
<img src="https://img.shields.io/badge/version-v0.1.0--poc-blue">
</div>

Created as an ambitious, modular Next-Generation Antivirus (NGAV) and Endpoint Detection and Response (EDR) system for Linux, `Bouclier Bleu` leverages eBPF (BPF LSM) in kernel-space and fearless concurrency and memory safety in user-space via Rust. 

Its primary goals are to: 1.) aggressively prevent ransomware and 2.) stop memory corruption (overflows) before they compromise the system.

## Architecture Overview

`Bouclier Bleu` is designed to be modular and it is divided into four main directories:

- **`core/`**: The Rust userland daemon. It loads the eBPF programs into the kernel and routes asynchronous events to the highly decoupled defense mechanisms.
- **`bpf/`**: The kernel-space eBPF code. It hooks into Linux Security Modules (LSM) to monitor or pause execution.
- **`modules/`**: The userland modules. Defensive mechanisms (e.g. canary files, YARA scanners) and analysis logic. 
- **`cli/`**: The Control Plane. Allows users to toggle specific protections and interact with the core daemon on the fly.

### Modularity

Each "defense capability" is implemented as a standalone module. A complete module consists of a kernel-space eBPF program (`bpf/<module>.bpf.c`) and a user-space Rust component (`modules/src/<module>.rs`).

## Compilation & Usage

```bash
# If using NixOS, load the declarative dev environment first
nix-shell

# Compile the eBPF C code and Rust userland binaries
cargo build --release

# The core daemon requires root to load BPF programs
sudo ./target/release/core
```

We also include an automated release pipeline (`scripts/release.sh`) for cross-distribution packaging (`via fpm`), GitHub Relases, and package manager repository updates.

```bash
./scripts/release.sh -h
```

## Testing Pipeline

`Bouclier Bleu` uses an isolated testing infrastructure powered by `incus` to virtualize an Ubuntu 24.04 environment. This ensures that potentially destructive tests (like malware execution) do not harm the host system.

We manage the testing lifecycle using a custom `xtask` runner. Upon completion, it automatically generates a markdown report at `tests/Results.md` mapping out test statuses, durations, and environment metrics.

### Running the Tests

We manage the testing lifecycle using a custom `xtask` runner:

```bash
# Run all test suites
cargo xtask test

# Run a specific suit
cargo xtask test component
cargo xtask test integration
```

> [!Note]
> The test runner requires a base testing image (`bouclier-bleu-test-base.tar.gz/xz`). If this image is not found in the `tests/` directory (it is `.gitignore`d by default), `xtask` will automatically execute `scripts/build_image.sh` to provision, build, and export a fresh Ubuntu 24.04 image before running the tests. Therefore, for the first time you run `cargo xtask test`, it will take longer.

## Security

If you discover a security vulnerability, please check out our [Security Policy](SECURITY.md) for more details. All security vulnerabilities will be promptly addressed.

## LICENSE

This project is dual-licensed. The userland engine (`core`, `cli`, `modules`) is licensed under the [Apache](LICENSE) License. The kernel-space eBPF code (`bpf/`) is strictly [GPL-2.0](bpf/LICENSE) compliant due to Linux kernel API requirements. Feel free to use, modify, and distribute the code as needed. See the [LICENSE](LICENSE) file for more information.
