<div align="center">
<img align="center" width="128px" src="./assets/logo.png">
</div>

<h1 align="center">Bouclier Bleu</h1>

<div align="center">
<img src="https://img.shields.io/badge/version-v0.1.0--poc-blue">
</div>

Created as an ambitious, modular Next-Generation Antivirus (NGAV) and Endpoint Detection and Response (EDR) system for Linux, `Bouclier Bleu` leverages eBPF (BPF LSM) in kernel-space and fearless concurrency and memory safety in user-space via Rust. 

Its primary goals are to: 1.) aggressively prevent ransomware and 2.) stop memory corruption (overflows) before they compromise the system.

## Instructions

```bash
# If using NixOS, load the declarative dev environment first
nix-shell

# Compile the eBPF C code and Rust userland binaries
cargo build --release

# The core daemon requires root to load BPF programs
sudo ./target/release/core
```

## How it Works

For a deeper dive into the architecture, you can explore the source code directly, but the TL;DR is:

Bouclier Bleu bridges deep kernel-level visibility with flexible user-level analysis. The kernel component (`bpf/`) hooks into Linux Security Modules (LSM) to monitor or pause execution. The Rust userland daemon (`core/`) loads these BPF programs and routes asynchronous events to highly decoupled defense mechanisms (`modules/`) - such as Canary file monitors or YARA scanners - allowing users to toggle specific protections on the fly via the Control Plane (`cli/`).

## How to Reproduce the Tests

You can reproduce our initial Proof of Concept (PoC) kernel hook tests by following these steps across three separate terminal windows:

```bash
# Terminal 1: Start the core engine
sudo ./target/debug/core

# Terminal 2: Listen to the BPF telemetry output
sudo cat /sys/kernel/tracing/trace_pipe

# Terminal 3: Trigger an execution event and check the CLI
ls -la
./target/debug/cli status
```

## LICENSE

This project is dual-licensed. The userland engine (`core`, `cli`, `modules`) is licensed under the [Apache](LICENSE) License. The kernel-space eBPF code (`bpf/`) is strictly [GPL-2.0](bpf/LICENSE) compliant due to Linux kernel API requirements. Feel free to use, modify, and distribute the code as needed. See the [LICENSE](LICENSE) file for more information.
