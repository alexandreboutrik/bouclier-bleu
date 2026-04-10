# Bouclier Bleu : Architecture

`Bouclier Bleu` operates on a separation of concerns between high-performance kernel-space enforcement and safe, asynchronous user-space management. This document outlines the core architectural decisions, data flows, and security boundaries that power the NGAV/EDR.

## Kernel/User Split

`Bouclier Bleu` is split into two distinct execution domains:

* **Kernel-Space (eBPF / C)**: Responsible for interception and enforcement. Using the BPF Linux Security Module (LSM) hooks, these programs pause execution directly at the syscall boundary to evaluate rules in O(1) or in special cases O(n) time. If a threat is detected, the kernel atomically takes action (e.g. blocks the action (-EPERM) or terminates the process (SIGKILL)).

* **User-Space (Rust)**: Acts as the Control Plane and Telemetry Sink. It manages the lifecycle of the eBPF programs, loads configurations, updates hardware-backed watchlists (e.g. see [rename_entropy](modules/src/rename_entropy.rs)), and processes the forensic data stream.

## Why libbpf-rs and C instead of Aya?

While pure-Rust eBPF toolchains like `Aya` offer nice developer ergonomics, `Bouclier Bleu` intentionally utilizes `libbpf-rs` and writes its kernel-space hooks in C. This decision is primarily driven by ecosystem stability and the maturity of CO-RE (Compile Once – Run Everywhere). eBPF programs must access internal kernel structures that frequently change layout between kernel versions. CO-RE relies on BTF (BPF Type Format) and compiler relocations to dynamically adapt to the running kernel without recompilation. 

C remains the _lingua franca_ of the Linux kernel, and using it allows us to leverage the highly stable and production-grade `libbpf` ecosystem. Furthermore, developing the kernel hooks in C is more interesting for me personally because I have familiarity with the language, which ensures a higher standard of manual code review, memory auditing, and optimization. 

Also, to facilitate this architecture, our [build pipeline](core/build.rs) dynamically dumps the BTF of the host system into a fresh `vmlinux.h` at compile time via `bpftool`. This guarantees that our BPF objects align perfectly with the host’s memory layout while keeping the repository lightweight. Through `libbpf-rs`, we generate strongly typed Rust "skeletons" at compile time, seamlessly bridging the safety of user-space Rust with the rock-solid stability of kernel-space C.

## Zero-Copy Telemetry (BPF RingBuffer)

When a BPF hook detects anomalous behavior (e.g. a high-entropy file rename), it needs to pass that context back to user-space for logging or SIEM integration.

We utilize a BPF RingBuffer (_alerts map_, see [the definition](bpf/headers/module_core.h)) rather than the older perf buffer. The RingBuffer provides a shared, memory-mapped region between the kernel and user-space, allowing for high-throughput, zero-copy telemetry transfer.

A common vulnerability in Rust/C integrations is using `unsafe` blocks and `C-FFI` to cast raw byte pointers into Rust structs. `Bouclier Bleu` DO NOT accept `unsafe` or `FFI` code. We implemented a custom BpfReader utility that safely extracts fields from the raw byte slice. By utilizing `from_utf8_lossy()` and explicit bounds checking, we prevent buffer underruns, out-of-bounds access, and panics caused by malformed or truncated kernel strings.

## IPC Control Plane

To allow administrators to dynamically toggle defense heuristics without restarting the daemon or dropping the BPF LSM links, `Bouclier Bleu` exposes a local Inter-Process Communication (IPC) socket at `/var/run/bouclier-bleu/control.sock`.

Older BPF architectures manage state by loading and unloading the entire BPF program. This is slow and introduces security blind spots during the reload phase. Instead, `Bouclier Bleu` maintains active BPF skeletons strictly in memory. When a command is received via the IPC socket (e.g. `sudo cli disable rename_entropy`), the user-space daemon simply updates a shared `state_map` eBPF Map. The kernel hook reads this flag in real-time, effectively toggling the enforcement logic on or off without ever detaching the LSM hook.
