# Bouclier Bleu : Developing a new Module

This guide outlines the process of creating and integrating a new defense heuristic into `Bouclier Bleu`. The architecture strictly enforces a boundary between kernel-space execution (C) and user-space management (Rust).

> [!NOTE]
> Before writing any eBPF C code, we recommend you to compile the EDR at least once (`cargo build`). Our custom [build.rs](core/build.rs) pipeline dumps the BPF Type Format (BTF) of your current kernel and generates the `bpf/include/vmlinux.h` file. Without this file, your C Language Server (e.g. clangd) will throw constant syntax errors, and you will not have autocomplete for kernel structures like `task_struct` or `linux_binprm`.

## Example : Building a Basic `ptrace` Monitor

In this example, we will build a minimal module that intercepts the `ptrace` syscall (often used for hollow process injection or credential dumping) and logs it to the kernel trace pipe.

### Step 1. Kernel Hook `.bpf.c`

Create a new file at `bpf/ptrace_monitor.bpf.c`. This file will contain the Linux Security Module (LSM) hook.

```c
#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "headers/module_core.h"

/* Required */
char LICENSE[] SEC("license") = "GPL";

/*
 * Inject the shared state map to allow user-space toggling.
 * See bpf/headers/module_core.h file for more information.
 */
BOUCLIER_MODULE_STATE_MAP;

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_monitor_hook, struct task_struct *child, unsigned int mode) {
    /* First, check if the module is enabled via the Control Plane */
    if (!is_module_active(&state_map)) {
        return 0; // Allow
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 target_pid = child->pid;

    // Log the event (Note: For PoC only. See the Telemetry note below.)
    bpf_printk("Bouclier Bleu: PID %d attempted to ptrace target PID %d\\n",
        pid, target_pid);

    // Return 0 to allow, or -EPERM (1) to block
    return 0; 
}
```

### Step 2. User-Space Control Plane `.rs`

Next, we need to expose this module to the Rust EDR daemon so the Control Plane can manage its lifecycle, attach it to the kernel, and toggle its state. Create a new file at `modules/src/ptrace_monitor.rs`.

```rs
use crate::common::traits::BpfReader;
use crate::define_security_module;

// Define the telemetry payload (if we were using the RingBuffer)
#[derive(Debug)]
pub struct PtraceAlert {
    pub pid: u32,
    pub target_pid: u32,
}

impl PtraceAlert {
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("Payload too small");
        }

        let mut reader = BpfReader::new(data);

        Ok(Self {
            pid: reader.read_u32()?,
            target_pid: reader.read_u32()?,
        })
    }
}

// Use the factory macro to generate the boilerplate.
define_security_module!(
    struct: PtraceMonitor,
    name: "Ptrace Injection Monitor",
    slug: "ptrace_monitor",
    parser: PtraceAlert::try_from_bytes,
    handler: |alert: PtraceAlert| {
        println!(
            "Bouclier Bleu [ALERT]: PID {} is tracing PID {}",
            alert.pid, alert.target_pid
        );
    }
);
```

### Step 3. Registering the Module

Finally, we inject our new module into the EDR's Inversion of Control (IoC) registry. The core daemon uses this registry to dynamically load the compiled `.skel.rs` files and route IPC commands.

Open `modules/src/lib.rs` and make the following additions:

```rs
// Expose the module
pub mod exec_block;
pub mod rename_entropy;
pub mod ptrace_monitor; // <-- Add this line

```

The registry builder logic is inside the `common::macros` module. Open `modules/src/common/macros.rs`, locate the `build_registry()` function, and append your module

```rs
use crate::common::traits::SecurityModule;
use crate::{exec_block, mount_secure, rename_entropy, shield, strict_wx, ptrace_monitor}; // <- Add ptrace_monitor

use std::sync::Arc;

pub fn build_registry() -> Vec<Arc<dyn SecurityModule + Send + Sync>> {
    vec![
        Arc::new(shield::Shield::new()),
        // ...
        Arc::new(ptrace_monitor::PtraceMonitor::new()), // <-- Add this line
    ]
}
```

## Note on Telemetry and the RingBuffer

In the example above, we used `bpf_printk()`. This is strictly for local kernel debugging. You should never use `bpf_printk` in production, as it is incredibly slow and pollutes the global trace pipe.

To securely send forensic data from the kernel hook back up to the Rust daemon, you must utilize the zero-copy BPF RingBuffer. The user-space ingestion pipeline automatically intercepts safe Rust structs and forwards them to the standardized SIEM JSON log via the NDJSON forwarding engine in `common::telemetry`.

For example, look at `bpf/rename_entropy.bpf.c`. Notice how it defines a struct `rename_alert`, reserves space using `bpf_ringbuf_reserve()`, populates the data, and fires it off with `bpf_ringbuf_submit()`.

```c
struct rename_alert {
    __u32 pid;
    char dir_path[PATH_MAX];
    char file_name[256];
};

// ... inside BPF_PROG ...

event = bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
if (event) {
    /*
     * Clang's BPF backend cannot safely inline `memset` for large structs.
     * We utilize a volatile bounded loop to safely zero the memory block.
     */
    volatile __u8 *clear_ptr = (volatile __u8 *)event;
    for (int i = 0; i < sizeof(*event); i++) {
        clear_ptr[i] = 0;
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;

    bpf_probe_read_kernel_str(event->dir_path, sizeof(event->dir_path), dir_buf);
    bpf_probe_read_kernel_str(event->file_name, sizeof(event->file_name), scratch->name);

    bpf_ringbuf_submit(event, 0);
}
```

Then look at `modules/src/rename_entropy.rs`. Notice how it defines a mirroring Rust struct and uses the `BpfReader` utility to safely parse the raw bytes without using `unsafe` blocks or `FFI`.

```rs
use crate::common::traits::BpfReader;

#[derive(Debug)]
pub struct RenameAlert {
    pub pid: u32,
    pub full_path: String,
}

impl RenameAlert {
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        /*
         * Enforce strict structural boundaries:
         * 4 bytes (u32 PID) + 4096 bytes (dir_path) + 256 bytes (file_name) =
         * 4356 bytes.
         */
        if data.len() < 4356 {
            return Err("Telemetry payload violates minimum size constraints.");
        }

        let mut reader = BpfReader::new(data);

        let pid = reader.read_u32()?;
        let dir_path = reader.read_string(4096)?;
        let file_name = reader.read_string(256)?;

        let clean_dir = dir_path.trim_end_matches('/');
        let full_path = format!("{}/{}", clean_dir, file_name);

        Ok(Self { pid, full_path })
    }
}
```

## Note on Dynamic Map Sizing (Split-Phase Loading)

By default, eBPF maps (like `BPF_MAP_TYPE_HASH` or `BPF_MAP_TYPE_ARRAY`) require a hardcoded `max_entries` value in the C code. When the kernel loads the program, it immediately pre-allocates and locks this memory (`RLIMIT_MEMLOCK`). 

If you hardcode a worst-case scenario (e.g. `1,048,576` entries for tracking files), the kernel might lock ~90MB of RAM for your module alone, even if the user only has a few thousand files.

To keep `Bouclier Bleu` lightweight, the core daemon uses split-phase loading (`open()` -> mutate -> `load()`). This allows the Rust userland to intercept the BPF blueprint before the kernel allocates memory, calculate the exact capacity needed based on the current system state, and dynamically right-size the map.

### How to use the `capacities` Hook

To dynamically size a map, your C code should define a safe, minimal fallback for `max_entries` (e.g. `8192`). 

Then, in your Rust module, utilize the optional `capacities:` closure inside the `define_security_module!` macro. This closure must return a `HashMap` linking the C-defined map name to its new dynamically calculated capacity.

Here is how the `rename_entropy` module uses it to size the `protected_dirs` map:

> [!NOTE]
> The capacities hook executes strictly before the init hook. Because the Linux Virtual File System (VFS) heavily caches directory entries, scanning the disk in capacities pulls the metadata into RAM, making the second scan inside your init block nearly instantaneous.

```rs
use crate::common::traits::MapProvider;

define_security_module!(
    struct: RenameEntropy,
    name: "Ransomware Entropy Monitor",
    slug: "rename_entropy",
    parser: RenameAlert::try_from_bytes,
    handler: |alert: RenameAlert| {
        // ... handler logic ...
    },
    capacities: || -> std::collections::HashMap<String, u32> {
        /*
         * JUST-IN-TIME (JIT) MAP SIZING
         * Perform a rapid pre-scan of the target directories to count 
         * exactly how many inodes we need to protect.
         */
        let mut count = 0;
        let target_paths = ["/home", "/var", "/etc", "/opt"];

        // ... logic to walk directories and increment `count` ...

        // Apply a 25% safety buffer for new directories created during uptime,
        // with an absolute minimum fallback of 8192.
        let safe_capacity = ((count as f64 * 1.25) as u32).max(8192);

        let mut caps = std::collections::HashMap::new();
        
        // "protected_dirs" must exactly match the map name in your .bpf.c file
        caps.insert("protected_dirs".to_string(), safe_capacity);
        
        caps
    },
    init: |provider: &dyn MapProvider| -> Result<(), String> {
        // ... standard init logic to populate the map ...
        Ok(())
    }
);
```
