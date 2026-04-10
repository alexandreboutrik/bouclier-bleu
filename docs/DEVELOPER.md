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
use crate::{BpfReader, define_security_module};

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

Finally, we must inject our new module into the EDR's Inversion of Control (IoC) registry. The core daemon uses this registry to dynamically load the compiled `.skel.rs` files and route IPC commands.

Open `modules/src/lib.rs` and make the following additions:

```rs
// Expose the module
pub mod exec_block;
pub mod rename_entropy;
pub mod ptrace_monitor; // <-- Add this line

```

```rs
// Locate the `build_registry()` function and append your module
pub fn build_registry() -> Vec<Arc<dyn SecurityModule + Send + Sync>> {
    vec![
        Arc::new(exec_block::ExecBlock::new()),
        Arc::new(rename_entropy::RenameEntropy::new()),
        Arc::new(ptrace_monitor::PtraceMonitor::new()), // <-- Add this line
    ]
}
```

## Note on Telemetry and the RingBuffer

In the example above, we used `bpf_printk()`. This is strictly for local kernel debugging. You should never use `bpf_printk` in production, as it is incredibly slow and pollutes the global trace pipe.

To securely send forensic data from the kernel hook back up to the Rust daemon, you must utilize the zero-copy BPF RingBuffer (`alerts` map).

For example:

Look at `bpf/rename_entropy.bpf.c`. Notice how it defines a struct `rename_alert`, reserves space using `bpf_ringbuf_reserve()`, populates the data, and fires it off with `bpf_ringbuf_submit()`.

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
