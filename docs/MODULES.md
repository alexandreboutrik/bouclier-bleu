# Bouclier Bleu : Current Modules (Features)

`Bouclier Bleu` is built on a modular architecture. Each module operates across the user-kernel boundary, utilizing Linux Security Module (LSM) hooks in kernel-space to enforce policies and a decoupled Rust user-space daemon to orchestrate configuration and ingest telemetry.

> [!NOTE]
> Attackers often try to bypass mechanisms using tricks like mount namespace spoofing (`unshare -m`) or symlink manipulation. To counter this, our core modules ignore easily spoofed file paths and instead rely on hard hardware IDs (like the physical Inode and Superblock Device IDs).

## Performance & Memory Footprint

Security shouldn't bottleneck your system. We designed Bouclier Bleu to be as lightweight and performant as possible.

> [!IMPORTANT]
> Depending on the module and how often a syscall is triggered, the interception overhead typically adds 3ms to 8ms (tested on a Dell Rugged 5424: i5-8350u, NVMe SSD).

| Component / Module | Memory Consumption (kB) |
| :--- | :--- |
| **User-Space Daemon (VmRSS)** | 6636.00 |
| **`rename_entropy` (eBPF Maps)** | 2602.24 |
| **`exec_block` (eBPF Maps)** | 1008.31 |
| **`strict_wx` (eBPF Maps)** | 448.45 |
| **`shield` (eBPF Maps)** | 305.16 |
| **`mount_secure` (eBPF Maps)** | 302.61 |
| **Total Active Footprint** | **~11.30 MB** |

---

## Active Modules

Below is an overview of the currently active modules and their technical implementations.

### Ransomware Entropy Monitor (`rename_entropy`)

Detects and neutralizes ransomware encryption phases in real-time by evaluating the structural randomness of file modifications. 

* **eBPF Hook:** `lsm/path_rename`.

* **How it works:** When a file gets renamed (e.g., an attacker appends `.locked`), we calculate the new filename's Shannon entropy. Because the kernel's eBPF verifier is incredibly strict and lacks native floating-point math, we use a custom, pre-computed `scaled_log2` lookup table. This allows us to execute the math instantly in O(1) time using only integers. If the randomness crosses our threshold (a scaled value > 4300), the BPF program immediately fires a SIGKILL (signal 9) directly from kernel-space. This instantly terminates the thread before it can return to user-space, completely eliminating race conditions.

* **Watchlist:** By hooking `vfs_mkdir` and `vfs_rename`, the protection cascades. If a threat actor builds a payload in `/tmp` and moves it to a protected directory like `/home`, the kernel automatically adds those new child inodes to our hardware-backed watchlist.

### World-Writable Execution Block (`exec_block`)

This stops memory corruption exploits and web-shell droppers from running secondary payloads out of historically insecure, world-writable directories.

* **eBPF Hook:** `lsm/bprm_check_security`.

* **Path Validation:** As explained before, instead of looking at the easily spoofed `bprm->filename`, we check the underlying hardware IDs right from the dentry cache, completely bypassing namespace tricks.

* **Catching Fileless Malware**: Attackers frequently use memory-backed payloads (`memfd_create`) or nameless temporary files (`O_TMPFILE`) to avoid touching the disk. We catch these by checking if the VFS link count (`i_nlink`) is zero. If we detect a fileless execution attempt, we demand that the memory segment be completely immutable (`F_SEAL_WRITE`) - and if it isn't, we block it.

### Self-Defense Shield (`shield`)

This hardens `Bouclier Bleu` itself against tampering, unprivileged unloading, and privilege escalation attacks.

* **eBPF Hooks:** `lsm/file_open`, `lsm/bpf`, `lsm/syslog`.

* **Configuration Immutability:** It forces an `O_RDONLY` policy on core files (like `config.toml`) for unprivileged users. This acts as a fail-safe even if a sysadmin accidentally runs a reckless `chmod 777`.

* **Architecture Locking:** It restricts the `bpf()` syscall to root users, preventing advanced malware from detaching the our eBPF hooks.

* **KASLR Bypass Prevention:** Strict enforcement of `kernel.dmesg_restrict=1` at the LSM layer to stop unprivileged reads of the kernel ring buffer, thereby preventing attackers from scraping kernel pointer addresses.

### Removable Media Neutralizer (`mount_secure`)

Prevents physical USB drops or rogue SD cards from executing binaries or establishing privilege escalation footholds.

* **eBPF Hook:** `lsm/sb_mount`.

* **How it works:** We intercept mount operations and check the block device prefixes (like `/dev/sd*` or `/dev/mmcblk*`) targeting common directories (`/media`, `/mnt`, `/run/m`). When we see a match, we check the `MS_NOEXEC`, `MS_NOSUID`, and `MS_NODEV` flags. This guarantees the media is safe, regardless of what arbitrary filesystem is being used to try and bypass us.

### Strict Write XOR Execute (`strict_wx`)

> [!IMPORTANT]
> This is an OPT-IN module.

This module stops shellcode injection and in-memory staging by enforcing a simple rule: memory pages can never be writable and executable at the same time.

* **eBPF Hooks:** `lsm/file_mprotect`, `lsm/mmap_file`.

* **How it works:** System administrators can tag compiled binaries with the `user.bouclier.strict_wx` extended attribute. The module tracks these via a hardware-backed map. The module then blocks any memory allocations requesting `PROT_WRITE | PROT_EXEC`. It also blocks sequential bypasses, like trying to make a writable page executable after the fact. This strict protection automatically applies to any `.so` shared libraries mapped into the protected binary's memory.

---

## Upcoming Modules

`Bouclier Bleu` is in active development. The following heuristics are planned for near-term releases:

* **Process Injection Prevention (`ptrace_access_check` / `ptrace_traceme`):** Monitoring and restricting `ptrace` capabilities to block cross-process memory tampering, hollow process injection, and credential dumping.

* **Userfaultfd Confinement (`uffd_restrict`)** : Mitigates advanced heap-grooming and Use-After-Free (UAF) exploits. It severely restricts user-space page fault handling by globally denying access to `userfaultfd`, explicitly whitelisting only architecturally necessary processes (like QEMU/KVM).

* **Namespace Escape Monitor (`userns_restrict`)** : Provides a robust layer of defense against container escape vulnerabilities (e.g., Dirty Pipe, runc exploits). By hooking `bpf_lsm_userns_create`, `cap_capable`, and `bpf_lsm_sb_mount`, it instantly neutralizes processes inside restricted namespaces (Docker, Flatpak) that attempt to request `CAP_SYS_ADMIN` or mount the host's `/dev`.

* **Asynchronous I/O Confinement (`uring_restrict`)** : Disarms high-speed ransomware encryption phases. It hooks into `uring_setup` to restrict the instantiation of `io_uring` rings exclusively to a dynamic whitelist of high-performance binaries (e.g., Nginx, PostgreSQL), forcing dropped payloads to use slow, synchronous I/O.
