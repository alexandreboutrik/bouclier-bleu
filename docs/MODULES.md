# Bouclier Bleu : Current Modules (Features)

`Bouclier Bleu` is built on a modular architecture. Each module operates across the user-kernel boundary, utilizing Linux Security Module (LSM) hooks in kernel-space to enforce policies and a decoupled Rust user-space daemon to orchestrate configuration and ingest telemetry.

> [!NOTE]
> Attackers often try to bypass mechanisms using tricks like mount namespace spoofing (`unshare -m`) or symlink manipulation. To counter this, our core modules ignore easily spoofed file paths and instead rely on hard hardware IDs (like the physical Inode and Superblock Device IDs).

## Core Metrics, Memory Footprint & Performance

Security shouldn't bottleneck your system. We designed Bouclier Bleu to be as lightweight and performant as possible. Depending on the module and how often a syscall is triggered, the interception overhead typically adds 3ms to 8ms (tested on a Dell Rugged 5424: i5-8350u, NVMe SSD).

`Bouclier Bleu` currently operates across **33 eBPF hooks**, driving **10 active security detectors** (modules) that map directly to **19 MITRE ATT&CK techniques**. Its stability and regression prevention are guaranteed by a suite of **91 automated tests**, encompassing 19 unit, 65 component, 3 integration, and 4 benchmark validation pipelines.

### Memory Footprint

The system maintains a highly optimized memory footprint totaling approximately **21,237 kB (~21 MB)** during active enforcement:

- Userland Engine: 14,700 kB
- eBPF Maps (Kernel Memory): 6,537 kB (total)
    - rename_entropy: 1,554 kB
    - io_restrict: 1,096 kB
    - exec_block: 1,006 kB
    - madvise_ratelimit: 974 kB
    - strict_wx: 447 kB
    - shield: 304 kB
    - mount_secure: 301 kB
    - ptrace_block: 293 kB
    - dump_restrict: 287 kB
    - userns_restrict: 270 kB

---

## I. Core System Self-Defense

Tamper-protection mechanisms designed to ensure the integrity of the Bouclier Bleu architecture and the host kernel.

### Self-Defense Shield (`shield`)

This module hardens the endpoint detection agent against tampering, unprivileged unloading, and privilege escalation attacks utilizing BPF hooks at `lsm/file_open`, `lsm/bpf`, and `lsm/syslog`.

To guarantee configuration immutability, the module enforces a strict `O_RDONLY` policy on core operational files (such as `config.toml`) for all unprivileged users, acting as a fail-safe against reckless administrative permissions (`chmod 777`). Furthermore, it locks the system's architecture by restricting the `bpf()` syscall to root users, preventing advanced malware from detaching eBPF hooks. Finally, it prevents KASLR (Kernel Address Space Layout Randomization) bypasses by enforcing `kernel.dmesg_restrict=1` natively at the LSM layer, stopping unprivileged threat actors from scraping kernel pointer addresses from the syslog ring buffer.

## II. Ransomware & Filesystem Integrity

Heuristics designed to detect and intercept unauthorized mass-encryption events and destructive filesystem operations.

### Ransomware Entropy Monitor (`rename_entropy`)

Operating primarily on the `lsm/path_rename hook`, this module detects and neutralizes ransomware encryption phases in real-time by evaluating the structural randomness of file modifications.

When a file is renamed (e.g., an attacker appending a `.locked` extension), the engine calculates the newly generated filename's Shannon entropy. Because the kernel's eBPF verifier lacks native floating-point mathematics, we utilize a highly optimized, pre-computed `scaled_log2` lookup table, allowing O(1) integer-based execution. If the randomness exceeds the defined threshold (a scaled value > 4300), the BPF program immediately fires a `SIGKILL` (signal 9) directly from kernel-space. This instantly terminates the malicious thread before it can return to user-space, eliminating race conditions. The module also features a cascading watchlist by hooking `vfs_mkdir` and `vfs_rename`; if a threat actor builds a payload in an unmonitored directory like `/tmp` and moves it to a protected space, the kernel automatically inherits and indexes those new child inodes.

## III. Memory Corruption & Exploit Mitigation

Defense-in-depth mechanisms neutralizing buffer overflows, ROP chain staging, and unauthorized memory manipulations.

### Strict Write XOR Execute (`strict_wx`)

> [!IMPORTANT]
> This is an OPT-IN module configured via extended attributes.

This module stops shellcode injection and in-memory staging by enforcing a strict policy: memory pages can never be simultaneously writable and executable. Operating on `lsm/file_mprotect` and `lsm/mmap_file`, administrators can tag compiled binaries with the `user.bouclier.strict_wx` extended attribute, which the module indexes via a hardware-backed map. The engine then intercepts memory allocations, blocking any requests for `PROT_WRITE | PROT_EXEC` as well as sequential bypass attempts (e.g., attempting to make a writable page executable after initial allocation). This protection automatically extends to any .so shared libraries mapped into the protected binary's memory space.

### Process Injection & Credential Dumping Prevention (`ptrace_block`)

This module hardens the Linux `ptrace` and memory manipulation boundary using the `lsm/ptrace_access_check`, `lsm/ptrace_traceme` and `lsm/file_open` hooks.

To prevent credential dumping, it establishes an immutable, hardware-backed ring-fence around critical authentication daemons (e.g., `sshd`, `sudo`, `gnome-keyring-daemon`), instantly blocking unauthorized memory reads (`PTRACE_MODE_READ`).

To mitigate process injection, it evaluates the true global UID (`get_global_uid()`), bypassing container namespace mappings where a local process might falsely appear as root, universally blocking unprivileged cross-process attachments.

Additionally, it prevents hollow process injection by isolating `PTRACE_TRACEME` requests, denying unprivileged parent processes the ability to authorize trace actions on their children to stage dynamic shellcode.

Finally, it neutralizes VFS-based memory tampering by strictly blocking unprivileged writes to `/proc/*/mem`, effectively stopping advanced privilege escalation exploits and stealth injectors that bypass traditional hooks.

### Unprivileged Dump Restriction (`dump_restrict`)

Hardens the system against advanced memory corruption exploits. Attackers routinely crash worker threads intentionally to force the kernel to write a core dump, leaking memory layouts to bypass ASLR or exposing plaintext credentials left in memory. This module deploys a multi-layered defense utilizing `lsm/file_open`, `lsm/task_prctl`, `kprobe/call_usermodehelper_setup`, and `lsm/bprm_check_security`.

When a standard crash occurs, the kernel elevates the thread's flags to include `PF_DUMPCORE`. By intercepting file_open, the module cleanly blocks the creation of physical core files on disk for unprivileged processes. It also prevents state tampering by intercepting `prctl()` to deny unprivileged processes from re-enabling `PR_SET_DUMPABLE`.

Crucially, it utilizes a temporal Two-Hook Architecture to intercept piped core dumps routed to user-mode helpers (e.g., `systemd-coredump`), which otherwise obscure the attacker's identity via asynchronous root `kworker` threads:

- Observer Phase (`kprobe/call_usermodehelper_setup`): Intercepts the helper preparation API within the crashing thread's context, extracting the pristine, unprivileged UID/PID and securely stashing it into an atomic eBPF map "lockbox".

- Enforcement Phase (`lsm/bprm_check_security`): Evaluates the root `kworker` as it attempts to execute the core handler binary. It validates the handler's physical hardware footprint to prevent spoofing and cross-references the temporal lockbox. If the crash originated from an unprivileged user, it safely intercepts the execution (`-EPERM`), short-circuiting the pipeline while natively allowing legitimate administrative root crashes.

### Memory Advisory Race Condition Mitigator (`madvise_ratelimit`)

Operating on the `tracepoint/syscalls/sys_enter_madvise` hook, this module neutralizes Use-After-Free and Copy-on-Write race conditions (e.g., Dirty Cow) by intercepting abnormal memory advisory spam. To prevent adversaries from evading detection via "Process Sharding" - where an exploit's syscalls are divided across dozens of discrete, short-lived processes—the engine tracks the frequency of `MADV_DONTNEED` syscalls on a strict Global UID basis. It aggregates these calls across the user's entire session and utilizes 64-bit atomic operations (`BPF_XADD`) directly on the map pointers to safely handle multi-thread race conditions with minimal overhead.

When a thread aggressively exceeds a statistical threshold of invocations within a single-second rolling window, the engine identifies the heap-grooming attempt and instantly dispatches a `SIGKILL` directly from kernel-space. This terminates the malicious thread the exact microsecond it exits the syscall context, breaking the exploit cycle before the attacker can successfully win the race condition.

## IV. Execution Control & Attack Surface Reduction

Policies restricting initial access vectors, dropper execution, and payload staging.

### Untrusted Path Execution Prevention (`exec_block`)

Utilizing the `lsm/bprm_check_security` hook, this module neutralizes memory corruption exploits and web-shell droppers attempting to execute secondary payloads out of historically insecure, world-writable directories (e.g., `/tmp`, `/dev/shm`). Validation is performed strictly against underlying dentry cache hardware IDs to bypass namespace manipulation. Furthermore, it combats fileless malware by detecting memory-backed payloads (`memfd_create`) or nameless temporary files (`O_TMPFILE`) possessing a VFS link count (`i_nlink`) of zero. If a fileless execution attempt is detected, the engine demands that the memory segment be completely immutable (`F_SEAL_WRITE`), blocking the execution if the segment remains unsealed.

### Removable Media Neutralizer (`mount_secure`)

Prevents physical USB drops or rogue SD cards from executing binaries or establishing privilege escalation footholds. By intercepting both `lsm/sb_mount` (legacy) and `lsm/move_mount` (modern util-linux APIs) operations, the module inspects block device prefixes (such as `/dev/sd*` or `/dev/mmcblk*`) targeting common mount directories. Upon a match, it dynamically enforces the `MS_NOEXEC`, `MS_NOSUID`, and `MS_NODEV` flags, guaranteeing the removable media remains inert regardless of the arbitrary filesystem format utilized by an attacker.

### I/O Confinement Monitor (`io_restrict`)

> [!WARNING]  
> This module operates in a **strict default-deny posture** for asynchronous I/O. To prevent legitimate high-performance daemons from being terminated upon initializing an `io_uring` context, administrators must explicitly authorize compiled binaries by applying the `user.bouclier.io_restrict=1` extended attribute prior to enabling the module.

Hardens the kernel's advanced I/O pathways against exploitation by intercepting `io_uring_setup`, `vmsplice`, `splice`, and `write`/`close` syscalls. To disarm high-speed ransomware encryption phases, the engine enforces an aggressive default-deny posture on asynchronous I/O. It restricts the instantiation of `io_uring` rings exclusively to explicitly authorized high-performance binaries mapped via a hardware-backed extended attribute whitelist. This effectively strips dropped ransomware payloads of the ability to maximize storage throughput, forcing them to utilize slow and easily intercepted synchronous I/O.

Furthermore, the module neutralizes zero-copy memory corruption exploits by securing pipeline buffers and reducing the attack surface. Because `vmsplice` maps user pages directly into a pipe and is virtually never used by standard unprivileged applications, the engine applies strict confinement and completely blocks unprivileged invocations. For standard `splice` operations utilized by legitimate command-line utilities, the engine denies unprivileged access to advanced memory-gifting flags like `SPLICE_F_GIFT` and `SPLICE_F_MOVE` designed to manipulate the kernel's memory management unit.

To definitively neutralize zero-copy vulnerability chains, the engine enforces information flow tracking via a Tainted Pipeline invariant. By dynamically tracking the hardware addresses of pipes in an LRU hash map, the module detects when data flows from a read-only file into a pipe buffer and immediately marks that pipe as tainted. To break the exploitation laundry machine mechanism, any subsequent unprivileged attempts to mix malicious data into this tainted pipe, whether via additional `splice` operations or standard `write` calls, are immediately neutralized with a fatal signal. Standard unprivileged I/O that does not trigger these heuristics is safely permitted and audited via the telemetry pipeline.

## V. Privilege Escalation & Container Security

Safeguards against nested namespace abuse and host-level boundary violations.

### Namespace Escape Monitor (`userns_restrict`)

Provides a robust layer of defense against container escape vulnerabilities (e.g., Dirty Pipe, runc exploits) by monitoring `lsm/userns_create`, `lsm/capable`, and `lsm/sb_mount`.

Because attackers frequently exploit unprivileged user namespaces as a staging ground for kernel vulnerabilities, the module evaluates both the effective global UID and process ancestry to block `unshare(CLONE_NEWUSER)` for all unprivileged tasks. 

To defeat advanced evasion techniques where an attacker uses SUID binaries (like `su` or `bwrap`) as proxies or double-forks to reparent a malicious process to PID 1, the engine evaluates the immutable Audit Login UID (`loginuid`) and immediate parent credentials. This blocks adversaries from spoofing administrative origins, while natively permitting legitimate automated system daemons (like Docker or containerd) to provision infrastructure.

If an attacker compromises a legitimate nested container (like Docker or Flatpak), the module prevents them from acquiring host-level privileges by evaluating the user namespace depth and strictly denying `CAP_SYS_ADMIN` requests originating from sandboxes. It also mitigates host `/dev` mounts by denying nested processes from mapping physical block devices or establishing `devtmpfs` environments, neutralizing direct host tampering.

---

## Upcoming Modules

`Bouclier Bleu` is in active development. The following heuristics are planned for near-term releases:

* **Userfaultfd Confinement (`uffd_restrict`)** : Mitigates advanced heap-grooming and Use-After-Free (UAF) exploits. It severely restricts user-space page fault handling by globally denying access to `userfaultfd`, explicitly whitelisting only architecturally necessary processes (like QEMU/KVM).
