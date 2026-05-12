// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2026 The Bouclier Bleu Authors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __BPF_FALLBACKS_H
#define __BPF_FALLBACKS_H

/*
 * File Status & Access Flags
 */
#ifndef O_ACCMODE
#define O_ACCMODE 00000003
#endif
#ifndef O_RDONLY
#define O_RDONLY 00000000
#endif
#ifndef O_WRONLY
#define O_WRONLY 00000001
#endif
#ifndef O_RDWR
#define O_RDWR 00000002
#endif
#ifndef O_TRUNC
#define O_TRUNC 00001000
#endif

#ifndef FMODE_READ
#define FMODE_READ ((fmode_t)0x1)
#endif
#ifndef FMODE_WRITE
#define FMODE_WRITE ((fmode_t)0x2)
#endif

/*
 * VFS Inode Types & Macros
 */
#ifndef S_IFMT
#define S_IFMT 00170000
#endif
#ifndef S_IFIFO
#define S_IFIFO 00010000
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif

#ifndef S_ISFIFO
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#endif
#ifndef S_ISREG
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

/*
 * Splice / Zero-Copy Flags
 */
#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE 1
#endif
#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK 2
#endif
#ifndef SPLICE_F_MORE
#define SPLICE_F_MORE 4
#endif
#ifndef SPLICE_F_GIFT
#define SPLICE_F_GIFT 8
#endif

/*
 * Process & Memory Management
 */
#ifndef PTRACE_MODE_READ
#define PTRACE_MODE_READ 0x01
#endif
#ifndef PTRACE_MODE_ATTACH
#define PTRACE_MODE_ATTACH 0x02
#endif

#ifndef MADV_DONTNEED
#define MADV_DONTNEED 4
#endif

#ifndef PF_DUMPCORE
#define PF_DUMPCORE 0x00000200
#endif
#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif

#ifndef VM_WRITE
#define VM_WRITE 0x00000002
#endif
#ifndef VM_EXEC
#define VM_EXEC 0x00000004
#endif

/*
 * Filesystem & Mount Flags
 */
#ifndef MNT_NOSUID
#define MNT_NOSUID 0x01
#endif
#ifndef MNT_NODEV
#define MNT_NODEV 0x02
#endif
#ifndef MNT_NOEXEC
#define MNT_NOEXEC 0x04
#endif

#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x008
#endif

#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC 0x9fa0
#endif

/*
 * Capabilities & System Errors
 */
#ifndef CAP_SYS_ADMIN
#define CAP_SYS_ADMIN 21
#endif

#ifndef ENOSYS
#define ENOSYS 38
#endif

#endif /* __BPF_FALLBACKS_H */
