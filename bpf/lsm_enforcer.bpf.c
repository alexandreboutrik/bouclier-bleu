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

#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* 
 * BPF LSM programs are structurally required to be GPL licensed to interface
 * with the kernel's security subsystem.
 */
char LICENSE[] SEC("license") = "GPL";

/*
 * lsm/bprm_check_security triggers prior to the execution of a new binary.
 * - Returning 0 yields execution authority to the next LSM in the chain.
 * - Returning a negative error code (e.g., -EPERM) vetoes the execution
 * entirely.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm) {
    bpf_printk("Bouclier Bleu: Binary executed!\\n");
    
    return 0; 
}
