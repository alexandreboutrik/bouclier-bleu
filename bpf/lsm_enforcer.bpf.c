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

/* The license must be GPL to use BPF LSM hooks */
char LICENSE[] SEC("license") = "GPL";

/* Hook into the binary execution security check */
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm) {
    /* * Print to the kernel trace pipe. 
     * In a real EDR, you would send this to a BPF Ring Buffer instead.
     */
    bpf_printk("Bouclier Bleu: Binary executed!\\n");
    
    /* Return 0 to Allow. (Returning -EPERM would block execution) */
    return 0; 
}
