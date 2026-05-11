i#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 The Bouclier Bleu Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -uo pipefail

# Source the common utilities dynamically relative to the current script
source "$(dirname "${BASH_SOURCE[0]}")/common/common.sh"

# ==========================================
# CONFIGURATION
# ==========================================
: "${TEST_USER:="bb_madvise_user"}"
: "${MADVISE_TESTER:="/opt/bb_madvise_tester"}"
: "${SIGKILL_EXIT_CODE:=137}" # Standard bash exit code for fatal SIGKILL (128 + 9)

DAEMON_PID=""

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	cleanup_daemon
	rm -f "${MADVISE_TESTER}" "${DAEMON_LOG}"
	userdel -r "${TEST_USER}" 2>/dev/null || true
}

trap teardown EXIT

function provision_env() {
	echo "  [*] Provisioning Test Environment..."

	# Create unprivileged test user
	useradd -m -s /bin/bash "${TEST_USER}" || {
		echo "[-] Failed to create unprivileged test user."
		exit 1
	}

	# Compile inline C utility to simulate legitimate memory operations and
	# race condition exploits (tight loops).
	local tester_c="${MADVISE_TESTER}.c"
	cat <<'EOF' >"${tester_c}"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;

    // Allocate a single dummy page to apply memory advisories against
    size_t page_size = getpagesize();
    void *mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return 1;

    if (strcmp(argv[1], "benign") == 0) {
        // Legitimate behavior: an allocator releasing a few pages back to the OS
        for (int i = 0; i < 1500; i++) {
            madvise(mem, page_size, MADV_DONTNEED);
        }
        return 0; // LSM Allowed
    }

    if (strcmp(argv[1], "alternate_flag") == 0) {
        // Fast-path Deferral Test: Heavy usage of a different flag
        // MADV_NORMAL (0) should be ignored entirely by the eBPF hook
        for (int i = 0; i < 100000; i++) {
            madvise(mem, page_size, MADV_NORMAL);
        }
        return 0; 
    }

    if (strcmp(argv[1], "exploit") == 0) {
        // Dirty Cow / UAF Simulation: 
        // Spamming MADV_DONTNEED millions of times in a tight loop to force a 
        // race condition. The eBPF program should intercept and issue SIGKILL
        // long before this loop naturally terminates.
        for (int i = 0; i < 500000; i++) {
            madvise(mem, page_size, MADV_DONTNEED);
        }
        
        // If we reach here, the kernel failed to kill us!
        return 0; 
    }

    return 1;
}
EOF

	cc -o "${MADVISE_TESTER}" "${tester_c}" || {
		echo "[-] Failed to compile madvise tester."
		exit 1
	}
	rm -f "${tester_c}"
}

function verify_benign_madvise() {
	echo "  [*] Validating Legitimate Memory Allocation Patterns (Expected: ALLOW)..."

	set +e
	su - "${TEST_USER}" -c "${MADVISE_TESTER} benign" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Benign madvise usage was incorrectly blocked or killed! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Benign memory operations successfully allowed (Zero False Positives)."
}

function verify_alternate_flag() {
	echo "  [*] Validating eBPF Fast-Path Deferral (MADV_NORMAL) (Expected: ALLOW)..."

	set +e
	su - "${TEST_USER}" -c "${MADVISE_TESTER} alternate_flag" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: High frequency of non-target flags triggered the heuristic! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Non-destructive memory flags cleanly bypassed via BPF fast-path."
}

function verify_exploit_simulation() {
	echo "  [*] Validating Dirty Cow / Race Condition Mitigation (Expected: KILL)..."

	set +e
	su - "${TEST_USER}" -c "${MADVISE_TESTER} exploit" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq 0 ]]; then
		echo "[-] Assertion failed: Exploit simulation successfully executed all loop iterations. Race condition unmitigated!"
		exit 1
	fi

	# bpf_send_signal(9) queues a SIGKILL. The bash execution wrapper should
	# report exit code 137.
	if [[ "${exit_code}" -ne "${SIGKILL_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Expected fatal SIGKILL (${SIGKILL_EXIT_CODE}), but process exited with ${exit_code}."
		exit 1
	fi

	echo "  [+] Exploit tight-loop successfully intercepted and neutralized (SIGKILL)."
}

function verify_ipc_detachment() {
	echo "  [*] Validating dynamic LSM hook detachment..."

	"${BB_CLI_BIN}" disable madvise_ratelimit >/dev/null || {
		echo "[-] RPC invocation failed."
		exit 1
	}

	set +e
	su - "${TEST_USER}" -c "${MADVISE_TESTER} exploit" >/dev/null 2>&1
	local exit_code=$?
	set -e

	# Since the module is disabled, the massive loop should complete naturally
	# and return exit code 0.
	if [[ "${exit_code}" -eq "${SIGKILL_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Disabled module still killed the process."
		exit 1
	fi

	echo "  [+] Hook cleanly detached. Syscall rate-limiting bypassed."
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_env
initialize_daemon "madvise_ratelimit"

verify_benign_madvise
verify_alternate_flag
verify_exploit_simulation
verify_ipc_detachment

echo "  [+] Module 'madvise_ratelimit' validation passed."
