#!/usr/bin/env bash

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

	# Compile inline C utility to simulate legitimate memory operations,
	# standard race conditions, and process sharding evasion.
	local tester_c="${MADVISE_TESTER}.c"
	cat <<'EOF' >"${tester_c}"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

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
        // Spamming MADV_DONTNEED in a tight loop.
        for (int i = 0; i < 500000; i++) {
            madvise(mem, page_size, MADV_DONTNEED);
        }
        return 0; 
    }

	if (strcmp(argv[1], "window_reset") == 0) {
        /*
         * Temporal Reset Simulation
         * Execute 6,000 calls (below the 10,000 threshold), wait for the
         * 1-second rolling window to expire, and execute 6,000 more.
         */
        for (int i = 0; i < 6000; i++) {
            madvise(mem, page_size, MADV_DONTNEED);
        }
        
        sleep(2); // Wait for the eBPF temporal window to expire
        
        for (int i = 0; i < 6000; i++) {
            madvise(mem, page_size, MADV_DONTNEED);
        }
        return 0; // Should not be killed
    }

    if (strcmp(argv[1], "shard") == 0) {
        /*
         * Process Sharding Bypass Simulation
         * Spawn 10 concurrent processes executing 2,000 loops each.
         * Individually (2k) they are well below the 10k threshold.
         * Collectively (20k) they cross the Global UID threshold.
         */
        int num_shards = 10;
        int calls_per_shard = 2000;

        for (int i = 0; i < num_shards; i++) {
            pid_t pid = fork();
            if (pid == 0) { // Child Process
                for (int j = 0; j < calls_per_shard; j++) {
                    madvise(mem, page_size, MADV_DONTNEED);
                }
                exit(0); 
            }
        }
        
        int status;
        int killed_count = 0;
        while (wait(&status) > 0) {
            // Check if child was neutralized by SIGKILL (signal 9)
            if (WIFSIGNALED(status) && WTERMSIG(status) == 9) {
                killed_count++;
            }
        }
        
        // If Global UID tracking works, shards should have been killed
        return (killed_count > 0) ? 137 : 0;
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
		echo "[-] Assertion failed: Benign madvise usage was incorrectly blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Benign memory operations successfully allowed."
}

function verify_alternate_flag() {
	echo "  [*] Validating eBPF Fast-Path Deferral (MADV_NORMAL) (Expected: ALLOW)..."

	set +e
	su - "${TEST_USER}" -c "${MADVISE_TESTER} alternate_flag" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Non-target flags triggered the heuristic! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Non-destructive memory flags cleanly bypassed."
}

function verify_exploit_simulation() {
	echo "  [*] Validating Dirty Cow / Race Condition Mitigation (Expected: KILL)..."

	set +e
	su - "${TEST_USER}" -c "${MADVISE_TESTER} exploit" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${SIGKILL_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Expected fatal SIGKILL (${SIGKILL_EXIT_CODE}), but got ${exit_code}."
		exit 1
	fi

	echo "  [+] Exploit tight-loop successfully neutralized (SIGKILL)."
}

function verify_shard_simulation() {
	echo "  [*] Validating Process Sharding Mitigation (Expected: KILL)..."

	set +e
	su - "${TEST_USER}" -c "${MADVISE_TESTER} shard" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${SIGKILL_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Process sharding evaded the rate-limiter! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Process sharding successfully neutralized via Global UID tracking."
}

function verify_temporal_window_reset() {
	echo "  [*] Validating Temporal Rolling Window Reset (Expected: ALLOW)..."

	# Wait for the eBPF 1-second rolling window to expire from the previous
	# tests. Otherwise, residual counts from the multi-threaded 'shard' test
	# will cause the first 6,000 calls to immediately cross the 10,000
	# threshold and fail.
	sleep 2

	set +e
	su - "${TEST_USER}" -c "${MADVISE_TESTER} window_reset" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq "${SIGKILL_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Process was killed despite obeying the temporal window!"
		exit 1
	fi

	echo "  [+] Temporal window successfully reset state. Execution allowed."
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
verify_shard_simulation
verify_temporal_window_reset
verify_ipc_detachment

echo "  [+] Module 'madvise_ratelimit' validation passed."
