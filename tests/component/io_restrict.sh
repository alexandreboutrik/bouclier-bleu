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
: "${TEST_USER:="bb_io_user"}"
: "${TEST_UNAUTH_BIN:="/opt/bb_io_unauthorized"}"
# We use /opt because io_restrict.rs explicitly pre-scans this path at boot.
: "${TEST_AUTH_BIN:="/opt/bb_io_authorized"}"
: "${SIGKILL_EXIT_CODE:=137}" # Standard bash exit code for fatal SIGKILL (128 + 9)

DAEMON_PID=""

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	cleanup_daemon
	rm -f "${TEST_UNAUTH_BIN}" "${TEST_AUTH_BIN}" "${DAEMON_LOG}"
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

	# Compile inline C utility to trigger restricted I/O mechanisms
	local tester_c="/tmp/bb_io_tester.c"
	cat <<'EOF' >"${tester_c}"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/uio.h>

#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;

    /* * 1. Asynchronous I/O Simulation (Ransomware encryption vector)
     * Setup an io_uring instance.
     */
    if (strcmp(argv[1], "uring") == 0) {
        // We only care about the initialization, passing dummy parameters
        long ret = syscall(SYS_io_uring_setup, 10, NULL);
        // If the syscall returns normally (even with an error like EINVAL), 
        // the process wasn't killed by the eBPF hook.
        return 0; 
    }

    /* * 2. Zero-Copy Vmsplice (Dirty Pipe / Dirty Frag payload vector)
     * Map user-space memory directly into a pipe.
     */
    if (strcmp(argv[1], "vmsplice") == 0) {
        int p[2];
        if (pipe(p) < 0) return 1;
        
        char buf[] = "malicious_payload";
        struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
        
        long ret = vmsplice(p[1], &iov, 1, SPLICE_F_NONBLOCK);
        return 0; // Return 0 if not killed
    }

    /* * 3. Zero-Copy Splice (Audited capability)
     * Standard splice operation between two pipes.
     */
    if (strcmp(argv[1], "splice") == 0) {
        int p1[2], p2[2];
        if (pipe(p1) < 0 || pipe(p2) < 0) return 1;
        
        write(p1[1], "data", 4);
        long ret = splice(p1[0], NULL, p2[1], NULL, 4, SPLICE_F_NONBLOCK);
        return 0; 
    }

    return 1;
}
EOF

	cc -o "${TEST_UNAUTH_BIN}" "${tester_c}" || {
		echo "[-] Failed to compile I/O tester."
		exit 1
	}
	rm -f "${tester_c}"

	# Provision the authorized daemon copy
	cp "${TEST_UNAUTH_BIN}" "${TEST_AUTH_BIN}"
	chmod +x "${TEST_UNAUTH_BIN}" "${TEST_AUTH_BIN}"

	echo "  [*] Applying extended attributes (user.bouclier.io_restrict=1) to authorized binary..."
	if command -v setfattr >/dev/null 2>&1; then
		setfattr -n user.bouclier.io_restrict -v 1 "${TEST_AUTH_BIN}" || {
			echo "[-] Failed to set extended attribute. Ensure filesystem supports xattrs."
			exit 1
		}
	else
		echo "[-] 'setfattr' not found. Please install the 'attr' package in the test VM."
		exit 1
	fi
}

function verify_unauthorized_iouring() {
	echo "  [*] Validating Unauthorized io_uring_setup (Expected: KILL)..."

	set +e
	"${TEST_UNAUTH_BIN}" uring >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${SIGKILL_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Unauthorized io_uring_setup bypassed the LSM hook! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Unauthorized io_uring_setup successfully vetoed (SIGKILL)."
}

function verify_authorized_iouring() {
	echo "  [*] Validating Authorized io_uring_setup (Expected: ALLOW)..."

	set +e
	"${TEST_AUTH_BIN}" uring >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq "${SIGKILL_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Authorized high-performance daemon was incorrectly killed!"
		exit 1
	fi

	echo "  [+] Authorized asynchronous I/O cleanly bypassed (Hardware opt-in verified)."
}

function verify_unprivileged_vmsplice() {
	echo "  [*] Validating Unprivileged vmsplice Confinement (Expected: KILL)..."

	set +e
	su - "${TEST_USER}" -c "${TEST_UNAUTH_BIN} vmsplice" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${SIGKILL_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Unprivileged vmsplice tampering bypassed the LSM hook! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Unprivileged vmsplice memory tampering successfully vetoed (SIGKILL)."
}

function verify_privileged_vmsplice() {
	echo "  [*] Validating Privileged vmsplice Access (Expected: ALLOW)..."

	set +e
	# Run as root directly
	"${TEST_UNAUTH_BIN}" vmsplice >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq "${SIGKILL_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Legitimate root vmsplice was incorrectly blocked!"
		exit 1
	fi

	echo "  [+] Privileged vmsplice access cleanly bypassed."
}

function verify_unprivileged_splice() {
	echo "  [*] Validating Unprivileged splice Auditing (Expected: TELEMETRY ONLY)..."

	local baseline
	baseline=$(wc -l <"${DAEMON_LOG}" 2>/dev/null || echo 0)

	set +e
	su - "${TEST_USER}" -c "${TEST_UNAUTH_BIN} splice" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq "${SIGKILL_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Unprivileged splice was incorrectly killed instead of audited!"
		exit 1
	fi

	# Verify telemetry was dispatched
	local passed=0
	for _ in {1..20}; do
		if tail -n +$((baseline + 1)) "${DAEMON_LOG}" 2>/dev/null | grep -q "Bouclier Bleu \[BLOCK\]" && tail -n +$((baseline + 1)) "${DAEMON_LOG}" 2>/dev/null | grep -q "ZERO_COPY_SPLICE"; then
			passed=1
			break
		fi
		sleep 0.2
	done

	if [[ "${passed}" -eq 0 ]]; then
		echo "[-] Assertion failed: EDR failed to audit/log the unprivileged splice syscall!"
		exit 1
	fi

	echo "  [+] Unprivileged splice successfully audited via Telemetry."
}

function verify_ipc_detachment() {
	echo "  [*] Validating dynamic LSM hook detachment..."

	"${BB_CLI_BIN}" disable io_restrict >/dev/null || {
		echo "[-] RPC invocation failed."
		exit 1
	}

	set +e
	# Attempt an unauthorized io_uring operation, which should now pass
	"${TEST_UNAUTH_BIN}" uring >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq "${SIGKILL_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Disabled module still killed the process on io_uring_setup."
		exit 1
	fi

	echo "  [+] Hook cleanly detached. I/O confinement bypassed."
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_env
initialize_daemon "io_restrict"

verify_unauthorized_iouring
verify_authorized_iouring
verify_unprivileged_vmsplice
verify_privileged_vmsplice
verify_unprivileged_splice
verify_ipc_detachment

echo "  [+] Module 'io_restrict' validation passed."
