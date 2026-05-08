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
: "${TEST_USER:="bb_dump_user"}"
: "${DUMP_TESTER:="/opt/bb_dump_tester"}"
: "${TEST_WORK_DIR:="/opt/bb_dump_workspace"}"
: "${EPERM_EXIT_CODE:=126}"

DAEMON_PID=""
ORIGINAL_CORE_PATTERN=""

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	cleanup_daemon

	# Restore the original core dump pattern if it was captured
	if [[ -n "${ORIGINAL_CORE_PATTERN}" ]]; then
		sysctl -w kernel.core_pattern="${ORIGINAL_CORE_PATTERN}" >/dev/null 2>&1 || true
	fi
	if [[ -n "${ORIGINAL_CORE_USES_PID}" ]]; then
		sysctl -w kernel.core_uses_pid="${ORIGINAL_CORE_USES_PID}" >/dev/null 2>&1 || true
	fi

	rm -rf "${DUMP_TESTER}" "${TEST_WORK_DIR}" "${DAEMON_LOG}"
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

	mkdir -p "${TEST_WORK_DIR}"
	chmod 777 "${TEST_WORK_DIR}"

	# Capture existing core_pattern to restore later
	ORIGINAL_CORE_PATTERN=$(sysctl -n kernel.core_pattern)
	ORIGINAL_CORE_USES_PID=$(sysctl -n kernel.core_uses_pid 2>/dev/null || echo "1")

	# Force the kernel to write core dumps locally with a strict name
	# Bypassing piped handlers AND disabling PID appending
	sysctl -w kernel.core_pattern="core" >/dev/null 2>&1 || {
		echo "[-] Failed to set kernel.core_pattern for testing."
		exit 1
	}
	sysctl -w kernel.core_uses_pid=0 >/dev/null 2>&1 || true

	# Compile inline C utility to invoke prctl() and intentionally crash
	local tester_c="${DUMP_TESTER}.c"
	cat <<'EOF' >"${tester_c}"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    
    if (strcmp(argv[1], "prctl") == 0) {
        // Attempt to set the process as dumpable
        int ret = prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
        if (ret < 0 && errno == EPERM) return 126; // LSM Blocked
        if (ret < 0) return 1; // Standard error
        return 0; // LSM Allowed
    }
    
    if (strcmp(argv[1], "crash") == 0) {
        // Intentional null pointer dereference to trigger SIGSEGV
        // and force the kernel to invoke do_coredump()
        int *p = NULL;
        *p = 0xDEADBEEF;
        return 0;
    }
    
    return 1;
}
EOF

	cc -o "${DUMP_TESTER}" "${tester_c}" || {
		echo "[-] Failed to compile raw dump tester."
		exit 1
	}
	rm -f "${tester_c}"
}

function verify_unprivileged_prctl() {
	echo "  [*] Validating Unprivileged PR_SET_DUMPABLE Tampering (Expected: BLOCK)..."

	set +e
	su - "${TEST_USER}" -c "${DUMP_TESTER} prctl" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Unprivileged prctl(PR_SET_DUMPABLE) was not blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Unprivileged state tampering successfully vetoed (-EPERM)."
}

function verify_root_prctl() {
	echo "  [*] Validating Root PR_SET_DUMPABLE (Expected: ALLOW)..."

	set +e
	"${DUMP_TESTER}" prctl >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Root prctl(PR_SET_DUMPABLE) was incorrectly blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Root administrative state tampering correctly allowed."
}

function verify_unprivileged_crash() {
	echo "  [*] Validating Unprivileged Core Dump Generation (Expected: BLOCK)..."

	# Clear any old cores
	rm -f "${TEST_WORK_DIR}/core"

	set +e
	# Enable core dumps (ulimit -c unlimited) for the test user and trigger the crash
	su - "${TEST_USER}" -c "cd ${TEST_WORK_DIR} && ulimit -c unlimited && ${DUMP_TESTER} crash" >/dev/null 2>&1
	local exit_code=$?
	set -e

	# A segmentation fault typically yields exit code 139 (128 + 11)
	if [[ "${exit_code}" -ne 139 ]]; then
		echo "[-] Assertion failed: Crash binary did not terminate with SIGSEGV as expected."
		exit 1
	fi

	if [[ -s "${TEST_WORK_DIR}/core" ]]; then
		echo "[-] Assertion failed: Core dump file was successfully written for an unprivileged user! (ASLR Leak)"
		exit 1
	fi

	echo "  [+] Unprivileged core dump creation cleanly intercepted and blocked."
}

function verify_root_crash() {
	echo "  [*] Validating Root Core Dump Generation (Expected: ALLOW)..."

	rm -f "${TEST_WORK_DIR}/core"

	set +e
	# Trigger the crash as root
	bash -c "cd ${TEST_WORK_DIR} && ulimit -c unlimited && ${DUMP_TESTER} crash" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 139 ]]; then
		echo "[-] Assertion failed: Crash binary did not terminate with SIGSEGV as expected."
		exit 1
	fi

	if [[ ! -s "${TEST_WORK_DIR}/core" ]]; then
		echo "[-] Assertion failed: Core dump file was NOT written for root. Fast-path deferral failed."
		exit 1
	fi

	echo "  [+] Root core dump creation cleanly bypassed by fast-path."
}

function verify_ipc_detachment() {
	echo "  [*] Validating dynamic LSM hook detachment..."

	"${BB_CLI_BIN}" disable dump_restrict >/dev/null || {
		echo "[-] RPC invocation failed."
		exit 1
	}

	set +e
	su - "${TEST_USER}" -c "${DUMP_TESTER} prctl" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Disabled module still blocked prctl() operations."
		exit 1
	fi

	echo "  [+] Hook cleanly detached. Unprivileged state tampering allowed."
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_env
initialize_daemon "dump_restrict"

verify_unprivileged_prctl
verify_root_prctl
verify_unprivileged_crash
verify_root_crash
verify_ipc_detachment

echo "  [+] Module 'dump_restrict' validation passed."
