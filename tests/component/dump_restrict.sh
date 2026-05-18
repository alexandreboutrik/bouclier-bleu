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
ORIGINAL_CORE_USES_PID=""

# Dummy piped handler paths
DUMMY_HANDLER="/opt/bb_dummy_handler.sh"
HANDLER_LOG="/tmp/handler_called.log"

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
	rm -f "${DUMMY_HANDLER}" "${HANDLER_LOG}"
	rm -f /var/run/bouclier-bleu/control.sock # Ensure socket is cleaned up
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

	# Create a dummy piped handler
	cat <<'EOF' >"${DUMMY_HANDLER}"
#!/usr/bin/env bash
# Simply touch a file to prove execution occurred
echo "executed" > "/tmp/handler_called.log"
EOF
	chmod +x "${DUMMY_HANDLER}"

	# Capture existing core_pattern to restore later
	ORIGINAL_CORE_PATTERN=$(sysctl -n kernel.core_pattern)
	ORIGINAL_CORE_USES_PID=$(sysctl -n kernel.core_uses_pid 2>/dev/null || echo "1")

	# CRITICAL PRE-LOAD: Set the piped pattern BEFORE starting the daemon
	# This guarantees the Rust `init()` closure naturally discovers the handler
	# and populates the eBPF hardware map, avoiding mid-test daemon restarts.
	sysctl -w kernel.core_pattern="|${DUMMY_HANDLER}" >/dev/null 2>&1 || {
		echo "[-] Failed to set piped kernel.core_pattern."
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

	if (strcmp(argv[1], "prctl_disable") == 0) {
        // Attempt to benignly disable core dumping (arg2 == 0)
        int ret = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        if (ret < 0) return 1; // System error
        return 0; // Allowed by LSM
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

	# Dynamically switch back to a standard file-based core dump
	sysctl -w kernel.core_pattern="core" >/dev/null 2>&1
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

	# Ensure we are testing file-based dumps
	sysctl -w kernel.core_pattern="core" >/dev/null 2>&1
	rm -f "${TEST_WORK_DIR}/core"

	set +e
	# Trigger the crash inside a subshell to suppress bash's "Segmentation fault" std_err leak
	(
		cd "${TEST_WORK_DIR}" || exit 1
		ulimit -c unlimited
		"${DUMP_TESTER}" crash
	) >/dev/null 2>&1
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

function verify_unprivileged_piped_crash() {
	echo "  [*] Validating Unprivileged Piped Core Dump (Expected: BLOCK)..."

	# Switch the kernel back to piped mode. Because the handler was already indexed
	# by the daemon at boot, we do not need to restart the daemon.
	sysctl -w kernel.core_pattern="|${DUMMY_HANDLER}" >/dev/null 2>&1
	rm -f "${HANDLER_LOG}"

	set +e
	su - "${TEST_USER}" -c "cd ${TEST_WORK_DIR} && ulimit -c unlimited && ${DUMP_TESTER} crash" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 139 ]]; then
		echo "[-] Assertion failed: Crash binary did not terminate with SIGSEGV as expected."
		exit 1
	fi

	# The dual-hook state tracking architecture successfully extracts the context
	# via the kprobe and issues an -EPERM block via bprm_check_security.
	if [[ -f "${HANDLER_LOG}" ]]; then
		echo "[-] Assertion failed: Piped handler was executed for an unprivileged user! (Bypass detected)"
		exit 1
	fi

	echo "  [+] Unprivileged piped core dump cleanly short-circuited (-EPERM)."
}

function verify_root_piped_crash() {
	echo "  [*] Validating Root Piped Core Dump (Expected: ALLOW)..."

	sysctl -w kernel.core_pattern="|${DUMMY_HANDLER}" >/dev/null 2>&1
	rm -f "${HANDLER_LOG}"

	set +e
	# Suppress segfault text by running in a subshell
	(
		cd "${TEST_WORK_DIR}" || exit 1
		ulimit -c unlimited
		"${DUMP_TESTER}" crash
	) >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 139 ]]; then
		echo "[-] Assertion failed: Crash binary did not terminate with SIGSEGV as expected."
		exit 1
	fi

	sleep 0.5

	# Because we deployed the State-Tracking Architecture (kprobe + bprm_check_security),
	# the eBPF hook knows this crash originated from root and should allow it natively.
	if [[ ! -f "${HANDLER_LOG}" ]]; then
		echo "[-] Assertion failed: Piped handler was NOT executed for root. Dual-hook correlation failed."
		exit 1
	fi

	echo "  [+] Root piped core dump successfully dispatched."
}

function verify_benign_prctl() {
	echo "  [*] Validating Benign PR_SET_DUMPABLE Disabling (Expected: ALLOW)..."

	set +e
	su - "${TEST_USER}" -c "${DUMP_TESTER} prctl_disable" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Benign disabling of PR_SET_DUMPABLE was incorrectly blocked!"
		exit 1
	fi

	echo "  [+] Benign state tampering (disabling dumps) correctly allowed."
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
verify_unprivileged_piped_crash
verify_root_piped_crash
verify_benign_prctl
verify_ipc_detachment

echo "  [+] Module 'dump_restrict' validation passed."
