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

# ==========================================
# CONFIGURATION
# ==========================================
: "${BB_CORE_BIN:="./target/release/core"}"
: "${BB_CLI_BIN:="./target/release/cli"}"
: "${DAEMON_LOG:="/tmp/bb_daemon_strict_wx.log"}"

# We use /opt because strict_wx.rs explicitly pre-scans this path at boot.
: "${TEST_PROT_BIN:="/opt/bb_wx_protected"}"
: "${TEST_UNPROT_BIN:="/opt/bb_wx_unprotected"}"
: "${C_SOURCE_TMP:="/tmp/bb_wx_dropper.c"}"

DAEMON_PID=""

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	if [[ -n "${DAEMON_PID}" ]]; then
		kill -9 "${DAEMON_PID}" 2>/dev/null || true
	fi
	rm -f "${TEST_PROT_BIN}" "${TEST_UNPROT_BIN}" "${C_SOURCE_TMP}" "${DAEMON_LOG}"
}

trap teardown EXIT

function provision_payloads() {
	echo "  [*] Compiling inline Write XOR Execute (W^X) payloads..."

	cat <<'EOF' >"${C_SOURCE_TMP}"
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>

int main() {
    // Attempt 1: Direct RWX segment allocation via mmap
    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        return 13; // 13 is standard EACCES (Permission denied)
    }
    
    // Attempt 2: RW allocation followed by privilege escalation via mprotect
    void *ptr2 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr2 != MAP_FAILED) {
        if (mprotect(ptr2, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            return 13;
        }
    }

    return 0; // W^X execution succeeded
}
EOF

	cc -o "${TEST_PROT_BIN}" "${C_SOURCE_TMP}" || {
		echo "[-] Failed to compile protected payload."
		exit 1
	}

	cc -o "${TEST_UNPROT_BIN}" "${C_SOURCE_TMP}" || {
		echo "[-] Failed to compile unprotected payload."
		exit 1
	}

	chmod +x "${TEST_PROT_BIN}" "${TEST_UNPROT_BIN}"

	echo "  [*] Applying extended attributes (user.bouclier.strict_wx=1)..."
	if command -v setfattr >/dev/null 2>&1; then
		setfattr -n user.bouclier.strict_wx -v 1 "${TEST_PROT_BIN}" || {
			echo "[-] Failed to set extended attribute. Ensure filesystem supports xattrs."
			exit 1
		}
	else
		echo "[-] 'setfattr' not found. Please install the 'attr' package in the test VM."
		exit 1
	fi
}

function initialize_daemon() {
	echo "  [*] Initializing Bouclier Bleu Core Daemon..."

	# The daemon evaluates the extended attributes of /opt/* synchronously
	# during init()
	"${BB_CORE_BIN}" >"${DAEMON_LOG}" 2>&1 &
	DAEMON_PID=$!

	sleep 2

	if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
		echo "[-] Fatal error: Core daemon failed to bind or crashed instantly."
		echo "--- Daemon Output ---"
		cat "${DAEMON_LOG}"
		echo "---------------------"
		exit 1
	fi

	echo "  [+] Daemon bound successfully (PID: ${DAEMON_PID})."

	# Ensure the module is administratively enabled
	"${BB_CLI_BIN}" enable strict_wx >/dev/null 2>&1 || {
		echo "[-] Failed to enable strict_wx via CLI."
		exit 1
	}
}

function verify_unprotected_execution() {
	echo "  [*] Validating Unprotected Execution (Expected: ALLOW)..."

	set +e
	"${TEST_UNPROT_BIN}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Unprotected W^X execution was incorrectly blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Unprotected execution cleanly bypassed."
}

function verify_protected_execution() {
	echo "  [*] Validating Protected Execution (Expected: BLOCK)..."

	set +e
	"${TEST_PROT_BIN}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq 0 ]]; then
		echo "[-] Assertion failed: Protected binary successfully bypassed W^X mitigation!"
		exit 1
	fi

	# Ensure the process failed explicitly due to the eBPF EACCES drop
	if [[ "${exit_code}" -ne 13 ]]; then
		echo "[-] Assertion failed: Payload crashed unexpectedly. Expected EACCES (13), received ${exit_code}."
		exit 1
	fi

	echo "  [+] Protected W^X execution successfully vetoed (-EACCES)."
}

function verify_ipc_detachment() {
	echo "  [*] Validating dynamic LSM hook detachment..."

	"${BB_CLI_BIN}" disable strict_wx >/dev/null || {
		echo "[-] RPC invocation failed."
		exit 1
	}

	set +e
	"${TEST_PROT_BIN}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Disabled module still blocked memory allocation."
		exit 1
	fi

	echo "  [+] Hook cleanly detached. Allocation allowed."
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_payloads
initialize_daemon

verify_unprotected_execution
verify_protected_execution
verify_ipc_detachment

echo "  [+] Module 'strict_wx' validation passed."
