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
: "${TEST_PAYLOAD:="/tmp/bb_test_payload"}"
: "${DAEMON_LOG:="/tmp/bb_daemon.log"}"
: "${EPERM_EXIT_CODE:=126}"

DAEMON_PID=""

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
    if [[ -n "${DAEMON_PID}" ]]; then
        kill -9 "${DAEMON_PID}" 2>/dev/null || true
    fi
    rm -f "${TEST_PAYLOAD}" "${DAEMON_LOG}"
}

# Ensure deterministic teardown on exit or failure
trap teardown EXIT

function provision_payload() {
    # Dynamically resolve binaries to ensure cross-compatibility with immutable
	# distros (e.g., NixOS)
    local source_bin
    source_bin=$(command -v whoami)
    
    if [[ -z "${source_bin}" ]] || [[ ! -f "${source_bin}" ]]; then
        echo "[-] Failed to resolve system binary for payload testing."
        exit 1
    fi

    cp "${source_bin}" "${TEST_PAYLOAD}" ||
		{ echo "[-] Failed to stage payload."; exit 1; }

    chmod +x "${TEST_PAYLOAD}" ||
		{ echo "[-] Failed to assign execution permissions."; exit 1; }
}

function initialize_daemon() {
    echo "  [*] Initializing Bouclier Bleu Core Daemon..."
    
    "${BB_CORE_BIN}" > "${DAEMON_LOG}" 2>&1 &
    DAEMON_PID=$!

    # Await eBPF skeleton attachment and initialization
    sleep 2

    # Health Check: Ensure the daemon process survived initialization and
	# linking
    if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
        echo "[-] Fatal error: Core daemon failed to bind or crashed instantly."
        echo "--- Daemon Output ---"
        cat "${DAEMON_LOG}"
        echo "---------------------"
        exit 1
    fi
    
    echo "  [+] Daemon bound successfully (PID: ${DAEMON_PID})."
}

function verify_active_blocking() {
    echo "  [*] Validating BPF LSM enforcement logic..."
    
    # Temporarily disable 'exit-on-error' to safely capture the kernel
	# permission denial
    set +e 
    "${TEST_PAYLOAD}" > /dev/null 2>&1
    local exit_code=$?
    set -e

    # Exit codes 126 (Command invoked cannot execute) or 1 are standard
	# returns for EPERM
    if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]] && [[ "${exit_code}" -ne 1 ]]; then
        echo "[-] Assertion failed: Payload executed. Expected EPERM (${EPERM_EXIT_CODE}), received ${exit_code}."
        exit 1
    fi
    
    echo "  [+] Hook successfully vetoed execution (-EPERM)."
}

function verify_ipc_detachment() {
    echo "  [*] Validating dynamic LSM hook detachment..."
    
    "${BB_CLI_BIN}" disable exec_block > /dev/null || {
        echo "[-] RPC invocation failed."; exit 1;
    }

    # Validate bypassed execution. If the LSM is still enforcing, 'set -e' will
	# correctly crash the script.
    "${TEST_PAYLOAD}" > /dev/null
    
    echo "  [+] Hook cleanly detached. Execution allowed."
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_payload
initialize_daemon

verify_active_blocking
verify_ipc_detachment

echo "  [+] Module 'exec_block' validation passed."
