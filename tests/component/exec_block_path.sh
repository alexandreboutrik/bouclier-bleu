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
: "${TEST_SYMLINK:="/root/bb_test_symlink"}"
: "${TEST_UNMONITORED:="/var/crash/bb_test_payload"}"
: "${TEST_LONG_PATH_BASE:="/tmp/bb_long_path_test"}"
: "${DAEMON_LOG:="/tmp/bb_daemon_path.log"}"
: "${EPERM_EXIT_CODE:=126}"

DAEMON_PID=""
ORIGINAL_DIR=$(pwd)

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
    if [[ -n "${DAEMON_PID}" ]]; then
        kill -9 "${DAEMON_PID}" 2>/dev/null || true
    fi
    rm -f "${TEST_PAYLOAD}" "${TEST_SYMLINK}" "${TEST_UNMONITORED}" "${DAEMON_LOG}"
    cd "${ORIGINAL_DIR}" || true
}

# Ensure deterministic teardown on exit or failure
trap teardown EXIT

function provision_payload() {
    local source_bin
    source_bin=$(command -v whoami)
    
    if [[ -z "${source_bin}" ]] || [[ ! -f "${source_bin}" ]]; then
        echo "[-] Failed to resolve system binary for payload testing."
        exit 1
    fi

    # Stage the standard payload
    cp "${source_bin}" "${TEST_PAYLOAD}" ||
        { echo "[-] Failed to stage payload."; exit 1; }

    chmod +x "${TEST_PAYLOAD}" ||
        { echo "[-] Failed to assign execution permissions."; exit 1; }
        
    # Stage the symlink bypass vector in a safe, unmonitored directory
    ln -sf "${TEST_PAYLOAD}" "${TEST_SYMLINK}" ||
        { echo "[-] Failed to create test symlink."; exit 1; }
	
	# Ensure the unmonitored target directory actually exists in the test VM
    mkdir -p "$(dirname "${TEST_UNMONITORED}")" ||
        { echo "[-] Failed to create unmonitored directory."; exit 1; }

    # Stage the incomplete heuristic bypass vector
    cp "${source_bin}" "${TEST_UNMONITORED}" ||
        { echo "[-] Failed to stage unmonitored path payload."; exit 1; }

    chmod +x "${TEST_UNMONITORED}" ||
        { echo "[-] Failed to assign execution permissions to unmonitored payload."; exit 1; }
}

function initialize_daemon() {
    echo "  [*] Initializing Bouclier Bleu Core Daemon..."
    
    "${BB_CORE_BIN}" > "${DAEMON_LOG}" 2>&1 &
    DAEMON_PID=$!

    # Await eBPF skeleton attachment and initialization
    sleep 2

    if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
        echo "[-] Fatal error: Core daemon failed to bind or crashed instantly."
        echo "--- Daemon Output ---"
        cat "${DAEMON_LOG}"
        echo "---------------------"
        exit 1
    fi
    
    echo "  [+] Daemon bound successfully (PID: ${DAEMON_PID})."
}

function verify_path_normalization_bypass() {
    echo "  [*] Validating Path Normalization evasion vectors..."
    
    local payload_name
    payload_name=$(basename "${TEST_PAYLOAD}")

    # 1. Double-Slash Normalization (//tmp/payload)
    set +e 
    "//tmp/${payload_name}" > /dev/null 2>&1
    local exit_code_slash=$?
    set -e

    if [[ "${exit_code_slash}" -ne "${EPERM_EXIT_CODE}" ]] && [[ "${exit_code_slash}" -ne 1 ]]; then
        echo "[-] Assertion failed: //tmp/ normalization bypassed the LSM hook."
        exit 1
    fi
    echo "  [+] Double-slash execution successfully vetoed."

    # 2. Relative Path Normalization (./payload from within /tmp)
    cd /tmp || exit 1
    set +e 
    "./${payload_name}" > /dev/null 2>&1
    local exit_code_relative=$?
    set -e
    cd "${ORIGINAL_DIR}" || exit 1

    if [[ "${exit_code_relative}" -ne "${EPERM_EXIT_CODE}" ]] && [[ "${exit_code_relative}" -ne 1 ]]; then
        echo "[-] Assertion failed: Relative path ./ execution bypassed the LSM hook."
        exit 1
    fi
    echo "  [+] Relative path execution successfully vetoed."
}

function verify_symlink_bypass() {
    echo "  [*] Validating Symlink Indirection evasion vectors..."
    
    # Execute the payload via the unmonitored /root/ symlink
    set +e 
    "${TEST_SYMLINK}" > /dev/null 2>&1
    local exit_code_symlink=$?
    set -e

    if [[ "${exit_code_symlink}" -ne "${EPERM_EXIT_CODE}" ]] && [[ "${exit_code_symlink}" -ne 1 ]]; then
        echo "[-] Assertion failed: Symlink execution bypassed the LSM hook. bpf_d_path canonicalization failed."
        exit 1
    fi
    
    echo "  [+] Symlink execution successfully vetoed (Underlying inode path was correctly resolved)."
}

function verify_unmonitored_paths() {
    echo "  [*] Validating Incomplete Heuristic Coverage (Unmonitored Paths)..."
    
    # Execute the payload via the unmonitored /var/crash/ directory
    set +e 
    "${TEST_UNMONITORED}" > /dev/null 2>&1
    local exit_code_unmonitored=$?
    set -e

    if [[ "${exit_code_unmonitored}" -ne "${EPERM_EXIT_CODE}" ]] && [[ "${exit_code_unmonitored}" -ne 1 ]]; then
        echo "[-] Assertion failed: Execution from /var/crash/ bypassed the LSM hook. Heuristic coverage is incomplete."
        exit 1
    fi
    
    echo "  [+] Execution from unmonitored path successfully vetoed."
}

function verify_path_length_evasion() {
    echo "  [*] Validating Path Length Exhaustion (-ENAMETOOLONG) evasion vectors..."

    local current_path="${TEST_LONG_PATH_BASE}"
    mkdir -p "${current_path}" || { echo "[-] Failed to create base long path directory."; exit 1; }

    # Build a deeply nested directory structure exceeding 300 characters
    # to overflow the original 256-byte eBPF buffer limit.
    for i in {1..30}; do
        current_path="${current_path}/AAAAAAAAAA"
    done

    mkdir -p "${current_path}" ||
		{ echo "[-] Failed to create deeply nested path."; exit 1; }

    local long_payload="${current_path}/payload"
    cp "${TEST_PAYLOAD}" "${long_payload}" ||
		{ echo "[-] Failed to copy payload to nested path."; exit 1; }
    chmod +x "${long_payload}"

    # Attempt to execute the payload from the excessively long path
    set +e
    "${long_payload}" > /dev/null 2>&1
    local exit_code_long=$?
    set -e

    # If the execution succeeds (exit code 0), the eBPF program failed open.
    if [[ "${exit_code_long}" -ne "${EPERM_EXIT_CODE}" ]] && [[ "${exit_code_long}" -ne 1 ]]; then
        echo "[-] Assertion failed: Path length evasion bypassed the LSM hook. The eBPF program failed OPEN."
        exit 1
    fi

    echo "  [+] Path length evasion successfully vetoed (Program safely failed CLOSED or buffer was expanded)."
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_payload
initialize_daemon

verify_path_normalization_bypass
verify_symlink_bypass
verify_unmonitored_paths
verify_path_length_evasion

echo "  [+] Module 'exec_block_path' validation passed."
