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
: "${TEST_PAYLOAD:="/tmp/bb_test_payload"}"
: "${TEST_SYMLINK:="/root/bb_test_symlink"}"
: "${TEST_UNMONITORED:="/var/crash/bb_test_payload"}"
: "${TEST_LONG_PATH_BASE:="/tmp/bb_long_path_test"}"
: ${BB_DROPPER="/opt/bb_memfd_dropper"}
: "${EPERM_EXIT_CODE:=126}"

DAEMON_PID=""
ORIGINAL_DIR=$(pwd)

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	cleanup_daemon
	rm -f "${TEST_PAYLOAD}" "${TEST_SYMLINK}" "${TEST_UNMONITORED}" "${DAEMON_LOG}" "${BB_DROPPER}"
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
		{
			echo "[-] Failed to stage payload."
			exit 1
		}

	chmod +x "${TEST_PAYLOAD}" ||
		{
			echo "[-] Failed to assign execution permissions."
			exit 1
		}

	# Stage the symlink bypass vector in a safe, unmonitored directory
	ln -sf "${TEST_PAYLOAD}" "${TEST_SYMLINK}" ||
		{
			echo "[-] Failed to create test symlink."
			exit 1
		}

	# Ensure the unmonitored target directory actually exists in the test VM
	mkdir -p "$(dirname "${TEST_UNMONITORED}")" ||
		{
			echo "[-] Failed to create unmonitored directory."
			exit 1
		}

	# Stage the incomplete heuristic bypass vector
	cp "${source_bin}" "${TEST_UNMONITORED}" ||
		{
			echo "[-] Failed to stage unmonitored path payload."
			exit 1
		}

	chmod +x "${TEST_UNMONITORED}" ||
		{
			echo "[-] Failed to assign execution permissions to unmonitored payload."
			exit 1
		}
}

function provision_memfd_dropper() {
	echo "  [*] Compiling inline memfd dropper utility..."
	local dropper_c="${BB_DROPPER}.c"

	cat <<'EOF' >"${dropper_c}"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <string.h>

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U // Required on Linux 6.3+ for executable memfds
#endif

// Pull in the native environment pointer to prevent ELF interpreter crashes
extern char **environ; 

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "spoof") == 0) {
        prctl(PR_SET_NAME, "systemd", 0, 0, 0);
    }

	int is_sealed = (argc > 1 && strcmp(argv[1], "sealed") == 0);

    // 1. Attempt creation with explicit execute capabilities (modern kernels)
    // 2. Fallback to standard sealing flags (older kernels)
    int fd = memfd_create("dropper_test", MFD_ALLOW_SEALING | MFD_EXEC);
    if (fd < 0) {
        fd = memfd_create("dropper_test", MFD_ALLOW_SEALING);
    }
    if (fd < 0) return 1;

    // Resolve binary safely
    int src = open("/bin/true", O_RDONLY);
    if (src < 0) src = open("/usr/bin/true", O_RDONLY);
    if (src < 0) return 1;

    char buf[4096];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        write(fd, buf, n);
    }
    close(src);

	if (is_sealed) {
        // Legitimate execution requires the segment to be explicitly sealed
        if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) < 0) {
            return 1;
        }
    }

    // Duplicate the file descriptor as Read-Only and close the original 
    // Writable handle to bypass native ETXTBSY (Text file busy) kernel locks.
    char path[128];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    int fd_exec = open(path, O_RDONLY);
    if (fd_exec < 0) return 1;
    
    close(fd);

    char *exec_argv[] = {"true", NULL};

    // Execute using the safely inherited host environment
    fexecve(fd_exec, exec_argv, environ);
    
    // If we reach here, fexecve failed natively or was successfully blocked by eBPF
    return 126;
}
EOF

	cc -o "${BB_DROPPER}" "${dropper_c}" ||
		{
			echo "[-] Failed to compile memfd dropper."
			exit 1
		}
	rm -f "${dropper_c}"
}

function verify_active_blocking() {
	echo "  [*] Validating BPF LSM enforcement logic..."

	# Temporarily disable 'exit-on-error' to safely capture the kernel
	# permission denial
	set +e
	"${TEST_PAYLOAD}" >/dev/null 2>&1
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

	"${BB_CLI_BIN}" disable exec_block >/dev/null || {
		echo "[-] RPC invocation failed."
		exit 1
	}

	# Validate bypassed execution. If the LSM is still enforcing, 'set -e' will
	# correctly crash the script.
	"${TEST_PAYLOAD}" >/dev/null

	echo "  [+] Hook cleanly detached. Execution allowed."

	"${BB_CLI_BIN}" enable exec_block >/dev/null || {
		echo "[-] Failed to re-enable the module."
		exit 1
	}
}

function verify_path_normalization_bypass() {
	echo "  [*] Validating Path Normalization evasion vectors..."

	local payload_name
	payload_name=$(basename "${TEST_PAYLOAD}")

	# 1. Double-Slash Normalization (//tmp/payload)
	set +e
	"//tmp/${payload_name}" >/dev/null 2>&1
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
	"./${payload_name}" >/dev/null 2>&1
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
	"${TEST_SYMLINK}" >/dev/null 2>&1
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
	"${TEST_UNMONITORED}" >/dev/null 2>&1
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
	mkdir -p "${current_path}" || {
		echo "[-] Failed to create base long path directory."
		exit 1
	}

	# Build a deeply nested directory structure exceeding 300 characters
	# to overflow the original 256-byte eBPF buffer limit.
	for i in {1..30}; do
		current_path="${current_path}/AAAAAAAAAA"
	done

	mkdir -p "${current_path}" ||
		{
			echo "[-] Failed to create deeply nested path."
			exit 1
		}

	local long_payload="${current_path}/payload"
	cp "${TEST_PAYLOAD}" "${long_payload}" ||
		{
			echo "[-] Failed to copy payload to nested path."
			exit 1
		}
	chmod +x "${long_payload}"

	# Attempt to execute the payload from the excessively long path
	set +e
	"${long_payload}" >/dev/null 2>&1
	local exit_code_long=$?
	set -e

	# If the execution succeeds (exit code 0), the eBPF program failed open.
	if [[ "${exit_code_long}" -ne "${EPERM_EXIT_CODE}" ]] && [[ "${exit_code_long}" -ne 1 ]]; then
		echo "[-] Assertion failed: Path length evasion bypassed the LSM hook. The eBPF program failed OPEN."
		exit 1
	fi

	echo "  [+] Path length evasion successfully vetoed (Program safely failed CLOSED or buffer was expanded)."
}

function verify_mount_namespace_evasion() {
	echo "  [*] Validating Mount Namespace Evasion (Expected: BLOCK)..."

	local EVASION_DIR="/root/bb_exec_evasion"
	mkdir -p "${EVASION_DIR}"

	local payload_name
	payload_name=$(basename "${TEST_PAYLOAD}")

	set +e
	# -U: New user namespace, -r: Map to root, -m: New mount namespace
	# Bind mount the protected /tmp directory into an unmonitored location
	# (/root/...) and attempt execution. Before the fix, bpf_d_path would
	# resolve to /root/... and fail-open.
	unshare -Ur -m bash -c "
        mount --bind /tmp '${EVASION_DIR}'
        '${EVASION_DIR}/${payload_name}' > /dev/null 2>&1
    "
	local exit_code=$?
	set -e

	# Exit codes 126 or 1 are standard returns for -EPERM
	if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]] && [[ "${exit_code}" -ne 1 ]]; then
		echo "[-] Assertion failed: Mount namespace bind evasion was successful! Execution permitted."
		exit 1
	fi
	echo "  [+] Mount namespace evasion successfully thwarted (Hardware inode validated)."
}

function verify_memfd_execution() {
	echo "  [*] Validating Fileless Execution (memfd_create) Mitigation (Expected: BLOCK)..."

	set +e
	"${BB_DROPPER}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]] && [[ "${exit_code}" -ne 1 ]]; then
		echo "[-] Assertion failed: Unsealed memfd execution was permitted!"
		exit 1
	fi
	echo "  [+] Unsealed fileless execution successfully thwarted."
}

function verify_memfd_prctl_spoofing() {
	echo "  [*] Validating Fileless Execution with prctl() 'systemd' Spoofing (Expected: BLOCK)..."

	set +e
	"${BB_DROPPER}" spoof >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]] && [[ "${exit_code}" -ne 1 ]]; then
		echo "[-] Assertion failed: prctl() spoofed memfd execution was permitted!"
		exit 1
	fi
	echo "  [+] Spoofed fileless execution successfully thwarted (Seal Inspection held)."
}

function verify_sealed_memfd_execution() {
	echo "  [*] Validating Sealed Fileless Execution (Expected: ALLOW)..."

	set +e
	"${BB_DROPPER}" sealed >/dev/null 2>&1
	local exit_code=$?
	set -e

	# It should successfully execute 'true', yielding exit code 0
	if [[ "${exit_code}" -eq "${EPERM_EXIT_CODE}" ]] || [[ "${exit_code}" -eq 1 ]]; then
		echo "[-] Assertion failed: Properly sealed memfd execution was incorrectly blocked!"
		exit 1
	fi
	echo "  [+] Sealed fileless execution cleanly bypassed."
}

function verify_dynamic_watchlist_exec() {
	echo "  [*] Validating Dynamic Watchlist Inheritance (Expected: BLOCK)..."

	local NESTED_DIR="/tmp/bb_exec_nested"

	# Create the directory, triggering the vfs_mkdir eBPF hook
	mkdir -p "${NESTED_DIR}"

	local nested_payload="${NESTED_DIR}/payload"
	cp "${TEST_PAYLOAD}" "${nested_payload}"
	chmod +x "${nested_payload}"

	set +e
	"${nested_payload}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	rm -rf "${NESTED_DIR}"

	if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]] && [[ "${exit_code}" -ne 1 ]]; then
		echo "[-] Assertion failed: Execution from dynamically created nested directory bypassed the hook!"
		exit 1
	fi
	echo "  [+] Nested directory execution successfully vetoed (Inherited protection validated)."
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_payload
provision_memfd_dropper
initialize_daemon "exec_block"

verify_active_blocking
verify_ipc_detachment
verify_path_normalization_bypass
verify_symlink_bypass
verify_unmonitored_paths
verify_path_length_evasion
verify_mount_namespace_evasion
verify_memfd_execution
verify_memfd_prctl_spoofing
verify_sealed_memfd_execution
verify_dynamic_watchlist_exec

echo "  [+] Module 'exec_block_path' validation passed."
