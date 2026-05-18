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
# We use /opt because strict_wx.rs explicitly pre-scans this path at boot.
: "${TEST_PROT_BIN:="/opt/bb_wx_protected"}"
: "${TEST_UNPROT_BIN:="/opt/bb_wx_unprotected"}"
: "${C_SOURCE_TMP:="/tmp/bb_wx_dropper.c"}"

DAEMON_PID=""

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	cleanup_daemon
	rm -f "${TEST_PROT_BIN}" "${TEST_UNPROT_BIN}" "${C_SOURCE_TMP}" "${DAEMON_LOG}"
}

trap teardown EXIT

function provision_payloads() {
	echo "  [*] Provisioning W^X test payloads..."

	local C_SOURCE_TMP="/tmp/bb_strict_wx_payload.c"
	TEST_PROT_BIN="${TEST_PROT_BIN:-/opt/bb_wx_protected}"
	TEST_UNPROT_BIN="${TEST_UNPROT_BIN:-/opt/bb_wx_unprotected}"
	local SO_TARGET="/opt/bb_wx_protected.so"

	cat <<'EOF' >"${C_SOURCE_TMP}"
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;

    if (strcmp(argv[1], "direct_rwx") == 0) {
        void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED) return 13;
        return 0;
    }

    if (strcmp(argv[1], "sequential_w_to_x") == 0) {
        void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr != MAP_FAILED) {
            if (mprotect(ptr, 4096, PROT_READ | PROT_EXEC) != 0) return 13;
        }
        return 0;
    }

    if (strcmp(argv[1], "sequential_x_to_w") == 0) {
        void *ptr = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr != MAP_FAILED) {
            if (mprotect(ptr, 4096, PROT_READ | PROT_WRITE) != 0) return 13;
        }
        return 0;
    }

    if (strcmp(argv[1], "load_so") == 0) {
        // Attempt to directly map the protected file while explicitly requesting W^X.
        // The unprotected binary does not have the xattr, but the mapped_file DOES.
        int fd = open("/opt/bb_wx_protected.so", O_RDONLY);
        if (fd < 0) return 1;
        
        void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
        if (ptr == MAP_FAILED) {
            close(fd);
            return 13; // Blocked by eBPF mapped_file inspection (-EACCES)
        }
        
        close(fd);
        return 0;
    }

    return 1;
}
EOF

	# Compile the standard payloads
	cc -o "${TEST_PROT_BIN}" "${C_SOURCE_TMP}" || {
		echo "[-] Error: Failed to compile protected payload."
		exit 1
	}

	cc -o "${TEST_UNPROT_BIN}" "${C_SOURCE_TMP}" || {
		echo "[-] Error: Failed to compile unprotected payload."
		exit 1
	}

	# Compile a dummy shared library
	echo 'void dummy() {}' | cc -x c -shared -fPIC -o "${SO_TARGET}" - || {
		echo "[-] Error: Failed to compile dummy shared library (.so)."
		exit 1
	}

	# Set executable permissions
	chmod +x "${TEST_PROT_BIN}" "${TEST_UNPROT_BIN}" "${SO_TARGET}" || {
		echo "[-] Error: Failed to set executable permissions on payloads."
		exit 1
	}

	# Apply Bouclier Bleu strict_wx xattrs
	setfattr -n user.bouclier.strict_wx -v 1 "${TEST_PROT_BIN}" || {
		echo "[-] Error: Failed to set xattr on protected binary. Is the filesystem mounted with user_xattr?"
		exit 1
	}

	setfattr -n user.bouclier.strict_wx -v 1 "${SO_TARGET}" || {
		echo "[-] Error: Failed to set xattr on shared library."
		exit 1
	}

	# Cleanup C source
	rm -f "${C_SOURCE_TMP}"

	echo "  [+] Payloads provisioned successfully."
}

function verify_unprotected_execution() {
	echo "  [*] Validating Unprotected Execution (Expected: ALLOW)..."

	set +e
	"${TEST_UNPROT_BIN}" direct_rwx >/dev/null 2>&1
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
	"${TEST_PROT_BIN}" direct_rwx >/dev/null 2>&1
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

function verify_sequential_transitions() {
	echo "  [*] Validating Sequential State Transitions (Expected: BLOCK)..."

	set +e
	"${TEST_PROT_BIN}" sequential_w_to_x >/dev/null 2>&1
	local exit_w_to_x=$?

	"${TEST_PROT_BIN}" sequential_x_to_w >/dev/null 2>&1
	local exit_x_to_w=$?
	set -e

	if [[ "${exit_w_to_x}" -ne 13 ]] || [[ "${exit_x_to_w}" -ne 13 ]]; then
		echo "[-] Assertion failed: Sequential W^X bypass succeeded! (Codes: ${exit_w_to_x}, ${exit_x_to_w})"
		exit 1
	fi

	echo "  [+] Sequential mprotect bypasses successfully vetoed (-EACCES)."
}

function verify_shared_library_inheritance() {
	echo "  [*] Validating Protected Shared Library (.so) loading (Expected: BLOCK)..."

	set +e
	# We run the UNPROTECTED binary, but tell it to load the PROTECTED .so file
	"${TEST_UNPROT_BIN}" load_so >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 13 ]]; then
		echo "[-] Assertion failed: Protected .so file bypassed W^X mitigation when loaded by an unprotected binary!"
		exit 1
	fi

	echo "  [+] Protected Shared Library loading successfully vetoed (-EACCES)."
}

function verify_ipc_detachment() {
	echo "  [*] Validating dynamic LSM hook detachment..."

	"${BB_CLI_BIN}" disable strict_wx >/dev/null || {
		echo "[-] RPC invocation failed."
		exit 1
	}

	set +e
	"${TEST_PROT_BIN}" direct_rwx >/dev/null 2>&1
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
initialize_daemon "strict_wx"

verify_unprotected_execution
verify_protected_execution
verify_sequential_transitions
verify_shared_library_inheritance
verify_ipc_detachment

echo "  [+] Module 'strict_wx' validation passed."
