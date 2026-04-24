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
# Target files explicitly protected by the kernel-space shield module
: "${CONFIG_TARGET:="/etc/bouclier-bleu/config.toml"}"
: "${BINARY_TARGET:="/usr/bin/bouclier-bleu-core"}"

: "${SHIELD_TESTER:="/tmp/bb_shield_tester"}"
: "${SYMLINK_TARGET:="/tmp/bb_config_symlink"}"
: "${TEST_USER:="bb_shield_user"}"
: "${EPERM_EXIT_CODE:=126}"

DAEMON_PID=""

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	cleanup_daemon
	rm -f "${CONFIG_TARGET}" "${BINARY_TARGET}" "${SHIELD_TESTER}" "${SYMLINK_TARGET}" "${DAEMON_LOG}"
	userdel -r "${TEST_USER}" 2>/dev/null || true
}

trap teardown EXIT

function provision_env() {
	echo "  [*] Provisioning Test Environment..."

	# Create unprivileged test user
	useradd -m -s /bin/bash "${TEST_USER}" ||
		{
			echo "[-] Failed to create unprivileged test user."
			exit 1
		}

	# Provision protected target files
	mkdir -p "$(dirname "${CONFIG_TARGET}")"
	touch "${CONFIG_TARGET}" || {
		echo "[-] Failed to create config target."
		exit 1
	}
	touch "${BINARY_TARGET}" || {
		echo "[-] Failed to create binary target."
		exit 1
	}

	# Intentionally misconfigure the DAC permissions (chmod 777).
	# This proves the eBPF hook acts as a Mandatory Access Control (MAC)
	# fail-safe, overriding broken system permissions.
	chmod 777 "${CONFIG_TARGET}"
	chmod 777 "${BINARY_TARGET}"

	# Setup symlink evasion vector
	ln -sf "${CONFIG_TARGET}" "${SYMLINK_TARGET}"

	# Compile inline C utility to invoke raw kernel syscalls and assert
	# explicit EPERM returns, bypassing bash's generic permission abstractions.
	local tester_c="${SHIELD_TESTER}.c"
	cat <<'EOF' >"${tester_c}"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/klog.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    
    if (strcmp(argv[1], "bpf") == 0) {
        // Trigger a raw bpf() syscall. Invalid arguments do not matter as the
        // LSM hook evaluates credentials before the kernel validates the
		// payload.
        long ret = syscall(SYS_bpf, 0, NULL, 0);
        if (ret < 0 && errno == EPERM) return 126;
        return 0; // Test Failed (LSM allowed the call)
    }
    
    if (strcmp(argv[1], "syslog") == 0) {
        long ret = klogctl(3, NULL, 0); // Type 3: Read up to 0 bytes
        if (ret < 0 && errno == EPERM) return 126;
        return 0; 
    }
    
    return 1;
}
EOF

	cc -o "${SHIELD_TESTER}" "${tester_c}" ||
		{
			echo "[-] Failed to compile raw syscall tester."
			exit 1
		}
	rm -f "${tester_c}"
}

function verify_file_tampering() {
	echo "  [*] Validating Core File Tampering Prevention (Expected: BLOCK)..."

	set +e
	# Execute write attempt as the unprivileged user
	su - "${TEST_USER}" -c "echo 'malicious_config' > ${CONFIG_TARGET}" >/dev/null 2>&1
	local exit_config=$?

	su - "${TEST_USER}" -c "echo 'malicious_bytes' >> ${BINARY_TARGET}" >/dev/null 2>&1
	local exit_binary=$?
	set -e

	# Exit code 1 is standard for bash redirection "Permission denied" (-EACCES)
	if [[ "${exit_config}" -eq 0 ]] || [[ "${exit_binary}" -eq 0 ]]; then
		echo "[-] Assertion failed: Unprivileged user successfully wrote to a protected file (DAC override failed)!"
		exit 1
	fi

	echo "  [+] Unauthorized write access successfully vetoed (-EACCES)."
}

function verify_symlink_evasion() {
	echo "  [*] Validating Symlink Indirection Evasion (Expected: BLOCK)..."

	set +e
	# Attempt to write to the config file via an unprotected symlink in /tmp
	su - "${TEST_USER}" -c "echo 'symlink_evasion' > ${SYMLINK_TARGET}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq 0 ]]; then
		echo "[-] Assertion failed: Symlink evasion bypassed the LSM hook!"
		exit 1
	fi

	echo "  [+] Symlink evasion successfully thwarted (bpf_d_path resolved canonical path)."
}

function verify_file_read_allowed() {
	echo "  [*] Validating Fast-Path Deferral for Read Access (Expected: ALLOW)..."

	# Populate safe content via root
	echo "safe_config" >"${CONFIG_TARGET}"

	set +e
	# Ensure unprivileged reads are NOT blocked by the MAC
	su - "${TEST_USER}" -c "cat ${CONFIG_TARGET}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Legitimate unprivileged read access was incorrectly blocked!"
		exit 1
	fi

	echo "  [+] Unprivileged read access cleanly bypassed."
}

function verify_root_file_access() {
	echo "  [*] Validating Administrative Privileges (Expected: ALLOW)..."

	set +e
	# Root context (default execution of this script) should bypass the shield
	echo "root_config" >"${CONFIG_TARGET}" 2>/dev/null
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Root user was locked out of EDR configuration!"
		exit 1
	fi

	echo "  [+] Administrative modifications correctly allowed."
}

function verify_bpf_tampering() {
	echo "  [*] Validating bpf() Syscall Tampering Protection (Expected: BLOCK)..."

	set +e
	su - "${TEST_USER}" -c "${SHIELD_TESTER} bpf" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Unprivileged bpf() syscall was not blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Unprivileged BPF operations successfully vetoed (-EPERM)."
}

function verify_syslog_leak() {
	echo "  [*] Validating syslog() Kernel Info Leak Protection (Expected: BLOCK)..."

	set +e
	su - "${TEST_USER}" -c "${SHIELD_TESTER} syslog" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Unprivileged syslog() reads were not blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] KASLR bypass vector successfully mitigated (-EPERM)."
}

function verify_ipc_detachment() {
	echo "  [*] Validating dynamic LSM hook detachment..."

	"${BB_CLI_BIN}" disable shield >/dev/null || {
		echo "[-] RPC invocation failed."
		exit 1
	}

	set +e
	su - "${TEST_USER}" -c "echo 'tampered_while_disabled' > ${CONFIG_TARGET}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Disabled module still blocked file modifications."
		exit 1
	fi

	echo "  [+] Hook cleanly detached. Execution allowed."
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_env
initialize_daemon "shield"

verify_file_tampering
verify_symlink_evasion
verify_file_read_allowed
verify_root_file_access
verify_bpf_tampering
verify_syslog_leak
verify_ipc_detachment

echo "  [+] Module 'shield' validation passed."
