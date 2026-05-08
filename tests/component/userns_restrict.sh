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
: "${TEST_USER:="bb_userns_user"}"
: "${USERNS_TESTER:="/opt/bb_userns_tester"}"
: "${EPERM_EXIT_CODE:=126}"

DAEMON_PID=""

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	cleanup_daemon

	rm -f "${USERNS_TESTER}" "${DAEMON_LOG}"
	userdel -r "${TEST_USER}" 2>/dev/null || true
}

trap teardown EXIT

function provision_env() {
	echo "  [*] Provisioning Test Environment..."

	# Ensure the OS normally allows unprivileged user namespaces
	# so we can confidently assert that our LSM is the component blocking it.
	sysctl -w kernel.unprivileged_userns_clone=1 >/dev/null 2>&1 || true

	# Create unprivileged test user
	useradd -m -s /bin/bash "${TEST_USER}" || {
		echo "[-] Failed to create unprivileged test user."
		exit 1
	}

	# Compile inline C utility to invoke namespace manipulation and capability
	# checks
	local tester_c="${USERNS_TESTER}.c"
	cat <<'EOF' >"${tester_c}"
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;

    if (strcmp(argv[1], "unshare_user") == 0) {
        // Attempt to create an isolated user namespace
        int ret = unshare(CLONE_NEWUSER);
        if (ret < 0 && errno == EPERM) return 126; // LSM Blocked
        if (ret < 0) return 1; // Standard error
        return 0; // LSM Allowed
    }

    if (strcmp(argv[1], "nested_cap") == 0) {
        // Create a user namespace (Requires Root to bypass heuristic 1)
        if (unshare(CLONE_NEWUSER) != 0) return 1;
        
        // sethostname forces the kernel to check for CAP_SYS_ADMIN
        int ret = sethostname("sandbox_escape", 14);
        if (ret < 0 && errno == EPERM) return 126;
        if (ret < 0) return 1;
        return 0; 
    }

    if (strcmp(argv[1], "nested_mount_dev") == 0) {
        // Enter nested user and mount namespace
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
			if (errno == EPERM) return 126;
			return 1;
		}

        // Attempt to dynamically provision a physical device block (devtmpfs)
        int ret = mount("none", "/tmp", "devtmpfs", 0, NULL);
        if (ret < 0 && errno == EPERM) return 126;
        if (ret < 0) return 1;
        return 0;
    }

    return 1;
}
EOF

	cc -o "${USERNS_TESTER}" "${tester_c}" || {
		echo "[-] Failed to compile namespace tester."
		exit 1
	}
	rm -f "${tester_c}"
}

function verify_unprivileged_userns() {
	echo "  [*] Validating Unprivileged User Namespace Creation (Expected: BLOCK)..."

	set +e
	su - "${TEST_USER}" -c "${USERNS_TESTER} unshare_user" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Unprivileged unshare(CLONE_NEWUSER) was not blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Unprivileged namespace creation successfully vetoed (-EPERM)."
}

function verify_root_userns() {
	echo "  [*] Validating Root User Namespace Creation (Expected: ALLOW)..."

	set +e
	"${USERNS_TESTER}" unshare_user >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Root unshare(CLONE_NEWUSER) was incorrectly blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Root namespace creation cleanly allowed."
}

function verify_nested_cap_sys_admin() {
	echo "  [*] Validating CAP_SYS_ADMIN inside Nested Namespace (Expected: BLOCK)..."

	set +e
	"${USERNS_TESTER}" nested_cap >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: CAP_SYS_ADMIN acquisition inside sandbox was not blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Nested CAP_SYS_ADMIN capability check successfully vetoed (-EPERM)."
}

function verify_nested_dev_mount() {
	echo "  [*] Validating Physical /dev mount inside Nested Namespace (Expected: BLOCK)..."

	set +e
	"${USERNS_TESTER}" nested_mount_dev >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: devtmpfs mount inside sandbox was not blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Nested physical device mount successfully vetoed (-EPERM)."
}

function verify_ipc_detachment() {
	echo "  [*] Validating dynamic LSM hook detachment..."

	"${BB_CLI_BIN}" disable userns_restrict >/dev/null || {
		echo "[-] RPC invocation failed."
		exit 1
	}

	set +e
	su - "${TEST_USER}" -c "${USERNS_TESTER} unshare_user" >/dev/null 2>&1
	local exit_code=$?
	set -e

	# The tester should no longer return 126. It will return 0 if the host OS
	# allows it natively, or 1 if the host OS restricts unprivileged namespaces
	# without LSMs.
	if [[ "${exit_code}" -eq "${EPERM_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Disabled module still blocked unshare() operations."
		exit 1
	fi

	echo "  [+] Hook cleanly detached. Namespace manipulation evaluation bypassed."
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_env
initialize_daemon "userns_restrict"

verify_unprivileged_userns
verify_root_userns
verify_nested_cap_sys_admin
verify_nested_dev_mount
verify_ipc_detachment

echo "  [+] Module 'userns_restrict' validation passed."
