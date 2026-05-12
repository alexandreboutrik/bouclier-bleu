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
: "${USERNS_TESTER_SUID:="/opt/bb_userns_tester_suid"}"
: "${EPERM_EXIT_CODE:=126}"

DAEMON_PID=""

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	cleanup_daemon

	rm -f "${USERNS_TESTER}" "${USERNS_TESTER_SUID}" "${DAEMON_LOG}" "/tmp/userns_df_status"
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

	# Compile inline C utility to invoke namespace manipulation and capability checks
	local tester_c="${USERNS_TESTER}.c"
	cat <<'EOF' >"${tester_c}"
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;

    /* 1. Standard Unprivileged Attempt */
    if (strcmp(argv[1], "unshare_user") == 0) {
        int ret = unshare(CLONE_NEWUSER);
        if (ret < 0 && errno == EPERM) return 126; // LSM Blocked
        if (ret < 0) return 1; // Standard error
        return 0; // LSM Allowed
    }

    /* 2. SUID Proxy Evasion (e.g., sudo, su, bwrap) */
    if (strcmp(argv[1], "suid_proxy") == 0) {
		if (setuid(0) != 0) return 1;
        
        // Explicitly mock an interactive user session for CI environments
        FILE *lf = fopen("/proc/self/loginuid", "w");
        if (lf) {
            fprintf(lf, "1000");
            fclose(lf);
        }
        
        int ret = unshare(CLONE_NEWUSER);
        if (ret < 0 && errno == EPERM) return 126;
        if (ret < 0) return 1;
        return 0;
    }

    /* 3. Ancestry & Double-Fork Evasion (Reparenting to PID 1) */
    if (strcmp(argv[1], "double_fork") == 0) {
        if (setuid(0) != 0) return 1;

        // Force an unprivileged loginuid to ensure CI environments simulate 
        // a real SSH/TTY interactive user session
        FILE *lf = fopen("/proc/self/loginuid", "w");
        if (lf) {
            fprintf(lf, "1000");
            fclose(lf);
        }

        pid_t pid1 = fork();
        if (pid1 < 0) return 1;
        
        if (pid1 > 0) {
            // Original process waits for the grandchild's IPC status file
            int status;
            waitpid(pid1, &status, 0);
            
            // Wait slightly for grandchild to write status
            usleep(200000);
            
            FILE *sf = fopen("/tmp/userns_df_status", "r");
            if (!sf) return 1;
            int df_status = 1;
            if (fscanf(sf, "%d", &df_status) != 1) df_status = 1;
            fclose(sf);
            return df_status;
        }

        // Child 1: Create a new session and fork again
        setsid();
        pid_t pid2 = fork();
        if (pid2 < 0) exit(1);
        if (pid2 > 0) exit(0); // Child 1 exits immediately

        // Child 2 (Grandchild): Reparented to PID 1 (init/systemd)
        // Delay to ensure the kernel processes the reparenting
        usleep(100000);

        int ret = unshare(CLONE_NEWUSER);
        int exit_code = 0;
        
        if (ret < 0 && errno == EPERM) exit_code = 126;
        else if (ret < 0) exit_code = 1;

        FILE *sf = fopen("/tmp/userns_df_status", "w");
        if (sf) {
            fprintf(sf, "%d", exit_code);
            fclose(sf);
        }
        exit(0);
    }

    /* 4. Container Escape: Restricted Capability Acquisition */
    if (strcmp(argv[1], "nested_cap") == 0) {
        if (unshare(CLONE_NEWUSER) != 0) return 1;
        int ret = sethostname("sandbox_escape", 14);
        if (ret < 0 && errno == EPERM) return 126;
        if (ret < 0) return 1;
        return 0; 
    }

    /* 5. Container Escape: Host Physical Device Mounting */
    if (strcmp(argv[1], "nested_mount_dev") == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
			if (errno == EPERM) return 126;
			return 1;
		}
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

	# Provision the SUID binary copy for evasion tests
	cp "${USERNS_TESTER}" "${USERNS_TESTER_SUID}"
	chown root:root "${USERNS_TESTER_SUID}"
	chmod 4755 "${USERNS_TESTER_SUID}"
}

function verify_unprivileged_userns() {
	echo "  [*] Validating Direct Unprivileged Namespace Creation (Expected: BLOCK)..."

	set +e
	su - "${TEST_USER}" -c "${USERNS_TESTER} unshare_user" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Unprivileged unshare(CLONE_NEWUSER) was not blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Direct unprivileged namespace creation successfully vetoed (-EPERM)."
}

function verify_suid_proxy_evasion() {
	echo "  [*] Validating SUID Proxy Evasion [parent_uid logic] (Expected: BLOCK)..."

	set +e
	# Append '|| exit \$?' to defeat Bash tail-call optimization while strictly propagating
	# the exact exit code of the tester back up to the su wrapper.
	su - "${TEST_USER}" -c "${USERNS_TESTER_SUID} suid_proxy || exit \$?" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: SUID Proxy evasion was not blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] SUID Proxy evasion successfully vetoed (-EPERM)."
}

function verify_double_fork_evasion() {
	echo "  [*] Validating Ancestry Double-Fork Evasion [loginuid logic] (Expected: BLOCK)..."

	# Clean state file before test
	rm -f /tmp/userns_df_status

	set +e
	su - "${TEST_USER}" -c "${USERNS_TESTER_SUID} double_fork" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne "${EPERM_EXIT_CODE}" ]]; then
		echo "[-] Assertion failed: Double-Fork reparenting evasion was not blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Ancestry Double-Fork evasion successfully vetoed (-EPERM)."
}

function verify_root_userns() {
	echo "  [*] Validating Legitimate Root Namespace Creation (Expected: ALLOW)..."

	# Explicitly clear loginuid to simulate an automated system daemon (e.g., Docker)
	# rather than an interactive root user session, ensuring it passes the logic checks.
	echo "4294967295" >/proc/self/loginuid 2>/dev/null || true

	set +e
	"${USERNS_TESTER}" unshare_user >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Root unshare(CLONE_NEWUSER) was incorrectly blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] System daemon root namespace creation cleanly allowed."
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

	# The tester should no longer return 126.
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
verify_suid_proxy_evasion
verify_double_fork_evasion
verify_root_userns
verify_nested_cap_sys_admin
verify_nested_dev_mount
verify_ipc_detachment

echo "  [+] Module 'userns_restrict' validation passed."
