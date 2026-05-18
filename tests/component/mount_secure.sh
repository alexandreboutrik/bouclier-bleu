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
# Monitored directory (triggers Heuristic 2)
: "${TEST_MNT_DIR:="/mnt/bb_mount_test"}"
# Unmonitored directory (used to isolate and test Heuristic 1 FS types)
: "${TEST_SAFE_DIR:="/tmp/bb_mount_safe"}"

DAEMON_PID=""

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	cleanup_daemon
	# Ensure mounts are cleaned up to prevent VM state corruption
	umount "${TEST_MNT_DIR}" 2>/dev/null || true
	umount "${TEST_SAFE_DIR}" 2>/dev/null || true
	rm -rf "${TEST_MNT_DIR}" "${TEST_SAFE_DIR}" "${DAEMON_LOG}"
}

trap teardown EXIT

function provision_env() {
	echo "  [*] Provisioning Test Environment..."
	mkdir -p "${TEST_MNT_DIR}" || {
		echo "[-] Failed to create monitored target directory."
		exit 1
	}
	mkdir -p "${TEST_SAFE_DIR}" || {
		echo "[-] Failed to create unmonitored target directory."
		exit 1
	}

	# Compile inline C utility for modern mount API testing
	local tester_c="/tmp/bb_move_mount_tester.c"
	cat <<'EOF' >"${tester_c}"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>

#ifndef SYS_open_tree
#define SYS_open_tree 428
#endif
#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif

#define OPEN_TREE_CLONE 1
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004

int main(int argc, char *argv[]) {
    if (argc < 3) return 1;
    
    // 1. Create a detached mount from the source
    int fd = syscall(SYS_open_tree, AT_FDCWD, argv[1], OPEN_TREE_CLONE);
    if (fd < 0) return 1;

    // 2. Attach it to the VFS tree at the destination using the CORRECT flag
    int ret = syscall(SYS_move_mount, fd, "", AT_FDCWD, argv[2], MOVE_MOUNT_F_EMPTY_PATH);
    
    // If our eBPF lsm/move_mount hook blocks it, it returns EPERM (1)
    if (ret < 0 && errno == EPERM) return 126;
    if (ret < 0) return 1;

    return 0;
}
EOF

	cc -o "/opt/bb_move_mount_tester" "${tester_c}" || {
		echo "[-] Failed to compile modern mount tester."
		exit 1
	}
	rm -f "${tester_c}"
}

function verify_insecure_path_mount() {
	echo "  [*] Validating Insecure Target Path Mount (/mnt/...) (Expected: BLOCK)..."

	set +e
	# Attempt to mount a tmpfs volume into a monitored path without secure flags
	mount -t tmpfs none "${TEST_MNT_DIR}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq 0 ]]; then
		echo "[-] Assertion failed: Insecure mount to /mnt was permitted!"
		umount "${TEST_MNT_DIR}" 2>/dev/null || true
		exit 1
	fi

	echo "  [+] Insecure path mount successfully vetoed (-EPERM)."
}

function verify_secure_path_mount() {
	echo "  [*] Validating Secure Target Path Mount (/mnt/...) (Expected: ALLOW)..."

	set +e
	# Include the required trio: noexec, nosuid, nodev
	mount -t tmpfs -o noexec,nosuid,nodev none "${TEST_MNT_DIR}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Secure mount to /mnt was incorrectly blocked! (Exit code: ${exit_code})"
		exit 1
	fi

	echo "  [+] Secure path mount cleanly bypassed."
	umount "${TEST_MNT_DIR}" || true
}

function verify_insecure_fstype_mount() {
	echo "  [*] Validating Insecure Filesystem Type Mount (vfat) (Expected: BLOCK)..."

	set +e
	# Spoof a USB block device prefix. The LSM hook catches this before the
	# VFS realizes the backing device doesn't actually exist.
	mount -t tmpfs /dev/sda1 "${TEST_SAFE_DIR}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq 0 ]]; then
		echo "[-] Assertion failed: Insecure block device mount was permitted!"
		umount "${TEST_SAFE_DIR}" 2>/dev/null || true
		exit 1
	fi

	echo "  [+] Insecure block device mount successfully vetoed (-EPERM)."
}

function verify_move_mount_api() {
	echo "  [*] Validating Modern Mount API (move_mount) (Expected: BLOCK)..."

	# Setup a dummy source directory
	mkdir -p "/tmp/bb_mount_src"

	set +e
	# Attempt an insecure attachment using the new API directly
	"/opt/bb_move_mount_tester" "/tmp/bb_mount_src" "${TEST_MNT_DIR}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	rm -rf "/tmp/bb_mount_src"

	if [[ "${exit_code}" -ne 126 ]]; then
		echo "[-] Assertion failed: Insecure move_mount attachment was permitted! (Exit Code: ${exit_code})"
		umount "${TEST_MNT_DIR}" 2>/dev/null || true
		exit 1
	fi

	echo "  [+] Modern move_mount attachment successfully vetoed (-EPERM)."
}

function verify_ipc_detachment() {
	echo "  [*] Validating dynamic LSM hook detachment..."

	"${BB_CLI_BIN}" disable mount_secure >/dev/null || {
		echo "[-] RPC invocation failed."
		exit 1
	}

	set +e
	# Attempt the exact same insecure mount that was blocked in test #1
	mount -t tmpfs none "${TEST_MNT_DIR}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Disabled module still blocked mount operation."
		exit 1
	fi

	echo "  [+] Hook cleanly detached. Insecure mount allowed."
	umount "${TEST_MNT_DIR}" || true
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_env
initialize_daemon "mount_secure"

verify_insecure_path_mount
verify_secure_path_mount
verify_insecure_fstype_mount
verify_move_mount_api
verify_ipc_detachment

echo "  [+] Module 'mount_secure' validation passed."
