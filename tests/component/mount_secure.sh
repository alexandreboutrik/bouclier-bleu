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
: "${DAEMON_LOG:="/tmp/bb_daemon_mount.log"}"

# Monitored directory (triggers Heuristic 2)
: "${TEST_MNT_DIR:="/mnt/bb_mount_test"}"
# Unmonitored directory (used to isolate and test Heuristic 1 FS types)
: "${TEST_SAFE_DIR:="/tmp/bb_mount_safe"}"

DAEMON_PID=""

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	if [[ -n "${DAEMON_PID}" ]]; then
		kill -9 "${DAEMON_PID}" 2>/dev/null || true
	fi
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
}

function initialize_daemon() {
	echo "  [*] Initializing Bouclier Bleu Core Daemon..."

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

	# Pre-emptively enforce module via CLI to ensure active state
	"${BB_CLI_BIN}" enable mount_secure >/dev/null 2>&1 || {
		echo "[-] Failed to enable the module."
		exit 1
	}
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
	# Mount into an unmonitored directory (/tmp) but use a monitored FS type
	# (vfat). The LSM runs before the VFS validates the backing block device,
	# so it will  block it with EPERM before failing due to a missing real
	# disk.
	mount -t vfat none "${TEST_SAFE_DIR}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq 0 ]]; then
		echo "[-] Assertion failed: Insecure vfat mount was permitted!"
		umount "${TEST_SAFE_DIR}" 2>/dev/null || true
		exit 1
	fi

	echo "  [+] Insecure filesystem type mount successfully vetoed (-EPERM)."
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
initialize_daemon

verify_insecure_path_mount
verify_secure_path_mount
verify_insecure_fstype_mount
verify_ipc_detachment

echo "  [+] Module 'mount_secure' validation passed."
