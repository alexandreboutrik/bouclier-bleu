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
: "${DAEMON_LOG:="/tmp/bb_daemon_rename.log"}"

# We use /var/ because it is in the BPF sensitive directory list
: "${TEST_DIR_SENSITIVE:="/var/bb_rename_test"}"
# We use /tmp/ because it is explicitly excluded from the BPF sensitive list
: "${TEST_DIR_UNMONITORED:="/tmp/bb_rename_test"}"

# A 64-character string with 64 unique characters guarantees an entropy of ~6.0
# (Threshold is ~4.2 / 4300 scaled)
: "${HIGH_ENTROPY_NAME:="0123456789_abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ"}"
: "${LOW_ENTROPY_NAME:="document_backup_v2_final.txt"}"

DAEMON_PID=""

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	if [[ -n "${DAEMON_PID}" ]]; then
		kill -9 "${DAEMON_PID}" 2>/dev/null || true
	fi
	rm -rf "${TEST_DIR_SENSITIVE}" "${TEST_DIR_UNMONITORED}" "${DAEMON_LOG}"
}

trap teardown EXIT

function provision_env() {
	mkdir -p "${TEST_DIR_SENSITIVE}" ||
		{
			echo "[-] Failed to create sensitive test dir."
			exit 1
		}
	mkdir -p "${TEST_DIR_UNMONITORED}" ||
		{
			echo "[-] Failed to create unmonitored test dir."
			exit 1
		}

	for i in {1..8}; do
		touch "${TEST_DIR_SENSITIVE}/base_file_${i}"
	done
	touch "${TEST_DIR_UNMONITORED}/base_file_1"
}

function initialize_daemon() {
	echo "  [*] Initializing Bouclier Bleu Core Daemon..."

	# Pre-emptively enable the module explicitly via CLI in case config.toml
	# doesn't have it yet
	"${BB_CORE_BIN}" >"${DAEMON_LOG}" 2>&1 &
	DAEMON_PID=$!

	# Dynamically wait for the IPC socket to be ready (up to 10 seconds)
	# instead of a hardcoded `sleep 2` which causes TOCTOU races on cold boots.
	local retries=10
	while [[ ! -S "/var/run/bouclier-bleu/control.sock" ]] && [[ "${retries}" -gt 0 ]]; do
		sleep 1
		((retries--))
	done

	if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
		echo "[-] Fatal error: Core daemon failed to bind or crashed instantly."
		echo "--- Daemon Output ---"
		cat "${DAEMON_LOG}"
		echo "---------------------"
		exit 1
	fi

	echo "  [+] Daemon bound successfully (PID: ${DAEMON_PID})."

	"${BB_CLI_BIN}" enable rename_entropy >/dev/null 2>&1 || {
		echo "[-] Failed to enable the module."
		exit 1
	}
}

function verify_low_entropy_rename() {
	echo "  [*] Validating Low-Entropy Rename (Expected: ALLOW)..."

	set +e
	mv "${TEST_DIR_SENSITIVE}/base_file_1" "${TEST_DIR_SENSITIVE}/${LOW_ENTROPY_NAME}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Low entropy rename was blocked (Exit Code: ${exit_code}). False positive detected."
		exit 1
	fi
	echo "  [+] Low-entropy rename successfully allowed."
}

function verify_high_entropy_rename() {
	echo "  [*] Validating High-Entropy Ransomware Rename (Expected: BLOCK/KILL)..."

	set +e
	# Because standard 'mv' spawns a sub-process, the userland daemon will
	# SIGKILL this specific 'mv' instance without crashing our parent test
	# script.
	mv "${TEST_DIR_SENSITIVE}/base_file_2" "${TEST_DIR_SENSITIVE}/${HIGH_ENTROPY_NAME}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	# Exit code 1 indicates standard -EPERM failure from the syscall.
	# Exit code 137 indicates SIGKILL (128 + 9) from our userland daemon before
	# mv could handle the EPERM.
	if [[ "${exit_code}" -eq 0 ]]; then
		echo "[-] Assertion failed: High-entropy rename was permitted! Evasion successful."
		exit 1
	fi
	echo "  [+] High-entropy rename successfully vetoed/killed (Exit Code: ${exit_code})."
}

function verify_short_name_bypass() {
	echo "  [*] Validating Short-Name Length Check (Expected: ALLOW)..."

	# 7 characters: highly random, but falls below the nlen < 8 threshold.
	set +e
	mv "${TEST_DIR_SENSITIVE}/base_file_3" "${TEST_DIR_SENSITIVE}/aB9xZ_Q" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Short file name was incorrectly blocked."
		exit 1
	fi
	echo "  [+] Short-name file successfully ignored by heuristics."
}

function verify_extension_whitelist() {
	echo "  [*] Validating Extension Whitelisting (Expected: ALLOW)..."

	# Target name has extremely high entropy, but ends in '.log'
	set +e
	mv "${TEST_DIR_SENSITIVE}/base_file_4" "${TEST_DIR_SENSITIVE}/${HIGH_ENTROPY_NAME}.log" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Whitelisted extension (.log) was incorrectly blocked."
		exit 1
	fi
	echo "  [+] High-entropy .log file successfully ignored by heuristics."
}

function verify_unmonitored_directory() {
	echo "  [*] Validating Unmonitored Directory Filter (Expected: ALLOW)..."

	# Executing the exact same high-entropy string, but in /tmp/
	set +e
	mv "${TEST_DIR_UNMONITORED}/base_file_1" "${TEST_DIR_UNMONITORED}/${HIGH_ENTROPY_NAME}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Unmonitored directory (/tmp/) triggered heuristic!"
		exit 1
	fi
	echo "  [+] Unmonitored directory successfully ignored by heuristics."
}

function verify_mount_namespace_evasion() {
	echo "  [*] Validating Mount Namespace Evasion (Expected: BLOCK/KILL)..."

	local EVASION_DIR="/tmp/bb_evasion_test"
	mkdir -p "${EVASION_DIR}"

	set +e
	# -U: New user namespace, -r: Map to root, -m: New mount namespace
	# Bind mount the sensitive directory into an unmonitored location and
	# execute rename
	unshare -Ur -m bash -c "
        mount --bind '${TEST_DIR_SENSITIVE}' '${EVASION_DIR}'
        mv '${EVASION_DIR}/base_file_6' '${EVASION_DIR}/${HIGH_ENTROPY_NAME}_evaded' > /dev/null 2>&1
    "
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq 0 ]]; then
		echo "[-] Assertion failed: Mount namespace bind evasion was successful!"
		exit 1
	fi
	echo "  [+] Mount namespace evasion successfully thwarted (Exit Code: ${exit_code})."
}

function verify_cross_directory_evasion() {
	echo "  [*] Validating Cross-Directory Evasion Prevention (Expected: BLOCK/KILL)..."

	# Let the EDR's 2-second sliding window expire so we don't accumulate
	# strikes against the test script.
	sleep 2.1

	# ADVANCED THREAT: Moving a file FROM a protected directory (/var/...)
	# TO an unprotected directory with a high-entropy name.
	# We use a temporary unmonitored directory on the rootfs (/root/)
	# specifically to avoid EXDEV cross-filesystem `cp` fallbacks from /tmp,
	# ensuring the `rename` syscall is actually triggered by the mv command.
	local LOCAL_UNMONITORED="/root/bb_rename_cross_test"
	mkdir -p "${LOCAL_UNMONITORED}"

	set +e
	mv "${TEST_DIR_SENSITIVE}/base_file_7" "${LOCAL_UNMONITORED}/${HIGH_ENTROPY_NAME}_cross" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq 0 ]]; then
		echo "[-] Assertion failed: Cross-directory staging evasion was permitted!"
		exit 1
	fi
	echo "  [+] Cross-directory evasion successfully thwarted (Exit Code: ${exit_code})."
}

function verify_deep_path_handling() {
	echo "  [*] Validating Deep Path (PATH_MAX) Boundary Handling (Expected: BLOCK/KILL)..."

	# Let the EDR's 2-second sliding window expire so we don't accumulate
	# strikes against the test script.
	sleep 2.1

	# Create a deeply nested directory path that intentionally exceeds the old
	# 2048-byte limit but stays within the safe 4096 PATH_MAX boundary.
	local deep_dir="${TEST_DIR_SENSITIVE}"
	for i in {1..12}; do
		# 200 characters per loop * 12 = ~2400 character path length
		deep_dir="${deep_dir}/$(printf 'a%.0s' {1..200})"
	done

	mkdir -p "${deep_dir}"
	touch "${deep_dir}/base_file_deep"

	set +e
	mv "${deep_dir}/base_file_deep" "${deep_dir}/${HIGH_ENTROPY_NAME}" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -eq 0 ]]; then
		echo "[-] Assertion failed: Deep path rename evasion was permitted!"
		exit 1
	fi
	echo "  [+] Deep path safely processed without truncation EFAULTs."
}

function verify_process_tree_eradication() {
	echo "  [*] Validating Asynchronous Process Tree Eradication (Expected: KILL PPID & SIBLINGS)..."

	# Provision target files for the 3 strikes
	touch "${TEST_DIR_SENSITIVE}/strike_1"
	touch "${TEST_DIR_SENSITIVE}/strike_2"
	touch "${TEST_DIR_SENSITIVE}/strike_3"

	# Build the mock orchestrator payload dynamically
	local orchestrator="${TEST_DIR_SENSITIVE}/orchestrator.sh"
	cat <<EOF >"${orchestrator}"
#!/usr/bin/env bash
# Spawn a long-running, benign sibling process (simulating legitimate background work)
sleep 300 &
echo \$! > /tmp/bb_benign_sibling.pid

# Strike 1
mv "${TEST_DIR_SENSITIVE}/strike_1" "${TEST_DIR_SENSITIVE}/${HIGH_ENTROPY_NAME}_1" > /dev/null 2>&1 &
sleep 0.2

# Strike 2
mv "${TEST_DIR_SENSITIVE}/strike_2" "${TEST_DIR_SENSITIVE}/${HIGH_ENTROPY_NAME}_2" > /dev/null 2>&1 &
sleep 0.2

# Strike 3 - This crosses the temporal threshold and triggers the tree kill
mv "${TEST_DIR_SENSITIVE}/strike_3" "${TEST_DIR_SENSITIVE}/${HIGH_ENTROPY_NAME}_3" > /dev/null 2>&1 &

# Wait to be targeted by the Rust daemon's sysinfo eradication loop
sleep 10
EOF
	chmod +x "${orchestrator}"

	# Execute the orchestrator in the background to act as the PPID
	"${orchestrator}" &
	local orchestrator_pid=$!

	# Allow a generous 2 seconds for the Rust daemon to aggregate the strikes
	# and execute the userland remediation sweep.
	sleep 2

	# Assert Orchestrator Decapitation
	if kill -0 "${orchestrator_pid}" 2>/dev/null; then
		echo "[-] Assertion failed: Orchestrator PPID (${orchestrator_pid}) survived 3 strikes!"
		kill -9 "${orchestrator_pid}" 2>/dev/null || true
		exit 1
	fi

	# Assert Sibling Eradication (Collateral cleanup)
	if [[ -f /tmp/bb_benign_sibling.pid ]]; then
		local sibling_pid=$(cat /tmp/bb_benign_sibling.pid)
		if kill -0 "${sibling_pid}" 2>/dev/null; then
			echo "[-] Assertion failed: Benign sibling (${sibling_pid}) was not eradicated!"
			kill -9 "${sibling_pid}" 2>/dev/null || true
			exit 1
		fi
	else
		echo "[-] Test infrastructure failure: Sibling PID not recorded."
		exit 1
	fi

	echo "  [+] Orchestrator and entire process tree successfully eradicated."
}

function verify_ipc_detachment() {
	echo "  [*] Validating dynamic LSM hook detachment..."

	"${BB_CLI_BIN}" disable rename_entropy >/dev/null || {
		echo "[-] RPC invocation failed."
		exit 1
	}

	# Now that it's disabled, the high-entropy rename should succeed in the
	# sensitive directory
	set +e
	mv "${TEST_DIR_SENSITIVE}/base_file_5" "${TEST_DIR_SENSITIVE}/${HIGH_ENTROPY_NAME}_disabled" >/dev/null 2>&1
	local exit_code=$?
	set -e

	if [[ "${exit_code}" -ne 0 ]]; then
		echo "[-] Assertion failed: Disabled module still blocked the rename operation."
		exit 1
	fi

	echo "  [+] Hook cleanly detached. Execution allowed."
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_env
initialize_daemon

verify_low_entropy_rename
verify_high_entropy_rename
verify_short_name_bypass
verify_extension_whitelist
verify_unmonitored_directory
verify_mount_namespace_evasion
verify_cross_directory_evasion
verify_deep_path_handling
verify_process_tree_eradication
verify_ipc_detachment

echo "  [+] Module 'rename_entropy' validation passed."
