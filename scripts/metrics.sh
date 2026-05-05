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

# Exit immediately on uninitialized variables or pipe failures
set -uo pipefail

# ==========================================
# DEFAULT VARIABLES & OPTIONS
# ==========================================
: "${BB_HELP:=0}"

# Resolve the absolute path of the project root
: "${SCRIPT_DIR:="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"}"
: "${MAIN_DIR:="$(dirname "${SCRIPT_DIR}")"}"
: "${BPF_DIR:="${MAIN_DIR}/bpf"}"
: "${MODULES_DIR:="${MAIN_DIR}/modules/src"}"
: "${TESTS_DIR:="${MAIN_DIR}/tests"}"
: "${SOCKET_PATH:="/var/run/bouclier-bleu/control.sock"}"

# Global Metrics
HOOKS_COUNT=0
DETECTORS_COUNT=0
TESTS_COUNT=0
USER_MEM="N/A"
BPF_MEM="N/A"
TOTAL_MEM="N/A"

# Detail strings for the report
TESTS_DETAILS=""
MODULE_MEM_DETAILS=""

# Daemon State
DAEMON_PID=""
DAEMON_STARTED_BY_SCRIPT=0

# ==========================================
# COMMAND LINE ARGUMENT PARSING
# ==========================================

while [ $# -ne 0 ]; do
	case "${1}" in
	"-help" | "-h" | "help")
		BB_HELP=1
		;;
	*)
		echo "Error: Unknown argument '${1}'"
		echo
		BB_HELP=1
		;;
	esac
	shift
done

# ==========================================
# FUNCTIONS
# ==========================================

function print_help() {
	if [ "${BB_HELP}" != "1" ]; then return; fi

	echo "USAGE:"
	echo "  ./scripts/metrics.sh [OPTIONS]"
	echo
	echo "DESCRIPTION:"
	echo "  Calculates and outputs key project metrics including the number of eBPF hooks,"
	echo "  userland detectors, test counts, and the active memory footprint (Userland RSS"
	echo "  + kernel-space eBPF maps) of the daemon."
	echo
	echo "OPTIONS:"
	echo "  -help, -h               Display this help message and exit."
	echo
	echo "EXAMPLES:"
	echo "  $ ./scripts/metrics.sh"
	exit 0
}

function cleanup() {
	if [ "${DAEMON_STARTED_BY_SCRIPT}" -eq 1 ] && [ -n "${DAEMON_PID}" ]; then
		echo "  [*] Stopping temporary daemon (PID ${DAEMON_PID})..."
		# Kill the actual core process, not the sleep pipe
		sudo kill -TERM "${DAEMON_PID}" 2>/dev/null || true
	fi
}
# Ensure daemon is stopped even if the script is interrupted
trap cleanup EXIT

function init_env() {
	echo "Calculating metrics for Bouclier Bleu..."
}

function gather_static_metrics() {
	echo -e "\n➤ Gathering Static Metrics..."

	# 1. eBPF Hooks
	if [ -d "${BPF_DIR}" ]; then
		local explicit_hooks
		explicit_hooks=$(grep -hoE 'SEC\("[^"]+"\)' "${BPF_DIR}"/*.bpf.c 2>/dev/null | grep -vE '(license|\.maps)' | wc -l | tr -d ' ')

		local macro_hooks=0
		local invoked_macros
		invoked_macros=$(grep -hoE 'BOUCLIER_GENERATE_[A-Z_]+_HOOKS?' "${BPF_DIR}"/*.bpf.c 2>/dev/null | sort -u || true)

		for macro in ${invoked_macros}; do
			local uses
			uses=$(grep -hoE "${macro}\(" "${BPF_DIR}"/*.bpf.c 2>/dev/null | wc -l | tr -d ' ')

			local secs_in_def
			secs_in_def=$(awk "/#define ${macro}/ {flag=1} flag && /SEC\(/ && !/license/ && !/\\.maps/ {count++} flag && !/\\\\$/ {flag=0} END {print count+0}" "${BPF_DIR}"/headers/*.h 2>/dev/null)

			macro_hooks=$((macro_hooks + (uses * secs_in_def)))
		done

		HOOKS_COUNT=$((explicit_hooks + macro_hooks))
		echo "  [+] Found ${HOOKS_COUNT} eBPF Hooks."
	else
		echo "  [-] eBPF directory not found at ${BPF_DIR}"
	fi

	# 2. Detectors
	if [ -d "${MODULES_DIR}" ]; then
		DETECTORS_COUNT=$(find "${MODULES_DIR}" -maxdepth 1 -type f -name '*.rs' ! -name 'lib.rs' | wc -l | tr -d ' ')
		echo "  [+] Found ${DETECTORS_COUNT} Detectors/Modules."

		# 2.2. MITRE ATT&CKs covered
		UNIQUE_MITRE_COUNT=$(find "${MODULES_DIR}" -maxdepth 1 -type f -name "*.rs" -exec grep -h -oP 'mitre:\s*\[\K[^\]]*' {} + |
			grep -oP '"\K[^"]+(?=")' | sort -u | wc -l)

		echo "  [+] Found ${UNIQUE_MITRE_COUNT} MITRE ATT&CK techniques covered."
	else
		echo "  [-] Modules directory not found at ${MODULES_DIR}"
	fi

	# 3. Tests
	# First, count inline Unit Tests in the source directories by looking for
	# the #[test] macro
	local unit_count=0
	unit_count=$(grep -rhoE '^\s*#\[test\]' "${MAIN_DIR}/modules/src" "${MAIN_DIR}/core/src" "${MAIN_DIR}/cli/src" 2>/dev/null | wc -l | tr -d ' ')

	if [ "${unit_count}" -gt 0 ]; then
		TESTS_COUNT=$((TESTS_COUNT + unit_count))
		TESTS_DETAILS="${TESTS_DETAILS}\n      - unit: ${unit_count}"
	fi

	# Then count the external test suites
	if [ -d "${TESTS_DIR}" ]; then
		for category in component integration fuzzing benchmark threat; do
			local cat_dir="${TESTS_DIR}/${category}"
			if [ -d "${cat_dir}" ]; then
				local count
				# Refined to only count actual test scripts/code to avoid
				# counting READMEs or data files
				count=$(find "${cat_dir}" -type f \( -name '*.rs' -o -name '*.sh' \) 2>/dev/null | wc -l | tr -d ' ')
				TESTS_COUNT=$((TESTS_COUNT + count))
				if [ "${count}" -gt 0 ]; then
					TESTS_DETAILS="${TESTS_DETAILS}\n      - ${category}: ${count}"
				fi
			fi
		done
		echo "  [+] Found ${TESTS_COUNT} Tests."
	else
		echo "  [-] Tests directory not found at ${TESTS_DIR}"
	fi
}

function gather_memory_metrics() {
	echo -e "\n➤ Gathering Memory Metrics..."

	# Pre-authenticate sudo in the foreground
	if ! sudo -v; then
		echo "  [-] Error: Sudo authentication failed. Cannot gather memory metrics."
		return
	fi

	local core_pid
	core_pid=$(pgrep -x "core" | head -n 1 || true)

	if [ -z "${core_pid}" ]; then
		local core_bin="${MAIN_DIR}/target/release/core"
		if [ ! -x "${core_bin}" ]; then
			echo "  [-] Error: Executable not found at ${core_bin}."
			return
		fi

		echo "  [*] Daemon not running. Removing any stale IPC sockets..."
		sudo rm -f "${SOCKET_PATH}"

		echo "  [*] Starting daemon temporarily in the background..."
		# Pipe an infinite sleep into the daemon to prevent it from exiting due
		# to stdin EOF.
		# Redirect all output to a log file so we can debug if it fails again
		(sleep infinity | sudo "${core_bin}" >/tmp/bb_core_metrics.log 2>&1) &
		DAEMON_STARTED_BY_SCRIPT=1

		# Wait briefly for the OS to register the process
		sleep 2
		core_pid=$(pgrep -x "core" | head -n 1 || true)

		if [ -z "${core_pid}" ]; then
			echo "  [-] Error: Daemon crashed immediately after starting."
			echo "      Please inspect the log: cat /tmp/bb_core_metrics.log"
			return
		fi

		# Register the actual daemon PID for cleanup
		DAEMON_PID="${core_pid}"

		echo -n "  [*] Waiting for daemon socket to initialize"
		local timeout=30
		local elapsed=0
		# FIX: Use 'sudo test -S' so we can check root-owned sockets!
		while ! sudo test -S "${SOCKET_PATH}" && [ "${elapsed}" -lt "${timeout}" ]; do
			sleep 1
			elapsed=$((elapsed + 1))
			echo -n "."
		done
		echo

		if ! sudo test -S "${SOCKET_PATH}"; then
			echo "  [-] Error: Daemon running (PID ${core_pid}) but failed to bind socket."
			echo "      Please inspect the log: cat /tmp/bb_core_metrics.log"
			return
		fi
		# Brief pause to ensure all maps are fully populated
		sleep 1
	else
		echo "  [+] Daemon is already running (PID ${core_pid})."
	fi

	# 1. User-Space Memory (VmRSS)
	# Use sudo here! Regular users cannot read memory status of root processes.
	local vm_rss_kb
	vm_rss_kb=$(sudo grep VmRSS "/proc/${core_pid}/status" 2>/dev/null | awk '{print $2}' || echo "0")
	if [ "${vm_rss_kb}" -gt 0 ]; then
		USER_MEM="${vm_rss_kb} kB"
	else
		USER_MEM="Unknown"
		vm_rss_kb=0
	fi
	echo "  [+] Captured Userland Memory (PID ${core_pid}): ${USER_MEM}"

	# 2. Kernel-Space Memory (eBPF Maps)
	if ! command -v jq >/dev/null 2>&1 || ! command -v bpftool >/dev/null 2>&1; then
		echo "  [-] Missing 'jq' or 'bpftool'. Cannot calculate eBPF map memory."
		return
	fi

	local cli_bin="${MAIN_DIR}/target/release/cli"
	local active_modules=""

	if [ -x "${cli_bin}" ]; then
		active_modules=$(sudo "${cli_bin}" list 2>/dev/null | awk '/\[ACTIVE\]|\[INACTIVE\]/ {print $2}' | tr '\n' '|' | sed 's/|$//')
	fi

	if [ -z "${active_modules}" ]; then
		active_modules=$(find "${MODULES_DIR}" -maxdepth 1 -name '*.rs' ! -name 'lib.rs' -exec basename {} .rs \; | tr '\n' '|' | sed 's/|$//')
	fi

	local regex="^(${active_modules})"
	local total_bpf_bytes=0

	# Calculate deduplicated total memory across all active modules
	local all_map_ids
	all_map_ids=$(sudo bpftool prog show -j | jq -r '.[] | select(.name | test("'"${regex}"'")) | .map_ids[]?' 2>/dev/null | sort -u)

	for id in ${all_map_ids}; do
		local mem
		mem=$(sudo bpftool map show id "${id}" -j | jq '.bytes_memlock' 2>/dev/null)
		if [[ "${mem}" =~ ^[0-9]+$ ]]; then
			total_bpf_bytes=$((total_bpf_bytes + mem))
		fi
	done

	local bpf_mem_kb=$((total_bpf_bytes / 1024))
	BPF_MEM="${bpf_mem_kb} kB"
	echo "  [+] Captured Kernel-Space eBPF Memory: ${BPF_MEM}"

	# Calculate Total Footprint
	TOTAL_MEM="$((vm_rss_kb + bpf_mem_kb)) kB"

	# Calculate Per-Module Breakdown
	local mod_list
	mod_list=$(echo "${active_modules}" | tr '|' ' ')

	for mod in ${mod_list}; do
		local mod_map_ids
		mod_map_ids=$(sudo bpftool prog show -j | jq -r '.[] | select(.name | test("^('"${mod}"')")) | .map_ids[]?' 2>/dev/null | sort -u)

		local mod_total_bytes=0
		for id in ${mod_map_ids}; do
			local mem
			mem=$(sudo bpftool map show id "${id}" -j | jq '.bytes_memlock' 2>/dev/null)
			if [[ "${mem}" =~ ^[0-9]+$ ]]; then
				mod_total_bytes=$((mod_total_bytes + mem))
			fi
		done

		if [ "${mod_total_bytes}" -gt 0 ]; then
			local mod_mem_kb=$((mod_total_bytes / 1024))
			MODULE_MEM_DETAILS="${MODULE_MEM_DETAILS}\n      - ${mod}: ${mod_mem_kb} kB"
		fi
	done
}

function print_report() {
	echo
	echo -e "\033[1;34m==================================================\033[0m"
	echo -e "\033[1;37m        Bouclier Bleu - Core Metrics\033[0m"
	echo -e "\033[1;34m==================================================\033[0m"
	echo -e "  \033[1;32meBPF Hooks\033[0m        : ${HOOKS_COUNT}"
	echo -e "  \033[1;36mDetectors\033[0m         : ${DETECTORS_COUNT}"
	echo -e "  \033[1;38;5;208mMITRE Coverage\033[0m    : ${UNIQUE_MITRE_COUNT}"
	echo -e "  \033[1;35mTests\033[0m             : ${TESTS_COUNT}${TESTS_DETAILS}"
	echo -e "\033[1;34m--------------------------------------------------\033[0m"
	echo -e "  \033[1;33mUserland Mem\033[0m      : ${USER_MEM}"
	echo -e "  \033[1;33meBPF Maps Mem\033[0m     : ${BPF_MEM}${MODULE_MEM_DETAILS}"
	echo -e "\033[1;34m--------------------------------------------------\033[0m"
	echo -e "  \033[1;31mTotal Footprint\033[0m   : ${TOTAL_MEM}"
	echo -e "\033[1;34m==================================================\033[0m"
	echo
}

# ==========================================
# MAIN EXECUTION
# ==========================================

print_help
init_env

gather_static_metrics
gather_memory_metrics
print_report
