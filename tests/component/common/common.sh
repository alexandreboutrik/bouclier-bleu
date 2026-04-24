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

# Note: We omit `set -uo pipefail` here to inherit the caller's strict mode settings.

# ==========================================
# COMMON CONFIGURATION
# ==========================================
: "${BB_CORE_BIN:="./target/release/core"}"
: "${BB_CLI_BIN:="./target/release/cli"}"
: "${DAEMON_LOG:="/tmp/bb_daemon.log"}"

# Global state for the daemon process, accessible by the calling script
DAEMON_PID=""

# ==========================================
# COMMON FUNCTIONS
# ==========================================

# Initializes the core daemon and optionally enables a specific module.
# Usage: initialize_daemon [module_name]
function initialize_daemon() {
	local target_module="${1:-}"

	echo "  [*] Initializing Bouclier Bleu Core Daemon..."

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

	# Pre-emptively enforce module via CLI to ensure active state
	if [[ -n "${target_module}" ]]; then
		"${BB_CLI_BIN}" enable "${target_module}" >/dev/null 2>&1 || {
			echo "[-] Failed to enable the module: ${target_module}"
			exit 1
		}
	fi
}

# Safely terminates the daemon if it is running.
function cleanup_daemon() {
	if [[ -n "${DAEMON_PID:-}" ]]; then
		kill -9 "${DAEMON_PID}" 2>/dev/null || true
	fi
}
