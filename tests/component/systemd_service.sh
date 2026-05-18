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
: "${BB_SVC_SRC:="./systemd/bouclier-bleu.service"}"
: "${SVC_DEST:="/etc/systemd/system/bouclier-bleu.service"}"
: "${BIN_DEST:="/usr/bin/bouclier-bleu-core"}"

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	# Stop and disable to ensure a clean state for subsequent tests
	systemctl stop bouclier-bleu 2>/dev/null || true
	systemctl disable bouclier-bleu 2>/dev/null || true

	rm -f "${SVC_DEST}" "${BIN_DEST}"
	systemctl daemon-reload
}

# Ensure deterministic teardown on exit or failure
trap teardown EXIT

function provision_service() {
	echo "  [*] Provisioning Systemd service environment..."

	if [[ ! -f "${BB_CORE_BIN}" ]]; then
		echo "[-] Failed to locate compiled core binary at ${BB_CORE_BIN}."
		exit 1
	fi

	if [[ ! -f "${BB_SVC_SRC}" ]]; then
		echo "[-] Failed to locate systemd unit file at ${BB_SVC_SRC}."
		exit 1
	fi

	# Stage the binary to the absolute path expected by the service file
	cp "${BB_CORE_BIN}" "${BIN_DEST}" ||
		{
			echo "[-] Failed to copy binary to ${BIN_DEST}."
			exit 1
		}
	chmod +x "${BIN_DEST}"

	# Stage the service file
	cp "${BB_SVC_SRC}" "${SVC_DEST}" ||
		{
			echo "[-] Failed to copy unit file to ${SVC_DEST}."
			exit 1
		}

	# Notify systemd of the new unit
	systemctl daemon-reload ||
		{
			echo "[-] Failed to reload systemd daemon."
			exit 1
		}
}

function verify_service_start() {
	echo "  [*] Validating service startup..."

	systemctl start bouclier-bleu ||
		{
			echo "[-] Failed to execute systemctl start."
			exit 1
		}

	# Dynamically wait for the IPC socket to be ready (up to 10 seconds)
	# instead of a hardcoded `sleep 2` which causes TOCTOU races on cold boots.
	local retries=10
	while [[ ! -S "/var/run/bouclier-bleu/control.sock" ]] && [[ "${retries}" -gt 0 ]]; do
		sleep 1
		((retries--))
	done

	if ! systemctl is-active --quiet bouclier-bleu; then
		echo "[-] Assertion failed: Service is not active after start command."
		echo "--- Systemd Journal ---"
		journalctl -u bouclier-bleu -n 20 --no-pager
		echo "-----------------------"
		exit 1
	fi

	echo "  [+] Service started successfully."
}

function verify_service_stop() {
	echo "  [*] Validating service shutdown..."

	local start_time=$(date +%s)
	systemctl stop bouclier-bleu || exit 1
	local end_time=$(date +%s)

	local duration=$((end_time - start_time))

	if [[ $duration -gt 5 ]]; then
		echo "[-] Assertion failed: Service took too long to stop (${duration}s). Possible signal deadlock!"
		exit 1
	fi

	echo "  [+] Service cleanly shut down in ${duration}s."
}

function verify_auto_restart() {
	echo "  [*] Validating crash recovery (Restart=on-failure)..."

	systemctl start bouclier-bleu
	sleep 2

	local old_pid
	old_pid=$(systemctl show --property MainPID --value bouclier-bleu)

	if [[ -z "${old_pid}" ]] || [[ "${old_pid}" == "0" ]]; then
		echo "[-] Failed to resolve MainPID for the service."
		exit 1
	fi

	echo "  [*] Simulating fatal daemon crash (kill -6 ${old_pid})..."
	kill -6 "${old_pid}"

	echo "  [*] Awaiting systemd resurrection (polling up to 15s)..."

	local new_pid=""
	local retries=15

	while [[ "${retries}" -gt 0 ]]; do
		new_pid=$(systemctl show --property MainPID --value bouclier-bleu)

		# Check if the service is active AND the PID has actually changed to a
		# valid new process
		if systemctl is-active --quiet bouclier-bleu && [[ -n "${new_pid}" ]] && [[ "${new_pid}" != "0" ]] && [[ "${new_pid}" != "${old_pid}" ]]; then
			break
		fi
		sleep 1
		((retries--))
	done

	if [[ "${retries}" -eq 0 ]]; then
		echo "[-] Assertion failed: Systemd failed to auto-restart the crashed service within 15 seconds."
		echo "--- Systemd Journal ---"
		journalctl -u bouclier-bleu -n 25 --no-pager
		echo "-----------------------"
		exit 1
	fi

	echo "  [+] Service successfully auto-restarted (Old PID: ${old_pid} -> New PID: ${new_pid})."
}

function verify_service_enable() {
	echo "  [*] Validating service enablement (Boot persistency)..."

	systemctl enable bouclier-bleu 2>/dev/null ||
		{
			echo "[-] Failed to enable service."
			exit 1
		}

	if ! systemctl is-enabled --quiet bouclier-bleu; then
		echo "[-] Assertion failed: Service is not marked as enabled."
		exit 1
	fi

	echo "  [+] Service cleanly enabled for boot persistence."
}

function verify_memlock_limit() {
	echo "  [*] Validating LimitMEMLOCK=infinity..."

	local pid=$(systemctl show --property MainPID --value bouclier-bleu)
	local memlock=$(grep "Max locked memory" /proc/$pid/limits | awk '{print $4}')

	if [[ "$memlock" != "unlimited" ]]; then
		echo "[-] Assertion failed: MEMLOCK is not unlimited (Current: $memlock)."
		exit 1
	fi
	echo "  [+] LimitMEMLOCK successfully set to unlimited."
}

function verify_runtime_directory() {
	echo "  [*] Validating RuntimeDirectory permissions..."

	local dir_perms=$(stat -c "%a" /run/bouclier-bleu)

	if [[ "$dir_perms" != "700" ]]; then
		echo "[-] Assertion failed: /run/bouclier-bleu has incorrect permissions ($dir_perms != 700)."
		exit 1
	fi
	echo "  [+] RuntimeDirectory permissions cleanly enforced."
}

function verify_systemd_sandbox() {
	echo "  [*] Validating Systemd Sandbox Exposure Score..."

	# Isolate the exact line containing the final score to avoid matching
	# random decimals
	# systemd-analyze outputs a score like "1.2 OK" or "9.5 UNSAFE"
	local score=$(systemd-analyze security bouclier-bleu.service | grep "Overall exposure level" | grep -oP '\d+\.\d+')

	if [[ -z "$score" ]]; then
		echo "[-] Assertion failed: Could not parse security score from systemd-analyze."
		exit 1
	fi

	# Assert that the score is strictly less than 6.0 (it's 5.5 currently)
	if awk -v s="$score" 'BEGIN { exit !(s > 6.0) }'; then
		echo "[-] Assertion failed: Security exposure score is too high ($score). Sandbox degraded!"
		exit 1
	fi

	echo "  [+] Sandbox exposure score is secure ($score)."
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_service

verify_service_start
verify_service_stop
verify_auto_restart
verify_service_enable
verify_memlock_limit
verify_runtime_directory
verify_systemd_sandbox

echo "  [+] Systemd service validation passed."
