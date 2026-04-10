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
        { echo "[-] Failed to copy binary to ${BIN_DEST}."; exit 1; }
    chmod +x "${BIN_DEST}"

    # Stage the service file
    cp "${BB_SVC_SRC}" "${SVC_DEST}" ||
        { echo "[-] Failed to copy unit file to ${SVC_DEST}."; exit 1; }

    # Notify systemd of the new unit
    systemctl daemon-reload ||
        { echo "[-] Failed to reload systemd daemon."; exit 1; }
}

function verify_service_start() {
    echo "  [*] Validating service startup..."

    systemctl start bouclier-bleu || 
        { echo "[-] Failed to execute systemctl start."; exit 1; }
    
    # Allow a moment for eBPF to attach and the daemon to fully initialize
    sleep 2

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

    systemctl stop bouclier-bleu || 
        { echo "[-] Failed to execute systemctl stop."; exit 1; }

    if systemctl is-active --quiet bouclier-bleu; then
        echo "[-] Assertion failed: Service is still active after stop command."
        exit 1
    fi

    echo "  [+] Service cleanly shut down."
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

    echo "  [*] Simulating fatal daemon crash (kill -9 ${old_pid})..."
    kill -9 "${old_pid}"

    # The service file specifies RestartSec=5, so we must wait longer than 5
    # seconds to verify that systemd has actually resurrected the process.
    echo "  [*] Awaiting systemd resurrection (waiting 7s)..."
    sleep 7

    if ! systemctl is-active --quiet bouclier-bleu; then
        echo "[-] Assertion failed: Systemd failed to auto-restart the crashed service."
        echo "--- Systemd Journal ---"
        journalctl -u bouclier-bleu -n 20 --no-pager
        echo "-----------------------"
        exit 1
    fi

    local new_pid
    new_pid=$(systemctl show --property MainPID --value bouclier-bleu)

    if [[ "${old_pid}" == "${new_pid}" ]]; then
        echo "[-] Assertion failed: PID did not change. The process may not have crashed."
        exit 1
    fi

    echo "  [+] Service successfully auto-restarted (Old PID: ${old_pid} -> New PID: ${new_pid})."
}

function verify_service_enable() {
    echo "  [*] Validating service enablement (Boot persistency)..."

    systemctl enable bouclier-bleu 2>/dev/null || 
        { echo "[-] Failed to enable service."; exit 1; }

    if ! systemctl is-enabled --quiet bouclier-bleu; then
        echo "[-] Assertion failed: Service is not marked as enabled."
        exit 1
    fi

    echo "  [+] Service cleanly enabled for boot persistence."
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_service

verify_service_start
verify_service_stop
verify_auto_restart
verify_service_enable

echo "  [+] Systemd service validation passed."
