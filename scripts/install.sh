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

# ==========================================
# COMMAND LINE ARGUMENT PARSING
# ==========================================

# Parse arguments
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
	echo "  ./scripts/install.sh [OPTIONS]"
	echo
	echo "DESCRIPTION:"
	echo "  Compiles the Bouclier Bleu binaries from source, installs them to the"
	echo "  host system, provisions the configuration directory, and automatically"
	echo "  detects and enables the appropriate service daemon (systemd or OpenRC)."
	echo
	echo "OPTIONS:"
	echo "  -help, -h               Display this help message and exit."
	echo
	echo "EXAMPLES:"
	echo "  $ ./scripts/install.sh"
	exit 0
}

function init_env() {
	echo "Starting source installation for Bouclier Bleu..."

	# Pre-authenticate sudo to prevent prompt interruptions mid-install
	if ! sudo -v; then
		echo "  [-] Error: Sudo authentication failed. Installation requires root privileges."
		exit 1
	fi
}

function build_project() {
	echo -e "\n➤ Building Bouclier Bleu (Release mode)..."

	pushd "${MAIN_DIR}" >/dev/null || exit 1

	if ! command -v cargo >/dev/null 2>&1; then
		echo "  [-] Error: cargo is not installed. Please install the Rust toolchain."
		exit 1
	fi

	cargo build --release ||
		{
			echo "  [-] Build failed. Exiting."
			exit 1
		}

	echo "  [+] Build successful."
	popd >/dev/null || exit 1
}

function install_binaries() {
	echo -e "\n➤ Installing binaries to /usr/bin/..."

	sudo cp "${MAIN_DIR}/target/release/core" /usr/bin/bouclier-bleu-core ||
		{
			echo "  [-] Failed to install core binary. Exiting."
			exit 1
		}
	sudo chmod 755 /usr/bin/bouclier-bleu-core

	sudo cp "${MAIN_DIR}/target/release/cli" /usr/bin/bouclier-bleu-cli ||
		{
			echo "  [-] Failed to install cli binary. Exiting."
			exit 1
		}
	sudo chmod 755 /usr/bin/bouclier-bleu-cli

	echo "  [+] Binaries installed successfully."
}

function provision_config() {
	echo -e "\n➤ Provisioning configuration directory..."

	sudo mkdir -p /etc/bouclier-bleu
	sudo chmod 755 /etc/bouclier-bleu

	if [ ! -f /etc/bouclier-bleu/config.toml ]; then
		sudo cp "${MAIN_DIR}/config.toml" /etc/bouclier-bleu/config.toml ||
			{
				echo "  [-] Failed to copy default config.toml. Exiting."
				exit 1
			}
		sudo chmod 600 /etc/bouclier-bleu/config.toml
		echo "  [+] Installed default config.toml"
	else
		echo "  [*] config.toml already exists, skipping overwrite."
	fi
}

function install_service() {
	echo -e "\n➤ Detecting Init System and installing service..."

	if [ -d /run/systemd/system ]; then
		echo "  [*] Systemd detected."

		sudo cp "${MAIN_DIR}/systemd/bouclier-bleu.service" /etc/systemd/system/ ||
			{
				echo "  [-] Failed to install systemd service file. Exiting."
				exit 1
			}

		sudo systemctl daemon-reload
		sudo systemctl enable --now bouclier-bleu

		echo "  [+] Systemd service installed and started."
		echo "  [*] Check daemon status with: sudo systemctl status bouclier-bleu"

	elif command -v openrc-run >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then
		echo "  [*] OpenRC detected."

		# Generate a standard OpenRC init script dynamically
		cat <<-'EOF' | sudo tee /etc/init.d/bouclier-bleu >/dev/null
			#!/sbin/openrc-run

			name="Bouclier Bleu Daemon"
			description="Next-Generation Antivirus (NGAV) and EDR"
			command="/usr/bin/bouclier-bleu-core"
			command_background=true
			pidfile="/run/bouclier-bleu.pid"

			depend() {
			    need localmount
			    after bootmisc
			}
		EOF

		sudo chmod +x /etc/init.d/bouclier-bleu
		sudo rc-update add bouclier-bleu default
		sudo rc-service bouclier-bleu start

		echo "  [+] OpenRC service installed and started."
		echo "  [*] Check daemon status with: sudo rc-service bouclier-bleu status"

	else
		echo "  [-] Unsupported or undetectable init system."
		echo "  [*] Please start the daemon manually: sudo /usr/bin/bouclier-bleu-core"
	fi
}

# ==========================================
# MAIN EXECUTION
# ==========================================

print_help
init_env

build_project
install_binaries
provision_config
install_service

echo -e "\nInstallation process finished successfully!"
