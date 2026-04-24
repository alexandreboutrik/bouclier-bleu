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

# Project Paths
: "${MAIN_DIR:="$(pwd)"}"
: "${TESTS_DIR:="${MAIN_DIR}/tests"}"
: "${IMAGE_PATH:="${TESTS_DIR}/bouclier-bleu-test-base.tar.gz"}"
: "${VM_NAME:="bb-manual-shell"}"

# ==========================================
# COMMAND LINE ARGUMENT PARSING
# ==========================================

while [ $# -ne 0 ]; do
	case "${1}" in
	"-help" | "-h" | "help")
		BB_HELP=1
		;;
	"-image")
		if [ -n "${2:-}" ]; then
			IMAGE_PATH="${2}"
			shift
		else
			echo "Error: -image requires a path to the tarball."
			BB_HELP=1
		fi
		;;
	"-name")
		if [ -n "${2:-}" ]; then
			VM_NAME="${2}"
			shift
		else
			echo "Error: -name requires a string argument for the VM name."
			BB_HELP=1
		fi
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
	echo "  ./scripts/incus_shell.sh [-image <path>] [-name <vm_name>]"
	echo
	echo "DESCRIPTION:"
	echo "  Imports a compiled Bouclier Bleu base image (if not cached), launches a"
	echo "  temporary VM, injects the current workspace code, and drops the user"
	echo "  into an interactive root shell for manual compilation and testing."
	echo
	echo "OPTIONS:"
	echo "  -image                  Optional. Path to the exported image tarball."
	echo "                          Defaults to 'tests/bouclier-bleu-test-base.tar.gz'."
	echo "  -name                   Optional. Name of the temporary Incus VM."
	echo "                          Defaults to 'bb-manual-shell'."
	echo "  -help, -h               Display this help message and exit."
	echo
	echo "EXAMPLES:"
	echo "  $ ./scripts/run_shell.sh"
	echo "  $ ./scripts/run_shell.sh -image tests/bb-fedora-43-base.tar.gz -name my-debug-vm"
	exit 0
}

function init_env() {
	if [ ! -f "${IMAGE_PATH}" ]; then
		echo "Error: Image tarball not found at '${IMAGE_PATH}'."
		echo "Please run build_image.sh first or provide a valid path via -image."
		echo
		exit 1
	fi

	if ! command -v sha256sum >/dev/null 2>&1; then
		echo "Error: 'sha256sum' is required but not installed."
		exit 1
	fi

	echo "Starting interactive shell session for Bouclier Bleu..."
}

function nuke_conflicts() {
	echo -e "\n[*] Ensuring clean VM environment..."

	if incus list --format csv -c n | grep -qx "${VM_NAME}"; then
		incus stop "${VM_NAME}" --force >/dev/null 2>&1 || true
		incus delete "${VM_NAME}" --force >/dev/null 2>&1 || true
	fi
}

function setup_and_launch() {
	echo -e "\n[*] Calculating image fingerprint..."
	local FINGERPRINT
	# Incus image fingerprints are exactly the sha256sum of the unified tarball
	FINGERPRINT=$(sha256sum "${IMAGE_PATH}" | awk '{print $1}')

	if incus image info "${FINGERPRINT}" >/dev/null 2>&1; then
		echo "[*] Image already cached in Incus store (Fingerprint: ${FINGERPRINT:0:12})."
		echo "[*] Skipping import to speed up launch."
	else
		echo "[*] Importing image from ${IMAGE_PATH}..."
		incus image import "${IMAGE_PATH}" ||
			{
				echo "Failed to import Incus image. Exiting."
				exit 1
			}
	fi

	echo "[*] Launching interactive VM (${VM_NAME})..."
	incus launch "${FINGERPRINT}" "${VM_NAME}" --vm -c security.secureboot=false -c limits.cpu=4 -c limits.memory=8GB ||
		{
			echo "Failed to launch Incus VM. Exiting."
			exit 1
		}

	echo "[*] Waiting for VM to boot and network to initialize..."
	sleep 5
	while ! incus exec "${VM_NAME}" -- ping -c 1 8.8.8.8 >/dev/null 2>&1; do
		sleep 2
	done
}

function enable_bpf_lsm() {
	echo -e "\n[*] Enforcing BPF LSM boot parameters..."

	# Check if BPF is already in the GRUB config to avoid unnecessary reboots
	if ! incus exec "${VM_NAME}" -- grep -q "bpf" /etc/default/grub 2>/dev/null; then
		incus exec "${VM_NAME}" -- bash -c "
			sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=\"/GRUB_CMDLINE_LINUX_DEFAULT=\"lsm=landlock,lockdown,yama,integrity,apparmor,bpf /' /etc/default/grub
			
			# Distro-agnostic GRUB update
			if command -v update-grub >/dev/null 2>&1; then
				update-grub
			elif command -v grub2-mkconfig >/dev/null 2>&1; then
				grub2-mkconfig -o /boot/grub2/grub.cfg
			fi
		"
		echo "[*] Rebooting VM to apply new kernel parameters..."
		incus restart "${VM_NAME}"

		sleep 5
		while ! incus exec "${VM_NAME}" -- ping -c 1 8.8.8.8 >/dev/null 2>&1; do
			sleep 2
		done
	else
		echo "[*] BPF LSM is already enabled in this image."
	fi
}

function transfer_workspace() {
	echo -e "\n[*] Packaging and injecting source workspace..."
	local TARBALL_PATH="/tmp/bb-manual-src-bundle.tar.gz"

	# Compress the current directory, ignoring heavy/unnecessary folders
	tar --exclude=target --exclude=.git --exclude=*.tar.* -czf "${TARBALL_PATH}" . || {
		echo "Failed to archive host workspace. Exiting."
		exit 1
	}

	incus file push "${TARBALL_PATH}" "${VM_NAME}/root/src-bundle.tar.gz" || {
		echo "Host-to-Guest file injection failed. Exiting."
		rm -f "${TARBALL_PATH}"
		exit 1
	}

	rm -f "${TARBALL_PATH}"

	# Extract inside the VM
	incus exec "${VM_NAME}" -- bash -c "mkdir -p /workspace && tar -xzf /root/src-bundle.tar.gz -C /workspace" || {
		echo "Guest extraction phase failed. Exiting."
		exit 1
	}
}

function provision_default_config() {
	echo "[*] Provisioning default daemon configuration..."
	incus exec "${VM_NAME}" -- bash -c "mkdir -p /etc/bouclier-bleu && cp /workspace/config.toml /etc/bouclier-bleu/config.toml 2>/dev/null || true && chown root:root /etc/bouclier-bleu/config.toml 2>/dev/null || true && chmod 600 /etc/bouclier-bleu/config.toml 2>/dev/null || true"
}

function interactive_shell() {
	echo -e "\n[+] Environment ready! Source code has been loaded into /workspace."
	echo -e "[!] Type 'exit' or press Ctrl+D to leave the VM. Cleanup will trigger automatically.\n"

	# Start interactive bash session inside /workspace and ensure Cargo is in
	# PATH
	incus exec "${VM_NAME}" --cwd /workspace -- bash --login -c "source ~/.cargo/env 2>/dev/null || true; exec bash"
}

function cleanup() {
	echo -e "\n[*] Session ended. Cleaning up temporary VM..."
	incus stop "${VM_NAME}" --force >/dev/null 2>&1 || true
	incus delete "${VM_NAME}" --force >/dev/null 2>&1 || true
	echo "[+] Cleanup complete."
}

# ==========================================
# MAIN EXECUTION
# ==========================================

# Print help and exit if triggered
print_help

init_env
nuke_conflicts
setup_and_launch
enable_bpf_lsm
transfer_workspace
provision_default_config

# Catch unexpected exits (like Ctrl+C) to ensure cleanup always runs
trap cleanup EXIT

interactive_shell

# The script will naturally fall through to the trap when the shell exits
