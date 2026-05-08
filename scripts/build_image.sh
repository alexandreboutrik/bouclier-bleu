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
: "${TARGET_OS:=""}"
: "${OUTPUT_NAME:="bouclier-bleu-test-base"}"

# OS Version Configuration (Modify these to bump versions in the future)
: "${UBUNTU_VERSION:="24.04"}"
: "${FEDORA_VERSION:="43"}"

# Project Paths
: "${MAIN_DIR:="$(pwd)"}"
: "${TESTS_DIR:="${MAIN_DIR}/tests"}"

# Internal Variables (Populated in init_env)
IMAGE_ALIAS=""
BUILDER_VM=""

# ==========================================
# COMMAND LINE ARGUMENT PARSING
# ==========================================

# If no arguments are passed, trigger the help menu
if [ $# -eq 0 ]; then
	BB_HELP=1
fi

while [ $# -ne 0 ]; do
	case "${1}" in
	"-help" | "-h" | "help")
		BB_HELP=1
		;;
	"-os")
		if [ -n "${2:-}" ]; then
			TARGET_OS="${2}"
			shift
		else
			echo "Error: -os requires an argument ('ubuntu', 'fedora' or 'arch')."
			BB_HELP=1
		fi
		;;
	"-out")
		if [ -n "${2:-}" ]; then
			OUTPUT_NAME="${2}"
			shift
		else
			echo "Error: -out requires a string argument for the image alias."
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
	echo "  ./scripts/build_image.sh -os <ubuntu|fedora|arch> [-out <image_alias>]"
	echo
	echo "DESCRIPTION:"
	echo "  Provisions and exports a base testing VM image for Bouclier Bleu."
	echo "  This script generates a clean environment with all necessary eBPF"
	echo "  and Rust toolchains pre-installed."
	echo
	echo "OPTIONS:"
	echo "  -os                     Required. Target OS distribution ('ubuntu', 'fedora' or 'arch')."
	echo "  -out                    Optional. Output alias for the generated tarball."
	echo "                          Defaults to 'bouclier-bleu-test-base'."
	echo "  -help, -h               Display this help message and exit."
	echo
	echo "EXAMPLES:"
	echo "  $ ./scripts/build_image.sh -os ubuntu"
	echo "  $ ./scripts/build_image.sh -os fedora -out bb-fedora-43-base"
	exit 0
}

function init_env() {
	if [ -z "${TARGET_OS}" ]; then
		echo "Error: Target OS (-os) is strictly required."
		echo
		BB_HELP=1 print_help
		exit 1
	fi

	if [[ "${TARGET_OS}" != "ubuntu" ]] && [[ "${TARGET_OS}" != "fedora" ]] && [[ "${TARGET_OS}" != "arch" ]]; then
		echo "Error: Unsupported OS '${TARGET_OS}'."
		exit 1
	fi

	IMAGE_ALIAS="${OUTPUT_NAME}"
	BUILDER_VM="bb-image-builder-${TARGET_OS}"

	echo "Starting automated image builder for Bouclier Bleu (${TARGET_OS})..."
}

function nuke_conflicts() {
	echo -e "\n[*] Purging legacy build artifacts and freeing space..."

	# Aggressively find and delete ANY instance starting with 'bb-' or
	# 'bouclier-'
	local orphaned_vms
	orphaned_vms=$(incus list --format csv -c n | grep -E '^(bb-|bouclier-)' || true)
	if [ -n "$orphaned_vms" ]; then
		for vm in $orphaned_vms; do
			echo "    Force deleting orphaned VM: $vm"
			incus stop "$vm" --force >/dev/null 2>&1 || true
			incus delete "$vm" --force >/dev/null 2>&1 || true
		done
	fi

	# Aggressively find and delete ANY image alias starting with 'bb-' or
	# 'bouclier-'
	local orphaned_images
	orphaned_images=$(incus image list --format csv -c l | grep -E '^(bb-|bouclier-)' || true)
	if [ -n "$orphaned_images" ]; then
		for img in $orphaned_images; do
			echo "    Removing orphaned image: $img"
			incus image rm "$img" >/dev/null 2>&1 || true
		done
	fi
}

function provision_environment() {
	echo -e "\n[*] Provisioning base VM for ${TARGET_OS}..."

	local incus_image=""
	local setup_cmds=""

	# OS-Specific Package Mapping
	if [[ "${TARGET_OS}" == "ubuntu" ]]; then
		incus_image="images:ubuntu/${UBUNTU_VERSION}/cloud"
		setup_cmds="apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang llvm pkg-config curl linux-tools-common linux-tools-generic libelf-dev zlib1g-dev attr"
	elif [[ "${TARGET_OS}" == "fedora" ]]; then
		incus_image="images:fedora/${FEDORA_VERSION}/cloud"
		setup_cmds="dnf install -y @development-tools clang llvm pkgconf-pkg-config curl bpftool elfutils-libelf-devel zlib-devel attr grubby"
	elif [[ "${TARGET_OS}" == "arch" ]]; then
		incus_image="images:archlinux/current/cloud"
		setup_cmds="pacman-key --init && pacman-key --populate archlinux && pacman -Sy --noconfirm reflector && reflector --latest 10 --protocol https --sort rate --save /etc/pacman.d/mirrorlist && pacman -Syu --noconfirm base-devel clang llvm pkgconf curl bpf libelf zlib attr"
	fi

	# Added -d root,size=20GiB to ensure DNF and Rustup have enough extraction space
	incus launch "${incus_image}" "${BUILDER_VM}" --vm -c security.secureboot=false -c limits.cpu=4 -c limits.memory=8GB -d root,size=20GiB ||
		{
			echo "Failed to launch Incus VM. Exiting."
			exit 1
		}

	echo "[*] Waiting for Incus VM agent to initialize..."
	while ! incus exec "${BUILDER_VM}" -- true >/dev/null 2>&1; do
		sleep 2
	done

	echo "[*] Waiting for cloud-init to finish provisioning and resizing disks..."
	incus exec "${BUILDER_VM}" -- cloud-init status --wait || true

	echo "[*] Masking background updates to prevent BTF corruption..."
	if [[ "${TARGET_OS}" == "ubuntu" ]]; then
		incus exec "${BUILDER_VM}" -- systemctl stop unattended-upgrades.service apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
		incus exec "${BUILDER_VM}" -- systemctl mask unattended-upgrades.service apt-daily.service apt-daily-upgrade.service
	fi

	echo "[*] Injecting build dependencies..."
	incus exec "${BUILDER_VM}" -- bash -c "${setup_cmds}" ||
		{
			echo "Failed to install OS dependencies. Exiting."
			exit 1
		}

	incus exec "${BUILDER_VM}" -- bash -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y" ||
		{
			echo "Failed to install Rust toolchain. Exiting."
			exit 1
		}

	# Flush VFS cache to physical disk to prevent corruption during graceful shutdowns
	incus exec "${BUILDER_VM}" -- sync

	echo "[*] Synchronizing storage and halting VM..."
	incus stop "${BUILDER_VM}" ||
		{
			echo "Failed to stop builder VM safely. Exiting."
			exit 1
		}
	sleep 3
}

function publish_and_export() {
	echo -e "\n[*] Generating local VM snapshot..."
	incus publish "${BUILDER_VM}" --alias "${IMAGE_ALIAS}" ||
		{
			echo "Internal image publication failed. Exiting."
			exit 1
		}

	echo "[*] Exporting image to ${TESTS_DIR}..."

	mkdir -p "${TESTS_DIR}"
	rm -f "${TESTS_DIR}/${IMAGE_ALIAS}"*

	incus image export "${IMAGE_ALIAS}" "${TESTS_DIR}/${IMAGE_ALIAS}" ||
		{
			echo "Tarball export failed. Exiting."
			exit 1
		}

	echo "[+] Snapshot exported successfully to ${TESTS_DIR}/"
}

function cleanup() {
	echo -e "\n[*] Finalizing state..."
	incus delete "${BUILDER_VM}" --force >/dev/null 2>&1 || true
	incus image rm "${IMAGE_ALIAS}" >/dev/null 2>&1 || true
}

# ==========================================
# MAIN EXECUTION
# ==========================================

# Print help and exit if triggered
print_help

init_env
nuke_conflicts
provision_environment
publish_and_export
cleanup

echo -e "\n[+] Image build complete: ${IMAGE_ALIAS}.tar.gz"
