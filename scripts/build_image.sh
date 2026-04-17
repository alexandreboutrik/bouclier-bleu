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
: "${IMAGE_ALIAS:="bouclier-bleu-test-base"}"
: "${BUILDER_VM:="bb-image-builder"}"
: "${MAIN_DIR:="$(pwd)"}"
: "${TESTS_DIR:="${MAIN_DIR}/tests"}"

USER_ID=$(id -u)
GROUP_ID=$(id -g)

# ==========================================
# INFRASTRUCTURE LIFECYCLE
# ==========================================

function nuke_conflicts() {
	echo -e "\n[*] Purging legacy build artifacts..."

	if incus list --format csv -c n | grep -qx "${BUILDER_VM}"; then
		incus stop "${BUILDER_VM}" --force >/dev/null 2>&1 || true
		incus delete "${BUILDER_VM}" --force >/dev/null 2>&1 || true
	fi

	if incus image list --format csv -c l | grep -q "${IMAGE_ALIAS}"; then
		incus image delete "${IMAGE_ALIAS}" >/dev/null 2>&1 || true
	fi

	# Terminate background operations specific to our testing targets to
	# release locks
	local ops
	ops=$(incus operation list --format csv | grep -E "(${BUILDER_VM}|${IMAGE_ALIAS})" | cut -d',' -f1 || true)
	if [[ -n "$ops" ]]; then
		for op in $ops; do
			incus operation delete "$op" >/dev/null 2>&1 || true
		done
	fi
	sleep 1
}

function provision_vm() {
	echo -e "\n[*] Provisioning Ubuntu 24.04 toolchain environment..."

	if ! incus launch images:ubuntu/24.04 "${BUILDER_VM}" --vm -c security.secureboot=false; then
		# Handle persistent database locks by randomizing the instance
		# namespace
		BUILDER_VM="bb-builder-$(date +%s)"
		incus launch images:ubuntu/24.04 "${BUILDER_VM}" --vm -c security.secureboot=false || exit 1
	fi

	local attempts=0
	while ! incus exec "${BUILDER_VM}" -- echo "ready" >/dev/null 2>&1; do
		attempts=$((attempts + 1))
		[[ ${attempts} -ge 60 ]] && {
			echo "[-] VM Agent initialization timeout."
			exit 1
		}
		sleep 2
	done

	# Inject dependencies required for eBPF object compilation (libelf, zlib)
	# and Rust toolchains
	incus exec "${BUILDER_VM}" -- bash -c "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang llvm pkg-config curl linux-tools-common linux-tools-generic libelf-dev zlib1g-dev"
	incus exec "${BUILDER_VM}" -- bash -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"

	# Flush VFS cache to physical disk to prevent corruption during graceful
	# shutdowns
	incus exec "${BUILDER_VM}" -- sync

	echo "[*] Synchronizing storage and halting VM..."
	incus stop "${BUILDER_VM}"
	sleep 3
}

function publish_and_export() {
	echo -e "\n[*] Generating local VM snapshot..."
	if ! incus publish "${BUILDER_VM}" --alias "${IMAGE_ALIAS}"; then
		echo "[-] Internal image publication failed."
		exit 1
	fi

	echo "[*] Exporting image to ${TESTS_DIR}..."

	mkdir -p "${TESTS_DIR}"
	rm -f "${TESTS_DIR}/${IMAGE_ALIAS}"*

	if incus image export "${IMAGE_ALIAS}" "${TESTS_DIR}/${IMAGE_ALIAS}"; then
		echo "[+] Snapshot exported successfully to ${TESTS_DIR}/"
	else
		echo "[-] Tarball export failed."
		exit 1
	fi
}

function cleanup() {
	echo -e "\n[*] Finalizing state..."
	incus delete "${BUILDER_VM}" --force >/dev/null 2>&1 || true
	incus image delete "${IMAGE_ALIAS}" >/dev/null 2>&1 || true
}

# ==========================================
# ENTRYPOINT
# ==========================================
nuke_conflicts
provision_vm
publish_and_export
cleanup

echo -e "\n[+] Build process finished successfully."
