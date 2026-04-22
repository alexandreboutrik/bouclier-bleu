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
: "${SKIP_VERIFIER:=0}"

# Resolve the absolute path of the project root
: "${SCRIPT_DIR:="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"}"
: "${MAIN_DIR:="$(dirname "${SCRIPT_DIR}")"}"
: "${BPF_DIR:="${MAIN_DIR}/bpf"}"

# Temporary directory for compiled objects
: "${OUT_DIR:="${BPF_DIR}/.co-re-test"}"

# Compiler configuration (Supports NixOS overrides via shell.nix)
: "${BPF_CLANG:="clang"}"
: "${BPF_CFLAGS:=""}"

# ==========================================
# COMMAND LINE ARGUMENT PARSING
# ==========================================

while [ $# -ne 0 ]; do
	case "${1}" in
	"-help" | "-h" | "help")
		BB_HELP=1
		;;
	"--skip-verifier")
		SKIP_VERIFIER=1
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
	echo "  ./scripts/co-re.sh [OPTIONS]"
	echo
	echo "DESCRIPTION:"
	echo "  Compiles eBPF programs and verifies their CO-RE (Compile Once - Run Everywhere) compliance."
	echo "  This includes checking for BTF sections, CO-RE relocations, and optionally running a dry-run"
	echo "  against the active kernel verifier."
	echo
	echo "OPTIONS:"
	echo "  -help, -h               Display this help message and exit."
	echo "  --skip-verifier         Skip the in-kernel bpftool prog load dry-run (bypasses sudo requirement)."
	echo
	echo "EXAMPLES:"
	echo "  $ ./scripts/co-re.sh"
	echo "  $ ./scripts/co-re.sh --skip-verifier"
	exit 0
}

function init_env() {
	echo "Starting CO-RE compliance checker for Bouclier Bleu..."

	local missing_deps=0
	for cmd in "${BPF_CLANG}" llvm-readelf bpftool; do
		if ! command -v "${cmd}" >/dev/null 2>&1; then
			echo "  [-] Error: Required dependency '${cmd}' is not installed or not in PATH."
			missing_deps=1
		fi
	done

	if [ "${missing_deps}" -eq 1 ]; then
		echo "Exiting."
		exit 1
	fi

	# Create clean temporary directory for objects
	mkdir -p "${OUT_DIR}"
}

function cleanup() {
	# Ensure all isolated test mounts are cleanly unmounted and destroyed,
	# even if the script crashes or is terminated early (Ctrl+C).
	for pin_dir in /tmp/bb_core_test_$$_*; do
		if [ -d "${pin_dir}" ]; then
			sudo umount "${pin_dir}" >/dev/null 2>&1 || true
			rm -rf "${pin_dir}" >/dev/null 2>&1 || true
		fi
	done

	# Clean up compilation artifacts
	if [ -d "${OUT_DIR}" ]; then
		rm -rf "${OUT_DIR}"
	fi
}
# Ensure cleanup runs even if the script crashes or exits early
trap cleanup EXIT

function check_bpf_file() {
	local src_file="$1"
	local base_name="$(basename "${src_file}")"
	local obj_file="${OUT_DIR}/${base_name%.c}.o"

	echo -e "\n➤ Processing ${base_name}..."

	# 1. Compilation
	echo "  [*] Compiling with debug symbols (-g)..."
	local clang_out
	if ! clang_out=$(${BPF_CLANG} -g -O2 -target bpf -D__TARGET_ARCH_x86 -I "${BPF_DIR}/include" ${BPF_CFLAGS} -c "${src_file}" -o "${obj_file}" 2>&1); then
		echo "  [-] Compilation failed."
		echo "      Command output:"
		echo "${clang_out}" | sed 's/^/      /'
		exit 1
	fi

	# 2. BTF Section Verification
	echo "  [*] Verifying BTF sections..."
	local readelf_out
	readelf_out=$(llvm-readelf -S "${obj_file}" 2>&1)

	if ! echo "${readelf_out}" | grep -q '\.BTF'; then
		echo "  [-] Error: Base .BTF section missing."
		echo "      Command output:"
		echo "${readelf_out}" | sed 's/^/      /'
		exit 1
	fi

	local has_ext=1
	if ! echo "${readelf_out}" | grep -q '\.BTF\.ext'; then
		echo "  [~] Notice: .BTF.ext section missing entirely."
		has_ext=0
	else
		echo "  [+] BTF and BTF.ext sections found."
	fi

	# 3. CO-RE Relocation Verification
	if [ "${has_ext}" -eq 1 ]; then
		echo "  [*] Verifying CO-RE relocations..."
		local dump_out
		dump_out=$(bpftool btf dump file "${obj_file}" 2>&1)

		if ! echo "${dump_out}" | grep -q 'CO-RE RELOCS'; then
			echo "  [~] Notice: .BTF.ext exists (for line/func info), but no CO-RE relocations found."
			echo "      (This is completely normal if the module doesn't dereference kernel structs)."
		else
			echo "  [+] CO-RE relocations verified."
		fi
	fi

	# 4. Kernel Verifier Dry-Run
	if [ "${SKIP_VERIFIER}" -eq 1 ]; then
		echo "  [~] Skipping kernel verifier dry-run (--skip-verifier)."
	else
		echo "  [*] Running in-kernel verifier dry-run (requires sudo)..."

		# Create a strictly standard /tmp directory, and mount bpffs DIRECTLY to it
		# This completely bypasses the need for `mkdir` inside the BPF pseudo-filesystem
		local pin_dir="/tmp/bb_core_test_$$_${base_name%.c}"
		mkdir -p "${pin_dir}"

		if ! sudo mount -t bpf bpf "${pin_dir}"; then
			echo "  [-] Error: Failed to mount isolated BPF filesystem to ${pin_dir}."
			exit 1
		fi

		local load_out
		if ! load_out=$(sudo bpftool prog loadall "${obj_file}" "${pin_dir}" 2>&1); then
			# libbpf throws a pinning error for SEC("?...") programs because
			# they are intentionally not loaded into the kernel
			# (autoload=false). If this is the only error, the verifier passed.
			if echo "${load_out}" | grep -q "can't pin program that wasn't loaded"; then
				echo "  [+] Passed kernel verifier (Optional hooks safely skipped)."
			else
				echo "  [-] Error: Kernel verifier (or object loading) rejected the program!"
				echo "      Verifier Log / Error:"
				echo "${load_out}" | sed 's/^/      /'

				# Clean up before exiting on failure
				sudo umount "${pin_dir}" >/dev/null 2>&1 || true
				rm -rf "${pin_dir}" >/dev/null 2>&1 || true
				exit 1
			fi
		fi
		echo "  [+] Passed kernel verifier."

		# Clean up the isolated mount immediately upon success
		sudo umount "${pin_dir}" >/dev/null 2>&1 || true
		rm -rf "${pin_dir}" >/dev/null 2>&1 || true
	fi
}

function process_all() {
	# Find all .bpf.c files in the bpf directory (ignoring subdirectories)
	local bpf_files=($(find "${BPF_DIR}" -maxdepth 1 -type f -name '*.bpf.c'))

	if [ ${#bpf_files[@]} -eq 0 ]; then
		echo "  [-] No .bpf.c files found in ${BPF_DIR}."
		exit 1
	fi

	for file in "${bpf_files[@]}"; do
		check_bpf_file "${file}"
	done
}

# ==========================================
# MAIN EXECUTION
# ==========================================

# Print help and exit if triggered
print_help

init_env
process_all

echo -e "\nAll eBPF programs are successfully compiled and verified!"
