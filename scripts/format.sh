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
: "${BB_MODE:=""}"

# Resolve the absolute path of the project root
: "${SCRIPT_DIR:="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"}"
: "${MAIN_DIR:="$(dirname "${SCRIPT_DIR}")"}"

# Formatting rules (4-width tabs)
: "${BASH_INDENT:=0}"
CLANG_STYLE="{BasedOnStyle: LLVM, UseTab: Always, IndentWidth: 4, TabWidth: 4}"

# Tool flags (populated based on mode)
RUST_FLAGS=""
CLANG_FLAGS=""
SHFMT_FLAGS=""

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
	"apply")
		BB_MODE="apply"
		;;
	"check")
		BB_MODE="check"
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
	echo "  ./scripts/format.sh [MODE] [OPTIONS]"
	echo
	echo "MODES:"
	echo "  apply                   Format files in-place."
	echo "  check                   Check if files are formatted correctly (for CI/CD)."
	echo
	echo "OPTIONS:"
	echo "  -help, -h               Display this help message and exit."
	echo
	echo "EXAMPLES:"
	echo "  $ ./scripts/format.sh apply"
	echo "  $ ./scripts/format.sh check"
	exit 0
}

function init_env() {
	if [ -z "${BB_MODE}" ]; then
		echo "Error: Mode not specified. Use 'apply' or 'check'. Exiting."
		echo
		BB_HELP=1 print_help
		exit 1
	fi

	echo "Starting code formatter for Bouclier Bleu..."

	if [ "${BB_MODE}" == "check" ]; then
		echo "Mode: CHECK (No files will be modified)"
		RUST_FLAGS="--check"
		CLANG_FLAGS="--dry-run -Werror"
		SHFMT_FLAGS="-d"
	else
		echo "Mode: APPLY (Files will be modified in-place)"
		RUST_FLAGS=""
		CLANG_FLAGS="-i"
		SHFMT_FLAGS="-w"
	fi
}

function format_rust() {
	echo -e "\n➤ Processing Rust files..."

	pushd "${MAIN_DIR}" >/dev/null || exit 1

	if command -v cargo >/dev/null 2>&1; then
		cargo fmt -- ${RUST_FLAGS} --config hard_tabs=true,tab_spaces=4 ||
			{
				echo "Rust formatting failed. Exiting."
				exit 1
			}
		echo "  [+] Rust formatting complete."
	else
		echo "  [-] Warning: cargo is not installed. Skipping Rust formatting."
	fi

	popd >/dev/null || exit 1
}

function format_c() {
	echo -e "\n➤ Processing C and eBPF files..."

	if command -v clang-format >/dev/null 2>&1; then
		find "${MAIN_DIR}/bpf" -type f \( -name '*.c' -o -name '*.h' \) \
			-exec clang-format -style="${CLANG_STYLE}" ${CLANG_FLAGS} {} + ||
			{
				echo "C/eBPF formatting failed. Exiting."
				exit 1
			}

		echo "  [+] C formatting complete."
	else
		echo "  [-] Warning: clang-format is not installed. Skipping C formatting."
	fi
}

function format_bash() {
	echo -e "\n➤ Processing Bash scripts..."

	if command -v shfmt >/dev/null 2>&1; then
		find "${MAIN_DIR}" -type f -name '*.sh' ! -path "*/target/*" ! -path "*/.git/*" \
			-exec shfmt ${SHFMT_FLAGS} -i "${BASH_INDENT}" {} + ||
			{
				echo "Bash formatting failed. Exiting."
				exit 1
			}

		echo "  [+] Bash formatting complete."
	else
		echo "  [-] Warning: shfmt is not installed. Skipping Bash formatting."
	fi
}

# ==========================================
# MAIN EXECUTION
# ==========================================

# Print help and exit if triggered
print_help

# Standard execution flow
init_env
format_rust
format_c
format_bash

echo -e "\nFormatting process finished successfully!"
