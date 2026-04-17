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
set -euo pipefail

# ==========================================
# DEFAULT VARIABLES & OPTIONS
# ==========================================

# Resolve the absolute path of the project root regardless of where the script is called from
: "${SCRIPT_DIR:="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"}"
: "${MAIN_DIR:="$(dirname "${SCRIPT_DIR}")"}"

# Indentation configuration for Bash (0 = use tabs)
: "${BASH_INDENT:=0}"

# Inline configuration for C/eBPF
CLANG_STYLE="{BasedOnStyle: LLVM, UseTab: Always, IndentWidth: 4, TabWidth: 4}"

# ==========================================
# FUNCTIONS
# ==========================================

function format_rust() {
	echo -e "\n➤ Formatting Rust files..."

	pushd "${MAIN_DIR}" >/dev/null || exit 1

	if command -v cargo >/dev/null 2>&1; then
		# The '--' tells cargo fmt to pass the following arguments directly to
		# rustfmt
		cargo fmt -- --config hard_tabs=true,tab_spaces=4 ||
			{
				echo "Failed to format Rust files via cargo. Exiting."
				exit 1
			}
		echo "  [+] Rust formatting complete."
	else
		echo "  [-] Warning: cargo is not installed. Skipping Rust formatting."
	fi

	popd >/dev/null || exit 1
}

function format_c() {
	echo -e "\n➤ Formatting C and eBPF files..."

	if command -v clang-format >/dev/null 2>&1; then
		find "${MAIN_DIR}/bpf" -type f \( -name '*.c' -o -name '*.h' \) \
			-exec clang-format -style="${CLANG_STYLE}" -i {} + ||
			{
				echo "Failed to format C files. Exiting."
				exit 1
			}

		echo "  [+] C formatting complete."
	else
		echo "  [-] Warning: clang-format is not installed. Skipping C formatting."
	fi
}

function format_bash() {
	echo -e "\n➤ Formatting Bash scripts..."

	if command -v shfmt >/dev/null 2>&1; then
		# Find all .sh files but ignore the target/ dir (Rust build artifacts)
		# and .git/
		find "${MAIN_DIR}" -type f -name '*.sh' ! -path "*/target/*" ! -path "*/.git/*" \
			-exec shfmt -w -i "${BASH_INDENT}" {} + ||
			{
				echo "Failed to format Bash files. Exiting."
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

echo "Starting code formatter for Bouclier Bleu..."

format_rust
format_c
format_bash

echo -e "\nFormatting complete!"
