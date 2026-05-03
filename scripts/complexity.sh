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
: "${ANALYSIS_DIR:="${MAIN_DIR}/target/code-analysis"}"

# The Rust-related directories to scan
TARGET_DIRS=("cli" "core" "modules" "xtask")

# ==========================================
# COMMAND LINE ARGUMENT PARSING
# ==========================================

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
	echo "  ./scripts/analyze.sh [OPTIONS]"
	echo
	echo "DESCRIPTION:"
	echo "  Executes rust-code-analysis-cli across the userland Rust workspace crates"
	echo "  and formats the output into detailed file summaries."
	echo
	echo "OPTIONS:"
	echo "  -help, -h               Display this help message and exit."
	echo
	echo "EXAMPLES:"
	echo "  $ ./scripts/analyze.sh"
	exit 0
}

function init_env() {
	echo "Initializing Code Analysis for Bouclier Bleu..."

	if ! command -v rust-code-analysis-cli >/dev/null 2>&1; then
		echo "  [-] Error: 'rust-code-analysis-cli' is not installed."
		echo "      Run: cargo install rust-code-analysis-cli"
		exit 1
	fi

	if ! command -v jq >/dev/null 2>&1; then
		echo "  [-] Error: 'jq' is required to parse the analysis output."
		exit 1
	fi

	# Clean up previous runs to prevent stale data in the report
	if [ -d "${ANALYSIS_DIR}" ]; then
		rm -rf "${ANALYSIS_DIR}"
	fi
	mkdir -p "${ANALYSIS_DIR}"
}

function run_analysis() {
	echo -e "\n➤ Running rust-code-analysis..."

	for dir in "${TARGET_DIRS[@]}"; do
		local target_path="${MAIN_DIR}/${dir}"
		local out_path="${ANALYSIS_DIR}/${dir}"

		if [ -d "${target_path}" ]; then
			echo "  [*] Scanning crate: ${dir}..."

			# Ensure the output subdirectory exists to prevent tool panic
			mkdir -p "${out_path}"

			# Run analysis; silence stdout but keep stderr for debugging
			if ! rust-code-analysis-cli --metrics -O json -p "${target_path}" -o "${out_path}" >/dev/null; then
				echo "  [-] Error: rust-code-analysis-cli failed on ${dir}."
			fi
		else
			echo "  [-] Warning: Directory ${dir} not found. Skipping."
		fi
	done
}

# Helper function to return ANSI color codes based on metric thresholds
function get_color_code() {
	local metric=$1
	local val=$2
	awk -v m="$metric" -v v="$val" '
	BEGIN {
		GREEN="\033[1;32m" # ideal
		YELLOW="\033[1;33m" # acceptable
		ORANGE="\033[1;38;5;208m" # problematic
		RED="\033[1;31m" # critical
		RESET="\033[0m"
		
		color=RESET
		
		# Strip any percentage signs
		gsub("%", "", v);
		
		# Force awk to treat the variable as a number to prevent alphabetical string comparison bugs
		v = v + 0;
		
		if (m == "ploc") {
			if (v < 200) color=GREEN; else if (v < 500) color=YELLOW; else if (v < 800) color=ORANGE; else color=RED;
		} else if (m == "comment") {
			if (v >= 30) color=GREEN; else if (v >= 20) color=YELLOW; else if (v >= 10) color=ORANGE; else color=RED;
		} else if (m == "cyclo") {
			if (v <= 15) color=GREEN; else if (v <= 30) color=YELLOW; else if (v <= 50) color=ORANGE; else color=RED;
		} else if (m == "cog") {
			if (v <= 5) color=GREEN; else if (v <= 15) color=YELLOW; else if (v <= 30) color=ORANGE; else color=RED;
		} else if (m == "mi") {
			if (v >= 60) color=GREEN; else if (v >= 40) color=YELLOW; else if (v >= 20) color=ORANGE; else color=RED;
		} else if (m == "vol") {
			if (v < 3000) color=GREEN; else if (v < 6000) color=YELLOW; else if (v < 10000) color=ORANGE; else color=RED;
		} else if (m == "abc") {
			if (v < 30) color=GREEN; else if (v < 60) color=YELLOW; else if (v < 100) color=ORANGE; else color=RED;
		} else if (m == "fn_cog") {
			# Individual functions should be strictly graded for cognitive load
			if (v <= 5) color=GREEN; else if (v <= 10) color=YELLOW; else if (v <= 15) color=ORANGE; else color=RED;
		}
		printf "%s", color
	}'
}

function print_report() {
	echo
	echo -e "\033[1;34m==============================================================================\033[0m"
	echo -e "\033[1;37m                       Bouclier Bleu - Complexity Report\033[0m"
	echo -e "\033[1;34m==============================================================================\033[0m"

	# Find all generated JSON files and parse
	find "${ANALYSIS_DIR}" -type f -name '*.json' | sort | while read -r file; do

		# Extract main metrics via jq
		jq -r '
		[
			.name, 
			(.metrics.loc.ploc // 0), 
			(.metrics.loc.cloc // 0), 
			(.metrics.cyclomatic.sum // 0), 
			(.metrics.cognitive.sum // 0), 
			(.metrics.mi.mi_visual_studio // 0),
			(.metrics.halstead.volume // 0),
			(.metrics.abc.magnitude // 0)
		] | @tsv' "$file" | while IFS=$'\t' read -r name ploc cloc cyclo cog mi vol abc; do

			# Convert float strings to integers by stripping the decimal part
			# so Bash math works
			ploc=${ploc%.*}
			cloc=${cloc%.*}
			cyclo=${cyclo%.*}
			cog=${cog%.*}

			# Clean up the filepath
			local clean_name="${name#*${MAIN_DIR}/}"
			clean_name="${clean_name#./}"

			# Subtract the 15-line copyright header from the comment line count
			cloc=$((cloc - 15))
			if [ "$cloc" -lt 0 ]; then
				cloc=0
			fi

			# Calculate comment ratio and format floating point numbers using
			# awk
			local comment_ratio
			comment_ratio=$(awk -v p="$ploc" -v c="$cloc" 'BEGIN { if (p+c > 0) printf "%.2f%%", (c/(p+c))*100; else print "0.00%" }')

			local mi_fmt=$(awk -v v="$mi" 'BEGIN { printf "%.2f", v }')
			local vol_fmt=$(awk -v v="$vol" 'BEGIN { printf "%.2f", v }')
			local abc_fmt=$(awk -v v="$abc" 'BEGIN { printf "%.2f", v }')

			# Assign colors dynamically
			local c_ploc=$(get_color_code "ploc" "$ploc")
			local c_comment=$(get_color_code "comment" "$comment_ratio")
			local c_cyclo=$(get_color_code "cyclo" "$cyclo")
			local c_cog=$(get_color_code "cog" "$cog")
			local c_mi=$(get_color_code "mi" "$mi_fmt")
			local c_vol=$(get_color_code "vol" "$vol_fmt")
			local c_abc=$(get_color_code "abc" "$abc_fmt")
			local c_reset="\033[0m"

			echo -e "\033[1;36mFile: ${clean_name}\033[0m"
			echo -e "\033[1;37m  Metrics:\033[0m"
			echo -e "    - PLOC             : ${c_ploc}${ploc}${c_reset}"
			echo -e "    - Comment Ratio    : ${c_comment}${comment_ratio}${c_reset} (cloc: ${cloc})"
			echo -e "    - Cyclomatic       : ${c_cyclo}${cyclo}${c_reset}"
			echo -e "    - Cognitive        : ${c_cog}${cog}${c_reset}"
			echo -e "    - MI (VS)          : ${c_mi}${mi_fmt}${c_reset}"
			echo -e "    - Halstead Volume  : ${c_vol}${vol_fmt}${c_reset}"
			echo -e "    - ABC Magnitude    : ${c_abc}${abc_fmt}${c_reset}"
			echo -e "\033[1;37m  Most Complex Parts (Top 3 by Cognitive Load):\033[0m"

			# Recursive jq query to find functions/methods, sort by COGNITIVE
			# complexity descending, and grab top 3
			local complex_parts
			complex_parts=$(jq -r '
				.. | objects | select(has("kind") and (.kind == "function" or .kind == "method" or .kind == "closure")) |
				[
					.name,
					(.metrics.cognitive.sum // 0),
					.start_line,
					.end_line
				] | @tsv' "$file" 2>/dev/null | sort -k2 -nr | head -n 3)

			if [ -z "$complex_parts" ]; then
				echo "    (No functions or methods found)"
			else
				local count=1
				echo "$complex_parts" | while IFS=$'\t' read -r fn_name fn_cog fn_start fn_end; do
					# Format anonymous closures to be more readable
					if [ "$fn_name" == "<anonymous>" ]; then
						fn_name="<closure>"
					fi

					# Strip decimal if present for the function cognitive load
					# too
					fn_cog=${fn_cog%.*}

					local c_fn_cog=$(get_color_code "fn_cog" "$fn_cog")

					echo -e "    ${count}. \033[1;36m${fn_name}\033[0m (lines ${fn_start}-${fn_end}) - Cognitive: ${c_fn_cog}${fn_cog}${c_reset}"
					count=$((count + 1))
				done
			fi
			echo -e "\033[1;34m------------------------------------------------------------------------------\033[0m"
		done
	done
	echo
}

# ==========================================
# MAIN EXECUTION
# ==========================================

print_help
init_env
run_analysis
print_report
