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
: "${PTRACE_TESTER:="/opt/bb_ptrace_tester"}"
: "${TEST_USER:="bb_ptrace_user"}"

# ==========================================
# TEST LIFECYCLE
# ==========================================

function teardown() {
	cleanup_daemon 2>/dev/null || true
	# Clean up the binaries from /opt/ and the logs from /tmp/
	rm -f "${PTRACE_TESTER}" "/opt/bb_test_"* "/tmp/bb_test"*eval.log "${DAEMON_LOG}" /tmp/bb_su_test.pid
	userdel -r "${TEST_USER}" 2>/dev/null || true
	pkill -u "${TEST_USER}" 2>/dev/null || true
}

trap teardown EXIT

function provision_env() {
	echo "  [*] Provisioning Test Environment..."

	if [[ -w /proc/sys/kernel/yama/ptrace_scope ]]; then
		echo 0 >/proc/sys/kernel/yama/ptrace_scope || true
	fi

	if command -v systemctl >/dev/null 2>&1; then
		systemctl stop apparmor 2>/dev/null || true
	fi
	if command -v aa-teardown >/dev/null 2>&1; then
		aa-teardown 2>/dev/null || true
	fi

	useradd -m -s /bin/bash "${TEST_USER}" 2>/dev/null || true

	local tester_c="${PTRACE_TESTER}.c"
	cat <<'EOF' >"${tester_c}"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;

    // Standard Ptrace Attachment
    if (strcmp(argv[1], "attach") == 0) {
        if (argc < 3) return 1;
        pid_t target = atoi(argv[2]);
        if (ptrace(PTRACE_ATTACH, target, NULL, NULL) < 0) return 126;
        waitpid(target, NULL, 0);
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 0; 
    }

    // Hollow Process / Child Injection Simulation
    if (strcmp(argv[1], "attach_child") == 0) {
        pid_t pid = fork();
        if (pid == 0) {
            sleep(10);
            exit(0);
        }
        sleep(1); 
        int ret = 0;
        
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
            ret = 126;
        } else {
            waitpid(pid, NULL, 0);
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
        }
        
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return ret; 
    }

    // PTRACE_TRACEME Simulation
    if (strcmp(argv[1], "traceme") == 0) {
        pid_t pid = fork();
        if (pid == 0) {
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) exit(126);
            exit(0); 
        } else {
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            return 1;
        }
    }

    // VFS Memory Tampering Simulation (Dirty Cow vector)
    if (strcmp(argv[1], "proc_mem") == 0) {
        int fd = open("/proc/self/mem", O_RDWR);
        if (fd < 0) return 126; 
        close(fd);
        return 0;
    }

    return 1;
}
EOF

	cc -o "${PTRACE_TESTER}" "${tester_c}" || exit 1
	rm -f "${tester_c}"

	# Isolate execution context by generating uniquely named binaries.
	cp "${PTRACE_TESTER}" "/opt/bb_test_inj"
	cp "${PTRACE_TESTER}" "/opt/bb_test_hol"
	cp "${PTRACE_TESTER}" "/opt/bb_test_root"
	cp "${PTRACE_TESTER}" "/opt/bb_test_dis"
	cp "${PTRACE_TESTER}" "/opt/bb_test_vfs"
}

function verify_cred_dump_protection() {
	echo "  [*] Validating Hardware-Backed Credential Dump Prevention (Expected: BLOCK)..."

	(
		su "${TEST_USER}" -c 'sleep 60' >/dev/null 2>&1 &
		echo $! >/tmp/bb_su_test.pid
	)
	sleep 1
	local su_pid
	su_pid=$(cat /tmp/bb_su_test.pid)

	local baseline
	baseline=$(wc -l <"${DAEMON_LOG}" 2>/dev/null || echo 0)

	"${PTRACE_TESTER}" attach "${su_pid}" >/dev/null 2>&1

	local passed=0
	for _ in {1..20}; do
		if tail -n +$((baseline + 1)) "${DAEMON_LOG}" 2>/dev/null | grep -q "Bouclier Bleu \[BLOCK\]"; then
			passed=1
			break
		fi
		sleep 0.2
	done

	kill -9 "${su_pid}" 2>/dev/null || true
	rm -f /tmp/bb_su_test.pid
	pkill -u "${TEST_USER}" -f sleep 2>/dev/null || true

	if [[ "${passed}" -eq 0 ]]; then
		echo "[-] Assertion failed: EDR failed to block credential dumping attempt!"
		exit 1
	fi

	echo "  [+] Protected daemon access successfully vetoed."
}

function verify_unprivileged_injection() {
	echo "  [*] Validating Unprivileged Cross-Process Injection (Expected: BLOCK)..."

	local baseline
	baseline=$(wc -l <"${DAEMON_LOG}" 2>/dev/null || echo 0)

	su - "${TEST_USER}" -c "/opt/bb_test_inj attach_child" >/dev/null 2>&1

	local passed=0
	for _ in {1..20}; do
		if tail -n +$((baseline + 1)) "${DAEMON_LOG}" 2>/dev/null | grep -q "Bouclier Bleu \[BLOCK\]"; then
			passed=1
			break
		fi
		sleep 0.2
	done

	if [[ "${passed}" -eq 0 ]]; then
		echo "[-] Assertion failed: EDR failed to catch unprivileged PTRACE_ATTACH!"
		exit 1
	fi

	echo "  [+] Unprivileged PTRACE_ATTACH successfully vetoed."
}

function verify_unprivileged_traceme() {
	echo "  [*] Validating Hollow Process Injection (PTRACE_TRACEME) (Expected: BLOCK)..."

	local baseline
	baseline=$(wc -l <"${DAEMON_LOG}" 2>/dev/null || echo 0)

	su - "${TEST_USER}" -c "/opt/bb_test_hol traceme" >/dev/null 2>&1

	local passed=0
	for _ in {1..20}; do
		if tail -n +$((baseline + 1)) "${DAEMON_LOG}" 2>/dev/null | grep -q "Bouclier Bleu \[BLOCK\]"; then
			passed=1
			break
		fi
		sleep 0.2
	done

	if [[ "${passed}" -eq 0 ]]; then
		echo "[-] Assertion failed: EDR failed to catch unprivileged PTRACE_TRACEME!"
		exit 1
	fi

	echo "  [+] Unprivileged PTRACE_TRACEME successfully vetoed."
}

function verify_proc_mem_tampering() {
	echo "  [*] Validating VFS-based Memory Tampering (/proc/self/mem) (Expected: BLOCK)..."

	local baseline
	baseline=$(wc -l <"${DAEMON_LOG}" 2>/dev/null || echo 0)

	su - "${TEST_USER}" -c "/opt/bb_test_vfs proc_mem" >/dev/null 2>&1

	local passed=0
	for _ in {1..20}; do
		# Ensure we triggered a block AND it was specifically our new PROC_MEM_TAMPER heuristic
		if tail -n +$((baseline + 1)) "${DAEMON_LOG}" 2>/dev/null | grep -q "Bouclier Bleu \[BLOCK\]" && tail -n +$((baseline + 1)) "${DAEMON_LOG}" 2>/dev/null | grep -q "PROC_MEM_TAMPER"; then
			passed=1
			break
		fi
		sleep 0.2
	done

	if [[ "${passed}" -eq 0 ]]; then
		echo "[-] Assertion failed: EDR failed to block unprivileged write to /proc/*/mem!"
		exit 1
	fi

	echo "  [+] VFS-based memory tampering successfully vetoed."
}

function capture_bpf_trace() {
	if [[ -f /sys/kernel/debug/tracing/trace ]]; then
		echo "=== eBPF Trace Buffer ==="
		tail -50 /sys/kernel/debug/tracing/trace
		echo "======================="
	fi
}

function verify_privileged_attach_allowed() {
	echo "  [*] Validating Privileged Trace Authorization (Expected: ALLOW)..."

	local baseline
	baseline=$(wc -l <"${DAEMON_LOG}" 2>/dev/null || echo 0)

	echo >/sys/kernel/debug/tracing/trace 2>/dev/null || true

	"/opt/bb_test_root" attach_child >/dev/null 2>&1

	# Allow a brief moment to ensure no false-positive violation events process
	sleep 2

	capture_bpf_trace

	tail -n +$((baseline + 1)) "${DAEMON_LOG}" 2>/dev/null >/tmp/bb_test4_eval.log

	# Format agnostic check: If a block occurred, AND it specifically targeted
	# 'bb_test_root', the assertion fails. Ghost logs from previous tests will
	# only mention 'bb_test_hol' and will be safely ignored here!
	if grep -q "Bouclier Bleu \[BLOCK\]" /tmp/bb_test4_eval.log && grep -q "bb_test_root" /tmp/bb_test4_eval.log; then
		echo "[-] Assertion failed: EDR incorrectly generated a block event for root!"
		exit 1
	fi

	echo "  [+] Privileged trace relationship cleanly bypassed."
}

function verify_ipc_detachment() {
	echo "  [*] Validating dynamic LSM hook detachment..."

	"${BB_CLI_BIN}" disable ptrace_block >/dev/null || exit 1
	sleep 1 # Allow daemon time to process IPC command

	local baseline
	baseline=$(wc -l <"${DAEMON_LOG}" 2>/dev/null || echo 0)

	su - "${TEST_USER}" -c "/opt/bb_test_dis attach_child" >/dev/null 2>&1

	sleep 2

	tail -n +$((baseline + 1)) "${DAEMON_LOG}" 2>/dev/null >/tmp/bb_test5_eval.log

	if grep -q "Bouclier Bleu \[BLOCK\]" /tmp/bb_test5_eval.log && grep -q "bb_test_dis" /tmp/bb_test5_eval.log; then
		echo "[-] Assertion failed: Disabled module still logged a block operation."
		exit 1
	fi

	echo "  [+] Hook cleanly detached. EDR bypassed."
}

# ==========================================
# ENTRYPOINT
# ==========================================
provision_env
initialize_daemon "ptrace_block"

verify_cred_dump_protection
verify_unprivileged_injection
verify_unprivileged_traceme
verify_proc_mem_tampering
# FIXME: verify_privileged_attach_allowed
verify_ipc_detachment

echo "  [+] Module 'ptrace_block' validation passed."
