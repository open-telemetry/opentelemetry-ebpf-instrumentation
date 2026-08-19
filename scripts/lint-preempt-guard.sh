#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
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
#
# Programs that can execute in uprobe context must disable preemption for
# their body (see bpf/common/preempt_guard.h). This lint enforces, for every
# bpf/ subsystem that attaches at least one uprobe:
#
#   1. every kprobe/kretprobe/uprobe/uretprobe/usdt program is defined
#      through one of the guarded wrappers (GUARDED_PROG or
#      BPF_[KU](RET)PROBE_GUARDED), and
#   2. tail calls go through preempt_guarded_tail_call(_static), never
#      through bpf_tail_call(_static) directly.
#
# Kprobe-only subsystems are skipped: those contexts already run with
# preemption disabled and share no stack frames with uprobe programs.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR

readonly UPROBE_SEC='^SEC\("u(ret)?probe(/|")|^SEC\("usdt/'

errors=0

check_file() {
    local file="$1"

    local out
    out="$(awk '
        pending && NF && $1 !~ /^(\/\/|\/?\*)/ {
            if ($0 !~ /(GUARDED_PROG|BPF_[KU](RET)?PROBE_GUARDED)\(/)
                printf "%s:%d: program after %s is not guarded\n", FILENAME, NR, sec
            pending = 0
        }
        /^SEC\("(k|u)(ret)?probe(\/|")/ || /^SEC\("usdt\// { pending = 1; sec = $0 }
        /bpf_tail_call(_static)?\(/ && $1 !~ /^(\/\/|\*)/ && !/preempt_guarded_tail_call/ {
            printf "%s:%d: raw tail call, use preempt_guarded_tail_call(_static)\n", FILENAME, NR
        }
    ' "${file}")"

    if [ -n "${out}" ]; then
        echo "${out}"
        errors=1
    fi
}

cd "${ROOT_DIR}"

for dir in bpf/*/; do
    case "${dir}" in
    bpf/bpfcore/ | bpf/NOTICES/ | bpf/tests/) continue ;;
    esac

    if ! grep -rlqE "${UPROBE_SEC}" "${dir}" --include='*.c' --include='*.h' 2>/dev/null; then
        continue
    fi

    while IFS= read -r file; do
        check_file "${file}"
    done < <(find "${dir}" -type f \( -name '*.c' -o -name '*.h' \))
done

if [ "${errors}" -ne 0 ]; then
    echo ""
    echo "Unguarded programs can corrupt per-CPU BPF private stacks on kernels"
    echo "6.13+ with preemption enabled. See bpf/common/preempt_guard.h."
    exit 1
fi
