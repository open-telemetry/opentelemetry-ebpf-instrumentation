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
# Enforces the eBPF C header dependency boundary:
#   Code in bpf/common/, bpf/logger/, bpf/maps/, bpf/pid/, and bpf/shared/
#   must not include headers from any tracer-specific directory
#   (generictracer/, gotracer/, tpinjector/, etc.). Every map defined in an
#   included header is emitted into each ELF that includes it, so reverse
#   includes leak unrelated maps across tracers.
set -euo pipefail

ROOT_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
readonly ROOT_DIR

cd "${ROOT_DIR}"

tracer_dirs=""
for dir in bpf/*/; do
    if [ ! -d "${dir}" ]; then
        continue
    fi
    name="${dir#bpf/}"
    name="${name%/}"
    case "${name}" in
    bpfcore | common | logger | maps | NOTICES | pid | shared | tests)
        continue
        ;;
    esac
    if [ -n "${tracer_dirs}" ]; then
        tracer_dirs="${tracer_dirs} ${name}"
    else
        tracer_dirs="${name}"
    fi
done

if [ -z "${tracer_dirs}" ]; then
    exit 0
fi

errors=0

check_file() {
    local file="$1"
    local out
    out="$(awk -v tracer_list="${tracer_dirs}" '
        BEGIN {
            n = split(tracer_list, arr, " ")
            for (i = 1; i <= n; i++) {
                tracers[arr[i]] = 1
            }
            in_block_comment = 0
            quote = ""
        }
        {
            raw = $0
            sub(/\r$/, "", raw)
            len = length(raw)
            code = ""
            continued = 0
            i = 1
            while (i <= len) {
                c = substr(raw, i, 1)
                next_c = (i < len) ? substr(raw, i + 1, 1) : ""

                if (in_block_comment) {
                    if (c == "*" && next_c == "/") {
                        in_block_comment = 0
                        code = code " "
                        i += 2
                    } else {
                        i++
                    }
                    continue
                }

                if (quote != "") {
                    code = code c
                    if (c == "\\") {
                        if (i < len) {
                            code = code next_c
                            i += 2
                        } else {
                            continued = 1
                            i++
                        }
                        continue
                    }
                    if (c == quote) {
                        quote = ""
                    }
                    i++
                    continue
                }

                if (c == "/" && next_c == "/") {
                    break
                }
                if (c == "/" && next_c == "*") {
                    in_block_comment = 1
                    i += 2
                    continue
                }
                if (c == "\"" || c == "\047") {
                    quote = c
                    code = code c
                    i++
                    continue
                }

                code = code c
                i++
            }
            if (!continued) {
                quote = ""
            }

            if (code !~ /^[[:space:]]*#[[:space:]]*include[[:space:]]*[<"][^">]+[">]/) {
                next
            }

            inc = code
            sub(/^[[:space:]]*#[[:space:]]*include[[:space:]]*[<"]/, "", inc)
            sub(/[">].*$/, "", inc)

            parts_n = split(inc, raw_parts, "/")
            depth = 0
            for (i = 1; i <= parts_n; i++) {
                p = raw_parts[i]
                if (p == "" || p == ".") {
                    continue
                }
                if (p == "..") {
                    if (depth > 0) {
                        depth--
                    }
                    continue
                }
                seg[++depth] = p
            }

            if ((depth >= 2 && (seg[1] in tracers)) || (depth >= 3 && seg[1] == "bpf" && (seg[2] in tracers))) {
                printf "%s:%d: shared header includes tracer-specific header \"%s\"\n", FILENAME, FNR, inc
            }
        }
    ' "${file}")"

    if [ -n "${out}" ]; then
        echo "${out}"
        errors=1
    fi
}

for dir in bpf/common bpf/logger bpf/maps bpf/pid bpf/shared; do
    if [ ! -d "${dir}" ]; then
        continue
    fi
    while IFS= read -r file; do
        check_file "${file}"
    done < <(find "${dir}" -type f \( -name '*.c' -o -name '*.h' \) | sort)
done

if [ "${errors}" -ne 0 ]; then
    echo ""
    echo "Headers under bpf/common/, bpf/logger/, bpf/maps/, bpf/pid/, and"
    echo "bpf/shared/ must not include headers from tracer-specific directories."
    echo "Move the shared piece into bpf/common/ or bpf/maps/ instead."
    exit 1
fi
