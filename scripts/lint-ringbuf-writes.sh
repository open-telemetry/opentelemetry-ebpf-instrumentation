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

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR

readonly RAW_RINGBUF_WRITE='bpf_ringbuf_(reserve|output)[[:space:]]*\([[:space:]]*&[[:space:]]*(events|gpu_events|log_events)[[:space:]]*,'

actual="$(
    cd "${ROOT_DIR}"
    grep -RHnE "${RAW_RINGBUF_WRITE}" bpf \
        --include='*.c' \
        --include='*.h' \
        --exclude-dir=bpfcore \
        --exclude-dir=tests \
        2>/dev/null \
        | sed -E 's/^([^:]+):[0-9]+:/\1:/' \
        | LC_ALL=C sort \
        || true
)"

expected="$(LC_ALL=C sort <<'EOF'
bpf/common/ringbuf.h:    const long err = bpf_ringbuf_output(&events, data, size, flags);
bpf/common/ringbuf.h:    void *event = bpf_ringbuf_reserve(&events, size, flags);
bpf/gpuevent/gpu_ringbuf.h:    void *event = bpf_ringbuf_reserve(&gpu_events, size, flags);
bpf/logenricher/maps/log_events.h:    const long err = bpf_ringbuf_output(&log_events, data, size, flags);
EOF
)"

if [ "${actual}" != "${expected}" ]; then
    echo "ring buffer writes must use their accounting helpers" >&2
    echo "" >&2
    echo "expected raw writes:" >&2
    printf '%s\n' "${expected}" >&2
    echo "" >&2
    echo "found raw writes:" >&2
    printf '%s\n' "${actual:-none}" >&2
    exit 1
fi
