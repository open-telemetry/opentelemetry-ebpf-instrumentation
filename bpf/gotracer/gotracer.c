// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <bpfcore/utils.h>

#include <common/pin_internal.h>
#include <common/preempt_guard.h>

#include <gotracer/go_offsets.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, go_executable_key_t);
    __uint(max_entries, MAX_GO_PROGRAMS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_executable_identity_requests SEC(".maps");

SEC("kprobe/uprobe_register")
int GUARDED_PROG(obi_capture_go_executable_identity, struct pt_regs *, ctx) {
    const u32 tid = (u32)bpf_get_current_pid_tgid();
    go_executable_key_t *identity = bpf_map_lookup_elem(&go_executable_identity_requests, &tid);
    if (!identity) {
        return 0;
    }

    struct inode *inode = (struct inode *)PT_REGS_PARM1_CORE(ctx);
    go_executable_key(inode, identity);
    return 0;
}

#include "go_runtime.c"
#include "go_net.c"
#include "go_net_tls.c"
#include "go_nethttp.c"
#include "go_sql.c"
#include "go_grpc.c"
#include "go_redis.c"
#include "go_kafka_go.c"
#include "go_sarama.c"
#include "go_sdk.c"
#include "go_mongo.c"
//FIXME - move common code to common location
#include "generictracer/protocol_handler.c"

char __license[] SEC("license") = "Dual MIT/GPL";
