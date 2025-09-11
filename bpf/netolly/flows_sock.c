// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
// Copyright Red Hat / IBM
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

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <netolly/flows_common.h>

SEC("socket/filter")
int obi_socket__filter(struct __sk_buff *skb) {
    return flow_monitor(skb);
}

// Force emitting structs into the ELF for automatic creation of Golang struct
const flow_metrics *unused_flow_metrics __attribute__((unused));
const flow_id *unused_flow_id __attribute__((unused));
const flow_record *unused_flow_record __attribute__((unused));

char _license[] SEC("license") = "GPL";
