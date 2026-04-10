// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include "iter_tcp.c"
#include "java_tls.c"
#include "k_tracer.c"
#include "libssl.c"
#include "nginx.c"
#include "nodejs.c"
#include "python.c"
#include "protocol_handler.c"
#include "ruby.c"

char __license[] SEC("license") = "Dual MIT/GPL";
