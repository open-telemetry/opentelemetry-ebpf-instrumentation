//go:build obi_bpf_ignore
#include "k_tracer.c"
#include "iter_tcp.c"
#include "libssl.c"
#include "nginx.c"
#include "nodejs.c"

char __license[] SEC("license") = "Dual MIT/GPL";
