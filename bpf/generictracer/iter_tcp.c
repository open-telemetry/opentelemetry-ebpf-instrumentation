#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

#include <common/sock_port_ns.h>

#include <generictracer/maps/listening_ports.h>

SEC("iter/tcp")
int obi_iter_tcp(struct bpf_iter__tcp *ctx) {
    struct sock_common *skc = ctx->sk_common;
    if (!skc) {
        return 0;
    }

    const unsigned char skc_state = BPF_CORE_READ(skc, skc_state);
    if (skc_state != TCP_LISTEN) {
        return 0;
    }

    struct sock_port_ns pn = sock_port_ns_from_skc(skc);
    bpf_map_update_elem(&listening_ports, &pn, &(bool){true}, BPF_ANY);

    struct seq_file *seq = ctx->meta->seq;
    BPF_SEQ_PRINTF(seq, "Add listening port=%d netns=%d\n", pn.port, pn.netns);

    return 0;
}
