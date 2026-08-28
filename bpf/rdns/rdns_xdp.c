// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_endian.h>

#include <common/protocol_defs.h>
#include <logger/bpf_dbg.h>

// Reverse DNS implementation by means of XDP packet inspection.
// This eBPF program inspects DNS response packets at the XDP (eXpress Data Path) level
// to capture and analyze DNS responses. It uses a ring buffer to communicate the
// captured DNS packets to user space for further processing.
// For reference, see:
// https://datatracker.ietf.org/doc/html/rfc1035

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ring_buffer SEC(".maps");

// DNS header structure constants
enum {
    // the DNS header is made of 6 16-bit words
    DNS_HEADER_SIZE = 6 * sizeof(__u16),
};

// Bit offsets and masks for DNS header flags
enum offsets {
    QR_OFFSET = 7,     // Query/Response flag offset
    OPCODE_OFFSET = 3, // Operation code offset
    OPCODE_MASK = 0xf, // Operation code mask
    AA_OFFSET = 2,     // Authoritative Answer flag offset
    TC_OFFSET = 1,     // TrunCation flag offset
    RD_OFFSET = 0,     // Recursion Desired flag offset
    RA_OFFSET = 7,     // Recursion Available flag offset
    Z_OFFSET = 4,      // Reserved field offset
    Z_MASK = 0x7,      // Reserved field mask
    RCODE_OFFSET = 0,  // Response code offset
    RCODE_MASK = 0xf   // Response code mask
};

// DNS message types and constants
enum { QR_QUERY = 0, QR_RESPONSE = 1 };              // Query/Response types
enum { OP_QUERY = 0, OP_IQUERY = 1, OP_STATUS = 2 }; // Operation codes
enum { RB_RECORD_LEN = 256 };                        // Maximum record length for ring buffer
enum { DNS_PORT = 53 };                              // Standard DNS port
enum { UDP_HDR_SIZE = sizeof(struct udphdr), DNS_HDR_SIZE = 12 }; // Header sizes

// IPv6 next-header values used while walking the extension-header chain.
enum ipv6_next_header {
    IPV6_HOP_BY_HOP = 0,
    IPV6_ROUTING = 43,
    IPV6_FRAGMENT = 44,
    IPV6_AUTHENTICATION = 51,
    IPV6_DESTINATION_OPTIONS = 60,
};

enum { IPV4_FRAGMENT_MASK = 0x3fff };

static __always_inline __u8 get_bit(__u8 word, __u8 offset) {
    return (word >> offset) & 0x1;
}

// Helper functions to access packet data safely
static __always_inline void *ctx_xdp_data(struct xdp_md *ctx) {
    void *data;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct xdp_md, data)), "m"(*ctx));

    return data;
}

static __always_inline void *ctx_xdp_data_end(struct xdp_md *ctx) {
    void *data_end;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data_end)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct xdp_md, data_end)), "m"(*ctx));

    return data_end;
}

static __always_inline struct udphdr *validate_udp_header(unsigned char *cursor,
                                                          const unsigned char *packet_end,
                                                          const unsigned char *data_end) {
    struct udphdr *udp = (void *)cursor;

    if ((void *)(udp + 1) > (void *)packet_end || (void *)(udp + 1) > (void *)data_end) {
        return NULL;
    }

    const __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(*udp) || cursor + udp_len > packet_end || cursor + udp_len > data_end) {
        return NULL;
    }

    return udp;
}

static __always_inline struct udphdr *ipv4_udp_header(struct iphdr *iph,
                                                      const unsigned char *data_end) {
    if ((void *)(iph + 1) > (void *)data_end || iph->version != 4 || iph->ihl < 5 ||
        iph->protocol != IPPROTO_UDP || (iph->frag_off & bpf_htons(IPV4_FRAGMENT_MASK)) != 0) {
        return NULL;
    }

    const __u32 advance = iph->ihl * 4;
    const __u16 total_len = bpf_ntohs(iph->tot_len);
    if (total_len < advance + sizeof(struct udphdr)) {
        return NULL;
    }

    unsigned char *ip_end = (void *)iph + total_len;
    if (ip_end > data_end) {
        return NULL;
    }

    return validate_udp_header((void *)iph + advance, ip_end, data_end);
}

static __always_inline struct udphdr *ipv6_udp_header(struct ipv6hdr *iph,
                                                      const unsigned char *data_end) {
    if ((void *)(iph + 1) > (void *)data_end || iph->version != 6) {
        return NULL;
    }

    const __u16 payload_len = bpf_ntohs(iph->payload_len);
    // A zero payload length denotes an IPv6 jumbogram. UDP jumbograms use
    // a zero UDP length and need separate option parsing, so skip them.
    if (payload_len == 0) {
        return NULL;
    }

    unsigned char *ip_end = (void *)(iph + 1) + payload_len;
    if (ip_end > data_end) {
        return NULL;
    }

    __u8 next_header = iph->nexthdr;
    unsigned char *cursor = (void *)(iph + 1);

    // IPv6 extension-header chains are finite in valid traffic. Keep the
    // walk explicitly bounded so the BPF verifier can prove termination.
#pragma unroll
    for (__u8 i = 0; i < 6; ++i) {
        if (next_header == IPPROTO_UDP) {
            return validate_udp_header(cursor, ip_end, data_end);
        }

        // DNS messages spanning IPv6 fragments require reassembly, which
        // is intentionally outside the scope of this packet-level tracer.
        if (next_header == IPV6_FRAGMENT) {
            return NULL;
        }

        if (next_header != IPV6_HOP_BY_HOP && next_header != IPV6_ROUTING &&
            next_header != IPV6_DESTINATION_OPTIONS && next_header != IPV6_AUTHENTICATION) {
            return NULL;
        }

        struct ipv6_opt_hdr *extension = (void *)cursor;
        unsigned char *extension_end = (void *)(extension + 1);
        if (extension_end > ip_end || extension_end > data_end) {
            return NULL;
        }

        const __u8 extension_type = next_header;
        next_header = extension->nexthdr;
        __u32 extension_len;
        if (extension_type == IPV6_AUTHENTICATION) {
            // Authentication Header length is measured in 32-bit words,
            // excluding the first two words.
            if (extension->hdrlen < 1) {
                return NULL;
            }
            extension_len = ((__u32)extension->hdrlen + 2) * 4;
        } else {
            extension_len = ((__u32)extension->hdrlen + 1) * 8;
        }

        if (cursor + extension_len > ip_end || cursor + extension_len > data_end) {
            return NULL;
        }
        cursor += extension_len;
    }

    return NULL;
}

static __always_inline struct udphdr *udp_header(struct xdp_md *ctx) {
    void *data = ctx_xdp_data(ctx);
    void *data_end = ctx_xdp_data_end(ctx);
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return NULL;
    }

    switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
        return ipv4_udp_header((void *)(eth + 1), data_end);
    case ETH_P_IPV6:
        return ipv6_udp_header((void *)(eth + 1), data_end);
    default:
        return NULL;
    }
};

// Validates and calculates the size of a DNS question section
static __always_inline __u32 validate_qsection(const unsigned char *data,
                                               const unsigned char *data_end) {
    __u32 size = 0;

    // try at most 16 sections
    for (__u8 i = 0; i < 16; ++i) {
        if (data >= data_end) {
            return 0;
        }

        const __u8 len = data[0];

        ++size;
        ++data;

        if (len == 0) {
            const __u32 question_fields_size = 2 * sizeof(__u16); // QTYPE and QCLASS
            size += question_fields_size;

            if (data + question_fields_size <= data_end) {
                return size;
            } else {
                return 0;
            }
        }

        data += len;
        size += len;
    }

    return 0;
}

// Submits a DNS packet to the ring buffer for user space processing.
// Uses a bounded loop with per-iteration packet bounds checks so the BPF verifier
// can track each access, avoiding bpf_xdp_load_bytes which requires kernel 5.18+.
static __always_inline void submit_dns_packet(const unsigned char *const data,
                                              const unsigned char *const end) {
    const __u32 data_len = (end - data) & 0xffff;

    if (data_len == 0 || data_len > RB_RECORD_LEN) {
        return;
    }

    unsigned char *buf = bpf_ringbuf_reserve(&ring_buffer, RB_RECORD_LEN, 0);

    if (!buf) {
        bpf_d_printk("Failed to reserve %u bytes in the ring buffer", RB_RECORD_LEN);

        return;
    }

    for (__u32 i = 0; i < RB_RECORD_LEN; i++) {
        if (i >= data_len) {
            break;
        }
        if (data + i + 1 > end) {
            break;
        }
        buf[i] = data[i];
    }

    bpf_ringbuf_submit(buf, 0);
}

// Parses a DNS response packet and validates its structure
static __always_inline void parse_dns_response(const unsigned char *const data,
                                               const unsigned char *const data_end) {
    // Extract DNS header fields
    const __u8 flags0 = *(data + 2);
    const __u8 flags1 = *(data + 3);

    const __u8 qr = get_bit(flags0, QR_OFFSET);
    const __u8 opcode = (flags0 >> OPCODE_OFFSET) & OPCODE_MASK;
    const __u8 z = (flags1 >> Z_OFFSET) & Z_MASK;
    const __u8 rcode = (flags1 >> RCODE_OFFSET) & RCODE_MASK;
    const __u16 qdcount = bpf_ntohs(*(const __be16 *)(data + 4));
    const __u16 ancount = bpf_ntohs(*(const __be16 *)(data + 6));

    // heuristic check to see if this is a DNS response
    if (qr != QR_RESPONSE || opcode != OP_QUERY || z != 0 || rcode != 0 || qdcount == 0 ||
        ancount == 0) {
        return;
    }

    if (g_bpf_debug) {
        [[maybe_unused]] const __u16 id = bpf_ntohs(*(const __be16 *)(data));
        [[maybe_unused]] const __u8 aa = get_bit(flags0, AA_OFFSET);
        [[maybe_unused]] const __u8 tc = get_bit(flags0, TC_OFFSET);
        [[maybe_unused]] const __u8 rd = get_bit(flags0, RD_OFFSET);
        [[maybe_unused]] const __u8 ra = get_bit(flags1, RA_OFFSET);
        bpf_d_printk("Found possible DNS response: %x!", id);
        bpf_d_printk("flags[0]=%x", flags0);
        bpf_d_printk("id=%x, qr=%u, opcode=%u", id, qr, opcode);
        bpf_d_printk("aa=%u, tc=%u, rd=%u", aa, tc, rd);
        bpf_d_printk("ra=%u", ra);
        bpf_d_printk("flags[1]=%x", flags1);
        bpf_d_printk("z=%u, rcode=%u", z, rcode);
        bpf_d_printk("qdcount=%u, ancount=%u", qdcount, ancount);
    }

    // Parse question sections
    __u32 __attribute__((unused)) dns_packet_size = 0;

    const unsigned char *ptr = data + DNS_HEADER_SIZE;

    for (__u8 i = 0; i < 4 && i < qdcount; ++i) {
        const __u32 qsection_size = validate_qsection(ptr, data_end);

        if (qsection_size == 0) {
            bpf_d_printk("invalid qsection, bailing");
            return;
        }

        dns_packet_size += qsection_size;
        ptr += qsection_size;
    }

    bpf_d_printk("found qsection, dns_packet_size=%u", dns_packet_size);

    // Submit valid DNS packet to ring buffer
    submit_dns_packet(data, data_end);
}

// Main XDP program entry point
SEC("xdp")
int dns_response_tracker(struct xdp_md *ctx) {
    // Get UDP header
    const struct udphdr *udp = udp_header(ctx);

    if (!udp) {
        return XDP_PASS;
    }

    // Check if packet is from DNS port
    const __u16 source = bpf_ntohs(udp->source);

    if (source != DNS_PORT) {
        return XDP_PASS;
    }

    // Validate packet size
    const __u16 udp_len = bpf_ntohs(udp->len);

    bpf_d_printk("udp_len=%u", udp_len);

    if (udp_len < (UDP_HDR_SIZE + DNS_HDR_SIZE)) {
        return XDP_PASS;
    }

    const unsigned char *udp_end = (void *)udp + udp_len;
    if ((void *)udp + UDP_HDR_SIZE + DNS_HDR_SIZE >= (void *)udp_end) {
        return XDP_PASS;
    }

    // Parse and process DNS response
    parse_dns_response((unsigned char *)(udp) + UDP_HDR_SIZE, udp_end);

    return XDP_PASS;
}
