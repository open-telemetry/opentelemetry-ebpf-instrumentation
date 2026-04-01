// Week 1 - Day 4: 内存操作
// 主题: __builtin_memcpy, 数组操作, 内存布局, 边界检查
//
// 编译: gcc -o day4 memory_ops.c && ./day4
//
// 为什么学这个:
//   eBPF 不能使用标准库的 memcpy/memset, 必须用编译器内建函数
//   __builtin_memcpy。OBI 项目中大量使用此函数来拷贝 IP 地址、
//   协议头部等数据。另外，边界检查是通过 verifier 的关键。
//
// OBI 项目参考: bpf/netolly/flows.c 的 fill_iphdr()

#include <stdio.h>
#include <stdint.h>
#include <string.h>  // 用户态用 memcpy，eBPF 中用 __builtin_memcpy

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// ============================================================
// 练习 1: __builtin_memcpy 的使用
// ============================================================

// IPv4-in-IPv6 前缀: ::ffff:0:0/96
// 来自 OBI: bpf/netolly/flows.c
static const u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

void exercise_1_memcpy(void) {
    printf("=== 练习 1: memcpy 操作 (模拟 __builtin_memcpy) ===\n");

    // 模拟 OBI flows.c 中 fill_iphdr() 的 IP 地址拷贝过程:
    //   __builtin_memcpy(id->src_ip.s6_addr, ip4in6, sizeof(ip4in6));
    //   __builtin_memcpy(id->src_ip.s6_addr + sizeof(ip4in6), &ip->saddr, sizeof(ip->saddr));

    u8 src_ipv6[16] = {0};  // 目标: IPv6 格式的地址
    u32 ipv4_addr = 0x0100000A;  // 10.0.0.1 (网络字节序)

    // 步骤 1: 拷贝 IPv4-in-IPv6 前缀 (前 12 字节)
    memcpy(src_ipv6, ip4in6, sizeof(ip4in6));
    // 在 eBPF 中写成: __builtin_memcpy(src_ipv6, ip4in6, sizeof(ip4in6));

    // 步骤 2: 拷贝 IPv4 地址到后 4 字节
    memcpy(src_ipv6 + sizeof(ip4in6), &ipv4_addr, sizeof(ipv4_addr));
    // 在 eBPF 中写成: __builtin_memcpy(src_ipv6 + sizeof(ip4in6), &ip->saddr, sizeof(ip->saddr));

    printf("IPv6-mapped IPv4 address: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", src_ipv6[i]);
        if (i % 2 == 1 && i < 15) printf(":");
    }
    printf("\n");
    printf("解读: ::ffff:10.0.0.1\n");

    // TODO: 练习 — 对目标 IP 192.168.1.100 执行相同的操作
}

// ============================================================
// 练习 2: 数据包边界检查 — 通过 verifier 的关键
// ============================================================
void exercise_2_bounds_check(void) {
    printf("\n=== 练习 2: 边界检查 (verifier 必需) ===\n");

    // 模拟一个网络数据包缓冲区
    u8 packet[64];
    memset(packet, 0, sizeof(packet));
    // 假设这是一个 IP 头
    packet[0] = 0x45;  // version=4, header_len=5 (20 bytes)
    packet[9] = 6;     // protocol = TCP

    void *data = packet;
    void *data_end = packet + sizeof(packet);

    // 来自 OBI flows.c 的边界检查模式:
    //   if ((void *)ip + sizeof(*ip) > data_end) {
    //       return DISCARD;
    //   }
    // 这个检查告诉 verifier: 我保证不会越界访问

    // 模拟 IP 头结构 (简化)
    struct simple_iphdr {
        u8  version_ihl;
        u8  tos;
        u16 tot_len;
        u32 id_flags_frag;
        u8  ttl;
        u8  protocol;
        u16 check;
        u32 saddr;
        u32 daddr;
    };

    struct simple_iphdr *ip = (struct simple_iphdr *)data;

    // 关键的边界检查！没有这行，eBPF verifier 会拒绝程序
    if ((void *)ip + sizeof(*ip) > data_end) {
        printf("包太短，丢弃！\n");
        return;
    }

    // 通过检查后，安全地读取数据
    printf("IP version+ihl: 0x%02x\n", ip->version_ihl);
    printf("IP protocol:    %u (%s)\n", ip->protocol,
           ip->protocol == 6 ? "TCP" : "other");

    // 模拟包太短的情况
    u8 short_packet[10];
    void *short_data = short_packet;
    void *short_data_end = short_packet + sizeof(short_packet);
    struct simple_iphdr *short_ip = (struct simple_iphdr *)short_data;

    if ((void *)short_ip + sizeof(*short_ip) > short_data_end) {
        printf("短包 (10 bytes < %zu bytes header): 丢弃！ (正确行为)\n",
               sizeof(struct simple_iphdr));
    }

    // TODO: 练习 — 在 IP 头之后检查 TCP 头 (需要跳过 IP 头的长度)
}

// ============================================================
// 练习 3: 数组操作 — HTTP 方法匹配
// ============================================================
void exercise_3_array_ops(void) {
    printf("\n=== 练习 3: 数组与 HTTP 方法匹配 ===\n");

    // OBI 在内核中识别 HTTP 请求的方式:
    // 检查数据包前几个字节是否匹配 "GET ", "POST", "HTTP" 等

    u8 http_data[] = "GET /api/v1/users HTTP/1.1\r\n";

    // 方式 1: 逐字节比较 (eBPF 中最基本的方式)
    if (http_data[0] == 'G' && http_data[1] == 'E' &&
        http_data[2] == 'T' && http_data[3] == ' ') {
        printf("检测到 HTTP GET 请求\n");
    }

    // 方式 2: memcmp (用户态), eBPF 中通常用逐字节比较
    if (memcmp(http_data, "GET ", 4) == 0) {
        printf("memcmp 确认: GET 请求\n");
    }

    // 提取路径 (从第4个字节到空格)
    printf("路径: ");
    for (int i = 4; http_data[i] != ' ' && http_data[i] != '\0' && i < 30; i++) {
        printf("%c", http_data[i]);
    }
    printf("\n");

    // TODO: 练习 — 检测 "POST" 和 "HTTP/1.1" 方法
}

int main(void) {
    exercise_1_memcpy();
    exercise_2_bounds_check();
    exercise_3_array_ops();

    printf("\n✓ Day 4 完成！你学会了:\n");
    printf("  - __builtin_memcpy 是 eBPF 中唯一的内存拷贝方式\n");
    printf("  - 边界检查 (ptr + size > data_end) 是通过 verifier 的关键\n");
    printf("  - OBI 如何在内核中拷贝 IPv4-in-IPv6 地址\n");
    printf("  - 如何用数组操作识别 HTTP 方法\n");
    return 0;
}
