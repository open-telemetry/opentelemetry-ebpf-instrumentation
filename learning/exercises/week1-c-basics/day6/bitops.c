// Week 1 - Day 6: 枚举与位运算
// 主题: enum, 位运算 (|, &, <<, >>), TCP flags
//
// 编译: gcc -o day6 bitops.c && ./day6
//
// 为什么学这个:
//   网络编程大量使用位运算来处理标志位(flags)、解析协议头。
//   OBI 中 TCP flags 处理、协议类型枚举都是核心功能。
//
// OBI 项目参考: bpf/netolly/flows_common.h, bpf/netolly/flows.c 的 set_flags()

#include <stdio.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// ============================================================
// 练习 1: 枚举类型 — 可读的常量组
// ============================================================

// 来自 OBI: bpf/common/connection_info.h
enum protocol_type {
    k_protocol_type_unknown  = 0,
    k_protocol_type_mysql    = 1,
    k_protocol_type_postgres = 2,
    k_protocol_type_http     = 3,
    k_protocol_type_kafka    = 4,
    k_protocol_type_mqtt     = 5,
};

const char *protocol_name(enum protocol_type p) {
    switch (p) {
    case k_protocol_type_http:     return "HTTP";
    case k_protocol_type_mysql:    return "MySQL";
    case k_protocol_type_postgres: return "PostgreSQL";
    case k_protocol_type_kafka:    return "Kafka";
    case k_protocol_type_mqtt:     return "MQTT";
    default:                       return "Unknown";
    }
}

void exercise_1_enums(void) {
    printf("=== 练习 1: 枚举类型 ===\n");

    enum protocol_type protos[] = {
        k_protocol_type_http,
        k_protocol_type_mysql,
        k_protocol_type_kafka,
        k_protocol_type_unknown,
    };

    for (int i = 0; i < 4; i++) {
        printf("protocol %d => %s\n", protos[i], protocol_name(protos[i]));
    }

    // TODO: 练习 — 添加 k_protocol_type_redis = 6 到枚举中
}

// ============================================================
// 练习 2: 位运算 — TCP Flags
// ============================================================

// 直接来自 OBI: bpf/netolly/flows_common.h
#define FIN_FLAG     0x01
#define SYN_FLAG     0x02
#define RST_FLAG     0x04
#define PSH_FLAG     0x08
#define ACK_FLAG     0x10
#define URG_FLAG     0x20
#define ECE_FLAG     0x40
#define CWR_FLAG     0x80
// OBI 自定义的组合标志
#define SYN_ACK_FLAG 0x100
#define FIN_ACK_FLAG 0x200
#define RST_ACK_FLAG 0x400

void print_flags(u16 flags) {
    printf("  flags = 0x%03x =>", flags);
    if (flags & SYN_FLAG)     printf(" SYN");
    if (flags & ACK_FLAG)     printf(" ACK");
    if (flags & FIN_FLAG)     printf(" FIN");
    if (flags & RST_FLAG)     printf(" RST");
    if (flags & PSH_FLAG)     printf(" PSH");
    if (flags & SYN_ACK_FLAG) printf(" [SYN+ACK]");
    if (flags & FIN_ACK_FLAG) printf(" [FIN+ACK]");
    if (flags & RST_ACK_FLAG) printf(" [RST+ACK]");
    printf("\n");
}

// 模拟 TCP 头结构 (简化)
typedef struct {
    u16 source;
    u16 dest;
    u32 seq;
    u32 ack_seq;
    // TCP flags 在实际中是 bit fields
    u8 syn : 1;
    u8 ack : 1;
    u8 fin : 1;
    u8 rst : 1;
    u8 psh : 1;
    u8 urg : 1;
    u8 ece : 1;
    u8 cwr : 1;
} simple_tcphdr;

// 直接来自 OBI: bpf/netolly/flows.c 的 set_flags() 函数
void set_flags(simple_tcphdr *th, u16 *flags) {
    if (th->ack && th->syn) {
        *flags |= SYN_ACK_FLAG;
    } else if (th->ack && th->fin) {
        *flags |= FIN_ACK_FLAG;
    } else if (th->ack && th->rst) {
        *flags |= RST_ACK_FLAG;
    } else if (th->fin) {
        *flags |= FIN_FLAG;
    } else if (th->syn) {
        *flags |= SYN_FLAG;
    } else if (th->rst) {
        *flags |= RST_FLAG;
    } else if (th->psh) {
        *flags |= PSH_FLAG;
    }
}

void exercise_2_tcp_flags(void) {
    printf("\n=== 练习 2: TCP Flags 位运算 ===\n");

    // 模拟 TCP 三次握手的 flags 变化
    printf("TCP 三次握手:\n");

    // 第 1 步: Client -> Server: SYN
    simple_tcphdr syn_pkt = { .syn = 1 };
    u16 flags1 = 0;
    set_flags(&syn_pkt, &flags1);
    printf("  [1] Client->Server:");
    print_flags(flags1);

    // 第 2 步: Server -> Client: SYN+ACK
    simple_tcphdr synack_pkt = { .syn = 1, .ack = 1 };
    u16 flags2 = 0;
    set_flags(&synack_pkt, &flags2);
    printf("  [2] Server->Client:");
    print_flags(flags2);

    // 第 3 步: Client -> Server: ACK
    simple_tcphdr ack_pkt = { .ack = 1 };
    u16 flags3 = 0;
    set_flags(&ack_pkt, &flags3);
    printf("  [3] Client->Server:");
    print_flags(flags3);  // 注意: 纯 ACK 不在 set_flags 的分支中

    // 累积 flags (用 |= 操作)
    u16 all_flags = flags1 | flags2 | flags3;
    printf("\n  累积所有 flags:");
    print_flags(all_flags);
}

// ============================================================
// 练习 3: 位移操作 — 端口号和字节序
// ============================================================
void exercise_3_bit_shift(void) {
    printf("\n=== 练习 3: 位移操作 ===\n");

    // 网络字节序 (big-endian) vs 主机字节序 (little-endian)
    // eBPF 中使用 bpf_ntohs / bpf_htons 转换
    // 来自 OBI flows.c: id->src_port = __bpf_ntohs(tcp->source);

    u16 network_port = 0x0050;  // 网络字节序的 80 端口
    // 手动大端转小端 (模拟 __bpf_ntohs)
    u16 host_port = (network_port >> 8) | (network_port << 8);
    printf("网络字节序: 0x%04x\n", network_port);
    printf("主机字节序: 0x%04x (%u)\n", host_port, host_port);

    // PID + TID 的组合与拆分 (使用移位)
    u32 pid = 12345;
    u32 tid = 67890;
    u64 pid_tgid = ((u64)pid << 32) | tid;
    printf("\npid=%u, tid=%u\n", pid, tid);
    printf("组合: pid_tgid = 0x%016llx\n", (unsigned long long)pid_tgid);
    printf("拆分: pid=%u, tid=%u\n",
           (u32)(pid_tgid >> 32),
           (u32)(pid_tgid & 0xFFFFFFFF));

    // TODO: 练习 — 实现 my_ntohs(u16 netshort) 和 my_htons(u16 hostshort)
}

// ============================================================
// 练习 4: 掩码操作 — 检查和设置特定位
// ============================================================
void exercise_4_masks(void) {
    printf("\n=== 练习 4: 掩码操作 ===\n");

    u16 flags = 0;

    // 设置位: 用 |=
    flags |= SYN_FLAG;
    printf("设置 SYN: 0x%03x\n", flags);

    flags |= ACK_FLAG;
    printf("设置 ACK: 0x%03x\n", flags);

    // 检查位: 用 &
    if (flags & SYN_FLAG) {
        printf("SYN 已设置 ✓\n");
    }
    if (flags & FIN_FLAG) {
        printf("FIN 已设置\n");
    } else {
        printf("FIN 未设置 ✗\n");
    }

    // 清除位: 用 &= ~
    flags &= ~SYN_FLAG;
    printf("清除 SYN 后: 0x%03x\n", flags);

    // 翻转位: 用 ^=
    flags ^= ACK_FLAG;
    printf("翻转 ACK 后: 0x%03x\n", flags);

    // TODO: 练习 — 写一个函数 is_http_response(u16 flags)
    //       检查是否同时设置了 PSH 和 ACK (表示有数据传输)
}

int main(void) {
    exercise_1_enums();
    exercise_2_tcp_flags();
    exercise_3_bit_shift();
    exercise_4_masks();

    printf("\n✓ Day 6 完成！你学会了:\n");
    printf("  - enum 定义可读的常量组 (协议类型)\n");
    printf("  - |= 设置标志位, & 检查标志位, &= ~ 清除标志位\n");
    printf("  - TCP flags 在 OBI 中的处理方式 (set_flags 函数)\n");
    printf("  - 位移操作处理字节序和 PID/TID 组合\n");
    return 0;
}
