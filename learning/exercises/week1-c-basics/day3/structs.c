// Week 1 - Day 3: 结构体 — eBPF 的数据组织核心
// 主题: struct 定义、typedef、嵌套结构体、联合体 (union)
//
// 编译: gcc -o day3 structs.c && ./day3
//
// 为什么学这个:
//   eBPF 程序的所有数据都通过结构体组织:
//   - Map 的 key/value 是结构体
//   - RingBuffer 发送的事件是结构体
//   - 从内核读取的数据映射到结构体
//
// OBI 项目参考: bpf/common/connection_info.h, bpf/netolly/flow.h

#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define IP_V6_ADDR_LEN 16
#define IP_V6_ADDR_LEN_WORDS 4

// ============================================================
// 练习 1: 基本结构体定义和 typedef
// ============================================================

// 直接来自 OBI: bpf/netolly/flow.h
// 用于记录网络流量的指标
typedef struct flow_metrics_t {
    u64 bytes;
    u64 start_mono_time_ns;  // 开始时间 (纳秒)
    u64 end_mono_time_ns;    // 结束时间 (纳秒)
    u32 packets;
    u16 flags;               // TCP 标志位
    u8  iface_direction;     // 流量方向: INGRESS / EGRESS
    u8  initiator;           // 连接发起方
} flow_metrics;

void exercise_1_basic_struct(void) {
    printf("=== 练习 1: 基本结构体 ===\n");

    // 方式 1: 声明后逐个赋值
    flow_metrics m1;
    m1.bytes = 1500;
    m1.packets = 1;
    m1.flags = 0x02;  // SYN
    m1.start_mono_time_ns = 1000000000ULL;  // 1 秒
    m1.end_mono_time_ns   = 1000500000ULL;  // 1.0005 秒

    // 方式 2: 初始化为零 (eBPF 中最常见的方式)
    flow_metrics m2 = {0};

    // 方式 3: 指定成员初始化 (C99)
    flow_metrics m3 = {
        .bytes = 64,
        .packets = 1,
        .flags = 0x10,  // ACK
    };

    printf("m1: %u bytes, %u packets, flags=0x%x\n", (u32)m1.bytes, m1.packets, m1.flags);
    printf("m2: %u bytes (zero-init)\n", (u32)m2.bytes);
    printf("m3: %u bytes, flags=0x%x\n", (u32)m3.bytes, m3.flags);
    printf("sizeof(flow_metrics) = %zu bytes\n", sizeof(flow_metrics));

    // TODO: 练习 — 计算 m1 的延迟: end_time - start_time，打印微秒值
}

// ============================================================
// 练习 2: 联合体 (union) — 同一块内存的不同视图
// ============================================================

// 直接来自 OBI: bpf/common/connection_info.h
// 连接信息可以按字节 (u8[16]) 或按字 (u32[4]) 访问
typedef struct connection_info {
    union {
        u8  s_addr[IP_V6_ADDR_LEN];       // 按字节访问源 IP
        u32 s_ip[IP_V6_ADDR_LEN_WORDS];   // 按 32 位字访问源 IP
    };
    union {
        u8  d_addr[IP_V6_ADDR_LEN];       // 按字节访问目标 IP
        u32 d_ip[IP_V6_ADDR_LEN_WORDS];   // 按 32 位字访问目标 IP
    };
    u16 s_port;
    u16 d_port;
} connection_info_t;

void exercise_2_union(void) {
    printf("\n=== 练习 2: 联合体 (来自 OBI connection_info) ===\n");

    connection_info_t conn = {0};

    // IPv4 地址 10.0.0.1 在 IPv6 映射格式中的存储方式:
    // 前 12 字节是 ::ffff 前缀，后 4 字节是 IPv4 地址
    conn.s_addr[12] = 10;
    conn.s_addr[13] = 0;
    conn.s_addr[14] = 0;
    conn.s_addr[15] = 1;

    conn.d_addr[12] = 192;
    conn.d_addr[13] = 168;
    conn.d_addr[14] = 1;
    conn.d_addr[15] = 100;

    conn.s_port = 54321;
    conn.d_port = 80;

    // 同一块内存，用 u8 或 u32 访问
    printf("src IP (bytes): %u.%u.%u.%u\n",
           conn.s_addr[12], conn.s_addr[13], conn.s_addr[14], conn.s_addr[15]);
    printf("src IP (word):  0x%08x\n", conn.s_ip[3]);  // 最后一个字包含 IPv4 地址
    printf("connection: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
           conn.s_addr[12], conn.s_addr[13], conn.s_addr[14], conn.s_addr[15], conn.s_port,
           conn.d_addr[12], conn.d_addr[13], conn.d_addr[14], conn.d_addr[15], conn.d_port);
    printf("sizeof(connection_info_t) = %zu bytes\n", sizeof(connection_info_t));

    // TODO: 练习 — 用 s_ip[3] (u32) 直接设置 IP 为 172.16.0.1
    //       提示: 字节序问题，172 在最低字节
}

// ============================================================
// 练习 3: 嵌套结构体 — 组合更复杂的数据
// ============================================================

// 直接来自 OBI: bpf/common/connection_info.h
typedef struct http_pid_connection_info {
    connection_info_t conn;   // 嵌套: 连接信息
    u32 pid;                  // 进程 ID
} pid_connection_info_t;

typedef struct ssl_pid_connection_info {
    pid_connection_info_t p_conn;  // 嵌套: PID + 连接信息
    u16 orig_dport;                // 原始目标端口
    u8 _pad[6];                    // 填充对齐
} ssl_pid_connection_info_t;

void exercise_3_nested_structs(void) {
    printf("\n=== 练习 3: 嵌套结构体 (来自 OBI) ===\n");

    ssl_pid_connection_info_t ssl_conn = {0};

    // 访问嵌套成员: 一层一层用 . 访问
    ssl_conn.p_conn.pid = 12345;
    ssl_conn.p_conn.conn.s_port = 443;
    ssl_conn.p_conn.conn.d_port = 54321;
    ssl_conn.orig_dport = 8443;

    printf("PID: %u\n", ssl_conn.p_conn.pid);
    printf("src_port: %u, dst_port: %u\n",
           ssl_conn.p_conn.conn.s_port, ssl_conn.p_conn.conn.d_port);
    printf("orig_dport: %u\n", ssl_conn.orig_dport);

    // 嵌套层次:
    printf("\n结构体嵌套层次:\n");
    printf("  ssl_pid_connection_info_t  (%zu bytes)\n", sizeof(ssl_pid_connection_info_t));
    printf("  └─ pid_connection_info_t   (%zu bytes)\n", sizeof(pid_connection_info_t));
    printf("     └─ connection_info_t    (%zu bytes)\n", sizeof(connection_info_t));

    // TODO: 练习 — 设置 ssl_conn 的源 IP 为 127.0.0.1 (需要通过多层嵌套访问)
}

// ============================================================
// 练习 4: 结构体初始化模式 — eBPF 中的 {0} 和 {} 模式
// ============================================================
void exercise_4_init_patterns(void) {
    printf("\n=== 练习 4: eBPF 常见初始化模式 ===\n");

    // 模式 1: {0} — 最常见，所有成员置零
    // 来自 OBI k_tracer.c: sock_args_t args = {0};
    flow_metrics zero_init = {0};
    printf("zero init: bytes=%llu, packets=%u\n",
           (unsigned long long)zero_init.bytes, zero_init.packets);

    // 模式 2: {} — 空初始化 (在 eBPF 中等效于 {0})
    // 来自 OBI libssl.c: ssl_args_t args = {};
    flow_metrics empty_init = {};
    printf("empty init: bytes=%llu, packets=%u\n",
           (unsigned long long)empty_init.bytes, empty_init.packets);

    // 模式 3: 指定成员初始化
    // 来自 OBI: 用于创建 Map 查找的 key
    connection_info_t key = {
        .s_port = 80,
        .d_port = 443,
    };
    printf("designated init: s_port=%u, d_port=%u\n", key.s_port, key.d_port);
}

int main(void) {
    exercise_1_basic_struct();
    exercise_2_union();
    exercise_3_nested_structs();
    exercise_4_init_patterns();

    printf("\n✓ Day 3 完成！你学会了:\n");
    printf("  - struct 定义和 typedef\n");
    printf("  - union 让同一块内存有不同视图 (u8[] vs u32[])\n");
    printf("  - 嵌套结构体 (OBI 中 ssl > pid_conn > conn 三层嵌套)\n");
    printf("  - {0} 和 {} 初始化模式\n");
    return 0;
}
