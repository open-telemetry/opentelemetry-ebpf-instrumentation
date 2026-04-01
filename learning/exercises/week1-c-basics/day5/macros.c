// Week 1 - Day 5: 预处理器 — 宏、条件编译、头文件
// 主题: #define, #pragma, #include, 条件编译
//
// 编译: gcc -o day5 macros.c && ./day5
//
// 为什么学这个:
//   eBPF 代码大量使用宏来定义常量、简化重复代码、条件编译。
//   OBI 项目的头文件组织方式是理解项目结构的关键。
//
// OBI 项目参考: bpf/common/common.h, bpf/netolly/flows_common.h

#include <stdio.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// ============================================================
// 练习 1: #define 常量 — eBPF 中定义大小限制和协议常量
// ============================================================

// 来自 OBI: bpf/common/common.h
#define K_TCP_MAX_LEN   256
#define K_TCP_RES_LEN   128
#define PATH_MAX_LEN    100
#define METHOD_MAX_LEN  7       // 最长方法: OPTIONS
#define HOST_LEN        64
#define SQL_MAX_LEN     500
#define KAFKA_MAX_LEN   256

// 来自 OBI: bpf/netolly/flows_common.h
#define DISCARD 1
#define SUBMIT  0

// 来自 OBI: 以太网和 IP 协议定义
#define ETH_P_IP   0x0800     // IPv4
#define ETH_P_IPV6 0x86DD     // IPv6
#define ETH_ALEN   6          // MAC 地址长度

void exercise_1_constants(void) {
    printf("=== 练习 1: #define 常量 ===\n");

    // 这些常量在 eBPF 中用于数组大小声明和缓冲区限制
    char path[PATH_MAX_LEN];
    char method[METHOD_MAX_LEN + 1];  // +1 for null terminator
    char host[HOST_LEN];

    printf("路径缓冲区: %d bytes\n", PATH_MAX_LEN);
    printf("方法缓冲区: %d bytes (最长: OPTIONS = 7 chars)\n", METHOD_MAX_LEN);
    printf("SQL缓冲区:  %d bytes\n", SQL_MAX_LEN);

    // 在 eBPF 中声明固定大小数组:
    // u8 buf[K_TCP_MAX_LEN];  // 不能用变长数组!
    printf("\n注意: eBPF 不支持变长数组 (VLA)，所有数组大小必须是编译时常量\n");

    // TODO: 练习 — 定义 REDIS_MAX_LEN 256, 用它声明一个缓冲区
}

// ============================================================
// 练习 2: 带参数的宏 — 简化重复代码
// ============================================================

// 来自 OBI bpf/bpfcore/utils.h 风格的 Map 定义宏
// 在 eBPF 中用宏来声明 Map 结构体
#define DEFINE_HASH_MAP(name, key_type, value_type, max_size) \
    struct {                                                   \
        const char *type;                                      \
        const char *key;                                       \
        const char *value;                                     \
        int max_entries;                                       \
    } name = { "HASH", #key_type, #value_type, max_size }

// 模拟 SEC() 宏 — 在 eBPF 中指定程序段
#define SEC(name) __attribute__((section(name)))

// 模拟 BPF_KPROBE 宏 — 简化 kprobe 函数定义
// 真实的 BPF_KPROBE 展开后很复杂，这里只展示概念
#define MY_BPF_KPROBE(func_name, ...) \
    int func_name(void *ctx, ##__VA_ARGS__)

void exercise_2_function_macros(void) {
    printf("\n=== 练习 2: 带参数的宏 ===\n");

    // 使用 Map 定义宏
    DEFINE_HASH_MAP(my_map, u32, u64, 1024);

    printf("Map '%s': type=%s, key=%s, value=%s, max=%d\n",
           "my_map", my_map.type, my_map.key, my_map.value, my_map.max_entries);

    // # 操作符: 字符串化 — 把宏参数变成字符串
    // #key_type 变成 "u32"
    printf("\n# 操作符 (字符串化):\n");
    printf("  #key_type => \"%s\"\n", my_map.key);

    // TODO: 练习 — 用 DEFINE_HASH_MAP 宏定义一个 pid_map
    //       key=u32 (PID), value=u64 (timestamp), max=10240
}

// ============================================================
// 练习 3: #pragma once 和头文件保护
// ============================================================
void exercise_3_headers(void) {
    printf("\n=== 练习 3: 头文件组织 ===\n");

    // OBI 的头文件使用 #pragma once 防止重复包含
    // 每个 .h 文件第一行都是:
    //   #pragma once
    //
    // OBI 的头文件目录结构:
    printf("OBI 头文件组织:\n");
    printf("  bpf/bpfcore/          — 内核头文件 (vmlinux.h, bpf_helpers.h)\n");
    printf("  bpf/common/           — 公共数据结构和工具\n");
    printf("  bpf/maps/             — Map 定义 (每个 Map 一个头文件)\n");
    printf("  bpf/pid/              — PID 过滤相关\n");
    printf("  bpf/logger/           — 调试打印\n");
    printf("  bpf/generictracer/    — 通用追踪器的头文件和实现\n");
    printf("  bpf/gotracer/         — Go 程序追踪器\n");

    // 包含顺序的约定 (来自 OBI k_tracer.c):
    printf("\n#include 顺序约定:\n");
    printf("  1. #include <bpfcore/vmlinux.h>     — 内核类型定义\n");
    printf("  2. #include <bpfcore/bpf_helpers.h>  — eBPF helper 函数\n");
    printf("  3. #include <bpfcore/bpf_tracing.h>  — tracing 宏\n");
    printf("  4. #include <common/...>             — 公共数据结构\n");
    printf("  5. #include <generictracer/...>      — 模块特定头文件\n");
    printf("  6. #include <maps/...>               — Map 定义\n");
    printf("  7. #include <pid/...>                — PID 过滤\n");
    printf("  8. #include <logger/...>             — 调试工具\n");
}

// ============================================================
// 练习 4: 条件编译 — 跨平台和调试
// ============================================================

// 模拟 OBI 中的调试打印宏
#ifdef DEBUG
    #define bpf_dbg_printk(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
    #define bpf_dbg_printk(fmt, ...) /* 什么都不做 */
#endif

// 模拟 __always_inline — eBPF 中的必须内联
#define __always_inline inline __attribute__((always_inline))

static __always_inline u32 extract_pid(u64 pid_tgid) {
    return (u32)(pid_tgid >> 32);
}

void exercise_4_conditional(void) {
    printf("\n=== 练习 4: 条件编译 ===\n");

    u64 pid_tgid = 0x0000303900001234ULL;
    u32 pid = extract_pid(pid_tgid);
    printf("PID: %u\n", pid);

    // DEBUG 宏控制调试输出
    bpf_dbg_printk("这条消息只在 DEBUG 模式下显示, pid=%u", pid);

#ifdef DEBUG
    printf("当前处于 DEBUG 模式\n");
#else
    printf("当前处于 RELEASE 模式 (debug 输出被禁用)\n");
    printf("重新编译试试: gcc -DDEBUG -o day5 macros.c\n");
#endif

    // __always_inline 在 eBPF 中非常重要:
    printf("\n__always_inline 的重要性:\n");
    printf("  eBPF verifier 不支持函数调用 (旧版本)\n");
    printf("  所有辅助函数必须内联到调用者中\n");
    printf("  OBI 中几乎所有 static 函数都标记为 __always_inline\n");
}

int main(void) {
    exercise_1_constants();
    exercise_2_function_macros();
    exercise_3_headers();
    exercise_4_conditional();

    printf("\n✓ Day 5 完成！你学会了:\n");
    printf("  - #define 定义常量 (eBPF 中的数组大小、协议号等)\n");
    printf("  - 带参数的宏 (Map 定义、SEC()、BPF_KPROBE() 等)\n");
    printf("  - #pragma once 和 OBI 的头文件组织结构\n");
    printf("  - 条件编译 (#ifdef DEBUG) 和 __always_inline\n");
    return 0;
}
