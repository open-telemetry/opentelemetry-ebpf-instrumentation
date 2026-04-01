// Week 1 - Day 1: 基本类型与控制流
// 主题: eBPF 常用的固定宽度整数类型 + if/else/switch
//
// 编译: gcc -o day1 types_and_control.c && ./day1
//
// 为什么学这个:
//   eBPF 程序必须使用固定宽度类型 (u8, u16, u32, u64)
//   而不是标准 C 的 int/long，因为需要精确的内存布局来匹配内核数据结构
//
// OBI 项目参考: bpf/netolly/flow.h 中的 typedef

#include <stdio.h>
#include <stdint.h>

// eBPF 中使用的类型别名 (在内核头文件中已定义，这里模拟)
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  s32;
typedef int64_t  s64;

// ============================================================
// 练习 1: 基本类型大小
// ============================================================
void exercise_1_type_sizes(void) {
    printf("=== 练习 1: 基本类型大小 ===\n");

    u8  val_8  = 255;          // 最大值 255
    u16 val_16 = 65535;        // 最大值 65535 (端口号范围)
    u32 val_32 = 4294967295U;  // 最大值 ~4.2 billion (PID, IP 地址)
    u64 val_64 = 0;            // 最大值 ~18.4 quintillion (时间戳, PID+TID 组合)

    printf("u8  size: %zu bytes, value: %u\n", sizeof(val_8), val_8);
    printf("u16 size: %zu bytes, value: %u\n", sizeof(val_16), val_16);
    printf("u32 size: %zu bytes, value: %u\n", sizeof(val_32), val_32);
    printf("u64 size: %zu bytes, value: %llu\n", sizeof(val_64), (unsigned long long)val_64);

    // TODO: 练习 — 声明一个 s32 类型变量存储 -1，打印它的值
}

// ============================================================
// 练习 2: eBPF 中常见的 PID/TID 操作
// ============================================================
void exercise_2_pid_tgid(void) {
    printf("\n=== 练习 2: PID/TID 拆分 ===\n");

    // eBPF 中 bpf_get_current_pid_tgid() 返回一个 u64:
    //   高 32 位 = PID (进程组ID/tgid)
    //   低 32 位 = TID (线程ID/pid)
    // 来自 OBI: bpf/generictracer/k_tracer.c 第 58 行
    u64 pid_tgid = 0x0000ABCD00001234ULL;  // 模拟返回值

    u32 pid = (u32)(pid_tgid >> 32);   // 高 32 位
    u32 tid = (u32)(pid_tgid & 0xFFFFFFFF);  // 低 32 位

    printf("pid_tgid = 0x%016llx\n", (unsigned long long)pid_tgid);
    printf("PID (tgid) = 0x%x (%u)\n", pid, pid);
    printf("TID (pid)  = 0x%x (%u)\n", tid, tid);

    // TODO: 练习 — 构造一个 pid_tgid 值，使得 PID=12345, TID=67890
}

// ============================================================
// 练习 3: switch 语句 — 协议类型判断
// ============================================================
void exercise_3_protocol_switch(void) {
    printf("\n=== 练习 3: 协议类型判断 (switch) ===\n");

    // 模拟 OBI 中对网络协议类型的判断
    // 来自 OBI: bpf/netolly/flows.c 的 fill_iphdr() 函数
    u8 protocols[] = { 6, 17, 1, 0 };  // TCP, UDP, ICMP, 未知
    const char *names[] = { "TCP", "UDP", "ICMP", "Unknown" };

    for (int i = 0; i < 4; i++) {
        u8 protocol = protocols[i];
        const char *name;

        switch (protocol) {
        case 6:   // IPPROTO_TCP
            name = "TCP";
            break;
        case 17:  // IPPROTO_UDP
            name = "UDP";
            break;
        case 1:   // IPPROTO_ICMP
            name = "ICMP";
            break;
        default:
            name = "Unknown";
            break;
        }

        printf("protocol %u => %s (expected: %s) %s\n",
               protocol, name, names[i],
               (name == names[i]) ? "OK" : "FAIL");  // 注意: 这里只是比较指针来验证
    }

    // TODO: 练习 — 添加 IPPROTO_UDP (17) 和 IPPROTO_SCTP (132) 的分支
}

int main(void) {
    exercise_1_type_sizes();
    exercise_2_pid_tgid();
    exercise_3_protocol_switch();

    printf("\n✓ Day 1 完成！你学会了:\n");
    printf("  - eBPF 使用固定宽度类型 (u8/u16/u32/u64)\n");
    printf("  - bpf_get_current_pid_tgid() 返回 u64，高32位是PID，低32位是TID\n");
    printf("  - switch 语句在协议判断中的使用\n");
    return 0;
}
