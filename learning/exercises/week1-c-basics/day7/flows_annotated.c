// Week 1 - Day 7: 综合练习 — 逐行注释 OBI 的 flows.c
// 主题: 把前 6 天学的 C 知识综合运用，读懂真实的 eBPF 代码
//
// 这不是可编译的程序，而是对 bpf/netolly/flows.c 核心代码的注释版
// 用于验证你是否已经掌握了所有 C 基础
//
// 原始文件: bpf/netolly/flows.c (OBI 的 TC 网络流追踪程序)

// =====================================================
// 第一部分: 头文件包含 (对应 Day 5 - 预处理器)
// =====================================================

// #include <bpfcore/vmlinux.h>
//   → 包含内核所有结构体定义 (struct iphdr, struct tcphdr, struct udphdr 等)
//   → 由 BTF (BPF Type Format) 自动生成，实现 CO-RE (一次编译到处运行)

// #include <bpfcore/bpf_helpers.h>
//   → eBPF helper 函数声明 (bpf_map_lookup_elem, bpf_ringbuf_submit 等)

// #include <bpfcore/bpf_endian.h>
//   → 字节序转换宏: __bpf_ntohs() (网络序→主机序), __bpf_htons() (主机序→网络序)

// #include <common/tc_act.h>
//   → TC (Traffic Control) 程序的返回值定义

// #include <logger/bpf_dbg.h>
//   → 调试打印宏 bpf_dbg_printk()

// #include <netolly/flows_common.h>
//   → 定义了 Map、flags 常量、flow 相关数据结构


// =====================================================
// 第二部分: set_flags 函数 (对应 Day 6 - 位运算)
// =====================================================

// static inline void set_flags(struct tcphdr *th, u16 *flags) {
//
// [static]   → 仅在当前文件可见 (C 的作用域控制)
// [inline]   → 请求编译器内联这个函数 (eBPF 中通常用 __always_inline)
// [void]     → 没有返回值
// [struct tcphdr *th]  → 指向 TCP 头的指针 (Day 2 - 结构体指针)
// [u16 *flags]         → 指向标志位变量的指针 (通过指针修改调用者的数据)
//
//     if (th->ack && th->syn) {
//         *flags |= SYN_ACK_FLAG;       // 0x100
//     }
//
// [th->ack]      → 通过指针访问 TCP 头的 ack 位字段 (Day 2 - -> 操作符)
// [&&]           → 逻辑与: 两个都为真才为真
// [*flags]       → 解引用指针，访问调用者的 flags 变量 (Day 2 - 指针)
// [|=]           → 按位或赋值: 设置对应的标志位 (Day 6 - 位运算)
// [SYN_ACK_FLAG] → #define SYN_ACK_FLAG 0x100 (Day 5 - 宏)
//
// TCP 三次握手中:
//   SYN      (0x02)  → 客户端发起连接
//   SYN+ACK  (0x100) → 服务端确认连接
//   ACK      (0x10)  → 客户端确认，连接建立
//
// 连接关闭:
//   FIN      (0x01)  → 一方发起关闭
//   FIN+ACK  (0x200) → 另一方确认关闭
//   RST+ACK  (0x400) → 异常终止连接


// =====================================================
// 第三部分: fill_iphdr 函数 (综合运用所有知识)
// =====================================================

// static inline int fill_iphdr(struct iphdr *ip, void *data_end, flow_id *id, u16 *flags) {
//
// 参数说明:
//   [struct iphdr *ip]   → 指向 IP 头的指针 (数据包中的位置)
//   [void *data_end]     → 数据包结束的位置 (用于边界检查)
//   [flow_id *id]        → 指向流标识结构体的指针 (输出参数)
//   [u16 *flags]         → 指向标志位的指针 (输出参数)
//
//     if ((void *)ip + sizeof(*ip) > data_end) {
//         return DISCARD;    // 值为 1
//     }
//
// ★ 关键的边界检查 (Day 4 - 边界检查)
//   → (void *)ip         把 ip 指针转为 void* 以便做地址算术
//   → sizeof(*ip)        IP 头结构体的大小 (20 bytes)
//   → > data_end         如果 IP 头超出数据包范围
//   → return DISCARD     丢弃这个包
//   → eBPF verifier 需要这个检查来证明后续访问是安全的
//
//     __builtin_memcpy(id->src_ip.s6_addr, ip4in6, sizeof(ip4in6));
//     __builtin_memcpy(id->dst_ip.s6_addr, ip4in6, sizeof(ip4in6));
//
// ★ 拷贝 IPv4-in-IPv6 前缀 (Day 4 - 内存操作)
//   → ip4in6 = {0,0,0,0,0,0,0,0,0,0,0xff,0xff} (12 bytes)
//   → 把 ::ffff 前缀拷贝到目标 IPv6 地址的前 12 字节
//   → id->src_ip.s6_addr 是通过 -> 和 . 的组合访问嵌套成员 (Day 3 - 嵌套结构体)
//
//     __builtin_memcpy(id->src_ip.s6_addr + sizeof(ip4in6), &ip->saddr, sizeof(ip->saddr));
//     __builtin_memcpy(id->dst_ip.s6_addr + sizeof(ip4in6), &ip->daddr, sizeof(ip->daddr));
//
// ★ 拷贝实际 IPv4 地址到后 4 字节 (Day 4 - 内存操作)
//   → s6_addr + sizeof(ip4in6) 就是偏移 12 字节的位置
//   → &ip->saddr 取 IP 头中源地址字段的地址
//   → 最终得到 ::ffff:10.0.0.1 这样的 IPv6 映射地址
//
//     id->transport_protocol = ip->protocol;
//
// → 从 IP 头读取传输层协议号 (6=TCP, 17=UDP, 1=ICMP)
//
//     id->src_port = 0;
//     id->dst_port = 0;
//
// → 先初始化为 0，如果是 TCP/UDP 再填入实际端口
//
//     switch (ip->protocol) {                          // Day 1 - switch
//     case IPPROTO_TCP: {                              // 值为 6
//         struct tcphdr *tcp = (struct tcphdr *)((void *)ip + sizeof(*ip));
//
// ★ 指针算术: 跳过 IP 头，定位到 TCP 头 (Day 2 - 指针)
//   → (void *)ip + sizeof(*ip)  = IP 头起始地址 + IP 头大小 = TCP 头起始地址
//   → (struct tcphdr *)          类型转换为 TCP 头指针
//
//         if ((void *)tcp + sizeof(*tcp) <= data_end) {   // 又一次边界检查!
//             id->src_port = __bpf_ntohs(tcp->source);    // 网络字节序→主机字节序
//             id->dst_port = __bpf_ntohs(tcp->dest);
//             set_flags(tcp, flags);                       // 设置 TCP flags
//         }
//     } break;
//
//     case IPPROTO_UDP: {                              // 值为 17
//         struct udphdr *udp = (struct udphdr *)((void *)ip + sizeof(*ip));
//         if ((void *)udp + sizeof(*udp) <= data_end) {
//             id->src_port = __bpf_ntohs(udp->source);
//             id->dst_port = __bpf_ntohs(udp->dest);
//             // UDP 没有 flags
//         }
//     } break;
//
//     default:
//         break;                                       // 其他协议: ICMP 等没有端口
//     }
//     return SUBMIT;                                   // 值为 0, 表示提交这个流
// }


// =====================================================
// 知识点总结: 一个函数用到了前 6 天的全部内容
// =====================================================
//
// Day 1 (类型+控制流): u8, u16, u32, switch/case
// Day 2 (指针):        struct iphdr *ip, th->ack, id->src_port, *flags
// Day 3 (结构体):      flow_id, connection_info, 嵌套访问 id->src_ip.s6_addr
// Day 4 (内存操作):    __builtin_memcpy, 边界检查 (ptr + size > data_end)
// Day 5 (预处理器):    #include, #define DISCARD/SUBMIT, IPPROTO_TCP
// Day 6 (位运算):      *flags |= SYN_ACK_FLAG, th->ack && th->syn


// =====================================================
// 验证练习: 回答以下问题 (答案在文件末尾)
// =====================================================
//
// Q1: 为什么需要 (void *)ip + sizeof(*ip) 而不能直接用 ip + 1?
//
// Q2: __bpf_ntohs 的作用是什么? 为什么端口号需要转换?
//
// Q3: 如果去掉 if ((void *)ip + sizeof(*ip) > data_end) 这行检查会怎样?
//
// Q4: 为什么 id->src_port 在 switch 之前先设为 0?
//
// Q5: set_flags 为什么用 u16 *flags 指针参数而不是返回值?


// =====================================================
// 答案
// =====================================================
//
// A1: ip + 1 会偏移 sizeof(struct iphdr) 字节 (因为指针算术基于类型大小)
//     实际上效果相同！但 OBI 用 void* 更明确地表达意图。
//     注意: void* 的算术在标准 C 中是未定义的，但 GCC/Clang 扩展支持 (按 1 字节偏移)。
//
// A2: 网络传输使用大端字节序 (Big Endian)，x86 主机使用小端字节序 (Little Endian)
//     ntohs = Network TO Host Short, 把 16 位值从网络序转为主机序
//     例: 端口 80 在网络序中是 0x0050, 在主机序中是 0x5000, 需要交换字节
//
// A3: eBPF verifier 会拒绝加载这个程序！verifier 不允许可能越界的内存访问。
//     边界检查是 verifier 确认安全性的唯一方式。
//
// A4: 因为 ICMP 等协议没有端口号，switch 的 default 分支不设置端口。
//     如果不先清零，可能包含上一次处理留下的脏数据。
//
// A5: 因为 set_flags 在 fill_iphdr 内部调用, flags 变量在 fill_iphdr 的调用者那里。
//     通过指针可以直接修改调用者的数据，这是 C 语言中 "输出参数" 的标准模式。
//     在 eBPF 中，减少返回值的复杂性有助于通过 verifier。
