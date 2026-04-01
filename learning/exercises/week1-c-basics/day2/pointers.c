// Week 1 - Day 2: 指针与地址
// 主题: eBPF 中最核心的操作 — 通过指针读取内核数据结构
//
// 编译: gcc -o day2 pointers.c && ./day2
//
// 为什么学这个:
//   eBPF 程序几乎每一行都在操作指针 — 读取内核结构体成员、
//   访问 Map 中的值、从用户态内存读取数据。
//   掌握指针是读懂 OBI 代码的前提。
//
// OBI 项目参考: bpf/generictracer/k_tracer.c 中大量的指针操作

#include <stdio.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// ============================================================
// 练习 1: 基本指针 — 取地址和解引用
// ============================================================
void exercise_1_basic_pointers(void) {
    printf("=== 练习 1: 基本指针操作 ===\n");

    u32 port = 8080;
    u32 *port_ptr = &port;  // & 取地址

    printf("port 的值:     %u\n", port);
    printf("port 的地址:   %p\n", (void *)port_ptr);
    printf("*port_ptr 的值: %u\n", *port_ptr);  // * 解引用

    // 通过指针修改值
    *port_ptr = 443;
    printf("修改后 port =  %u\n", port);

    // TODO: 练习 — 声明 u64 timestamp = 123456789
    //       创建指向它的指针，通过指针打印值
}

// ============================================================
// 练习 2: 结构体指针 — -> 操作符
// ============================================================

// 模拟 OBI 中 sock_args_t 的简化版
typedef struct {
    u64 addr;       // socket 地址
    u32 accept_fd;  // accept 返回的文件描述符
} sock_args_t;

void exercise_2_struct_pointers(void) {
    printf("\n=== 练习 2: 结构体指针 (-> 操作符) ===\n");

    sock_args_t args = {0};    // 初始化为全零 (eBPF 常见写法)
    sock_args_t *args_ptr = &args;

    // 两种访问结构体成员的方式:
    args.addr = 0xFFFF888012345678ULL;  // 方式 1: 直接访问 (变量.成员)
    args_ptr->accept_fd = 42;           // 方式 2: 指针访问 (指针->成员)

    // eBPF 代码中几乎总是使用 -> 方式，因为数据通常通过指针传递
    printf("args.addr      = 0x%llx\n", (unsigned long long)args.addr);
    printf("args_ptr->addr = 0x%llx\n", (unsigned long long)args_ptr->accept_fd);

    // 来自 OBI k_tracer.c:
    //   sock_args_t args = {0};
    //   args.addr = addr;
    //   bpf_map_update_elem(&active_accept_args, &id, &args, BPF_ANY);

    // TODO: 练习 — 创建另一个 sock_args_t 变量
    //       通过指针设置 addr = 0xDEADBEEF, accept_fd = 99
}

// ============================================================
// 练习 3: 指针作为函数参数 — eBPF 中传入/传出数据的方式
// ============================================================

// 模拟 OBI 中 fill_iphdr() 的简化版
// 来自: bpf/netolly/flows.c
typedef struct {
    u8 src_ip[4];
    u8 dst_ip[4];
    u16 src_port;
    u16 dst_port;
    u8 protocol;
} simple_flow_id;

// 在 eBPF 中，函数通过指针参数来"返回"多个值
int fill_flow_info(simple_flow_id *id, u16 *flags) {
    // 通过指针修改调用者的数据
    id->src_ip[0] = 10;
    id->src_ip[1] = 0;
    id->src_ip[2] = 0;
    id->src_ip[3] = 1;

    id->dst_ip[0] = 192;
    id->dst_ip[1] = 168;
    id->dst_ip[2] = 1;
    id->dst_ip[3] = 100;

    id->src_port = 12345;
    id->dst_port = 80;
    id->protocol = 6;  // TCP

    *flags = 0x02;  // SYN flag
    return 0;  // 成功
}

void exercise_3_pointer_params(void) {
    printf("\n=== 练习 3: 指针作为函数参数 ===\n");

    simple_flow_id flow = {0};  // 初始化为零
    u16 flags = 0;

    fill_flow_info(&flow, &flags);  // 传地址进去，函数内部修改

    printf("src: %u.%u.%u.%u:%u\n",
           flow.src_ip[0], flow.src_ip[1], flow.src_ip[2], flow.src_ip[3],
           flow.src_port);
    printf("dst: %u.%u.%u.%u:%u\n",
           flow.dst_ip[0], flow.dst_ip[1], flow.dst_ip[2], flow.dst_ip[3],
           flow.dst_port);
    printf("protocol: %u (TCP), flags: 0x%x\n", flow.protocol, flags);

    // TODO: 练习 — 写一个函数 extract_pid_tid(u64 pid_tgid, u32 *pid, u32 *tid)
    //       通过指针参数返回 PID 和 TID
}

// ============================================================
// 练习 4: void 指针和类型转换 — eBPF Map 查找的返回值
// ============================================================
void exercise_4_void_pointers(void) {
    printf("\n=== 练习 4: void 指针 (Map 查找模拟) ===\n");

    // bpf_map_lookup_elem 返回 void*，需要类型转换
    // 在 OBI 中:
    //   ssl_pid_connection_info_t *s_conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
    //   if (s_conn) { ... }

    sock_args_t data = { .addr = 0xCAFEBABE, .accept_fd = 7 };

    // 模拟 bpf_map_lookup_elem 返回 void*
    void *result = &data;

    // eBPF 常见模式: 检查非空后转换类型
    if (result) {
        sock_args_t *typed_result = (sock_args_t *)result;
        printf("Map 查找成功: addr=0x%llx, fd=%u\n",
               (unsigned long long)typed_result->addr,
               typed_result->accept_fd);
    } else {
        printf("Map 查找失败 (NULL)\n");
    }

    // 模拟查找失败的情况
    void *null_result = NULL;
    if (null_result) {
        printf("不应该打印这行\n");
    } else {
        printf("Map 查找失败: 这是 eBPF 中必须检查的情况！\n");
    }
}

int main(void) {
    exercise_1_basic_pointers();
    exercise_2_struct_pointers();
    exercise_3_pointer_params();
    exercise_4_void_pointers();

    printf("\n✓ Day 2 完成！你学会了:\n");
    printf("  - & 取地址，* 解引用\n");
    printf("  - 结构体指针用 -> 访问成员\n");
    printf("  - 指针作为函数参数传入/传出数据\n");
    printf("  - void 指针和类型转换 (Map 查找模式)\n");
    return 0;
}
