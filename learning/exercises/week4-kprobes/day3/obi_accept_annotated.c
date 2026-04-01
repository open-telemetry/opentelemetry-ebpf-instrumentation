// Week 4 - Day 3: 精读 OBI 的 security_socket_accept kprobe
// 这是注释学习文件，对照 bpf/generictracer/k_tracer.c 第 53-78 行

/*
=== 原始代码 (来自 k_tracer.c) ===

SEC("kprobe/security_socket_accept")
int BPF_KPROBE(obi_kprobe_security_socket_accept, struct socket *sock, struct socket *newsock) {

  [SEC("kprobe/security_socket_accept")]
    → 挂载到 security_socket_accept 内核函数
    → 这个函数在 accept() 系统调用的安全检查阶段被调用
    → 比 sys_accept 更早，但能获取到 socket 结构体

  [BPF_KPROBE(obi_kprobe_security_socket_accept, struct socket *sock, struct socket *newsock)]
    → BPF_KPROBE 宏自动展开为标准 kprobe 函数签名
    → 自动从 ctx (pt_regs) 中提取参数 sock 和 newsock
    → 等价于手动: struct socket *newsock = (struct socket *)PT_REGS_PARM2(ctx);

    (void)ctx;
    (void)sock;

    → 显式忽略未使用的参数，避免编译器警告
    → ctx 由 BPF_KPROBE 宏隐式声明

    const u64 id = bpf_get_current_pid_tgid();

    → 获取当前线程的 PID+TID 组合
    → 高 32 位 = TGID (进程组ID = 通常所说的 PID)
    → 低 32 位 = PID (线程ID = TID)

    if (!valid_pid(id)) {
        return 0;
    }

    → ★ PID 过滤! OBI 只追踪目标进程
    → valid_pid() 在 bpf/pid/pid.h 中定义
    → 检查 TGID 是否在 valid_pids Map 中
    → 如果不是目标进程，直接返回 (零开销)

    bpf_dbg_printk("=== kprobe/security_socket_accept id=%llx ===", id);

    → 调试打印，只在编译时开启 DEBUG 时有效
    → 生产环境中这行不会产生任何代码

    const u64 addr = (u64)newsock;

    → 记录新 socket 的内核地址
    → 为什么存地址而不是直接读取 sock？
    → 因为此时 newsock->sock 还没有被初始化！
    → accept 还没完成，sock 成员是无效的

    sock_args_t args = {0};
    args.addr = addr;

    → 创建一个参数结构体，初始化为零
    → 只存储 socket 地址，等 accept 完成后再读取详细信息

    bpf_map_update_elem(&active_accept_args, &id, &args, BPF_ANY);

    → 存入 HashMap: key=tid, value=sock_args
    → BPF_ANY 表示无论 key 是否存在都更新
    → 在 kretprobe/sys_accept4 中会取出这个数据

    return 0;
}

=== 配套的 kretprobe ===

SEC("kretprobe/sys_accept4")
int BPF_KRETPROBE(obi_kretprobe_sys_accept4, s32 fd) {

    → 在 accept4 系统调用返回时触发
    → fd 是返回的文件描述符 (新连接)
    → 此时 socket 已经完全初始化，可以读取连接信息了

    // 流程:
    // 1. 从 active_accept_args 中取出之前存的 socket 地址
    // 2. 通过 socket 地址读取 struct sock 的连接信息
    // 3. 提取: 源IP、目标IP、源端口、目标端口
    // 4. 存入连接追踪 Map
    // 5. 清理 active_accept_args
}

=== 设计模式总结 ===

为什么用 security_socket_accept 而不是 sys_accept?
  → security_socket_accept 能获取到 struct socket 指针
  → sys_accept 的参数是文件描述符和用户态地址，内核态不方便用

为什么需要 kprobe + kretprobe 配对?
  → kprobe 时: socket 还没初始化完，只能记录地址
  → kretprobe 时: socket 已初始化，可以读取完整连接信息
  → HashMap 作为两者之间的数据传递桥梁

*/
