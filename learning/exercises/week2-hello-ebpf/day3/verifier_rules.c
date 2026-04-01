// Week 2 - Day 3: Verifier 规则与限制
// 任务: 理解 eBPF verifier 的限制，以及 OBI 如何应对

/*
=== 今日学习任务 ===

eBPF Verifier 是内核中的安全检查器，加载 eBPF 程序前必须通过验证。

=== Verifier 核心规则 ===

1. 不能有不可达的代码
   → 所有代码路径必须有 return 语句

2. 不能有无限循环
   → 循环必须有编译时可确定的上限
   → OBI 中用 #pragma unroll 或有界循环

3. 栈大小限制: 512 字节
   → 不能声明大数组
   → OBI 的解决方案: 用 Map 作为临时存储 (bpf/common/scratch_mem.h)

4. 所有内存访问必须有边界检查
   → 在读取数据前必须证明不会越界
   → OBI 模式: if ((void *)ptr + sizeof(*ptr) > data_end) return;

5. 指针不能做算术比较 (除了与 data_end 比较)
   → 不能: if (ptr1 < ptr2) ...
   → 可以: if ((void *)ptr + size > data_end) ...

6. Map 查找结果必须检查 NULL
   → void *val = bpf_map_lookup_elem(...);
   → if (!val) return 0;  // 必须检查!

7. helper 函数的参数类型必须正确
   → verifier 知道每个 helper 的签名

=== OBI 中应对 verifier 的模式 ===

读以下文件，找到对应的模式:

文件: bpf/generictracer/k_tracer.c
  → 找到所有 "if (!valid_pid(id))" 检查  (规则 6 的变体)
  → 找到所有 "if ((void *)xxx > data_end)" 检查  (规则 4)

文件: bpf/common/scratch_mem.h
  → 理解为什么用 Map 替代栈上大数组  (规则 3)

文件: bpf/common/large_buffers.h
  → 理解 OBI 如何处理超过栈限制的缓冲区

=== 常见 verifier 错误和解决方案 ===

错误: "R1 type=map_value expected=map_ptr"
原因: (你遇到时填写)
解决: (你遇到时填写)

错误: "back-edge from insn X to Y"
原因: (你遇到时填写)
解决: (你遇到时填写)

错误: "invalid access to map value, value_size=X off=Y size=Z"
原因: (你遇到时填写)
解决: (你遇到时填写)

*/
