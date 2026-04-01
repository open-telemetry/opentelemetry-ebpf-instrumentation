#!/bin/bash
# Week 2 - Day 7: bpftool 调试实践
# 运行: chmod +x bpftool_debug.sh && sudo ./bpftool_debug.sh

echo "=== bpftool 调试实践 ==="
echo ""

echo "[1] 列出所有已加载的 eBPF 程序"
echo "命令: bpftool prog list"
echo "---"
bpftool prog list 2>/dev/null || echo "(需要 root 权限: sudo bpftool prog list)"
echo ""

echo "[2] 列出所有 eBPF Map"
echo "命令: bpftool map list"
echo "---"
bpftool map list 2>/dev/null || echo "(需要 root 权限)"
echo ""

echo "[3] 查看特定 Map 的内容 (替换 MAP_ID)"
echo "命令: bpftool map dump id <MAP_ID>"
echo "---"
echo "(示例: bpftool map dump id 42)"
echo ""

echo "[4] 查看 eBPF 程序的详细信息"
echo "命令: bpftool prog show id <PROG_ID>"
echo "---"
echo "(示例: bpftool prog show id 1)"
echo ""

echo "[5] 查看 BTF 信息 (内核类型)"
echo "命令: bpftool btf list"
echo "---"
bpftool btf list 2>/dev/null | head -10 || echo "(需要 root 权限)"
echo ""

echo "[6] 查看特定程序的字节码"
echo "命令: bpftool prog dump xlated id <PROG_ID>"
echo "---"
echo "(示例: bpftool prog dump xlated id 1)"
echo ""

echo "=== 常用调试流程 ==="
echo ""
echo "1. 加载问题调试:"
echo "   bpftool prog load my_prog.bpf.o /sys/fs/bpf/my_prog"
echo "   → verifier 错误会直接显示在输出中"
echo ""
echo "2. Map 内容检查:"
echo "   bpftool map dump id <ID> | head -20"
echo "   → 查看 Map 中的 key-value 对"
echo ""
echo "3. trace_pipe 实时查看 bpf_printk 输出:"
echo "   cat /sys/kernel/debug/tracing/trace_pipe"
echo ""
echo "4. 性能统计:"
echo "   bpftool prog profile id <PROG_ID> duration 5"
echo "   → 5 秒内的执行统计"
