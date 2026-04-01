#!/bin/bash
# Week 5 - Day 7: 验证 uprobe 挂载
echo "=== 查看已挂载的 uprobe ==="
echo "命令: cat /sys/kernel/debug/tracing/uprobe_events"
sudo cat /sys/kernel/debug/tracing/uprobe_events 2>/dev/null || echo "(需要 root)"
echo ""
echo "=== 查看 eBPF 程序列表 (过滤 uprobe) ==="
echo "命令: bpftool prog list | grep uprobe"
sudo bpftool prog list 2>/dev/null | grep -A2 uprobe || echo "(需要 root)"
echo ""
echo "=== 查看特定二进制的可用符号 ==="
echo "对于 Go 程序: go tool nm ./binary | grep 'main\\.'"
echo "对于 C 程序:  nm -D /usr/lib/x86_64-linux-gnu/libssl.so | grep SSL_read"
