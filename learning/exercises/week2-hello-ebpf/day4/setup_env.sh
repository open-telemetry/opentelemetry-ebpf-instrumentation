#!/bin/bash
# Week 2 - Day 4: 环境搭建
# 运行: chmod +x setup_env.sh && ./setup_env.sh

set -e

echo "=== eBPF 开发环境搭建 ==="
echo ""

# 1. 检查内核版本 (需要 >= 5.8 以获得良好的 eBPF 支持)
echo "[1/7] 检查内核版本..."
KERNEL_VERSION=$(uname -r)
echo "  当前内核: $KERNEL_VERSION"
echo ""

# 2. 安装编译工具
echo "[2/7] 安装编译工具 (clang, llvm)..."
echo "  运行: sudo apt install -y clang llvm"
# sudo apt install -y clang llvm
echo ""

# 3. 安装 eBPF 开发库
echo "[3/7] 安装 eBPF 开发库..."
echo "  运行: sudo apt install -y libbpf-dev linux-headers-\$(uname -r)"
# sudo apt install -y libbpf-dev linux-headers-$(uname -r)
echo ""

# 4. 安装 bpftool
echo "[4/7] 安装 bpftool..."
echo "  运行: sudo apt install -y linux-tools-common linux-tools-\$(uname -r) bpftool"
# sudo apt install -y linux-tools-common linux-tools-$(uname -r) bpftool
echo ""

# 5. 安装 Go 的 cilium/ebpf 库
echo "[5/7] 安装 Go cilium/ebpf 库..."
echo "  运行: go install github.com/cilium/ebpf/cmd/bpf2go@latest"
# go install github.com/cilium/ebpf/cmd/bpf2go@latest
echo ""

# 6. 验证安装
echo "[6/7] 验证安装..."
echo "  --- 验证清单 ---"

check_tool() {
    if command -v "$1" &>/dev/null; then
        echo "  ✓ $1: $(${@:2} 2>&1 | head -1)"
    else
        echo "  ✗ $1: 未安装"
    fi
}

check_tool clang clang --version
check_tool llc llc --version
check_tool bpftool bpftool version
check_tool bpf2go bpf2go --help

echo ""

# 7. 检查内核 BTF 支持 (CO-RE 需要)
echo "[7/7] 检查内核 BTF 支持..."
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "  ✓ BTF 可用: /sys/kernel/btf/vmlinux"
else
    echo "  ✗ BTF 不可用 (CO-RE 可能不工作)"
    echo "    尝试: sudo apt install linux-image-\$(uname -r)-dbg"
fi

echo ""
echo "=== 环境搭建完成！==="
echo ""
echo "下一步: 明天 (Day 5) 写第一个 eBPF Hello World 程序"
