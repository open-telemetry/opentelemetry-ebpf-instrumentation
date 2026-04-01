#!/bin/bash
# Week 8 - Day 5: 编译和构建 OBI 项目
# 运行: bash build_obi.sh
# 前提: Go 1.22+, clang, llvm, libbpf-dev

set -e

echo "================================================"
echo "  OBI (OpenTelemetry eBPF Instrumentation) 构建指南"
echo "================================================"

# ==========================================
# Step 0: 检查构建环境
# ==========================================
echo ""
echo "=== Step 0: 检查构建环境 ==="

check_tool() {
    if command -v "$1" &>/dev/null; then
        echo "  ✓ $1: $(command -v $1)"
    else
        echo "  ✗ $1: 未安装!"
        MISSING=1
    fi
}

MISSING=0
check_tool go
check_tool clang
check_tool llvm-strip
check_tool bpftool
check_tool make

if [ "$MISSING" -eq 1 ]; then
    echo ""
    echo "缺少必要工具，请安装:"
    echo ""
    echo "  # Ubuntu/Debian:"
    echo "  sudo apt-get install -y clang llvm libbpf-dev linux-headers-\$(uname -r) bpftool"
    echo ""
    echo "  # Go (如果没装):"
    echo "  wget https://go.dev/dl/go1.22.linux-amd64.tar.gz"
    echo "  sudo tar -C /usr/local -xzf go1.22.linux-amd64.tar.gz"
    echo "  export PATH=\$PATH:/usr/local/go/bin"
    echo ""
    echo "安装完成后重新运行此脚本。"
    exit 1
fi

echo ""
echo "Go 版本: $(go version)"
echo "Clang 版本: $(clang --version | head -1)"
echo "内核版本: $(uname -r)"

# ==========================================
# Step 1: 检查内核 BTF 支持
# ==========================================
echo ""
echo "=== Step 1: 检查内核 BTF 支持 ==="

if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "  ✓ BTF 可用: /sys/kernel/btf/vmlinux"
    echo "    大小: $(ls -lh /sys/kernel/btf/vmlinux | awk '{print $5}')"
else
    echo "  ✗ BTF 不可用!"
    echo "  需要 CONFIG_DEBUG_INFO_BTF=y 的内核"
    echo "  检查: zcat /proc/config.gz | grep CONFIG_DEBUG_INFO_BTF"
fi

# ==========================================
# Step 2: 检查 eBPF 支持
# ==========================================
echo ""
echo "=== Step 2: 检查 eBPF 支持 ==="

if [ -d /sys/fs/bpf ]; then
    echo "  ✓ BPF 文件系统已挂载: /sys/fs/bpf"
else
    echo "  ✗ BPF 文件系统未挂载"
    echo "  运行: sudo mount -t bpf bpf /sys/fs/bpf"
fi

# 检查关键的 eBPF 特性
echo ""
echo "  eBPF 特性检查:"
for feature in kprobe_multi uprobe_multi ringbuf; do
    if bpftool feature probe kernel 2>/dev/null | grep -q "$feature"; then
        echo "    ✓ $feature"
    else
        echo "    ? $feature (无法确认，可能需要 root)"
    fi
done

# ==========================================
# Step 3: 获取 OBI 源码
# ==========================================
echo ""
echo "=== Step 3: 获取 OBI 源码 ==="

# 假设已经在 OBI 项目目录中
OBI_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo '')"
if [ -z "$OBI_ROOT" ]; then
    echo "  不在 git 仓库中，请先克隆:"
    echo ""
    echo "  git clone https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation.git"
    echo "  cd opentelemetry-ebpf-instrumentation"
    exit 1
fi

echo "  OBI 项目根目录: $OBI_ROOT"
echo "  Go Module: $(head -1 $OBI_ROOT/go.mod)"

# ==========================================
# Step 4: 生成 vmlinux.h
# ==========================================
echo ""
echo "=== Step 4: 生成 vmlinux.h ==="
echo "  vmlinux.h 包含内核所有类型定义 (通过 BTF)"
echo ""
echo "  生成命令:"
echo "    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h"
echo ""
echo "  注意: OBI 通常使用预生成的 vmlinux.h 或 CO-RE 方式"

# 检查项目中是否已有 vmlinux.h
VMLINUX=$(find "$OBI_ROOT" -name "vmlinux.h" -type f 2>/dev/null | head -1)
if [ -n "$VMLINUX" ]; then
    echo "  ✓ 项目中已有 vmlinux.h: $VMLINUX"
    echo "    大小: $(ls -lh "$VMLINUX" | awk '{print $5}')"
else
    echo "  项目中没有 vmlinux.h (可能使用其他方式)"
fi

# ==========================================
# Step 5: 构建 eBPF 程序
# ==========================================
echo ""
echo "=== Step 5: 构建 eBPF 程序 ==="
echo ""
echo "  OBI 的构建流程:"
echo ""
echo "  1. 编译 eBPF C 代码:"
echo "     clang -O2 -g -target bpf \\"
echo "       -D__TARGET_ARCH_x86 \\"
echo "       -I\$OBI_ROOT/bpf/common \\"
echo "       -c bpf/generictracer/k_tracer.c \\"
echo "       -o bpf/generictracer/k_tracer_bpfel.o"
echo ""
echo "  2. 去除调试符号 (可选):"
echo "     llvm-strip -g k_tracer_bpfel.o"
echo ""
echo "  3. 运行 bpf2go 生成 Go 代码:"
echo "     go generate ./..."
echo ""
echo "  4. 编译 Go 程序:"
echo "     go build -o obi ./cmd/..."

# ==========================================
# Step 6: 尝试构建
# ==========================================
echo ""
echo "=== Step 6: 构建命令 ==="
echo ""
echo "  完整构建 (推荐):"
echo "    cd $OBI_ROOT"
echo "    make build"
echo ""
echo "  或分步构建:"
echo "    make generate  # 生成 eBPF Go 绑定"
echo "    make compile   # 编译 Go 程序"
echo ""
echo "  只编译 eBPF 部分:"
echo "    make bpf"

# 检查 Makefile
if [ -f "$OBI_ROOT/Makefile" ]; then
    echo ""
    echo "  可用的 Make 目标:"
    grep -E "^[a-zA-Z_-]+:" "$OBI_ROOT/Makefile" 2>/dev/null | head -20 | sed 's/://' | while read target; do
        echo "    - make $target"
    done
fi

# ==========================================
# Step 7: 验证构建结果
# ==========================================
echo ""
echo "=== Step 7: 验证构建结果 ==="
echo ""
echo "  构建完成后，验证步骤:"
echo ""
echo "  1. 检查 eBPF .o 文件:"
echo "     find $OBI_ROOT -name '*.bpf.o' -o -name '*_bpfel.o'"
echo ""
echo "  2. 查看 eBPF 程序信息:"
echo "     llvm-objdump -d k_tracer_bpfel.o | head -50"
echo ""
echo "  3. 查看 Map 定义:"
echo "     bpftool btf dump file k_tracer_bpfel.o"
echo ""
echo "  4. 运行单元测试:"
echo "     go test ./..."

# ==========================================
# 常见构建问题
# ==========================================
echo ""
echo "=== 常见构建问题 ==="
echo ""
cat << 'PROBLEMS'
问题 1: "cannot find vmlinux.h"
  → 运行: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
  → 确保 -I 包含 vmlinux.h 所在目录

问题 2: "unknown type name '__u64'"
  → vmlinux.h 应该定义了这些类型
  → 检查 #include 顺序: vmlinux.h 必须在 bpf_helpers.h 之前

问题 3: "program too large" (验证器拒绝)
  → 确保使用 -O2 优化
  → 检查循环是否有上界
  → 使用 #pragma unroll

问题 4: "BTF is not available"
  → 内核需要 CONFIG_DEBUG_INFO_BTF=y
  → Ubuntu 5.8+ 默认启用
  → 检查: ls /sys/kernel/btf/vmlinux

问题 5: Go 构建失败 "missing go.sum entry"
  → 运行: go mod tidy
  → 然后重新构建
PROBLEMS

echo ""
echo "================================================"
echo "  构建环境检查完成！"
echo "  请根据上述指导完成 OBI 的构建。"
echo "================================================"
