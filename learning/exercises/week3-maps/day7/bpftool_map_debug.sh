#!/bin/bash
# ============================================================================
# Week 3 Day 7: bpftool map 调试命令大全
# ============================================================================
#
# 学习目标:
#   1. 掌握 bpftool map 的各种子命令
#   2. 学会用 bpftool 观察、调试、操作 BPF Map
#   3. 理解如何在开发中用 bpftool 排查问题
#
# OBI 参考:
#   - OBI 的 Map 都会出现在 bpftool 的输出中
#   - 可以用 bpftool 实时查看 OBI 正在追踪的连接、请求等信息
#   - 当 OBI 行为异常时，bpftool 是最直接的调试工具
#
# 运行:
#   chmod +x bpftool_map_debug.sh
#   sudo ./bpftool_map_debug.sh
#
# 前提:
#   - 需要 root 权限
#   - 需要安装 bpftool (sudo apt install linux-tools-common)
#   - 建议先加载 Day 1 或 Day 5 的 BPF 程序，这样有Map可以操作
#
# ============================================================================

set -e  # 遇到错误就停止

# 颜色定义（让输出更好看）
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

# 辅助函数: 打印章节标题
section() {
    echo ""
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN}  $1${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo ""
}

# 辅助函数: 打印说明
note() {
    echo -e "${YELLOW}[说明] $1${NC}"
}

# 辅助函数: 打印命令
show_cmd() {
    echo -e "${BLUE}[命令] $1${NC}"
}

# 检查是否有 root 权限
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}错误: 需要 root 权限，请使用 sudo 运行${NC}"
    echo "  sudo $0"
    exit 1
fi

# 检查 bpftool 是否可用
if ! command -v bpftool &> /dev/null; then
    echo -e "${RED}错误: bpftool 未安装${NC}"
    echo "安装方法:"
    echo "  Ubuntu/Debian: sudo apt install linux-tools-common linux-tools-\$(uname -r)"
    echo "  Fedora/RHEL:   sudo dnf install bpftool"
    echo "  Arch Linux:    sudo pacman -S bpf"
    exit 1
fi

# ============================================================================
# 1. 列出所有 Map
# ============================================================================

section "1. 列出系统中所有 BPF Map"

note "bpftool map list 显示内核中当前存在的所有 BPF Map"
note "这包括系统组件（如 systemd、cgroup）创建的 Map"
note "如果运行了 OBI，会看到 fd_map, events, ongoing_http 等 Map"
echo ""

show_cmd "bpftool map list"
bpftool map list 2>/dev/null || echo "  (当前没有 BPF Map)"
echo ""

note "加上 --json 可以输出 JSON 格式（便于程序解析）"
show_cmd "bpftool map list --json | python3 -m json.tool | head -30"
bpftool map list --json 2>/dev/null | python3 -m json.tool 2>/dev/null | head -30 || echo "  (无输出)"

# ============================================================================
# 2. 查看 Map 详细信息
# ============================================================================

section "2. 查看 Map 详细信息"

note "bpftool map show 可以查看单个 Map 的详细属性"
note "可以通过 id 或 name 来指定 Map"
echo ""

# 获取第一个 Map 的 ID（如果存在的话）
FIRST_MAP_ID=$(bpftool map list --json 2>/dev/null | python3 -c "
import json, sys
try:
    maps = json.load(sys.stdin)
    if maps:
        print(maps[0]['id'])
except:
    pass
" 2>/dev/null)

if [ -n "$FIRST_MAP_ID" ]; then
    show_cmd "bpftool map show id $FIRST_MAP_ID"
    bpftool map show id "$FIRST_MAP_ID" 2>/dev/null
    echo ""
    note "字段含义:"
    note "  id: Map 的内核ID（唯一标识）"
    note "  type: Map 类型（hash, lru_hash, ringbuf 等）"
    note "  key: Key 的大小（字节）"
    note "  value: Value 的大小（字节）"
    note "  max_entries: 最大条目数"
    note "  flags: Map 的标志位"
else
    note "当前系统没有 BPF Map，跳过此步骤"
    note "加载一个 BPF 程序后再运行本脚本可以看到更多信息"
fi

# ============================================================================
# 3. 转储 Map 内容 (Dump)
# ============================================================================

section "3. 转储 Map 所有内容 (Dump)"

note "bpftool map dump 是最常用的调试命令"
note "它会显示 Map 中所有的 key-value 对"
echo ""

if [ -n "$FIRST_MAP_ID" ]; then
    show_cmd "bpftool map dump id $FIRST_MAP_ID"
    # 限制输出行数，避免大 Map 刷屏
    bpftool map dump id "$FIRST_MAP_ID" 2>/dev/null | head -40
    echo "  ... (只显示前40行)"
    echo ""

    note "以 JSON 格式输出（更适合脚本处理）:"
    show_cmd "bpftool map dump id $FIRST_MAP_ID --json"
    bpftool map dump id "$FIRST_MAP_ID" --json 2>/dev/null | python3 -m json.tool 2>/dev/null | head -30
    echo "  ... (只显示前30行)"
else
    note "当前没有 Map，跳过 dump"
fi

# ============================================================================
# 4. 查找单个条目 (Lookup)
# ============================================================================

section "4. 查找单个条目 (Lookup)"

note "bpftool map lookup 用于查找指定 key 的 value"
note "key 以十六进制字节指定"
echo ""

note "语法: bpftool map lookup id <MAP_ID> key <HEX_BYTES>"
note "例如查找 key = PID 1 (0x01000000, 小端序 uint32):"
echo ""

if [ -n "$FIRST_MAP_ID" ]; then
    show_cmd "bpftool map lookup id $FIRST_MAP_ID key 01 00 00 00"
    bpftool map lookup id "$FIRST_MAP_ID" key 01 00 00 00 2>/dev/null || echo "  key 不存在（这是正常的）"
    echo ""

    note "关于字节序（非常重要!）:"
    note "  x86/x86_64 是小端序（Little Endian）"
    note "  数字 1 的 uint32 表示: 01 00 00 00 (不是 00 00 00 01)"
    note "  数字 1000 = 0x3E8 的 uint32: e8 03 00 00"
    note "  这是初学者最常见的错误!"
else
    note "当前没有 Map，跳过 lookup"
fi

# ============================================================================
# 5. 更新条目 (Update)
# ============================================================================

section "5. 更新/创建条目 (Update)"

note "bpftool map update 可以创建或更新 Map 条目"
note "这对于在运行时注入配置非常有用"
echo ""

note "语法: bpftool map update id <MAP_ID> key <HEX> value <HEX>"
note "标志: any (默认) | exist | noexist"
echo ""

note "示例命令（不执行，仅展示语法）:"
echo ""
show_cmd "bpftool map update id <ID> key 01 00 00 00 value 2a 00 00 00 00 00 00 00"
note "  → 设置 key=1, value=42 (0x2a, uint64小端序)"
echo ""
show_cmd "bpftool map update id <ID> key 01 00 00 00 value 2a 00 00 00 00 00 00 00 noexist"
note "  → 仅当 key 不存在时才创建"

# ============================================================================
# 6. 删除条目 (Delete)
# ============================================================================

section "6. 删除条目 (Delete)"

note "bpftool map delete 删除指定 key 的条目"
echo ""

note "语法: bpftool map delete id <MAP_ID> key <HEX_BYTES>"
note "示例:"
show_cmd "bpftool map delete id <ID> key 01 00 00 00"
note "  → 删除 key=1 的条目"

# ============================================================================
# 7. 按名字操作 Map
# ============================================================================

section "7. 按名字操作 Map"

note "除了用 id，还可以用 name 指定 Map（更方便）"
echo ""

show_cmd "bpftool map dump name syscall_count"
note "  → 转储名为 syscall_count 的 Map"
echo ""

show_cmd "bpftool map dump name events"
note "  → 查看 OBI 的 events ringbuf"
echo ""

note "对于 pinned Map（如 OBI 使用的），还可以通过路径访问:"
show_cmd "bpftool map dump pinned /sys/fs/bpf/my_map"

# ============================================================================
# 8. Pinned Map 操作
# ============================================================================

section "8. Pinned Map 操作"

note "Pinning 将 Map 持久化到 BPF 文件系统"
note "OBI 使用 OBI_PIN_INTERNAL 来在多个 BPF 程序间共享 Map"
echo ""

note "查看已 pinned 的对象:"
show_cmd "ls -la /sys/fs/bpf/"
ls -la /sys/fs/bpf/ 2>/dev/null || echo "  (bpffs 未挂载或目录为空)"
echo ""

note "手动 pin 一个 Map:"
show_cmd "bpftool map pin id <ID> /sys/fs/bpf/my_pinned_map"
echo ""

note "从 pinned 路径操作:"
show_cmd "bpftool map dump pinned /sys/fs/bpf/my_pinned_map"

# ============================================================================
# 9. Map 统计信息
# ============================================================================

section "9. Map 元信息和统计"

note "查看 Map 的元信息（btf 类型信息等）"
echo ""

if [ -n "$FIRST_MAP_ID" ]; then
    show_cmd "bpftool map show id $FIRST_MAP_ID --json --pretty"
    bpftool map show id "$FIRST_MAP_ID" --json --pretty 2>/dev/null | head -20
else
    note "当前没有 Map，跳过"
fi

echo ""
note "查看系统中 Map 的数量统计:"
MAP_COUNT=$(bpftool map list --json 2>/dev/null | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
echo "  当前系统中有 $MAP_COUNT 个 BPF Map"

# ============================================================================
# 10. 实用调试技巧
# ============================================================================

section "10. 实用调试技巧"

note "技巧 1: 持续监控 Map 变化"
show_cmd "watch -n 1 'bpftool map dump name syscall_count 2>/dev/null | tail -20'"
note "  → 每秒刷新一次，观察计数变化"
echo ""

note "技巧 2: 统计 Map 条目数"
show_cmd "bpftool map dump name my_map --json | python3 -c \"import json,sys; print(len(json.load(sys.stdin)))\""
note "  → 输出当前 Map 中的条目数量"
echo ""

note "技巧 3: 导出 Map 内容到文件"
show_cmd "bpftool map dump name my_map --json > map_snapshot.json"
note "  → 保存快照，用于后续分析"
echo ""

note "技巧 4: 查看 Map 关联的 BPF 程序"
show_cmd "bpftool prog list"
note "  → 列出所有 BPF 程序，可以看到每个程序使用了哪些 Map"
echo ""

note "技巧 5: 查看 Map 的 BTF 类型信息（如果有）"
show_cmd "bpftool btf dump id <BTF_ID>"
note "  → 显示 Map 的 key/value 的结构体定义（如果编译时包含了 BTF）"
echo ""

note "技巧 6: 用 bpftool 创建 Map（无需写 BPF 程序）"
show_cmd "bpftool map create /sys/fs/bpf/test_map type hash key 4 value 8 entries 1024 name test_map"
note "  → 直接创建一个 Map，适合快速测试"
echo ""

# ============================================================================
# 11. OBI 调试专用命令
# ============================================================================

section "11. OBI 项目调试命令"

note "以下命令在 OBI 运行时使用，用于调试 OBI 的 BPF Map"
echo ""

note "查看 OBI 的所有 Map:"
show_cmd "bpftool map list | grep -E '(fd_map|events|ongoing_http|trace_map|clone_map|sock_pids|server_traces|accepted_conn)'"
echo ""

note "查看正在追踪的 HTTP 连接:"
show_cmd "bpftool map dump name ongoing_http --json --pretty | head -50"
echo ""

note "查看 trace context 信息:"
show_cmd "bpftool map dump name trace_map --json --pretty | head -50"
echo ""

note "查看连接到文件描述符的映射:"
show_cmd "bpftool map dump name fd_map --json --pretty | head -50"
echo ""

note "查看进程克隆关系:"
show_cmd "bpftool map dump name clone_map --json --pretty | head -50"
echo ""

note "查看 events ringbuf 的状态:"
show_cmd "bpftool map show name events"
echo ""

note "监控 OBI 的 Map 使用情况（条目数）:"
cat << 'SCRIPT'
  # 可以保存为独立脚本使用
  while true; do
    echo "--- $(date) ---"
    for name in fd_map ongoing_http trace_map clone_map sock_pids events; do
      count=$(bpftool map dump name "$name" --json 2>/dev/null | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "N/A")
      printf "  %-20s: %s entries\n" "$name" "$count"
    done
    sleep 5
  done
SCRIPT

echo ""

# ============================================================================
# 总结
# ============================================================================

section "命令速查表"

echo "  bpftool map list                         # 列出所有 Map"
echo "  bpftool map show id <ID>                 # 查看 Map 详情"
echo "  bpftool map dump id <ID>                 # 转储所有条目"
echo "  bpftool map dump name <NAME>             # 按名字转储"
echo "  bpftool map lookup id <ID> key <HEX>     # 查找单条"
echo "  bpftool map update id <ID> key <HEX> value <HEX>  # 更新"
echo "  bpftool map delete id <ID> key <HEX>     # 删除"
echo "  bpftool map pin id <ID> <PATH>           # Pin 到 BPF FS"
echo "  bpftool map dump pinned <PATH>           # 从 pin 路径读取"
echo "  bpftool map create <PATH> type <T> key <N> value <N> entries <N>  # 创建"
echo ""
echo "  常用选项:"
echo "    --json         JSON 输出格式"
echo "    --pretty       美化 JSON 输出"
echo "    -d / --debug   调试模式（显示系统调用细节）"
echo ""

echo -e "${GREEN}=== 脚本执行完毕 ===${NC}"
