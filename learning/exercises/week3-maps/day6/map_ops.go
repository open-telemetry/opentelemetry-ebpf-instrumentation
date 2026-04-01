// ============================================================================
// Week 3 Day 6: Go 用户态 Map CRUD 操作 (cilium/ebpf)
// ============================================================================
//
// 学习目标:
//   1. 使用 cilium/ebpf 库在 Go 中操作 BPF Map
//   2. 掌握 Map 的 Create / Read / Update / Delete 操作
//   3. 学会遍历 Map 中的所有条目
//   4. 理解 OBI 项目中 Go 端如何与 BPF Map 交互
//
// OBI 参考:
//   - OBI 使用 cilium/ebpf 库加载和管理所有 BPF 程序和 Map
//   - 用户态通过 Map 操作来配置 BPF 程序、读取收集到的数据
//   - ringbuf.Reader 用于读取 events ringbuf
//
// 运行:
//   go run map_ops.go
//   (需要 root 权限: sudo go run map_ops.go)
//
// 依赖:
//   go get github.com/cilium/ebpf
//
// ============================================================================

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
)

// ============================================================================
// 第一步: 理解 cilium/ebpf 的 Map 操作方式
// ============================================================================
//
// cilium/ebpf 提供两种使用 Map 的方式:
//
// 方式 1: 从 BPF 程序加载（最常用，OBI 的做法）
//   spec, _ := ebpf.LoadCollectionSpec("program.bpf.o")
//   coll, _ := ebpf.NewCollection(spec)
//   myMap := coll.Maps["my_map_name"]
//
// 方式 2: 纯 Go 创建（不需要 BPF 程序，适合学习和测试）
//   myMap, _ := ebpf.NewMap(&ebpf.MapSpec{...})
//
// 本例使用方式 2，方便独立运行和学习。

func main() {
	// ========================================================================
	// 第二步: 创建 Map (Create)
	// ========================================================================
	//
	// ebpf.MapSpec 定义 Map 的规格（类型、key/value大小、容量）
	// 这等同于 BPF C 代码中的 struct { __uint(type, ...); ... } SEC(".maps")
	//
	// 对照 Day 1 的 C 定义:
	//   struct {
	//       __uint(type, BPF_MAP_TYPE_HASH);
	//       __type(key, __u32);         // 4 bytes
	//       __type(value, __u64);       // 8 bytes
	//       __uint(max_entries, 10240);
	//   } syscall_count SEC(".maps");

	spec := &ebpf.MapSpec{
		Name:       "demo_map",          // Map 名称（用于 bpftool 查看）
		Type:       ebpf.Hash,           // BPF_MAP_TYPE_HASH
		KeySize:    4,                   // sizeof(__u32) = 4 bytes
		ValueSize:  8,                   // sizeof(__u64) = 8 bytes
		MaxEntries: 1024,                // 最多 1024 个条目
	}

	// ebpf.NewMap 实际调用 bpf() 系统调用来创建 Map
	// 需要 CAP_BPF 权限（通常需要 root）
	demoMap, err := ebpf.NewMap(spec)
	if err != nil {
		log.Fatalf("创建 Map 失败: %v\n"+
			"提示: 需要 root 权限，请用 sudo 运行\n", err)
	}
	defer demoMap.Close() // 记得关闭！否则内核中的 Map 会泄漏

	fmt.Println("=== BPF Map CRUD 演示 ===")
	fmt.Printf("Map 创建成功: %s (type=%s, fd=%d)\n\n",
		spec.Name, spec.Type, demoMap.FD())

	// ========================================================================
	// 第三步: 写入数据 (Update / Put)
	// ========================================================================
	//
	// Map.Put(key, value) 等同于 bpf_map_update_elem(&map, &key, &value, BPF_ANY)
	//
	// key 和 value 可以是:
	//   - 基本类型 (uint32, uint64 等)
	//   - 字节切片 ([]byte)
	//   - 实现了 encoding.BinaryMarshaler 接口的类型
	//
	// 注意: Go 的类型大小必须与 MapSpec 中的 KeySize/ValueSize 匹配!

	fmt.Println("--- 写入数据 (Put) ---")

	// 模拟几个进程的系统调用计数
	// key: PID (uint32), value: 调用次数 (uint64)
	type pidCount struct {
		pid   uint32
		count uint64
	}

	testData := []pidCount{
		{pid: 1, count: 100},       // init 进程
		{pid: 1000, count: 5000},   // 某个服务进程
		{pid: 1001, count: 3200},   // 另一个服务进程
		{pid: 2000, count: 150},    // 用户进程
		{pid: 9999, count: 42},     // 测试进程
	}

	for _, d := range testData {
		// Put 方法: 如果 key 存在则更新，不存在则创建（等同于 BPF_ANY）
		if err := demoMap.Put(d.pid, d.count); err != nil {
			log.Fatalf("Put 失败 (pid=%d): %v\n", d.pid, err)
		}
		fmt.Printf("  Put: pid=%d → count=%d\n", d.pid, d.count)
	}
	fmt.Println()

	// ========================================================================
	// 第四步: 读取数据 (Lookup / Get)
	// ========================================================================
	//
	// Map.Lookup(key, valueOut) 等同于 bpf_map_lookup_elem(&map, &key)
	//
	// 与 BPF C 代码的区别:
	//   C 端: 返回指向 Map 内部数据的指针（零拷贝）
	//   Go 端: 将数据拷贝到 valueOut 变量中（有拷贝）
	//
	// 这是因为用户态不能直接访问内核内存，
	// 必须通过 bpf() 系统调用拷贝数据

	fmt.Println("--- 读取数据 (Lookup) ---")

	var value uint64

	// 查找存在的 key
	pid := uint32(1000)
	if err := demoMap.Lookup(pid, &value); err != nil {
		log.Fatalf("Lookup 失败: %v\n", err)
	}
	fmt.Printf("  Lookup: pid=%d → count=%d\n", pid, value)

	// 查找不存在的 key
	missingPid := uint32(8888)
	err = demoMap.Lookup(missingPid, &value)
	if err != nil {
		// 这不是错误，而是"key 不存在"的正常情况
		// 类似 Go map 的 val, ok := m[key] 中 ok == false
		fmt.Printf("  Lookup: pid=%d → 不存在 (err: %v)\n", missingPid, err)
	}
	fmt.Println()

	// ========================================================================
	// 第五步: 更新数据 (Update)
	// ========================================================================
	//
	// Put 是更新的简便方式（等同于 BPF_ANY flag）
	// 如果需要更精细的控制，可以使用 Update 方法指定 flag:
	//
	// Map.Update(key, value, flags)
	//   ebpf.UpdateAny     = BPF_ANY     (0): 存在则更新，不存在则创建
	//   ebpf.UpdateNoExist = BPF_NOEXIST (1): 仅创建，已存在则失败
	//   ebpf.UpdateExist   = BPF_EXIST   (2): 仅更新，不存在则失败

	fmt.Println("--- 更新数据 (Update) ---")

	// 更新已有条目
	pid = uint32(1000)
	newCount := uint64(9999)
	if err := demoMap.Update(pid, newCount, ebpf.UpdateExist); err != nil {
		log.Fatalf("Update 失败: %v\n", err)
	}
	demoMap.Lookup(pid, &value)
	fmt.Printf("  Update(Exist): pid=%d → count=%d (原值5000)\n", pid, value)

	// 尝试创建已存在的条目（应该失败）
	err = demoMap.Update(pid, uint64(0), ebpf.UpdateNoExist)
	if err != nil {
		fmt.Printf("  Update(NoExist): pid=%d → 预期的失败: %v\n", pid, err)
	}

	// 创建新条目
	newPid := uint32(3000)
	if err := demoMap.Update(newPid, uint64(777), ebpf.UpdateNoExist); err != nil {
		log.Fatalf("创建新条目失败: %v\n", err)
	}
	fmt.Printf("  Update(NoExist): pid=%d → count=777 (新创建)\n", newPid)
	fmt.Println()

	// ========================================================================
	// 第六步: 遍历所有条目 (Iterate)
	// ========================================================================
	//
	// Map.Iterate() 返回一个迭代器，用于遍历 Map 中的所有 key-value 对
	// 等同于多次调用 bpf_map_get_next_key()
	//
	// 注意事项:
	//   1. 遍历期间如果 Map 被修改，行为是未定义的（可能跳过或重复条目）
	//   2. 对于 LRU_HASH，遍历顺序是不确定的
	//   3. cilium/ebpf 的 Iterate() 已经处理了底层的 next_key 逻辑

	fmt.Println("--- 遍历所有条目 (Iterate) ---")

	var iterKey uint32
	var iterValue uint64
	totalEntries := 0

	iter := demoMap.Iterate()
	for iter.Next(&iterKey, &iterValue) {
		fmt.Printf("  pid=%d → count=%d\n", iterKey, iterValue)
		totalEntries++
	}
	if err := iter.Err(); err != nil {
		log.Fatalf("遍历出错: %v\n", err)
	}
	fmt.Printf("  共 %d 个条目\n\n", totalEntries)

	// ========================================================================
	// 第七步: 删除数据 (Delete)
	// ========================================================================
	//
	// Map.Delete(key) 等同于 bpf_map_delete_elem(&map, &key)
	//
	// 在 OBI 中，LRU_HASH 的条目通常不需要手动删除，
	// 因为 LRU 机制会自动淘汰旧条目。
	// 但在某些场景下（如进程退出时清理），手动删除是必要的。

	fmt.Println("--- 删除数据 (Delete) ---")

	deletePid := uint32(9999)
	if err := demoMap.Delete(deletePid); err != nil {
		log.Fatalf("Delete 失败: %v\n", err)
	}
	fmt.Printf("  Delete: pid=%d → 已删除\n", deletePid)

	// 验证删除成功
	err = demoMap.Lookup(deletePid, &value)
	if err != nil {
		fmt.Printf("  Lookup: pid=%d → 确认已删除: %v\n", deletePid, err)
	}
	fmt.Println()

	// ========================================================================
	// 第八步: 删除后再次遍历验证
	// ========================================================================

	fmt.Println("--- 删除后遍历验证 ---")
	totalEntries = 0
	iter = demoMap.Iterate()
	for iter.Next(&iterKey, &iterValue) {
		fmt.Printf("  pid=%d → count=%d\n", iterKey, iterValue)
		totalEntries++
	}
	fmt.Printf("  共 %d 个条目 (之前是6个，删了1个)\n\n", totalEntries)

	// ========================================================================
	// 第九步: 批量操作演示 (BatchLookup / BatchUpdate / BatchDelete)
	// ========================================================================
	//
	// 批量操作在 Linux 5.6+ 可用，性能远优于逐条操作
	// 但不是所有 Map 类型都支持
	//
	// OBI 的场景通常不需要批量操作，因为:
	//   - BPF 端逐条更新Map
	//   - 用户态通过 ringbuf 接收事件（而不是批量读Map）
	//   - Map 更多是存储中间状态，不需要批量导出

	fmt.Println("--- 额外知识: Per-CPU Map 读取示意 ---")
	showPercpuExample()

	fmt.Println("=== 演示完成 ===")
}

// showPercpuExample 演示如何读取 PERCPU_HASH 的值
// 对应 Day 5 的 percpu_counter.bpf.c
func showPercpuExample() {
	// PERCPU Map 的 value 会被 cilium/ebpf 自动展开为切片
	// 每个元素对应一个CPU的值
	//
	// 创建一个 PERCPU Map 来演示
	numCPU := numPossibleCPUs()
	fmt.Printf("  当前系统有 %d 个可用 CPU\n", numCPU)
	fmt.Println()

	// 伪代码演示（真实代码需要 root 权限）:
	//
	// percpuSpec := &ebpf.MapSpec{
	//     Type:       ebpf.PerCPUHash,      // BPF_MAP_TYPE_PERCPU_HASH
	//     KeySize:    4,                     // uint32
	//     ValueSize:  8,                     // uint64
	//     MaxEntries: 1024,
	// }
	// percpuMap, _ := ebpf.NewMap(percpuSpec)
	//
	// 写入 (每个CPU都会收到相同的初始值):
	// percpuMap.Put(uint32(100), uint64(0))
	//
	// 读取 (返回每个CPU的独立值):
	// values := make([]uint64, numCPU)
	// percpuMap.Lookup(uint32(100), &values)
	//
	// 汇总:
	// var total uint64
	// for cpu, v := range values {
	//     fmt.Printf("    CPU %d: %d\n", cpu, v)
	//     total += v
	// }
	// fmt.Printf("    总计: %d\n", total)

	fmt.Println("  Per-CPU Map 读取模式:")
	fmt.Println("    1. Lookup 返回 []uint64 切片，长度 = CPU数量")
	fmt.Println("    2. 每个元素是对应CPU上的独立值")
	fmt.Println("    3. 用户态需要自行汇总（sum）得到最终结果")
	fmt.Println("    4. cilium/ebpf 自动处理内核的per-CPU内存布局转换")
	fmt.Println()
}

// numPossibleCPUs 返回系统中可用的 CPU 数量
// 这是读取 /sys/devices/system/cpu/possible 的简化版本
// cilium/ebpf 内部也有类似的实现
func numPossibleCPUs() int {
	// 简化实现: 读取 /sys/devices/system/cpu/possible
	data, err := os.ReadFile("/sys/devices/system/cpu/possible")
	if err != nil {
		return 1
	}
	// 格式通常是 "0-N"，表示 CPU 0 到 N
	// 简单解析取最后一个数字+1
	var low, high int
	fmt.Sscanf(string(data), "%d-%d", &low, &high)
	return high + 1
}

// ============================================================================
// 学习笔记: cilium/ebpf Map API 速查表
// ============================================================================
//
// 创建:
//   map, err := ebpf.NewMap(spec)          // 从 MapSpec 创建
//   map := collection.Maps["name"]          // 从 Collection 获取
//
// CRUD 操作:
//   map.Put(key, value)                     // 写入/更新 (BPF_ANY)
//   map.Lookup(key, &value)                 // 读取
//   map.Update(key, value, flags)           // 带 flag 的更新
//   map.Delete(key)                         // 删除
//
// 遍历:
//   iter := map.Iterate()
//   for iter.Next(&key, &value) { ... }
//   err := iter.Err()
//
// 批量操作 (Linux 5.6+):
//   map.BatchLookup(cursor, keys, values, nil)
//   map.BatchUpdate(keys, values, nil)
//   map.BatchDelete(keys, nil)
//
// 信息:
//   map.Info() → MapInfo                    // Map 的元信息
//   map.FD() → int                          // 文件描述符
//   map.Pin(path)                            // Pin 到 BPF 文件系统
//
// RingBuffer 读取:
//   reader := ringbuf.NewReader(map)
//   record, err := reader.Read()            // 阻塞等待新事件
//   reader.SetDeadline(time)                // 设置超时
//   reader.Close()                           // 关闭
//
// ============================================================================

// 确保编译器不会因为 unused import 报错
var _ = binary.LittleEndian
var _ = unsafe.Sizeof
