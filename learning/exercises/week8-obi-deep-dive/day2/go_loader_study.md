# Week 8 - Day 2: Go 加载 eBPF 程序的完整流程

## 学习目标
理解 OBI 如何用 Go (cilium/ebpf) 加载、配置、运行 eBPF 程序。

## cilium/ebpf 的 bpf2go 模式

OBI 使用 `bpf2go` 工具从 .bpf.c 文件生成 Go 代码:

```
编译流程:
  .bpf.c  ──clang──→  .bpf.o  ──bpf2go──→  .go (生成代码)
  
  k_tracer.c → k_tracer_bpfel.o → k_tracer_bpfel.go
                                   k_tracer_bpfeb.go (big-endian)
```

### bpf2go 生成的代码结构

```go
// 自动生成，不要手动编辑

// 所有 Map 的集合
type tracerMaps struct {
    ActiveAcceptArgs *ebpf.Map `ebpf:"active_accept_args"`
    OngoingHttp      *ebpf.Map `ebpf:"ongoing_http"`
    Events           *ebpf.Map `ebpf:"events"`
    // ... 每个 SEC(".maps") 对应一个字段
}

// 所有 Program 的集合
type tracerPrograms struct {
    ObiKprobeSecuritySocketAccept *ebpf.Program `ebpf:"obi_kprobe_security_socket_accept"`
    ObiKprobeTcpSendmsg          *ebpf.Program `ebpf:"obi_kprobe_tcp_sendmsg"`
    // ... 每个 SEC("kprobe/...") 对应一个字段
}

// 加载函数
func loadTracer() (*tracerObjects, error) {
    // 读取嵌入的 .o 文件
    // 通过 ebpf.LoadCollection 加载到内核
    // 返回包含所有 Maps 和 Programs 的对象
}
```

## Go 加载器的完整生命周期

### Phase 1: 编译和嵌入

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tracer ./bpf/k_tracer.c

// 生成的代码使用 //go:embed 嵌入编译后的 .o 文件
// 这样 Go binary 包含了 eBPF 字节码，不需要运行时编译
```

### Phase 2: 加载到内核

```go
func setupTracer() error {
    // 1. 创建 CollectionSpec (描述所有程序和 Map)
    spec, err := loadTracer()
    
    // 2. 替换常量 (CO-RE)
    //    相当于在加载时修改 eBPF 程序的 "volatile const" 变量
    err = spec.RewriteConstants(map[string]interface{}{
        "filter_enabled": uint32(1),
        "wakeup_data_bytes": uint32(4096),
    })
    
    // 3. 加载到内核
    //    内核验证器(Verifier)在这一步检查程序安全性
    objs := tracerObjects{}
    err = spec.LoadAndAssign(&objs, nil)
    // 如果验证器拒绝，这里会返回错误
    
    return nil
}
```

### Phase 3: 附加到内核函数

```go
func attachProbes(objs *tracerObjects) error {
    // kprobe 附加
    link1, err := link.Kprobe("tcp_sendmsg", objs.ObiKprobeTcpSendmsg, nil)
    
    // kretprobe 附加
    link2, err := link.Kretprobe("tcp_recvmsg", objs.ObiKretprobeTcpRecvmsg, nil)
    
    // uprobe 附加 (需要指定二进制文件路径)
    ex, err := link.OpenExecutable("/usr/lib/libssl.so")
    link3, err := ex.Uprobe("SSL_read", objs.ObiUprobeSslRead, nil)
    
    // TC 附加 (需要创建 qdisc)
    // ... 更复杂的设置
    
    // 保存 link 用于后续清理
    return nil
}
```

### Phase 4: 读取事件

```go
func readEvents(objs *tracerObjects) {
    // 创建 RingBuffer reader
    reader, err := ringbuf.NewReader(objs.Events)
    
    for {
        record, err := reader.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                return // 正常关闭
            }
            continue
        }
        
        // 解析二进制数据为 Go 结构体
        event := parseHTTPEvent(record.RawSample)
        
        // 处理事件...
        fmt.Printf("HTTP %s %s → %d (%dms)\n",
            event.Method, event.Path, event.Status, event.LatencyMs)
    }
}
```

### Phase 5: Map 操作

```go
func managePIDs(objs *tracerObjects) {
    // 写入 PID 到过滤 Map
    pid := uint32(1234)
    val := uint8(1)
    objs.TargetPids.Put(pid, val)
    
    // 读取 Map
    var count uint64
    objs.SyscallCount.Lookup(uint32(1), &count)
    
    // 遍历 Map
    iter := objs.LatencyHist.Iterate()
    var key uint32
    var value uint64
    for iter.Next(&key, &value) {
        fmt.Printf("bucket %d: %d\n", key, value)
    }
    
    // 删除 Map 条目 (进程退出时)
    objs.TargetPids.Delete(pid)
}
```

### Phase 6: 清理

```go
func cleanup(objs *tracerObjects, links []link.Link) {
    // 关闭所有 link (从内核函数解除挂载)
    for _, l := range links {
        l.Close()
    }
    
    // 关闭所有 Map 和 Program
    objs.Close()
    
    // eBPF 程序和 Map 的引用计数归零后，内核自动释放
}
```

## OBI 特有的加载模式

### CO-RE (Compile Once Run Everywhere)

```go
// OBI 使用 BTF 确保在不同内核版本上运行
// cilium/ebpf 自动处理:
//   1. 读取目标内核的 BTF 信息
//   2. 重写 eBPF 程序中的结构体偏移量
//   3. 使得同一个 .o 文件在不同内核上都能工作
```

### 动态附加和分离

```go
// OBI 的 ProcessWatcher 发现新进程时:
//   1. 检查是否是目标进程 (通过进程名、容器ID等)
//   2. 把 PID 写入 valid_pids Map
//   3. 如果需要 uprobe，找到进程的二进制文件
//   4. 对该二进制文件附加 uprobe
//
// 进程退出时:
//   1. 从 valid_pids Map 删除 PID
//   2. 关闭对应的 uprobe link
```

## 练习任务

### TODO 1: 找到 OBI 的 bpf2go 生成命令
```bash
grep -r "go:generate.*bpf2go" --include="*.go" .
```

### TODO 2: 查看生成的 Go 文件
```bash
find . -name "*_bpfel.go" | head -5
# 阅读其中一个，理解自动生成的结构体
```

### TODO 3: 找到 OBI 的加载入口
```bash
grep -r "LoadAndAssign\|loadTracer\|loadGenerictracer" --include="*.go" .
```

### TODO 4: 理解 link 管理
```bash
grep -r "link.Kprobe\|link.Kretprobe\|link.Uprobe" --include="*.go" .
```

## 参考文件

| 文件 | 内容 |
|------|------|
| `pkg/ebpf/tracer.go` | 主要加载逻辑 |
| `go.mod` | cilium/ebpf 版本 |
| `*_bpfel.go` | bpf2go 生成的代码 |
| cilium/ebpf 文档 | https://pkg.go.dev/github.com/cilium/ebpf |
