# Week 8 - Day 3: 进程发现与自动附加机制

## 学习目标
理解 OBI 如何自动发现目标进程并附加 eBPF 探针。

## 为什么需要进程发现?

传统 eBPF 工具:
```
sudo bpftrace -p 1234 ...    ← 需要手动指定 PID
```

OBI 的目标:
```
自动发现运行中的 HTTP/gRPC 服务 → 自动附加探针 → 自动生成 Trace
不需要修改应用代码，不需要知道 PID
```

## OBI 的进程发现架构

```
┌──────────────────────────────────────────────┐
│             ProcessWatcher (Go)               │
│                                               │
│  ┌─────────────┐     ┌───────────────────┐   │
│  │ /proc 扫描   │     │ Netlink 监听      │   │
│  │ (启动时)     │     │ (实时, 进程事件)   │   │
│  └──────┬──────┘     └────────┬──────────┘   │
│         │                     │               │
│         └─────────┬───────────┘               │
│                   ↓                           │
│         ┌─────────────────┐                   │
│         │ 进程过滤器       │                   │
│         │ - 命名空间      │                   │
│         │ - 容器 ID       │                   │
│         │ - 进程名        │                   │
│         │ - 端口          │                   │
│         └────────┬────────┘                   │
│                  ↓                            │
│         ┌─────────────────┐                   │
│         │ 探针管理器       │                   │
│         │ - 更新 PID Map  │                   │
│         │ - 附加 uprobe   │                   │
│         │ - 清理退出进程   │                   │
│         └─────────────────┘                   │
└──────────────────────────────────────────────┘
```

## Phase 1: 进程扫描

### 启动时扫描 /proc

```go
// 伪代码: 扫描所有运行中的进程
func scanExistingProcesses() []Process {
    entries, _ := os.ReadDir("/proc")
    
    var processes []Process
    for _, entry := range entries {
        pid, err := strconv.Atoi(entry.Name())
        if err != nil {
            continue // 跳过非 PID 目录
        }
        
        // 读取进程信息
        proc := Process{
            PID:     pid,
            Comm:    readFile(fmt.Sprintf("/proc/%d/comm", pid)),
            Exe:     readLink(fmt.Sprintf("/proc/%d/exe", pid)),
            CgroupID: getCgroupID(pid),
        }
        
        processes = append(processes, proc)
    }
    return processes
}
```

### 实时监听新进程 (Netlink)

```go
// Netlink PROC_EVENT 监听
// Linux 内核通过 Netlink 通知用户态进程创建/退出事件
func watchProcessEvents() <-chan ProcessEvent {
    // 创建 Netlink socket
    sock, _ := netlink.Subscribe(
        netlink.PROC_CN_MCAST_LISTEN,
    )
    
    events := make(chan ProcessEvent)
    go func() {
        for {
            msg, _ := sock.Receive()
            switch msg.Type {
            case PROC_EVENT_EXEC:
                events <- ProcessEvent{Type: "exec", PID: msg.PID}
            case PROC_EVENT_EXIT:
                events <- ProcessEvent{Type: "exit", PID: msg.PID}
            }
        }
    }()
    return events
}
```

## Phase 2: 进程过滤

### 判断是否是目标进程

```go
func shouldTrace(proc Process) bool {
    // 1. 命名空间过滤 (Kubernetes 环境)
    if config.Namespace != "" {
        if proc.Namespace != config.Namespace {
            return false
        }
    }
    
    // 2. 容器过滤
    if config.ContainerID != "" {
        if proc.ContainerID != config.ContainerID {
            return false
        }
    }
    
    // 3. 服务名过滤
    if config.ServiceFilter != "" {
        if !matchGlob(proc.Comm, config.ServiceFilter) {
            return false
        }
    }
    
    // 4. 检查是否监听网络端口 (只追踪网络服务)
    if !hasListeningPorts(proc.PID) {
        return false
    }
    
    return true
}
```

### 检查监听端口

```go
func hasListeningPorts(pid int) bool {
    // 读取 /proc/{pid}/net/tcp 和 /proc/{pid}/net/tcp6
    // 检查是否有 LISTEN 状态的 socket
    
    data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/net/tcp", pid))
    // 解析格式:
    //   sl  local_address rem_address   st tx_queue rx_queue ...
    //   0: 00000000:1F90 00000000:0000 0A ...
    //                    ^^^^          ^^ 
    //                    port=8080     state=0A(LISTEN)
    
    return containsListenState(data)
}
```

## Phase 3: 探针附加

### 更新内核态 PID Map

```go
func attachToProcess(objs *tracerObjects, pid uint32) error {
    // 1. 把 PID 写入 valid_pids Map
    val := uint8(1)
    err := objs.ValidPids.Put(pid, val)
    if err != nil {
        return fmt.Errorf("failed to add PID %d: %w", pid, err)
    }
    
    // 2. 如果需要 uprobe (SSL/Go 函数追踪)
    err = attachUprobes(objs, pid)
    
    return err
}
```

### 附加 Uprobe (需要找到二进制文件)

```go
func attachUprobes(objs *tracerObjects, pid uint32) error {
    // 找到进程的可执行文件
    exePath, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
    
    // 检查是否是 Go 程序
    if isGoBinary(exePath) {
        // Go 程序: 附加 Go HTTP 相关的 uprobe
        ex, _ := link.OpenExecutable(exePath)
        
        // 找到 Go 函数符号
        link1, _ := ex.Uprobe(
            "net/http.(*ServeMux).ServeHTTP",
            objs.ObiUprobeServeHTTP,
            &link.UprobeOptions{PID: int(pid)},
        )
        // 保存 link 用于后续清理
    }
    
    // 检查是否链接了 libssl
    if usesLibSSL(pid) {
        // 找到 libssl.so 的路径
        libsslPath := findLibrary(pid, "libssl.so")
        ex, _ := link.OpenExecutable(libsslPath)
        
        link2, _ := ex.Uprobe("SSL_read", objs.ObiUprobeSslRead,
            &link.UprobeOptions{PID: int(pid)})
    }
    
    return nil
}

// 检查进程是否加载了某个共享库
func findLibrary(pid int, libName string) string {
    // 读取 /proc/{pid}/maps
    // 找到 libssl.so 的内存映射
    data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
    // 格式: 7f1234000000-7f1234100000 r-xp ... /usr/lib/libssl.so.3
    
    for _, line := range strings.Split(string(data), "\n") {
        if strings.Contains(line, libName) {
            // 提取路径
            parts := strings.Fields(line)
            return parts[len(parts)-1]
        }
    }
    return ""
}
```

## Phase 4: 进程退出清理

```go
func detachFromProcess(pid uint32) {
    // 1. 从 valid_pids Map 删除
    objs.ValidPids.Delete(pid)
    
    // 2. 关闭该进程的 uprobe links
    if links, ok := processLinks[pid]; ok {
        for _, l := range links {
            l.Close()
        }
        delete(processLinks, pid)
    }
    
    // 3. 清理 ongoing_* Map 中该进程的条目
    //    (避免内存泄漏)
    cleanupMapsForPID(pid)
}
```

## 练习任务

### TODO 1: 查看 OBI 的进程发现代码
```bash
# 找到 ProcessWatcher 或类似的进程管理代码
grep -r "ProcessWatcher\|WatchProcesses\|proc.*scan" --include="*.go" .
find . -name "*.go" -path "*/process*"
```

### TODO 2: 理解 /proc 文件系统
```bash
# 查看一个进程的信息
ls /proc/$$/          # 当前 shell 进程
cat /proc/$$/comm     # 进程名
cat /proc/$$/maps | head -20  # 内存映射
cat /proc/$$/net/tcp  # TCP 连接
```

### TODO 3: 找到 uprobe 附加逻辑
```bash
grep -r "OpenExecutable\|Uprobe(" --include="*.go" .
```

### TODO 4: 理解 Netlink 进程监听
```bash
grep -r "netlink\|PROC_EVENT\|proc_connector" --include="*.go" .
```

## Kubernetes 环境下的进程发现

在 K8s 中，OBI 通常以 DaemonSet 方式运行:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: obi-agent
spec:
  template:
    spec:
      hostPID: true          # 必须: 访问宿主机的 /proc
      hostNetwork: true       # 可选: 访问宿主机网络
      containers:
      - name: obi
        securityContext:
          privileged: true    # 必须: 加载 eBPF 程序
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
      volumes:
      - name: proc
        hostPath:
          path: /proc
```

进程发现流程:
1. 通过 `hostPID: true` 看到所有宿主机进程
2. 通过 cgroup ID 关联到 Kubernetes Pod
3. 通过 Pod 标签/注解决定是否追踪
4. 自动附加探针，无需修改 Pod spec

## 参考文件

| 文件 | 内容 |
|------|------|
| `pkg/discover/` | 进程发现逻辑 |
| `pkg/ebpf/` | 探针附加逻辑 |
| `/proc/{pid}/` | Linux 进程信息 |
