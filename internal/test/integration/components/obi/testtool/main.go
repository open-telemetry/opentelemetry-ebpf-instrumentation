// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// obitesttool runs inside the OBI integration image:
//
//	obitesttool map-keys NAME          prints the u64 keys of every BPF map named NAME
//	obitesttool bitmap-pids NAME       prints the pids set in the pid-indexed bitmap named NAME
//	obitesttool host-pid NSINODE NSPID prints the pid OBI's /proc has for a pid in that namespace
//	obitesttool seccomp-exec MODE CMD  execs CMD with pidfd_getfd failing EPERM:
//	                                   none: never, all: always, probe-only: unless it asks for
//	                                   OBI's startup probe descriptor
package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// the descriptor OBI's startup probe asks pidfd_getfd for
const probeFD = math.MaxInt32

// struct seccomp_data offsets
const (
	offNr      = 0
	offArch    = 4
	offArg1Low = 24
)

func main() {
	if len(os.Args) < 3 {
		fail("usage: obitesttool map-keys|bitmap-pids NAME | host-pid NSINODE NSPID | seccomp-exec none|all|probe-only CMD [ARGS...]")
	}

	var err error
	switch os.Args[1] {
	case "map-keys":
		err = printMapKeys(os.Args[2])
	case "bitmap-pids":
		err = printBitmapPIDs(os.Args[2])
	case "host-pid":
		if len(os.Args) < 4 {
			fail("host-pid needs a namespace inode and a pid")
		}
		err = printHostPID(os.Args[2], os.Args[3])
	case "seccomp-exec":
		if len(os.Args) < 4 {
			fail("seccomp-exec needs a mode and a command")
		}
		err = seccompExec(os.Args[2], os.Args[3:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

// calls fn on every BPF map named name
func forEachMap(name string, fn func(*ebpf.Map) error) error {
	// the kernel keeps BPF_OBJ_NAME_LEN bytes of a name, its NUL included
	name = name[:min(len(name), unix.BPF_OBJ_NAME_LEN-1)]
	found := false
	var id ebpf.MapID
	for {
		next, err := ebpf.MapGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return err
		}
		id = next

		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err == nil && info.Name == name {
			found = true
			err = fn(m)
		} else {
			err = nil
		}
		m.Close()
		if err != nil {
			return err
		}
	}
	if !found {
		return fmt.Errorf("no BPF map named %q", name)
	}
	return nil
}

// a sockhash value can't be read back from user space, so only keys are walked
func printMapKeys(name string) error {
	return forEachMap(name, func(m *ebpf.Map) error {
		var key uint64
		err := m.NextKey(nil, &key)
		for err == nil {
			fmt.Println(key)
			prev := key
			err = m.NextKey(&prev, &key)
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	})
}

func printBitmapPIDs(name string) error {
	return forEachMap(name, func(m *ebpf.Map) error {
		var word uint32
		var bits uint64
		entries := m.Iterate()
		for entries.Next(&word, &bits) {
			for bit := range uint64(64) {
				if bits&(1<<bit) != 0 {
					fmt.Println(uint64(word)*64 + bit)
				}
			}
		}
		return entries.Err()
	})
}

// the pid whose own namespace has that inode and whose innermost NSpid is that pid
func printHostPID(nsInode, nsPID string) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, e := range entries {
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		var st unix.Stat_t
		if unix.Stat("/proc/"+pid+"/ns/pid", &st) != nil || strconv.FormatUint(st.Ino, 10) != nsInode {
			continue
		}
		status, err := os.ReadFile("/proc/" + pid + "/status")
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(status), "\n") {
			if fields, ok := strings.CutPrefix(line, "NSpid:"); ok {
				nspids := strings.Fields(fields)
				if len(nspids) > 0 && nspids[len(nspids)-1] == nsPID {
					fmt.Println(pid)
					return nil
				}
			}
		}
	}
	return fmt.Errorf("no process %s in pid namespace %s", nsPID, nsInode)
}

func seccompExec(mode string, command []string) error {
	path, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}

	if mode != "none" {
		filter, err := pidfdGetfdFilter(mode)
		if err != nil {
			return err
		}
		// the filter applies to this thread only, which is the one that execs
		runtime.LockOSThread()
		prog := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, unix.PR_SET_SECCOMP,
			unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog))); errno != 0 {
			return fmt.Errorf("installing seccomp filter: %w", errno)
		}
	}

	return syscall.Exec(path, command, os.Environ())
}

func pidfdGetfdFilter(mode string) ([]syscall.SockFilter, error) {
	var arch uint32
	switch runtime.GOARCH {
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	default:
		return nil, fmt.Errorf("unsupported architecture %s", runtime.GOARCH)
	}

	load := func(offset uint32) syscall.SockFilter {
		return syscall.SockFilter{Code: syscall.BPF_LD | syscall.BPF_W | syscall.BPF_ABS, K: offset}
	}
	jumpIfEqual := func(value uint32, skipTrue, skipFalse uint8) syscall.SockFilter {
		return syscall.SockFilter{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, Jt: skipTrue, Jf: skipFalse, K: value}
	}
	allow := syscall.SockFilter{Code: syscall.BPF_RET | syscall.BPF_K, K: unix.SECCOMP_RET_ALLOW}
	deny := syscall.SockFilter{Code: syscall.BPF_RET | syscall.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)}

	switch mode {
	case "all":
		return []syscall.SockFilter{
			load(offArch), jumpIfEqual(arch, 1, 0), allow,
			load(offNr), jumpIfEqual(unix.SYS_PIDFD_GETFD, 0, 1), deny, allow,
		}, nil
	case "probe-only":
		return []syscall.SockFilter{
			load(offArch), jumpIfEqual(arch, 1, 0), allow,
			load(offNr), jumpIfEqual(unix.SYS_PIDFD_GETFD, 0, 3),
			load(offArg1Low), jumpIfEqual(probeFD, 1, 0), deny, allow,
		}, nil
	default:
		return nil, fmt.Errorf("unknown seccomp mode %q", mode)
	}
}
