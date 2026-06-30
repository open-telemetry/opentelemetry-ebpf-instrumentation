// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package socktracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/socktracer"

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const (
	SO_NETNS_COOKIE  = 71    //nolint:revive,staticcheck // SO_NETNS_COOKIE, available since kernel 5.14
	ephemeralPortMin = 32768 // matches EPHEMERAL_PORT_MIN in bpf/common/protocol_defs.h
)

func (p *Tracer) backfillPidForSockets(pid app.PID) {
	if p.ingressObjs.ListenerPidMap == nil {
		return
	}

	fdDir := fmt.Sprintf("/proc/%d/fd", pid)

	entries, err := os.ReadDir(fdDir)
	if err != nil {
		p.log.Debug("readdir failed", "pid", pid, "error", err)
		return
	}

	pidfd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		p.log.Debug("pidfd_open failed", "pid", pid, "error", err)
		return
	}

	defer unix.Close(pidfd)

	val := buildListenerPidVal(pid)
	p.log.Info("scanning sockets", "pid", pid, "pidTgid", val.PidTgid, "fds", len(entries))

	for _, entry := range entries {
		fdPath := filepath.Join(fdDir, entry.Name())

		target, err := os.Readlink(fdPath)
		if err != nil || !strings.HasPrefix(target, "socket:") {
			continue
		}

		targetFd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		dupfd, err := unix.PidfdGetfd(pidfd, targetFd, 0)
		if err != nil {
			p.log.Debug("pidfd_getfd failed", "pid", pid, "fd", targetFd, "error", err)
			continue
		}

		p.log.Debug("found socket fd", "pid", pid, "fd", targetFd, "target", target)
		p.tryBackfillFd(dupfd, val)
		p.tryBackfillEstablished(dupfd, val)
		unix.Close(dupfd)
	}
}

func tcpState(fd int) (uint8, error) {
	var info unix.TCPInfo
	size := uint32(unsafe.Sizeof(info))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		unix.IPPROTO_TCP,
		unix.TCP_INFO,
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return info.State, nil
}

func buildConnInfo(local, remote unix.Sockaddr) (conn, sortedConn SocktracerEgressConnectionInfoT, skType uint8, ok bool) {
	var localIP net.IP
	var remoteIP net.IP
	var localPort, remotePort uint16

	switch l := local.(type) {
	case *unix.SockaddrInet4:
		localIP = net.IP(l.Addr[:]).To16()
		localPort = uint16(l.Port)
	case *unix.SockaddrInet6:
		localIP = net.IP(l.Addr[:]).To16()
		localPort = uint16(l.Port)
	default:
		return conn, sortedConn, 0, false
	}

	switch r := remote.(type) {
	case *unix.SockaddrInet4:
		remoteIP = net.IP(r.Addr[:]).To16()
		remotePort = uint16(r.Port)
	case *unix.SockaddrInet6:
		remoteIP = net.IP(r.Addr[:]).To16()
		remotePort = uint16(r.Port)
	default:
		return conn, sortedConn, 0, false
	}

	copy(conn.S_addr[:], localIP)
	copy(conn.D_addr[:], remoteIP)
	conn.S_port = localPort
	conn.D_port = remotePort

	sortedConn = conn
	sortConnectionInfo(&sortedConn)

	if localPort >= ephemeralPortMin {
		skType = 0 // sk_type_client
	} else {
		skType = 1 // sk_type_server
	}

	return conn, sortedConn, skType, true
}

// sortConnectionInfo mirrors sort_connection_info() in bpf/common/connection_info.h:
// normalises so that the ephemeral (client) port is always in S_port.
func sortConnectionInfo(c *SocktracerEgressConnectionInfoT) {
	sEphemeral := c.S_port >= ephemeralPortMin
	dEphemeral := c.D_port >= ephemeralPortMin

	if sEphemeral && !dEphemeral {
		return // already canonical
	}

	if (dEphemeral && !sEphemeral) || (c.D_port > c.S_port) {
		c.S_addr, c.D_addr = c.D_addr, c.S_addr
		c.S_port, c.D_port = c.D_port, c.S_port
	}
}

func (p *Tracer) tryBackfillEstablished(fd int, val SocktracerSockopsListenerPidVal) {
	state, err := tcpState(fd)
	if err != nil || state != unix.BPF_TCP_ESTABLISHED {
		return
	}

	cookie, err := socketOptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		p.log.Debug("SO_COOKIE failed", "fd", fd, "error", err)
		return
	}

	local, err := unix.Getsockname(fd)
	if err != nil {
		p.log.Debug("getsockname failed", "fd", fd, "error", err)
		return
	}

	remote, err := unix.Getpeername(fd)
	if err != nil {
		p.log.Debug("getpeername failed", "fd", fd, "error", err)
		return
	}

	conn, sortedConn, skType, ok := buildConnInfo(local, remote)
	if !ok {
		return
	}

	skData := SocktracerEgressSocketData{
		PidTgid:    val.PidTgid,
		Cookie:     cookie,
		PidInfo:    val.PidInfo,
		PidKey:     val.PidKey,
		Conn:       conn,
		SortedConn: sortedConn,
		SkType:     skType,
	}

	if p.egressObjs.SkDataMap != nil {
		if err := p.egressObjs.SkDataMap.Update(cookie, skData, ebpf.UpdateNoExist); err != nil {
			if !errors.Is(err, ebpf.ErrKeyExist) {
				p.log.Debug("sk_data_map update failed", "cookie", cookie, "error", err)
				return
			}
			// Key already exists from a previous scan; the entry is still valid.
			// Fall through to refresh sk_storage and sock_dir, which may have been
			// cleared (e.g. by the obi_socket_egress cleanup path).
			p.log.Debug("sk_data_map key already exists, refreshing storage and sockdir", "cookie", cookie)
		}
	}

	if p.egressObjs.SkStorageMap != nil {
		skStorage := SocktracerEgressSkStorageData{SkCookie: cookie, PidTgid: val.PidTgid}
		if err := p.egressObjs.SkStorageMap.Update(uint32(fd), skStorage, ebpf.UpdateAny); err != nil {
			p.log.Debug("sk_storage_map update failed", "cookie", cookie, "error", err)
		}
	}

	if p.egressObjs.SockDir != nil {
		if err := p.egressObjs.SockDir.Update(cookie, uint32(fd), ebpf.UpdateAny); err != nil {
			p.log.Debug("sock_dir update failed", "cookie", cookie, "error", err)
		}
	}

	p.log.Debug("backfilled established socket", "cookie", cookie, "skType", skType,
		"local", fmt.Sprintf("%v:%d", local, conn.S_port),
		"remote", fmt.Sprintf("%v:%d", remote, conn.D_port))
}

func buildListenerPidVal(pid app.PID) SocktracerSockopsListenerPidVal {
	val := SocktracerSockopsListenerPidVal{PidTgid: uint64(pid)<<32 | uint64(pid)}

	val.PidInfo.HostPid = uint32(pid)

	nsPids, err := procs.FindNamespacedPids(pid)

	if err == nil && len(nsPids) > 0 {
		userPid := uint32(nsPids[len(nsPids)-1])
		val.PidInfo.UserPid = userPid
		val.PidKey.Pid = userPid
		val.PidKey.Tid = userPid
	} else {
		// no namespaced PIDs found; assume root namespace
		val.PidKey.Pid = uint32(pid)
		val.PidKey.Tid = uint32(pid)
	}

	if info, err := os.Stat(fmt.Sprintf("/proc/%d/ns/pid", pid)); err == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			val.PidInfo.Ns = uint32(st.Ino)
			val.PidKey.Ns = uint32(st.Ino)
		}
	}

	return val
}

func (p *Tracer) tryBackfillFd(fd int, val SocktracerSockopsListenerPidVal) {
	netnsCookie, err := socketOptUint64(fd, unix.SOL_SOCKET, SO_NETNS_COOKIE)
	if err != nil {
		p.log.Debug("SO_NETNS_COOKIE failed", "fd", fd, "error", err)
		return
	}

	sa, err := unix.Getsockname(fd)
	if err != nil {
		p.log.Debug("getsockname failed", "fd", fd, "error", err)
		return
	}

	var localPort uint32

	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		localPort = uint32(a.Port)
	case *unix.SockaddrInet6:
		localPort = uint32(a.Port)
	default:
		return
	}

	key := SocktracerIngressListenerPidKey{
		NetnsCookie: netnsCookie,
		LocalPort:   localPort,
	}

	p.log.Debug("writing listener pid", "netns", netnsCookie, "port", localPort, "pidTgid", val.PidTgid)

	if err := p.ingressObjs.ListenerPidMap.Update(key, val, ebpf.UpdateAny); err != nil {
		p.log.Info("map update failed", "netns", netnsCookie, "port", localPort, "error", err)
	}
}

func socketOptUint64(fd, level, opt int) (uint64, error) {
	var val uint64
	size := uint32(unsafe.Sizeof(val))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(opt),
		uintptr(unsafe.Pointer(&val)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return val, nil
}
