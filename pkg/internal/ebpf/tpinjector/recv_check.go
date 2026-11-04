// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Some vendor kernels return zero instead of EAGAIN from an empty, still-open
// socket once it enters a sockhash. Event loops interpret this as EOF, even
// without a verdict program. Probe only throwaway connections before enrollment.
func sockhashReceiveProbe() error {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.SockHash, KeySize: 8, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		return err
	}
	defer m.Close()
	lsn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer lsn.Close()
	client, err := net.Dial("tcp4", lsn.Addr().String())
	if err != nil {
		return err
	}
	defer client.Close()
	peer, err := lsn.Accept()
	if err != nil {
		return err
	}
	defer peer.Close()
	raw, err := client.(*net.TCPConn).SyscallConn()
	if err != nil {
		return err
	}
	var result error
	err = raw.Control(func(fd uintptr) {
		if result = m.Update(uint64(1), uint32(fd), ebpf.UpdateAny); result != nil {
			return
		}
		var buf [1]byte
		n, _, readErr := unix.Recvfrom(int(fd), buf[:], unix.MSG_DONTWAIT)
		if !errors.Is(readErr, unix.EAGAIN) {
			if readErr != nil {
				result = fmt.Errorf("nonblocking sockhash read: %w", readErr)
			} else {
				result = fmt.Errorf("empty connected socket returned n=%d without EAGAIN", n)
			}
		}
	})
	if err != nil {
		return err
	}
	return result
}
