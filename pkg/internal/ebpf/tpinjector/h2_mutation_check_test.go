// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

const (
	h2ProbeFrameHeaderLen = 9
	h2ProbePayloadLen     = 8
	h2ProbeHPACKLen       = 69
)

var h2ProbeExpectedHPACK = []byte("\x00\x0btraceparent\x37" +
	"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")

func verifyH2MutationPeer() error {
	spec, err := LoadBpfH2MutationProbe()
	if err != nil {
		return fmt.Errorf("reading mutation probe: %w", err)
	}
	for _, probeMap := range spec.Maps {
		if probeMap.Pinning == ebpfconvenience.PinInternal {
			probeMap.Pinning = ebpf.PinNone
		}
	}

	var objects BpfH2MutationProbeObjects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return fmt.Errorf("loading rollback probe: %w", err)
	}
	defer objects.Close()

	attach := link.RawAttachProgramOptions{
		Target:  objects.Sockets.FD(),
		Program: objects.H2MutationPeer,
		Attach:  ebpf.AttachSkMsgVerdict,
	}
	if err := link.RawAttachProgram(attach); err != nil {
		return fmt.Errorf("attaching rollback probe: %w", err)
	}
	defer link.RawDetachProgram(link.RawDetachProgramOptions(attach)) //nolint:errcheck

	return verifyH2MutationPeerWrites(&objects)
}

func verifyH2MutationPeerWrites(objects *BpfH2MutationProbeObjects) error {
	client, peer, err := h2ProbeTCPPair()
	if err != nil {
		return err
	}
	defer client.Close()
	defer peer.Close()

	clientFD, err := h2ProbeSocketFD(client)
	if err != nil {
		return err
	}
	if err := objects.Sockets.Update(uint64(0), uint32(clientFD), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("inserting probe socket: %w", err)
	}
	if err := objects.Invocations.Update(uint32(0), uint32(0), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("resetting invocation count: %w", err)
	}

	first := h2ProbeFrame(1)
	if err := h2ProbeWrite(clientFD, first); err != nil {
		return fmt.Errorf("writing first frame: %w", err)
	}
	got, err := h2ProbeReadFrame(peer)
	if err != nil {
		return fmt.Errorf("reading first frame: %w", err)
	}
	if !bytes.Equal(got, h2ProbeMutatedFrame(first)) {
		return errors.New("first frame did not contain the expected mutation")
	}

	second := h2ProbeFrame(3)
	if err := h2ProbeWrite(clientFD, second); err != nil {
		return fmt.Errorf("writing subsequent frame: %w", err)
	}
	got, err = h2ProbeReadFrame(peer)
	if err != nil {
		return fmt.Errorf("reading subsequent frame: %w", err)
	}
	if !bytes.Equal(got, h2ProbeMutatedFrame(second)) {
		return errors.New("subsequent frame did not commit on the same connection")
	}

	var invocations uint32
	if err := objects.Invocations.Lookup(uint32(0), &invocations); err != nil {
		return fmt.Errorf("reading invocation count: %w", err)
	}
	if invocations != 2 {
		return fmt.Errorf("SK_MSG ran %d times for two writes", invocations)
	}
	return nil
}

func h2ProbeMutatedFrame(frame []byte) []byte {
	expected := append(append([]byte(nil), frame...), h2ProbeExpectedHPACK...)
	expected[0] = 0
	expected[1] = 0
	expected[2] = h2ProbePayloadLen + h2ProbeHPACKLen
	return expected
}

func h2ProbeTCPPair() (*net.TCPConn, *net.TCPConn, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, fmt.Errorf("listening on loopback: %w", err)
	}
	defer listener.Close()

	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to probe listener: %w", err)
	}
	peer, err := listener.AcceptTCP()
	if err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("accepting probe connection: %w", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		client.Close()
		peer.Close()
		return nil, nil, err
	}
	if err := peer.SetDeadline(deadline); err != nil {
		client.Close()
		peer.Close()
		return nil, nil, err
	}
	return client, peer, nil
}

func h2ProbeSocketFD(conn *net.TCPConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var fd int
	if err := raw.Control(func(socket uintptr) { fd = int(socket) }); err != nil {
		return 0, err
	}
	return fd, nil
}

func h2ProbeFrame(streamID uint32) []byte {
	frame := make([]byte, h2ProbeFrameHeaderLen+h2ProbePayloadLen)
	frame[2] = h2ProbePayloadLen
	frame[3] = 1
	frame[4] = 4
	binary.BigEndian.PutUint32(frame[5:9], streamID)
	copy(frame[h2ProbeFrameHeaderLen:], []byte{0x82, 0x86, 0x84, 0x41, 0x81, 0xf3, 0x87, 0xbf})
	return frame
}

func h2ProbeWrite(fd int, data []byte) error {
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if err != nil {
			return err
		}
		if n >= len(data) {
			return nil
		}
		data = data[n:]
	}
	return nil
}

func h2ProbeReadFrame(peer net.Conn) ([]byte, error) {
	header := make([]byte, h2ProbeFrameHeaderLen)
	if _, err := io.ReadFull(peer, header); err != nil {
		return nil, err
	}
	payloadLen := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(peer, payload); err != nil {
		return nil, err
	}
	return append(header, payload...), nil
}
