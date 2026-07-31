// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func TestUniqueNonLoopbackIPs(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		&net.IPNet{IP: net.ParseIP("172.17.0.2"), Mask: net.CIDRMask(16, 32)},
		&net.IPNet{IP: net.ParseIP("172.17.0.2"), Mask: net.CIDRMask(16, 32)}, // dup
		&net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPAddr{IP: net.ParseIP("10.0.0.1")}, // wrong type, ignored
	}
	assert.Equal(t, []string{"172.17.0.2", "fd00::1"}, uniqueNonLoopbackIPs(addrs))
}

func TestIPsForPID_usesNetNS(t *testing.T) {
	origWith := withNetNS
	origAddrs := interfaceAddrs
	t.Cleanup(func() {
		withNetNS = origWith
		interfaceAddrs = origAddrs
	})

	var sawPID int
	withNetNS = func(pid int, fn func() error) error {
		sawPID = pid
		return fn()
	}
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("10.88.0.5"), Mask: net.CIDRMask(16, 32)},
		}, nil
	}

	ips, err := IPsForPID(app.PID(4242))
	require.NoError(t, err)
	assert.Equal(t, 4242, sawPID)
	assert.Equal(t, []string{"10.88.0.5"}, ips)
}

func TestIPsForPID_propagatesNetNSError(t *testing.T) {
	origWith := withNetNS
	t.Cleanup(func() { withNetNS = origWith })

	sentinel := errors.New("setns denied")
	withNetNS = func(int, func() error) error { return sentinel }

	_, err := IPsForPID(app.PID(1))
	assert.ErrorIs(t, err, sentinel)
}
