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
	origIso := isIsolatedNetNS
	origWith := withNetNS
	origAddrs := interfaceAddrs
	t.Cleanup(func() {
		isIsolatedNetNS = origIso
		withNetNS = origWith
		interfaceAddrs = origAddrs
	})

	var sawPID int
	isIsolatedNetNS = func(pid int) (bool, error) {
		assert.Equal(t, 4242, pid)
		return true, nil
	}
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

func TestIPsForPID_sharedNetNSReturnsNoIPs(t *testing.T) {
	origIso := isIsolatedNetNS
	origWith := withNetNS
	t.Cleanup(func() {
		isIsolatedNetNS = origIso
		withNetNS = origWith
	})

	listed := false
	isIsolatedNetNS = func(int) (bool, error) { return false, nil }
	withNetNS = func(int, func() error) error {
		listed = true
		return nil
	}

	ips, err := IPsForPID(app.PID(1))
	require.NoError(t, err)
	assert.Empty(t, ips)
	assert.False(t, listed)
}

func TestIPsForPID_propagatesIsolationError(t *testing.T) {
	origIso := isIsolatedNetNS
	t.Cleanup(func() { isIsolatedNetNS = origIso })

	sentinel := errors.New("stat netns")
	isIsolatedNetNS = func(int) (bool, error) { return false, sentinel }

	_, err := IPsForPID(app.PID(1))
	assert.ErrorIs(t, err, sentinel)
}

func TestIPsForPID_propagatesNetNSError(t *testing.T) {
	origIso := isIsolatedNetNS
	origWith := withNetNS
	t.Cleanup(func() {
		isIsolatedNetNS = origIso
		withNetNS = origWith
	})

	isIsolatedNetNS = func(int) (bool, error) { return true, nil }
	sentinel := errors.New("setns denied")
	withNetNS = func(int, func() error) error { return sentinel }

	_, err := IPsForPID(app.PID(1))
	assert.ErrorIs(t, err, sentinel)
}
