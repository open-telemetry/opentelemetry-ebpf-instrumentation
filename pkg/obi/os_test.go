// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package obi

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/helpers"
)

type testCase struct {
	maj int
	min int
}

var overrideKernelVersion = func(tc testCase) {
	kernelVersion = func() (major, minor int) {
		return tc.maj, tc.min
	}
}

func TestCheckOSSupport_Supported(t *testing.T) {
	isRHELBased = func() bool { return false }
	hasBTF = func() bool { return true }
	for _, tc := range []testCase{
		{maj: 5, min: 8},
		{maj: 6, min: 0},
		{maj: 7, min: 15},
	} {
		t.Run(fmt.Sprintf("%d.%d", tc.maj, tc.min), func(t *testing.T) {
			overrideKernelVersion(tc)
			require.NoError(t, checkOSSupport())
		})
	}
}

func TestCheckOSSupport_Unsupported(t *testing.T) {
	isRHELBased = func() bool { return false }
	hasBTF = func() bool { return true }
	for _, tc := range []testCase{
		{maj: 0, min: 0},
		{maj: 3, min: 11},
		{maj: 4, min: 0},
		{maj: 4, min: 17},
		{maj: 5, min: 7},
	} {
		t.Run(fmt.Sprintf("%d.%d", tc.maj, tc.min), func(t *testing.T) {
			overrideKernelVersion(tc)
			require.Error(t, checkOSSupport())
		})
	}
}

func TestCheckOSSupport_RHELBased(t *testing.T) {
	hasBTF = func() bool { return true }
	for _, tc := range []struct {
		name     string
		isRHEL   bool
		maj, min int
		wantErr  bool
	}{
		{name: "RHEL 4.18 supported", isRHEL: true, maj: 4, min: 18, wantErr: false},
		{name: "RHEL 4.17 unsupported", isRHEL: true, maj: 4, min: 17, wantErr: true},
		{name: "RHEL 5.8 supported", isRHEL: true, maj: 5, min: 8, wantErr: false},
		{name: "non-RHEL 4.18 unsupported", isRHEL: false, maj: 4, min: 18, wantErr: true},
		{name: "non-RHEL 5.8 supported", isRHEL: false, maj: 5, min: 8, wantErr: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			overrideKernelVersion(testCase{tc.maj, tc.min})
			rhel := tc.isRHEL
			isRHELBased = func() bool { return rhel }
			if tc.wantErr {
				require.Error(t, checkOSSupport())
			} else {
				require.NoError(t, checkOSSupport())
			}
		})
	}
}

func TestCheckOSSupport_NoBTF(t *testing.T) {
	overrideKernelVersion(testCase{6, 0})
	isRHELBased = func() bool { return false }
	hasBTF = func() bool { return false }
	err := checkOSSupport()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BTF")
}

func TestParseOSReleaseIsRHEL(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    bool
	}{
		{name: "RHEL", content: "ID=\"rhel\"\n", want: true},
		{name: "Rocky via ID_LIKE", content: "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n", want: true},
		{name: "AlmaLinux via ID_LIKE", content: "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n", want: true},
		{name: "CentOS", content: "ID=\"centos\"\n", want: true},
		{name: "RHEL unquoted", content: "ID=rhel\n", want: true},
		{name: "RHEL single-quoted", content: "ID='rhel'\n", want: true},
		{name: "Rocky via ID_LIKE single-quoted", content: "ID='rocky'\nID_LIKE='rhel centos fedora'\n", want: true},
		{name: "Ubuntu", content: "ID=ubuntu\nID_LIKE=debian\n", want: false},
		{name: "Debian", content: "ID=debian\n", want: false},
		{name: "empty file", content: "", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseOSReleaseIsRHEL([]byte(tc.content)))
		})
	}
}

func TestOSCapabilitiesError_Empty(t *testing.T) {
	var capErr osCapabilitiesError

	assert.True(t, capErr.Empty())
	assert.Empty(t, capErr.Error())
}

func TestOSCapabilitiesError_Set(t *testing.T) {
	var capErr osCapabilitiesError

	for c := helpers.OSCapability(0); c <= unix.CAP_LAST_CAP; c++ {
		assert.False(t, capErr.IsSet(c))
		capErr.Set(c)
		assert.True(t, capErr.IsSet(c))
		capErr.Clear(c)
		assert.False(t, capErr.IsSet(c))
	}
}

func TestOSCapabilitiesError_ErrorString(t *testing.T) {
	var capErr osCapabilitiesError

	assert.Empty(t, capErr.Error())

	capErr.Set(unix.CAP_BPF)

	// no separator (,)
	assert.Equal(t, "the following capabilities are required: CAP_BPF", capErr.Error())

	capErr.Set(unix.CAP_NET_RAW)

	// capabilities appear in ascending order (they are just numeric
	// constants) separated by a comma
	assert.Equal(t, "the following capabilities are required: CAP_NET_RAW, CAP_BPF", capErr.Error())
}

type capClass int

const (
	capCore = capClass(iota + 1)
	capApp
	capNet
)

type capTestData struct {
	osCap         helpers.OSCapability
	class         capClass
	kernMaj       int
	kernMin       int
	tcSource      bool // use TC as network source (capNet only)
	contextPropOn bool // enable context propagation (capApp only)
}

var capTests = []capTestData{
	// core
	{osCap: unix.CAP_BPF, class: capCore, kernMaj: 6, kernMin: 10},

	// app o11y
	{osCap: unix.CAP_CHECKPOINT_RESTORE, class: capApp, kernMaj: 6, kernMin: 10},
	{osCap: unix.CAP_DAC_READ_SEARCH, class: capApp, kernMaj: 6, kernMin: 10},
	{osCap: unix.CAP_SYS_PTRACE, class: capApp, kernMaj: 6, kernMin: 10},
	{osCap: unix.CAP_PERFMON, class: capApp, kernMaj: 6, kernMin: 10},
	{osCap: unix.CAP_NET_RAW, class: capApp, kernMaj: 6, kernMin: 10},
	{osCap: unix.CAP_NET_ADMIN, class: capApp, kernMaj: 6, kernMin: 10, contextPropOn: true},

	// net o11y
	{osCap: unix.CAP_NET_RAW, class: capNet, kernMaj: 6, kernMin: 10},
	{osCap: unix.CAP_PERFMON, class: capNet, kernMaj: 6, kernMin: 10, tcSource: true},
	{osCap: unix.CAP_NET_ADMIN, class: capNet, kernMaj: 6, kernMin: 10, tcSource: true},
}

func TestCheckOSCapabilities(t *testing.T) {
	caps, err := helpers.GetCurrentProcCapabilities()

	require.NoError(t, err)

	// assume this proc doesn't have any caps set (which is usually the case
	// for non privileged processes) instead of turning this into a privileged
	// test and manually dropping capabilities
	assert.Zero(t, caps[0].Effective)
	assert.Zero(t, caps[1].Effective)

	test := func(data *capTestData) {
		overrideKernelVersion(testCase{data.kernMaj, data.kernMin})

		netSource := EbpfSourceSock
		if data.tcSource {
			netSource = EbpfSourceTC
		}

		contextProp := config.ContextPropagationDisabled
		if data.contextPropOn {
			contextProp = config.ContextPropagationHeaders
		}

		cfg := Config{
			NetworkFlows: NetworkConfig{Enable: data.class == capNet, Source: netSource},
			EBPF:         config.EBPFTracer{ContextPropagation: contextProp},
		}
		if data.class == capApp {
			// activates app o11y feature
			require.NoError(t, cfg.Exec.UnmarshalText([]byte(".")))
		}

		err := CheckOSCapabilities(&cfg)

		require.Error(t, err, "CheckOSCapabilities() should have returned an error")

		var osCapErr osCapabilitiesError

		if !errors.As(err, &osCapErr) {
			assert.Fail(t, "CheckOSCapabilities failed", err)
		}

		assert.Truef(t, osCapErr.IsSet(data.osCap),
			"%s should be present in error", data.osCap.String())
	}

	for i := range capTests {
		c := capTests[i]
		t.Run(fmt.Sprintf("%s %d.%d", c.osCap.String(), c.kernMaj, c.kernMin), func(*testing.T) {
			test(&c)
		})
	}
}
