// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package obi // import "go.opentelemetry.io/obi/pkg/obi"

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/helpers"
)

// Minimum required Kernel version: 5.8 (or 4.18 for RHEL-based distros)
const (
	minKernMaj, minKernMin         = 5, 8
	minRHELKernMaj, minRHELKernMin = 4, 18
)

var (
	kernelVersion = ebpfcommon.KernelVersion
	readOSRelease = func() ([]byte, error) {
		return os.ReadFile("/etc/os-release")
	}
)

func isRHELBased() bool {
	data, err := readOSRelease()
	if err != nil {
		return false
	}
	content := strings.ToLower(string(data))
	// matches ID="rhel" or ID_LIKE containing "rhel" (e.g. Rocky, AlmaLinux, CentOS set ID_LIKE="rhel ...")
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "id=") || strings.HasPrefix(line, "id_like=") {
			if strings.Contains(line, "rhel") || strings.Contains(line, "centos") ||
				strings.Contains(line, "rocky") || strings.Contains(line, "alma") {
				return true
			}
		}
	}
	return false
}

// CheckOSSupport returns an error if the running operating system does not support
// the minimum required OBI features.
func CheckOSSupport() error {
	major, minor := kernelVersion()
	maj, min := minKernMaj, minKernMin
	if isRHELBased() {
		maj, min = minRHELKernMaj, minRHELKernMin
	}
	if major < maj || (major == maj && minor < min) {
		return fmt.Errorf("kernel version %d.%d not supported. Minimum required version is %d.%d",
			major, minor, maj, min)
	}

	if _, err := btf.LoadKernelSpec(); err != nil {
		return fmt.Errorf("kernel does not support BTF (CONFIG_DEBUG_INFO_BTF): %w", err)
	}

	return nil
}

type osCapabilitiesError uint64

func (e *osCapabilitiesError) Set(c helpers.OSCapability) {
	*e |= 1 << c
}

func (e *osCapabilitiesError) Clear(c helpers.OSCapability) {
	*e &= ^(1 << c)
}

func (e osCapabilitiesError) IsSet(c helpers.OSCapability) bool {
	return e&(1<<c) > 0
}

func (e osCapabilitiesError) Empty() bool {
	return e == 0
}

func (e osCapabilitiesError) Error() string {
	if e == 0 {
		return ""
	}

	var sb strings.Builder

	sb.WriteString("the following capabilities are required: ")

	sep := ""

	for i := helpers.OSCapability(0); i <= unix.CAP_LAST_CAP; i++ {
		if e.IsSet(i) {
			sb.WriteString(sep)
			sb.WriteString(i.String())

			sep = ", "
		}
	}

	return sb.String()
}

func testAndSet(caps *helpers.OSCapabilities, capError *osCapabilitiesError, c helpers.OSCapability) {
	if !caps.Has(c) {
		capError.Set(c)
	}
}

func checkCapabilitiesForSetOptions(config *Config, caps *helpers.OSCapabilities, capError *osCapabilitiesError) {
	if config.Enabled(FeatureAppO11y) {
		testAndSet(caps, capError, unix.CAP_CHECKPOINT_RESTORE)
		testAndSet(caps, capError, unix.CAP_DAC_READ_SEARCH)
		testAndSet(caps, capError, unix.CAP_SYS_PTRACE)
		testAndSet(caps, capError, unix.CAP_PERFMON)
		testAndSet(caps, capError, unix.CAP_NET_RAW)

		if config.EBPF.ContextPropagation.IsEnabled() {
			testAndSet(caps, capError, unix.CAP_NET_ADMIN)
		}
	}

	if config.Enabled(FeatureNetO11y) {
		switch config.NetworkFlows.Source {
		case EbpfSourceSock:
			testAndSet(caps, capError, unix.CAP_NET_RAW)
		case EbpfSourceTC:
			testAndSet(caps, capError, unix.CAP_PERFMON)
			testAndSet(caps, capError, unix.CAP_NET_ADMIN)
		}
	}

	// Note: these should be the minimum caps needed to run statsolly right now.
	// As metrics are added in the future, this list may change depending on
	// the probe used to calculate the metric.
	if config.Enabled(FeatureStatsO11y) {
		testAndSet(caps, capError, unix.CAP_SYS_PTRACE)
		testAndSet(caps, capError, unix.CAP_PERFMON)
		testAndSet(caps, capError, unix.CAP_NET_RAW)
	}
}

func CheckOSCapabilities(config *Config) error {
	caps, err := helpers.GetCurrentProcCapabilities()
	if err != nil {
		return fmt.Errorf("unable to query OS capabilities: %w", err)
	}

	var capError osCapabilitiesError

	major, minor := kernelVersion()

	// below kernels 5.8 all BPF permissions were bundled under SYS_ADMIN
	if (major == 5 && minor < 8) || (major < 5) {
		testAndSet(caps, &capError, unix.CAP_SYS_ADMIN)

		if capError.Empty() {
			return nil
		}

		return capError
	}

	// if sys admin is set, we have all capabilities
	if caps.Has(unix.CAP_SYS_ADMIN) {
		return nil
	}

	// core capabilities
	testAndSet(caps, &capError, unix.CAP_BPF)

	// CAP_SYS_RESOURCE is only required on kernels < 5.11
	if (major == 5 && minor < 11) || (major < 5) {
		testAndSet(caps, &capError, unix.CAP_SYS_RESOURCE)
	}

	checkCapabilitiesForSetOptions(config, caps, &capError)

	if capError.Empty() {
		return nil
	}

	return capError
}
