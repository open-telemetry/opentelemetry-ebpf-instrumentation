// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

// procPIDInitIno is PROC_PID_INIT_INO (include/linux/proc_ns.h), the inode of
// the initial pid namespace on every kernel.
const procPIDInitIno = 0xEFFFFFFC

// PIDNamespaceMode tells valid_pid() (bpf/pid/pid.h) how to number the current
// task the way OBI's /proc numbers it.
type PIDNamespaceMode uint32

const (
	// OBI's /proc is the initial pid namespace: the key is the host tgid.
	PIDNamespaceInit = PIDNamespaceMode(BpfPidNamespaceModeK_pidNsModeInit)
	// OBI's /proc is a pod's pid namespace: bpf_get_ns_current_pid_tgid()
	// gives the key, and rejects tasks outside that namespace.
	PIDNamespacePodHelper = PIDNamespaceMode(BpfPidNamespaceModeK_pidNsModePodHelper)
	// Same rule as PIDNamespacePodHelper, computed with CO-RE reads for
	// kernels and program types that lack the helper.
	PIDNamespacePodEmulated = PIDNamespaceMode(BpfPidNamespaceModeK_pidNsModePodEmulated)
)

type pidNamespace struct {
	dev uint64
	ino uint64
}

func pidNamespaceMode(ns pidNamespace, haveHelper func() error) PIDNamespaceMode {
	if ns.ino == procPIDInitIno {
		return PIDNamespaceInit
	}

	if haveHelper() == nil {
		return PIDNamespacePodHelper
	}

	return PIDNamespacePodEmulated
}

func pidFilterConstants(mode PIDNamespaceMode, ns pidNamespace) map[string]any {
	return map[string]any{
		"pid_ns_mode":    uint32(mode),
		"obi_pid_ns_dev": ns.dev,
		"obi_pid_ns_ino": ns.ino,
	}
}
