// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"io/fs"
	"syscall"
)

func pythonSourceFileVersion(info fs.FileInfo) (pythonSourceVersion, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return pythonSourceVersion{}, false
	}
	return pythonSourceVersion{
		device:   stat.Dev,
		inode:    stat.Ino,
		size:     info.Size(),
		modified: info.ModTime().UnixNano(),
	}, true
}
