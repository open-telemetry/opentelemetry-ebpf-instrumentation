// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import "io/fs"

func pythonSourceFileVersion(_ fs.FileInfo) (pythonSourceVersion, bool) {
	return pythonSourceVersion{}, false
}
