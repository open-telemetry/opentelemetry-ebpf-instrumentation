// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"log/slog"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func debugLogResponseLargeBufferOnParseFail(responseBuffer *largebuf.LargeBuffer, respErr error) {
	if respErr == nil {
		return
	}
	p := largebuf.ProbeShape(responseBuffer)
	slog.Debug("HTTP response large buffer shape on parse failure",
		"respErr", respErr,
		"responseBufferLen", p.Len,
		"headerTerminatorOffset", p.HeaderTerminatorOffset,
		"startsWithHTTP", p.StartsWithHTTP,
		"head64Hex", p.Head64Hex,
		"tail64Hex", p.Tail64Hex,
	)
}
