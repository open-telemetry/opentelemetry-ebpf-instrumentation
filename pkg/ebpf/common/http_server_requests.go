// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"math"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// VisitOngoingHTTPServerRequests visits each candidate once per scan.
// The request pointer is valid only during the call to visit.
func VisitOngoingHTTPServerRequests(
	requests *ebpf.Map,
	pids ServiceFilter,
	visit func(BpfGoAddrKeyT, *request.Span),
) error {
	const handlerReturned = math.MaxUint64

	var key BpfGoAddrKeyT
	var entry BpfServerHttpFuncInvocationT
	var span request.Span

	servicesByPID := pids.CurrentPIDs(PIDTypeGo)
	seen := make(map[BpfGoAddrKeyT]struct{})
	it := requests.Iterate()
	for it.Next(&key, &entry) {
		if entry.StartMonotimeNs == 0 || entry.Status == handlerReturned {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		scheme := "http"
		if entry.IsTls != 0 {
			scheme = "https"
		}
		span = request.Span{
			Type:   request.EventTypeHTTP,
			Method: cstr(entry.Method[:]),
			Path:   cstr(entry.Path[:]),
			Pid: request.PidInfo{
				HostPID:   app.PID(entry.Pid.HostPid),
				UserPID:   app.PID(entry.Pid.UserPid),
				Namespace: entry.Pid.Ns,
			},
			Statement:        scheme + request.SchemeHostSeparator,
			RequestAuthority: cstr(entry.Host[:]),
		}
		service, ok := servicesByPID[span.Pid.Namespace][span.Pid.UserPID]
		if !ok {
			continue
		}
		span.Service = service
		if _, port := splitAuthority(span.RequestAuthority); port > 0 && port <= math.MaxUint16 {
			span.HostPort = port
		}
		visit(key, &span)
	}
	return it.Err()
}
