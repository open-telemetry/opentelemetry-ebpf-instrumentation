// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func TestOTelTracesPIDFilter(t *testing.T) {
	original := readNamespacePIDs
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid, pid / 1000}, nil
	}
	t.Cleanup(func() { readNamespacePIDs = original })

	for _, tc := range []struct {
		name    string
		exclude bool
		path    string
		status  int
		marked  bool
	}{
		{name: "trace export", exclude: true, path: "/v1/traces", status: 200, marked: true},
		{name: "metric export", exclude: true, path: "/v1/metrics", status: 200},
		{name: "failed trace export", exclude: true, path: "/v1/traces", status: 500},
		{name: "exclusion disabled", path: "/v1/traces", status: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pf := NewPIDsFilter(&services.DiscoveryConfig{
				ExcludeOTelInstrumentedServices: tc.exclude,
			}, slog.Default(), nil)
			pf.AllowPID(1000, 42, exec.New(exec.Init{}), PIDTypeKProbes)
			pf.AllowPID(2000, 42, exec.New(exec.Init{}), PIDTypeGo)
			marked := map[app.PID]bool{}
			pf.SetOTelTracesPIDFilter(func(pid app.PID, selected bool) error {
				marked[pid] = selected
				return nil
			})

			pf.Filter([]request.Span{{
				Type: request.EventTypeHTTPClient, Path: tc.path, Status: tc.status,
				Pid: request.PidInfo{UserPID: 1, HostPID: 9000, Namespace: 42},
			}})
			assert.Equal(t, map[app.PID]bool{1000: tc.marked, 2000: false}, marked)
			pf.BlockPID(1000, 42)
			assert.False(t, marked[1000])
		})
	}
}

func TestOTelTracesPIDFilterRetriesAndFollowsPIDLifecycle(t *testing.T) {
	original := readNamespacePIDs
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) { return []app.PID{pid}, nil }
	t.Cleanup(func() { readNamespacePIDs = original })

	pf := NewPIDsFilter(&services.DiscoveryConfig{
		ExcludeOTelInstrumentedServices: true,
	}, slog.Default(), nil)
	fi := exec.New(exec.Init{})
	pf.AllowPID(1000, 42, fi, PIDTypeGo)
	span := request.Span{
		Type: request.EventTypeHTTPClient, Path: "/v1/traces", Status: 200,
		Pid: request.PidInfo{UserPID: 1000, Namespace: 42},
	}
	pf.Filter([]request.Span{span})

	var selected bool
	attempts := 0
	pf.SetOTelTracesPIDFilter(func(_ app.PID, mark bool) error {
		attempts++
		if attempts == 1 {
			return errors.New("map update failed")
		}
		selected = mark
		return nil
	})
	assert.False(t, selected)
	pf.Filter([]request.Span{span})
	assert.True(t, selected, "an already detected service must retry failed map updates")

	pf.BlockPID(1000, 42)
	assert.False(t, selected)
	pf.Filter([]request.Span{span})
	assert.False(t, selected, "late spans must not mark removed PIDs")

	pf.AllowPID(1000, 42, exec.New(exec.Init{}), PIDTypeGo)
	pf.Filter([]request.Span{span})
	assert.False(t, selected, "late spans must not mark a reused PID")
	span.End = int64(pidsFilterMonoNow() + time.Second)
	pf.Filter([]request.Span{span})
	assert.True(t, selected)

	pf.RemoveOTelTracesPIDFilter()
	beforeDetach := attempts
	pf.BlockPID(1000, 42)
	require.Equal(t, beforeDetach, attempts, "detaching must stop updates before the BPF map closes")
}
