// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type PIDType uint8

const (
	PIDTypeKProbes PIDType = 1 << iota
	PIDTypeGo
)

// injectable functions (can be replaced in tests). It reads the
// current process namespace from the /proc filesystem. It is required to
// choose to filter traces using whether the User-space or Host-space PIDs
var readNamespacePIDs = procs.FindNamespacedPids
var childFileInfoFromProc = fileInfoFromProc

type PIDInfo struct {
	fileInfo       *exec.FileInfo
	pidTypes       PIDType
	otherKnownPids []app.PID
}

type ServiceFilter interface {
	AllowPID(app.PID, uint32, *exec.FileInfo, PIDType)
	BlockPID(app.PID, uint32)
	ValidPID(app.PID, uint32, PIDType) bool
	Filter(inputSpans []request.Span) []request.Span
	CurrentPIDs(PIDType) map[uint32]map[app.PID]svc.Attrs
}

type parentAwareServiceFilter interface {
	AllowPIDFromParent(pid app.PID, hostPID app.PID, parentPID app.PID, ns uint32, pidType PIDType, processName string) bool
}

// PIDsFilter keeps a thread-safe copy of the PIDs whose traces are allowed to
// be forwarded. Its Filter method filters the request.Span instances whose
// PIDs are not in the allowed list.
type PIDsFilter struct {
	log                 *slog.Logger
	current             map[uint32]map[app.PID]PIDInfo
	mux                 *sync.RWMutex
	ignoreOtel          bool
	ignoreOtelSpan      bool
	defaultOtlpGRPCPort int
	metrics             imetrics.Reporter
}

func NewPIDsFilter(c *services.DiscoveryConfig, log *slog.Logger, metrics imetrics.Reporter) *PIDsFilter {
	return &PIDsFilter{
		log:                 log,
		current:             map[uint32]map[app.PID]PIDInfo{},
		mux:                 &sync.RWMutex{},
		ignoreOtel:          c.ExcludeOTelInstrumentedServices,
		ignoreOtelSpan:      c.ExcludeOTelInstrumentedServicesSpanMetrics,
		defaultOtlpGRPCPort: c.DefaultOtlpGRPCPort,
		metrics:             metrics,
	}
}

func (pf *PIDsFilter) AllowPID(pid app.PID, ns uint32, fi *exec.FileInfo, pidType PIDType) {
	pf.mux.Lock()
	defer pf.mux.Unlock()
	pf.addPID(pid, ns, fi, pidType)
}

func (pf *PIDsFilter) BlockPID(pid app.PID, ns uint32) {
	pf.mux.Lock()
	defer pf.mux.Unlock()
	pf.removePID(pid, ns)
}

func (pf *PIDsFilter) ValidPID(userPID app.PID, ns uint32, pidType PIDType) bool {
	pf.mux.RLock()
	defer pf.mux.RUnlock()

	if ns, nsExists := pf.current[ns]; nsExists {
		if info, pidExists := ns[userPID]; pidExists {
			return info.pidTypes&pidType != 0
		}
	}

	return false
}

func (pf *PIDsFilter) AllowPIDFromParent(pid app.PID, hostPID app.PID, parentPID app.PID, ns uint32, pidType PIDType, processName string) bool {
	if pid == 0 || parentPID == 0 {
		return false
	}

	pf.mux.Lock()
	defer pf.mux.Unlock()

	nsPIDs, nsExists := pf.current[ns]
	if !nsExists {
		return false
	}

	parentInfo, parentExists := nsPIDs[parentPID]
	if !parentExists || parentInfo.pidTypes&pidType == 0 || parentInfo.fileInfo == nil {
		return false
	}

	childFileInfo := parentInfo.fileInfo
	if resolved, err := childFileInfoFromProc(pid, hostPID, parentPID, ns, parentInfo.fileInfo); err == nil {
		childFileInfo = resolved
	} else {
		if processName != "" {
			childFileInfo = fileInfoFromProcessName(pid, parentPID, ns, parentInfo.fileInfo, processName)
		} else {
			pf.log.Debug("couldn't resolve child process identity; inheriting parent service identity",
				"function", "PIDsFilter.AllowPIDFromParent", "pid", pid, "hostPID", hostPID, "parentPID", parentPID, "error", err)
		}
	}

	childInfo := nsPIDs[pid]
	childInfo.fileInfo = childFileInfo
	childInfo.pidTypes |= pidType
	childInfo.otherKnownPids = appendPIDIfMissing(childInfo.otherKnownPids, pid)
	nsPIDs[pid] = childInfo

	parentInfo.otherKnownPids = appendPIDIfMissing(parentInfo.otherKnownPids, pid)
	nsPIDs[parentPID] = parentInfo

	return true
}

func validKProbePID(filter ServiceFilter, pid app.PID, hostPID app.PID, parentPID app.PID, ns uint32, processName string) bool {
	if filter.ValidPID(pid, ns, PIDTypeKProbes) {
		return true
	}

	parentAware, ok := filter.(parentAwareServiceFilter)
	if !ok {
		return false
	}

	return parentAware.AllowPIDFromParent(pid, hostPID, parentPID, ns, PIDTypeKProbes, processName)
}

func fileInfoFromProc(pid app.PID, hostPID app.PID, parentPID app.PID, ns uint32, parent *exec.FileInfo) (*exec.FileInfo, error) {
	if hostPID == 0 {
		return nil, os.ErrNotExist
	}

	proExeLinkPath := filepath.Join("/proc", strconv.FormatUint(uint64(hostPID), 10), "exe")
	exePath, err := os.Readlink(proExeLinkPath)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(proExeLinkPath)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, syscall.EINVAL
	}

	service := parent.ServiceAttrs()
	service.UID.Name = filepath.Base(exePath)
	service.SDKLanguage = svc.InstrumentableGeneric
	service.ProcPID = hostPID

	return exec.New(exec.Init{
		Service:        service,
		CmdExePath:     exePath,
		ProExeLinkPath: proExeLinkPath,
		Pid:            pid,
		Ppid:           parentPID,
		Dev:            uint64(stat.Dev),
		Ino:            stat.Ino,
		Ns:             ns,
	}), nil
}

func fileInfoFromProcessName(pid app.PID, parentPID app.PID, ns uint32, parent *exec.FileInfo, processName string) *exec.FileInfo {
	service := parent.ServiceAttrs()
	service.UID.Name = processName
	service.SDKLanguage = svc.InstrumentableGeneric
	service.ProcPID = pid

	return exec.New(exec.Init{
		Service: service,
		Pid:     pid,
		Ppid:    parentPID,
		Ns:      ns,
	})
}

func processNameFromComm(comm []byte) string {
	end := 0
	for end < len(comm) && comm[end] != 0 {
		end++
	}
	name := strings.TrimSpace(string(comm[:end]))
	if name == "" {
		return ""
	}
	if first, _, ok := strings.Cut(name, " "); ok {
		return first
	}
	return name
}

func (pf *PIDsFilter) CurrentPIDs(t PIDType) map[uint32]map[app.PID]svc.Attrs {
	pf.mux.RLock()
	defer pf.mux.RUnlock()
	cp := map[uint32]map[app.PID]svc.Attrs{}

	for k, v := range pf.current {
		cVal := map[app.PID]svc.Attrs{}
		for kv, vv := range v {
			if vv.pidTypes&t != 0 {
				cVal[kv] = vv.fileInfo.ServiceAttrs()
			}
		}
		cp[k] = cVal
	}

	return cp
}

func (pf *PIDsFilter) normalizeTraceContext(span *request.Span) {
	if !span.TraceID.IsValid() {
		span.TraceID = idgen.RandomTraceID()
		span.TraceFlags = 1
	}
	if !span.SpanID.IsValid() {
		span.SpanID = idgen.RandomSpanID()
	}
}

func (pf *PIDsFilter) Filter(inputSpans []request.Span) []request.Span {
	pf.mux.RLock()
	defer pf.mux.RUnlock()
	// todo: adaptive presizing as a function of the historical percentage
	// of filtered spans
	outputSpans := make([]request.Span, 0, len(inputSpans))
	for i := range inputSpans {
		span := &inputSpans[i]

		// We first confirm that the current namespace seen by BPF is tracked by OBI
		ns, nsExists := pf.current[span.Pid.Namespace]

		if !nsExists {
			continue
		}

		// If the namespace exist, we confirm that we are tracking the user PID that OBI
		// saw. We don't check for the host pid, because we can't be sure of the number
		// of container layers. The Host PID is always the outer most layer.
		if info, pidExists := ns[span.Pid.UserPID]; pidExists {
			if pf.ignoreOtel {
				pf.checkIfExportsOTel(info.fileInfo, span, pf.defaultOtlpGRPCPort)
			}
			if pf.ignoreOtelSpan {
				pf.checkIfExportsOTelSpanMetrics(info.fileInfo, span, pf.defaultOtlpGRPCPort)
			}
			inputSpans[i].Service = info.fileInfo.ServiceAttrs()
			pf.normalizeTraceContext(&inputSpans[i])
			outputSpans = append(outputSpans, inputSpans[i])
		}
	}

	if len(outputSpans) != len(inputSpans) {
		pf.log.Debug("filtered spans from processes that did not match discovery",
			"function", "PIDsFilter.Filter", "inLen", len(inputSpans), "outLen", len(outputSpans),
			"pids", pf.current,
		)
	}
	return outputSpans
}

func (pf *PIDsFilter) addPID(pid app.PID, nsid uint32, fi *exec.FileInfo, t PIDType) {
	ns, nsExists := pf.current[nsid]
	if !nsExists {
		ns = make(map[app.PID]PIDInfo)
		pf.current[nsid] = ns
	}

	allPids, err := readNamespacePIDs(pid)
	if err != nil {
		pf.log.Debug("Error looking up namespaced pids", "pid", pid, "error", err)
		return
	}

	for _, p := range allPids {
		pidInfo := ns[p]
		pidInfo.fileInfo = fi
		pidInfo.pidTypes |= t
		pidInfo.otherKnownPids = allPids
		ns[p] = pidInfo
	}
}

func appendPIDIfMissing(pids []app.PID, pid app.PID) []app.PID {
	for _, currentPID := range pids {
		if currentPID == pid {
			return pids
		}
	}

	return append(pids, pid)
}

func (pf *PIDsFilter) removePID(pid app.PID, nsid uint32) {
	ns, nsExists := pf.current[nsid]
	if !nsExists {
		return
	}

	if pidInfo, pidExists := ns[pid]; pidExists {
		for _, otherPid := range pidInfo.otherKnownPids {
			delete(ns, otherPid)
		}
	}

	delete(ns, pid)
	if len(ns) == 0 {
		delete(pf.current, nsid)
	}
}

// IdentityPidsFilter is a PIDsFilter that does not filter anything. It is feasible
// for concrete cases like GPU tracer
type IdentityPidsFilter struct{}

func (pf *IdentityPidsFilter) AllowPID(_ app.PID, _ uint32, _ *exec.FileInfo, _ PIDType) {}

func (pf *IdentityPidsFilter) BlockPID(_ app.PID, _ uint32) {}

func (pf *IdentityPidsFilter) ValidPID(_ app.PID, _ uint32, _ PIDType) bool {
	return true
}

func (pf *IdentityPidsFilter) CurrentPIDs(_ PIDType) map[uint32]map[app.PID]svc.Attrs {
	return nil
}

func (pf *IdentityPidsFilter) Filter(inputSpans []request.Span) []request.Span {
	return inputSpans
}

func (pf *PIDsFilter) checkIfExportsOTel(fi *exec.FileInfo, span *request.Span, defaultOtlpGRPCPort int) {
	if span.IsExportMetricsSpan(defaultOtlpGRPCPort) && fi.EnsureExportsOTelMetrics() {
		pf.reportAvoidedService(fi, "metrics")
	} else if span.IsExportTracesSpan(defaultOtlpGRPCPort) && fi.EnsureExportsOTelTraces() {
		pf.reportAvoidedService(fi, "traces")
	}
}

func (pf *PIDsFilter) checkIfExportsOTelSpanMetrics(fi *exec.FileInfo, span *request.Span, defaultOtlpGRPCPort int) {
	if span.IsExportTracesSpan(defaultOtlpGRPCPort) && fi.EnsureExportsOTelMetricsSpan() {
		pf.reportAvoidedService(fi, "metrics_span")
	}
}

func (pf *PIDsFilter) reportAvoidedService(fi *exec.FileInfo, telemetryType string) {
	if pf.metrics == nil || imetrics.IsBuiltinNoopReporter(pf.metrics) {
		return
	}

	snap := fi.ServiceAttrs()
	serviceName := snap.UID.Name
	serviceNamespace := snap.UID.Namespace
	serviceInstance := snap.UID.Instance

	switch telemetryType {
	case "metrics", "metrics_span":
		pf.metrics.AvoidInstrumentationMetrics(serviceName, serviceNamespace, serviceInstance)
	case "traces":
		pf.metrics.AvoidInstrumentationTraces(serviceName, serviceNamespace, serviceInstance)
	}
}
