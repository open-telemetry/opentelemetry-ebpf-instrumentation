// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	outgoingTraceHandoffMapName       = "outgoing_trace_handoff"
	outgoingTraceLocatorMapName       = "outgoing_trace_handoff_locators"
	outgoingTraceClaimMapName         = "outgoing_trace_handoff_claims"
	outgoingTraceEgressClaimMapName   = "outgoing_trace_handoff_egress_claims"
	outgoingTraceLegacyMapName        = "outgoing_trace_map"
	goOutgoingTraceRefMapName         = "go_outgoing_trace_handoffs"
	grpcOutgoingTraceRefMapName       = "grpc_client_request_handoffs"
	outgoingTraceScanBudget           = 512
	outgoingTraceReferenceScanBudget  = 512
	outgoingTraceReaperInterval       = 250 * time.Millisecond
	outgoingTraceReaperJitter         = outgoingTraceReaperInterval / 10
	outgoingTraceDeadObservationDelay = time.Second
	outgoingTraceOrphanTTL            = 10 * time.Minute
	outgoingTraceHardTTL              = 2 * time.Hour
	outgoingTraceBookkeepingLimit     = 4096
	// Match the repository's maximum supported scaled eBPF map capacity.
	outgoingTraceMaxTraversalEntries = 1 << 24
	linuxUserClockTick               = 10 * time.Millisecond
)

const (
	outboundTraceWritten = 1
)

type outgoingTraceEgressKey struct {
	SourceAddress      [16]byte
	DestinationAddress [16]byte
	PID                uint32
	StreamID           uint32
	SourcePort         uint16
	DestinationPort    uint16
}

type outgoingTraceToken struct {
	MapEpoch         uint64
	Sequence         uint64
	ProcessStartTime uint64
	CPU              uint32
	Pad              uint32
}

type outgoingTraceHandoffKey struct {
	Egress outgoingTraceEgressKey
	Pad    uint32
	Token  outgoingTraceToken
}

type outgoingTraceParent struct {
	TraceID          [16]byte
	SpanID           [8]byte
	ParentID         [8]byte
	Timestamp        uint64
	Flags            uint8
	SamplingDecision uint8
	ParentRemote     uint8
	Pad              [5]byte
}

type outgoingTraceParentPID struct {
	Trace       outgoingTraceParent
	PID         uint32
	Valid       uint8
	Written     uint8
	RequestType uint8
	Pad         uint8
}

type outgoingTraceHandoffValue struct {
	Trace           outgoingTraceParentPID
	CreatedAt       uint64
	LastProgress    uint64
	TerminalAt      uint64
	LocalConsumed   uint8
	RetireRequested uint8
	TerminalReason  uint8
	Pad             [5]byte
}

type outgoingTraceHandoffRef struct {
	Egress outgoingTraceEgressKey
	Pad    uint32
	Token  outgoingTraceToken
}

type outgoingTraceProcessKey struct {
	PID       uint32
	StartTime uint64
}

type outgoingTraceDeadObservation struct {
	firstSeen uint64
	order     *list.Element
}

type outgoingTraceTimeNamespaceOffsets struct {
	monotonic int64
	boottime  int64
}

type outgoingTraceReferenceCandidate struct {
	misses   uint8
	revision uint64
}

// Reference-map traversal is intentionally bounded and is not a linearizable
// absence snapshot. The exact progress revision and map generation are the
// handshake that makes a completed two-cycle observation safe to act on.
type outgoingTraceReferenceProof struct {
	absent     bool
	revision   uint64
	generation uint64
}

// OutgoingTraceHandoffReaperStats is a lock-free snapshot of reaper health.
// Values are cumulative except OldestAgeNanoseconds, which reflects the last
// completed bounded scan.
type OutgoingTraceHandoffReaperStats struct {
	Scans                uint64
	Retired              uint64
	ClaimConflicts       uint64
	StuckClaimConflicts  uint64
	FullScans            uint64
	OldestAgeNanoseconds uint64
}

type outgoingTraceHandoffReaperCounters struct {
	scans               atomic.Uint64
	retired             atomic.Uint64
	claimConflicts      atomic.Uint64
	stuckClaimConflicts atomic.Uint64
	fullScans           atomic.Uint64
	oldestAge           atomic.Uint64
}

type outgoingTraceMap interface {
	Lookup(key, valueOut any) error
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
	NextKey(key, nextKeyOut any) error
}

type outgoingTraceMapCapacity interface {
	outgoingTraceCapacity() int
}

type outgoingTraceReferenceSource interface {
	scan(
		[]byte,
		int,
		func([]byte) bool,
		func(outgoingTraceHandoffKey),
	) ([]byte, int, bool, error)
	capacity() int
}

type ebpfOutgoingTraceReferenceSource struct {
	m *ebpf.Map
}

func (s ebpfOutgoingTraceReferenceSource) scan(
	cursor []byte,
	budget int,
	visitRaw func([]byte) bool,
	visit func(outgoingTraceHandoffKey),
) ([]byte, int, bool, error) {
	if s.m == nil {
		return nil, 0, true, nil
	}

	current := cursor
	for visited := 0; visited < budget; visited++ {
		var after any
		if len(current) != 0 {
			after = current
		}
		next, err := s.m.NextKeyBytes(after)
		if err != nil {
			return nil, visited, false, err
		}
		if next == nil {
			return nil, visited, true, nil
		}
		if !visitRaw(next) {
			return nil, visited + 1, false, errOutgoingTraceScanRestart
		}

		var ref outgoingTraceHandoffRef
		if err := s.m.Lookup(next, &ref); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil, visited + 1, false, err
			}
		} else {
			visit(outgoingTraceHandoffKey{
				Egress: ref.Egress,
				Token:  ref.Token,
			})
		}
		current = next
	}

	return current, budget, false, nil
}

func (s ebpfOutgoingTraceReferenceSource) capacity() int {
	if s.m == nil {
		return 0
	}
	info, err := s.m.Info()
	if err != nil {
		return outgoingTraceMaxTraversalEntries
	}
	return boundedOutgoingTraceCapacity(int(info.MaxEntries))
}

type outgoingTraceReferenceCycle struct {
	generation  uint64
	sourceIndex int
	cursor      []byte
	sourceFirst []byte
	sourceWork  int
	sourceLimit int
	active      map[outgoingTraceHandoffKey]outgoingTraceReferenceCandidate
	pending     map[outgoingTraceHandoffKey]outgoingTraceReferenceCandidate
}

type outgoingTraceHandoffReaper struct {
	authority    outgoingTraceMap
	locators     outgoingTraceMap
	claims       outgoingTraceMap
	egressClaims outgoingTraceMap

	optionalMu sync.RWMutex
	legacy     outgoingTraceMap
	goRefs     outgoingTraceReferenceSource
	grpcRefs   outgoingTraceReferenceSource
	optionalID uint64

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	nextKey        *outgoingTraceHandoffKey
	authorityFirst *outgoingTraceHandoffKey
	authorityWork  int
	authorityLimit int
	referenceCycle outgoingTraceReferenceCycle
	// The map and FIFO are capped at the authority map's reported MaxEntries.
	deadObservations     map[outgoingTraceProcessKey]outgoingTraceDeadObservation
	deadObservationOrder list.List
	deadObservationLimit int
	claimConflicts       map[outgoingTraceHandoffKey]uint8
	counters             outgoingTraceHandoffReaperCounters

	timeOffsets      outgoingTraceTimeNamespaceOffsets
	timeOffsetsValid bool
}

var (
	errOutgoingTraceHandoffMapsUnavailable = errors.New(
		"outgoing trace handoff authority map is unavailable",
	)
	newOutgoingTraceHandoffReaperForContext = newOutgoingTraceHandoffReaper
	outgoingTraceClockGettime               = unix.ClockGettime
	outgoingTraceReadlink                   = os.Readlink
	outgoingTraceReadFile                   = os.ReadFile
	outgoingTraceProcStartTimeForStatus     = outgoingTraceProcStartTime
	errOutgoingTraceScanRestart             = errors.New(
		"outgoing trace map traversal restarted",
	)
)

func newOutgoingTraceHandoffReaper(ctx *EBPFEventContext) (*outgoingTraceHandoffReaper, error) {
	if ctx == nil {
		return nil, errors.New("nil eBPF event context")
	}

	ctx.MapsLock.Lock()
	defer ctx.MapsLock.Unlock()

	if ctx.EBPFMaps[outgoingTraceHandoffMapName] == nil {
		return nil, errOutgoingTraceHandoffMapsUnavailable
	}
	required := func(name string) (*ebpf.Map, error) {
		m := ctx.EBPFMaps[name]
		if m == nil {
			return nil, fmt.Errorf("required map %q is unavailable", name)
		}
		return m, nil
	}

	authority, err := required(outgoingTraceHandoffMapName)
	if err != nil {
		return nil, err
	}
	locators, err := required(outgoingTraceLocatorMapName)
	if err != nil {
		return nil, err
	}
	claims, err := required(outgoingTraceClaimMapName)
	if err != nil {
		return nil, err
	}
	egressClaims, err := required(outgoingTraceEgressClaimMapName)
	if err != nil {
		return nil, err
	}
	timeOffsets, timeOffsetsValid := outgoingTraceLoadTimeNamespaceOffsets()

	return &outgoingTraceHandoffReaper{
		authority:            authority,
		locators:             locators,
		claims:               claims,
		egressClaims:         egressClaims,
		legacy:               ctx.EBPFMaps[outgoingTraceLegacyMapName],
		goRefs:               outgoingTraceReferenceMap(ctx.EBPFMaps[goOutgoingTraceRefMapName]),
		grpcRefs:             outgoingTraceReferenceMap(ctx.EBPFMaps[grpcOutgoingTraceRefMapName]),
		stop:                 make(chan struct{}),
		done:                 make(chan struct{}),
		deadObservations:     map[outgoingTraceProcessKey]outgoingTraceDeadObservation{},
		deadObservationLimit: outgoingTraceMapTraversalCapacity(authority),
		claimConflicts:       map[outgoingTraceHandoffKey]uint8{},
		timeOffsets:          timeOffsets,
		timeOffsetsValid:     timeOffsetsValid,
	}, nil
}

func outgoingTraceReferenceMap(m *ebpf.Map) outgoingTraceReferenceSource {
	if m == nil {
		return nil
	}
	return ebpfOutgoingTraceReferenceSource{m: m}
}

func (r *outgoingTraceHandoffReaper) refreshOptionalMaps(ctx *EBPFEventContext) {
	if r == nil || ctx == nil {
		return
	}
	ctx.MapsLock.Lock()
	legacy := ctx.EBPFMaps[outgoingTraceLegacyMapName]
	goRefs := ctx.EBPFMaps[goOutgoingTraceRefMapName]
	grpcRefs := ctx.EBPFMaps[grpcOutgoingTraceRefMapName]
	ctx.MapsLock.Unlock()

	r.optionalMu.Lock()
	r.legacy = legacy
	r.goRefs = outgoingTraceReferenceMap(goRefs)
	r.grpcRefs = outgoingTraceReferenceMap(grpcRefs)
	r.optionalID++
	r.optionalMu.Unlock()
}

func (r *outgoingTraceHandoffReaper) optionalMaps() (
	outgoingTraceMap,
	outgoingTraceReferenceSource,
	outgoingTraceReferenceSource,
	uint64,
) {
	r.optionalMu.RLock()
	defer r.optionalMu.RUnlock()
	return r.legacy, r.goRefs, r.grpcRefs, r.optionalID
}

// StartOutgoingTraceHandoffReaper acquires one process-tracer lifecycle lease.
// The returned function must run only after that tracer has detached and
// joined. Multiple process tracers share one reaper.
func (ctx *EBPFEventContext) StartOutgoingTraceHandoffReaper() func() {
	if ctx == nil {
		return func() {}
	}

	ctx.handoffReaperMu.Lock()
	ctx.handoffReaperRun++
	ctx.tryStartOutgoingTraceHandoffReaperLocked()
	ctx.handoffReaperMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			ctx.handoffReaperMu.Lock()
			defer ctx.handoffReaperMu.Unlock()
			if ctx.handoffReaperRun > 0 {
				ctx.handoffReaperRun--
			}
			if ctx.handoffReaperRun == 0 && ctx.handoffReaper != nil {
				ctx.handoffReaper.stopAndWait()
				ctx.handoffReaper = nil
			}
		})
	}
}

// NotifyOutgoingTraceHandoffMapsLoaded retries activation after a successful
// spec load. A lease can intentionally exist before the first spec creates the
// shared map group.
func (ctx *EBPFEventContext) NotifyOutgoingTraceHandoffMapsLoaded() {
	if ctx == nil {
		return
	}
	ctx.handoffReaperMu.Lock()
	defer ctx.handoffReaperMu.Unlock()
	ctx.tryStartOutgoingTraceHandoffReaperLocked()
	if ctx.handoffReaper != nil {
		ctx.handoffReaper.refreshOptionalMaps(ctx)
	}
}

func (ctx *EBPFEventContext) tryStartOutgoingTraceHandoffReaperLocked() {
	if ctx.handoffReaperRun == 0 || ctx.handoffReaper != nil {
		return
	}
	reaper, err := newOutgoingTraceHandoffReaperForContext(ctx)
	if errors.Is(err, errOutgoingTraceHandoffMapsUnavailable) {
		return
	}
	if err != nil {
		if message := err.Error(); ctx.handoffReaperErr != message {
			ctx.handoffReaperErr = message
			slog.Error("outgoing trace handoff reaper initialization failed", "error", err)
		}
		return
	}
	ctx.handoffReaperErr = ""
	ctx.handoffReaper = reaper
	go reaper.run()
}

// StopOutgoingTraceHandoffReaper is an idempotent shutdown barrier used before
// shared maps are closed. Retained-resource shutdown stops the goroutine but
// deliberately leaves every map and entry intact.
func (ctx *EBPFEventContext) StopOutgoingTraceHandoffReaper() {
	if ctx == nil {
		return
	}
	ctx.handoffReaperMu.Lock()
	defer ctx.handoffReaperMu.Unlock()
	ctx.handoffReaperRun = 0
	if ctx.handoffReaper != nil {
		ctx.handoffReaper.stopAndWait()
		ctx.handoffReaper = nil
	}
	ctx.handoffReaperErr = ""
}

func (ctx *EBPFEventContext) OutgoingTraceHandoffReaperStats() OutgoingTraceHandoffReaperStats {
	if ctx == nil {
		return OutgoingTraceHandoffReaperStats{}
	}
	ctx.handoffReaperMu.Lock()
	defer ctx.handoffReaperMu.Unlock()
	if ctx.handoffReaper == nil {
		return OutgoingTraceHandoffReaperStats{}
	}
	return ctx.handoffReaper.stats()
}

func (r *outgoingTraceHandoffReaper) stats() OutgoingTraceHandoffReaperStats {
	return OutgoingTraceHandoffReaperStats{
		Scans:                r.counters.scans.Load(),
		Retired:              r.counters.retired.Load(),
		ClaimConflicts:       r.counters.claimConflicts.Load(),
		StuckClaimConflicts:  r.counters.stuckClaimConflicts.Load(),
		FullScans:            r.counters.fullScans.Load(),
		OldestAgeNanoseconds: r.counters.oldestAge.Load(),
	}
}

func (r *outgoingTraceHandoffReaper) stopAndWait() {
	r.stopOnce.Do(func() { close(r.stop) })
	<-r.done
}

func (r *outgoingTraceHandoffReaper) run() {
	defer close(r.done)
	for {
		timer := time.NewTimer(outgoingTraceReaperDelay())
		select {
		case <-timer.C:
			r.scan()
		case <-r.stop:
			if !timer.Stop() {
				<-timer.C
			}
			return
		}
	}
}

func outgoingTraceReaperDelay() time.Duration {
	width := int64(2*outgoingTraceReaperJitter + 1)
	jitter := time.Duration(time.Now().UnixNano()%width) - outgoingTraceReaperJitter
	return outgoingTraceReaperInterval + jitter
}

func outgoingTraceLoadTimeNamespaceOffsets() (
	outgoingTraceTimeNamespaceOffsets,
	bool,
) {
	const (
		timeNamespacePath         = "/proc/self/ns/time"
		timeChildrenNamespacePath = "/proc/self/ns/time_for_children"
		timeOffsetsPath           = "/proc/self/timens_offsets"
	)

	timeNamespace, timeErr := outgoingTraceReadlink(timeNamespacePath)
	childrenNamespace, childrenErr := outgoingTraceReadlink(
		timeChildrenNamespacePath,
	)
	if errors.Is(timeErr, unix.ENOENT) &&
		errors.Is(childrenErr, unix.ENOENT) {
		_, offsetsErr := outgoingTraceReadFile(timeOffsetsPath)
		if errors.Is(offsetsErr, unix.ENOENT) {
			// Linux before time namespaces has neither namespace link nor
			// offsets file, so its clocks already share BPF's domain.
			return outgoingTraceTimeNamespaceOffsets{}, true
		}
		return outgoingTraceTimeNamespaceOffsets{}, false
	}
	if timeErr != nil || childrenErr != nil ||
		timeNamespace != childrenNamespace {
		// timens_offsets describes time_for_children until the caller joins
		// that namespace. Applying it to the current namespace would invent
		// an offset that CLOCK_MONOTONIC does not have.
		return outgoingTraceTimeNamespaceOffsets{}, false
	}

	data, err := outgoingTraceReadFile(timeOffsetsPath)
	if err != nil {
		return outgoingTraceTimeNamespaceOffsets{}, false
	}
	offsets, ok := outgoingTraceParseTimeNamespaceOffsets(data)
	if !ok {
		return outgoingTraceTimeNamespaceOffsets{}, false
	}

	// Namespace membership can change on another thread while /proc is read.
	// Accept the offsets only if both links remained the same.
	currentTimeNamespace, timeErr := outgoingTraceReadlink(timeNamespacePath)
	currentChildrenNamespace, childrenErr := outgoingTraceReadlink(
		timeChildrenNamespacePath,
	)
	if timeErr != nil || childrenErr != nil ||
		currentTimeNamespace != timeNamespace ||
		currentChildrenNamespace != childrenNamespace ||
		currentTimeNamespace != currentChildrenNamespace {
		return outgoingTraceTimeNamespaceOffsets{}, false
	}
	return offsets, true
}

func outgoingTraceParseTimeNamespaceOffsets(
	data []byte,
) (outgoingTraceTimeNamespaceOffsets, bool) {
	var offsets outgoingTraceTimeNamespaceOffsets
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 ||
			(fields[0] != "monotonic" && fields[0] != "boottime") ||
			seen[fields[0]] {
			return outgoingTraceTimeNamespaceOffsets{}, false
		}
		seconds, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return outgoingTraceTimeNamespaceOffsets{}, false
		}
		nanoseconds, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || nanoseconds < 0 ||
			nanoseconds >= int64(time.Second) {
			return outgoingTraceTimeNamespaceOffsets{}, false
		}
		offset, ok := outgoingTraceCheckedOffsetNanoseconds(
			seconds,
			nanoseconds,
		)
		if !ok {
			return outgoingTraceTimeNamespaceOffsets{}, false
		}
		if fields[0] == "monotonic" {
			offsets.monotonic = offset
		} else {
			offsets.boottime = offset
		}
		seen[fields[0]] = true
	}
	if !seen["monotonic"] || !seen["boottime"] {
		return outgoingTraceTimeNamespaceOffsets{}, false
	}
	return offsets, true
}

func outgoingTraceCheckedOffsetNanoseconds(
	seconds int64,
	nanoseconds int64,
) (int64, bool) {
	value := big.NewInt(seconds)
	value.Mul(value, big.NewInt(int64(time.Second)))
	value.Add(value, big.NewInt(nanoseconds))
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

func outgoingTraceAddSignedOffset(value uint64, offset int64) (uint64, bool) {
	if offset >= 0 {
		addend := uint64(offset)
		if value > math.MaxUint64-addend {
			return 0, false
		}
		return value + addend, true
	}
	magnitude := uint64(-(offset + 1)) + 1
	if value < magnitude {
		return 0, false
	}
	return value - magnitude, true
}

func outgoingTraceSubtractSignedOffset(value uint64, offset int64) (uint64, bool) {
	if offset >= 0 {
		subtrahend := uint64(offset)
		if value < subtrahend {
			return 0, false
		}
		return value - subtrahend, true
	}
	magnitude := uint64(-(offset + 1)) + 1
	if value > math.MaxUint64-magnitude {
		return 0, false
	}
	return value + magnitude, true
}

// bpf_ktime_get_ns() and every authority timestamp use the host's raw
// CLOCK_MONOTONIC domain. A time namespace offsets userspace CLOCK_MONOTONIC,
// so subtract its signed offset before comparing it with BPF timestamps.
func outgoingTraceMonotonicNanoseconds(
	offsets outgoingTraceTimeNamespaceOffsets,
) (uint64, bool) {
	var ts unix.Timespec
	if err := outgoingTraceClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, false
	}
	if ts.Sec < 0 || ts.Nsec < 0 ||
		ts.Nsec >= int64(time.Second) ||
		uint64(ts.Sec) > math.MaxUint64/uint64(time.Second) {
		return 0, false
	}
	namespaced := uint64(ts.Sec) * uint64(time.Second)
	if uint64(ts.Nsec) > math.MaxUint64-namespaced {
		return 0, false
	}
	namespaced += uint64(ts.Nsec)
	return outgoingTraceSubtractSignedOffset(namespaced, offsets.monotonic)
}

func boundedOutgoingTraceCapacity(capacity int) int {
	if capacity <= 0 || capacity > outgoingTraceMaxTraversalEntries {
		return outgoingTraceMaxTraversalEntries
	}
	return capacity
}

func outgoingTraceMapTraversalCapacity(m outgoingTraceMap) int {
	if capacity, ok := m.(outgoingTraceMapCapacity); ok {
		return boundedOutgoingTraceCapacity(capacity.outgoingTraceCapacity())
	}
	if kernelMap, ok := m.(*ebpf.Map); ok {
		info, err := kernelMap.Info()
		if err == nil {
			return boundedOutgoingTraceCapacity(int(info.MaxEntries))
		}
	}
	return outgoingTraceMaxTraversalEntries
}

func (r *outgoingTraceHandoffReaper) resetAuthorityTraversal() {
	r.nextKey = nil
	r.authorityFirst = nil
	r.authorityWork = 0
	r.authorityLimit = outgoingTraceMapTraversalCapacity(r.authority)
}

func (r *outgoingTraceHandoffReaper) observeAuthorityKey(
	key outgoingTraceHandoffKey,
) bool {
	if r.authorityWork == 0 {
		first := key
		r.authorityFirst = &first
	} else if r.authorityFirst != nil && key == *r.authorityFirst {
		return false
	}
	r.authorityWork++
	return r.authorityWork <= r.authorityLimit
}

func (r *outgoingTraceHandoffReaper) scan() {
	if !r.timeOffsetsValid {
		return
	}
	now, ok := outgoingTraceMonotonicNanoseconds(r.timeOffsets)
	if !ok || now == 0 {
		return
	}
	r.counters.scans.Add(1)

	r.advanceReferenceCycle(now)
	var key outgoingTraceHandoffKey
	if r.nextKey != nil {
		key = *r.nextKey
	} else {
		r.resetAuthorityTraversal()
		if err := r.authority.NextKey(nil, &key); err != nil {
			r.resetAuthorityTraversal()
			r.counters.oldestAge.Store(0)
			return
		}
		if !r.observeAuthorityKey(key) {
			r.resetAuthorityTraversal()
			r.counters.oldestAge.Store(0)
			return
		}
	}

	var oldest uint64
	for processed := 0; processed < outgoingTraceScanBudget; processed++ {
		var next outgoingTraceHandoffKey
		nextErr := r.authority.NextKey(&key, &next)
		if nextErr != nil && !errors.Is(nextErr, ebpf.ErrKeyNotExist) {
			r.resetAuthorityTraversal()
			break
		}
		if nextErr == nil && !r.observeAuthorityKey(next) {
			// Deleting a hash-map cursor can make NextKey restart at the
			// first key. More general churn is capped by MaxEntries.
			r.resetAuthorityTraversal()
			break
		}

		var value outgoingTraceHandoffValue
		if err := r.authority.Lookup(&key, &value); err == nil {
			created := value.CreatedAt
			if created == 0 {
				created = value.LastProgress
			}
			if created != 0 && now >= created && now-created > oldest {
				oldest = now - created
			}
			r.trackReferenceCandidate(key, value, now)
			r.maybeRetire(key, value, now)
		}

		if nextErr != nil {
			r.resetAuthorityTraversal()
			break
		}
		key = next
		if processed == outgoingTraceScanBudget-1 {
			r.nextKey = &key
			r.counters.fullScans.Add(1)
		}
	}
	r.counters.oldestAge.Store(oldest)
}

func (r *outgoingTraceHandoffReaper) ensureReferenceCycle() {
	if r.referenceCycle.active == nil {
		r.referenceCycle.active = map[outgoingTraceHandoffKey]outgoingTraceReferenceCandidate{}
	}
	if r.referenceCycle.pending == nil {
		r.referenceCycle.pending = map[outgoingTraceHandoffKey]outgoingTraceReferenceCandidate{}
	}
}

func (r *outgoingTraceHandoffReaper) resetReferenceSourceTraversal() {
	r.referenceCycle.cursor = nil
	r.referenceCycle.sourceFirst = nil
	r.referenceCycle.sourceWork = 0
	r.referenceCycle.sourceLimit = 0
}

func (r *outgoingTraceHandoffReaper) resetReferenceCycle(generation uint64) {
	r.ensureReferenceCycle()
	for key, candidate := range r.referenceCycle.pending {
		candidate.misses = 0
		r.referenceCycle.pending[key] = candidate
	}
	for key, candidate := range r.referenceCycle.active {
		if len(r.referenceCycle.pending) >= outgoingTraceReferenceScanBudget {
			break
		}
		candidate.misses = 0
		r.referenceCycle.pending[key] = candidate
	}
	clear(r.referenceCycle.active)
	r.referenceCycle.generation = generation
	r.referenceCycle.sourceIndex = 0
	r.resetReferenceSourceTraversal()
}

func (r *outgoingTraceHandoffReaper) advanceReferenceCycle(now uint64) {
	_, goRefs, grpcRefs, generation := r.optionalMaps()
	r.ensureReferenceCycle()
	if r.referenceCycle.generation != generation {
		r.resetReferenceCycle(generation)
	}
	if r.referenceCycle.sourceIndex == 0 &&
		len(r.referenceCycle.cursor) == 0 &&
		len(r.referenceCycle.active) == 0 {
		r.promotePendingReferenceCandidates()
	}

	sources := [...]outgoingTraceReferenceSource{goRefs, grpcRefs}
	remaining := outgoingTraceReferenceScanBudget
	for remaining > 0 && r.referenceCycle.sourceIndex < len(sources) {
		source := sources[r.referenceCycle.sourceIndex]
		if source == nil {
			r.referenceCycle.sourceIndex++
			r.resetReferenceSourceTraversal()
			continue
		}
		if r.referenceCycle.sourceLimit == 0 {
			r.referenceCycle.sourceLimit = boundedOutgoingTraceCapacity(
				source.capacity(),
			)
		}

		cursor, visited, complete, err := source.scan(
			r.referenceCycle.cursor,
			remaining,
			r.observeReferenceRawKey,
			r.observeReference,
		)
		if err != nil {
			r.resetReferenceCycle(generation)
			return
		}
		if visited < 0 || visited > remaining {
			r.resetReferenceCycle(generation)
			return
		}
		remaining -= visited
		r.referenceCycle.cursor = cursor
		if !complete {
			return
		}
		r.referenceCycle.sourceIndex++
		r.resetReferenceSourceTraversal()
	}

	if r.referenceCycle.sourceIndex == len(sources) {
		_, _, _, currentGeneration := r.optionalMaps()
		if currentGeneration != r.referenceCycle.generation {
			r.resetReferenceCycle(currentGeneration)
			return
		}
		r.finishReferenceCycle(now)
	}
}

func (r *outgoingTraceHandoffReaper) observeReferenceRawKey(key []byte) bool {
	if len(key) == 0 {
		return false
	}
	if r.referenceCycle.sourceWork == 0 {
		r.referenceCycle.sourceFirst = append(
			r.referenceCycle.sourceFirst[:0],
			key...,
		)
	} else if bytes.Equal(key, r.referenceCycle.sourceFirst) {
		return false
	}
	r.referenceCycle.sourceWork++
	return r.referenceCycle.sourceWork <= r.referenceCycle.sourceLimit
}

func (r *outgoingTraceHandoffReaper) observeReference(
	key outgoingTraceHandoffKey,
) {
	delete(r.referenceCycle.active, key)
}

func (r *outgoingTraceHandoffReaper) finishReferenceCycle(now uint64) {
	_, _, _, generation := r.optionalMaps()
	if generation != r.referenceCycle.generation {
		r.resetReferenceCycle(generation)
		return
	}
	next := make(
		map[outgoingTraceHandoffKey]outgoingTraceReferenceCandidate,
		outgoingTraceReferenceScanBudget,
	)
	for key, candidate := range r.referenceCycle.active {
		if candidate.misses != 0 {
			r.retireReferenceCandidate(
				key,
				candidate.revision,
				generation,
				now,
			)
			continue
		}
		candidate.misses = 1
		next[key] = candidate
	}
	_, _, _, currentGeneration := r.optionalMaps()
	if currentGeneration != generation {
		r.resetReferenceCycle(currentGeneration)
		return
	}
	r.referenceCycle.active = next
	r.promotePendingReferenceCandidates()
	r.referenceCycle.sourceIndex = 0
	r.resetReferenceSourceTraversal()
}

func (r *outgoingTraceHandoffReaper) retireReferenceCandidate(
	key outgoingTraceHandoffKey,
	expectedRevision uint64,
	generation uint64,
	now uint64,
) {
	if r.authority == nil {
		return
	}
	var value outgoingTraceHandoffValue
	if err := r.authority.Lookup(&key, &value); err != nil ||
		!outgoingTraceReferenceCandidateExpired(value, now) {
		return
	}
	if outgoingTraceProgressRevision(value) != expectedRevision {
		r.trackReferenceCandidate(key, value, now)
		return
	}

	r.maybeRetireWithProof(key, value, now, outgoingTraceReferenceProof{
		absent:     true,
		revision:   expectedRevision,
		generation: generation,
	})

	var remaining outgoingTraceHandoffValue
	if err := r.authority.Lookup(&key, &remaining); err == nil &&
		outgoingTraceReferenceCandidateExpired(remaining, now) &&
		len(r.referenceCycle.pending) < outgoingTraceReferenceScanBudget {
		// A claim conflict or transient delete failure retries only after
		// another complete reference cycle.
		candidate := outgoingTraceReferenceCandidate{
			misses:   1,
			revision: outgoingTraceProgressRevision(remaining),
		}
		_, _, _, currentGeneration := r.optionalMaps()
		if candidate.revision != expectedRevision ||
			currentGeneration != generation {
			candidate.misses = 0
		}
		r.referenceCycle.pending[key] = candidate
	}
}

func (r *outgoingTraceHandoffReaper) promotePendingReferenceCandidates() {
	for key, candidate := range r.referenceCycle.pending {
		if len(r.referenceCycle.active) >= outgoingTraceReferenceScanBudget {
			return
		}
		r.referenceCycle.active[key] = candidate
		delete(r.referenceCycle.pending, key)
	}
}

func (r *outgoingTraceHandoffReaper) trackReferenceCandidate(
	key outgoingTraceHandoffKey,
	value outgoingTraceHandoffValue,
	now uint64,
) {
	r.ensureReferenceCycle()
	if !outgoingTraceReferenceCandidateExpired(value, now) {
		r.forgetReferenceCandidate(key)
		return
	}
	revision := outgoingTraceProgressRevision(value)
	if candidate, ok := r.referenceCycle.active[key]; ok {
		if candidate.revision == revision {
			return
		}
		delete(r.referenceCycle.active, key)
	}
	if candidate, ok := r.referenceCycle.pending[key]; ok {
		if candidate.revision == revision {
			return
		}
		r.referenceCycle.pending[key] = outgoingTraceReferenceCandidate{
			revision: revision,
		}
		return
	}
	if len(r.referenceCycle.pending) < outgoingTraceReferenceScanBudget {
		r.referenceCycle.pending[key] = outgoingTraceReferenceCandidate{
			revision: revision,
		}
	}
}

func (r *outgoingTraceHandoffReaper) maybeRetire(
	key outgoingTraceHandoffKey,
	value outgoingTraceHandoffValue,
	now uint64,
) {
	r.maybeRetireWithProof(
		key,
		value,
		now,
		outgoingTraceReferenceProof{},
	)
}

func (r *outgoingTraceHandoffReaper) maybeRetireWithProof(
	key outgoingTraceHandoffKey,
	value outgoingTraceHandoffValue,
	now uint64,
	proof outgoingTraceReferenceProof,
) {
	dead := r.deadProcessConfirmed(key, now)
	if !outgoingTraceReferenceProofMatches(value, proof) ||
		!outgoingTraceShouldRetire(value, proof.absent, dead, now) {
		return
	}

	claimed := uint8(1)
	if err := r.claims.Update(&key, &claimed, ebpf.UpdateNoExist); err != nil {
		r.recordClaimConflict(key)
		return
	}
	defer func() { _ = r.claims.Delete(&key) }()

	var current outgoingTraceHandoffValue
	if err := r.authority.Lookup(&key, &current); err != nil {
		delete(r.claimConflicts, key)
		return
	}
	dead = r.deadProcessConfirmed(key, now)
	if !outgoingTraceReferenceProofMatches(current, proof) ||
		!outgoingTraceShouldRetire(current, proof.absent, dead, now) {
		delete(r.claimConflicts, key)
		return
	}

	if err := r.egressClaims.Update(&key.Egress, &claimed, ebpf.UpdateNoExist); err != nil {
		r.recordClaimConflict(key)
		return
	}
	delete(r.claimConflicts, key)
	defer func() { _ = r.egressClaims.Delete(&key.Egress) }()

	if err := r.authority.Lookup(&key, &current); err != nil {
		return
	}
	dead = r.deadProcessConfirmed(key, now)
	if !outgoingTraceReferenceProofMatches(current, proof) ||
		!outgoingTraceShouldRetire(current, proof.absent, dead, now) {
		return
	}

	var legacyMap outgoingTraceMap
	if proof.absent {
		r.optionalMu.RLock()
		if r.optionalID != proof.generation {
			r.optionalMu.RUnlock()
			return
		}
		if err := r.authority.Lookup(&key, &current); err != nil {
			r.optionalMu.RUnlock()
			return
		}
		dead = r.deadProcessConfirmed(key, now)
		if !outgoingTraceReferenceProofMatches(current, proof) ||
			!outgoingTraceShouldRetire(current, true, dead, now) {
			r.optionalMu.RUnlock()
			return
		}
		if err := r.authority.Delete(&key); err != nil {
			r.optionalMu.RUnlock()
			return
		}
		legacyMap = r.legacy
		r.optionalMu.RUnlock()
	} else {
		if err := r.authority.Delete(&key); err != nil {
			return
		}
		legacyMap, _, _, _ = r.optionalMaps()
	}

	var located outgoingTraceToken
	if err := r.locators.Lookup(&key.Egress, &located); err == nil &&
		outgoingTraceTokensEqual(located, key.Token) {
		_ = r.locators.Delete(&key.Egress)
	}

	if legacyMap != nil {
		var legacy outgoingTraceParentPID
		if err := legacyMap.Lookup(&key.Egress, &legacy); err == nil &&
			outgoingTraceParentsEqual(legacy, current.Trace) {
			_ = legacyMap.Delete(&key.Egress)
		}
	}

	// Keep the mature process proof for other authority entries belonging to
	// the same dead incarnation. Alive evidence or bounded cache pressure
	// invalidates it.
	r.forgetReferenceCandidate(key)
	r.counters.retired.Add(1)
}

func outgoingTraceReferenceProofMatches(
	value outgoingTraceHandoffValue,
	proof outgoingTraceReferenceProof,
) bool {
	return !proof.absent ||
		outgoingTraceProgressRevision(value) == proof.revision
}

func (r *outgoingTraceHandoffReaper) forgetReferenceCandidate(
	key outgoingTraceHandoffKey,
) {
	delete(r.referenceCycle.active, key)
	delete(r.referenceCycle.pending, key)
}

func outgoingTraceShouldRetire(
	value outgoingTraceHandoffValue,
	referenceAbsent bool,
	dead bool,
	now uint64,
) bool {
	if value.RetireRequested != 0 || value.TerminalAt != 0 ||
		(value.Trace.Written == outboundTraceWritten && value.LocalConsumed != 0) {
		return true
	}
	if dead {
		return true
	}
	return referenceAbsent &&
		(outgoingTraceHardExpired(value, now) ||
			outgoingTraceOrphanExpired(value, now))
}

func outgoingTraceHardExpired(
	value outgoingTraceHandoffValue,
	now uint64,
) bool {
	return value.CreatedAt != 0 && now >= value.CreatedAt &&
		now-value.CreatedAt >= uint64(outgoingTraceHardTTL)
}

func outgoingTraceProgressRevision(value outgoingTraceHandoffValue) uint64 {
	if value.LastProgress != 0 {
		return value.LastProgress
	}
	return value.CreatedAt
}

func outgoingTraceReferenceCandidateExpired(
	value outgoingTraceHandoffValue,
	now uint64,
) bool {
	return outgoingTraceHardExpired(value, now) ||
		outgoingTraceOrphanExpired(value, now)
}

func outgoingTraceOrphanExpired(
	value outgoingTraceHandoffValue,
	now uint64,
) bool {
	progress := outgoingTraceProgressRevision(value)
	return progress != 0 && now >= progress &&
		now-progress >= uint64(outgoingTraceOrphanTTL)
}

func (r *outgoingTraceHandoffReaper) recordClaimConflict(key outgoingTraceHandoffKey) {
	r.counters.claimConflicts.Add(1)
	if _, exists := r.claimConflicts[key]; !exists &&
		len(r.claimConflicts) >= outgoingTraceBookkeepingLimit {
		// Preserve admitted streaks so a stream of distinct conflicts cannot
		// keep every stuck owner below the diagnostic threshold.
		return
	}
	count := r.claimConflicts[key]
	if count < math.MaxUint8 {
		count++
		r.claimConflicts[key] = count
	}
	if count == 3 {
		r.counters.stuckClaimConflicts.Add(1)
	}
}

func outgoingTraceTokensEqual(left, right outgoingTraceToken) bool {
	return left.MapEpoch == right.MapEpoch &&
		left.Sequence == right.Sequence &&
		left.ProcessStartTime == right.ProcessStartTime &&
		left.CPU == right.CPU
}

func outgoingTraceParentsEqual(left, right outgoingTraceParentPID) bool {
	return left.PID == right.PID &&
		left.Valid != 0 &&
		left.RequestType == right.RequestType &&
		left.Trace == right.Trace
}

type outgoingTraceProcessStatus uint8

const (
	outgoingTraceProcessUnknown outgoingTraceProcessStatus = iota
	outgoingTraceProcessAlive
	outgoingTraceProcessDead
)

func (r *outgoingTraceHandoffReaper) deadProcessConfirmed(
	key outgoingTraceHandoffKey,
	now uint64,
) bool {
	processKey := outgoingTraceProcessKey{
		PID:       key.Egress.PID,
		StartTime: key.Token.ProcessStartTime,
	}
	switch outgoingTraceProcessIncarnationStatus(
		processKey,
		r.timeOffsets,
		r.timeOffsetsValid,
	) {
	case outgoingTraceProcessAlive:
		r.forgetDeadProcessObservation(processKey)
		return false
	case outgoingTraceProcessUnknown:
		return false
	}

	return r.rememberDeadProcessObservation(processKey, now)
}

func (r *outgoingTraceHandoffReaper) rememberDeadProcessObservation(
	processKey outgoingTraceProcessKey,
	now uint64,
) bool {
	observed, ok := r.deadObservations[processKey]
	if !ok {
		if r.deadObservations == nil {
			r.deadObservations = map[outgoingTraceProcessKey]outgoingTraceDeadObservation{}
		}
		limit := r.deadProcessObservationLimit()
		if len(r.deadObservations) >= limit {
			oldest := r.deadObservationOrder.Front()
			if oldest == nil {
				// The FIFO and map must agree. Fail closed instead of scanning
				// the entire cache to repair unexpected state.
				return false
			}
			oldestKey, valid := oldest.Value.(outgoingTraceProcessKey)
			oldestObservation, exists := r.deadObservations[oldestKey]
			if !valid || !exists || oldestObservation.order != oldest ||
				now < oldestObservation.firstSeen ||
				now-oldestObservation.firstSeen <
					uint64(outgoingTraceDeadObservationDelay) {
				// Insertion order is monotonic, so an immature oldest entry
				// means the whole admitted batch must remain undisturbed.
				return false
			}
			r.forgetDeadProcessObservation(oldestKey)
			if len(r.deadObservations) >= limit {
				return false
			}
		}
		order := r.deadObservationOrder.PushBack(processKey)
		r.deadObservations[processKey] = outgoingTraceDeadObservation{
			firstSeen: now,
			order:     order,
		}
		return false
	}
	return now >= observed.firstSeen &&
		now-observed.firstSeen >= uint64(outgoingTraceDeadObservationDelay)
}

func (r *outgoingTraceHandoffReaper) deadProcessObservationLimit() int {
	if r.deadObservationLimit <= 0 {
		r.deadObservationLimit = outgoingTraceMapTraversalCapacity(r.authority)
	}
	return boundedOutgoingTraceCapacity(r.deadObservationLimit)
}

func (r *outgoingTraceHandoffReaper) forgetDeadProcessObservation(
	processKey outgoingTraceProcessKey,
) {
	observed, ok := r.deadObservations[processKey]
	if !ok {
		return
	}
	if observed.order != nil {
		r.deadObservationOrder.Remove(observed.order)
	}
	delete(r.deadObservations, processKey)
}

func outgoingTraceProcessIncarnationStatus(
	process outgoingTraceProcessKey,
	offsets outgoingTraceTimeNamespaceOffsets,
	offsetsValid bool,
) outgoingTraceProcessStatus {
	if process.PID == 0 || process.StartTime == 0 || !offsetsValid {
		return outgoingTraceProcessUnknown
	}
	start, err := outgoingTraceProcStartTimeForStatus(process.PID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			return outgoingTraceProcessDead
		}
		return outgoingTraceProcessUnknown
	}
	namespacedTokenStart, ok := outgoingTraceAddSignedOffset(
		process.StartTime,
		offsets.boottime,
	)
	if !ok {
		return outgoingTraceProcessUnknown
	}
	expectedProcStart := namespacedTokenStart -
		(namespacedTokenStart % uint64(linuxUserClockTick))
	if start == expectedProcStart {
		return outgoingTraceProcessAlive
	}
	return outgoingTraceProcessDead
}

func outgoingTraceProcStartTime(pid uint32) (uint64, error) {
	file, err := os.Open("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return 0, err
	}
	if len(data) == 0 || len(data) > 4096 {
		return 0, errors.New("invalid process stat size")
	}
	commEnd := strings.LastIndexByte(string(data), ')')
	if commEnd < 0 {
		return 0, errors.New("malformed process stat")
	}
	fields := strings.Fields(string(data[commEnd+1:]))
	const startTimeIndex = 22 - 3
	if len(fields) <= startTimeIndex {
		return 0, errors.New("process stat has no start time")
	}
	ticks, err := strconv.ParseUint(fields[startTimeIndex], 10, 64)
	if err != nil || ticks == 0 || ticks > math.MaxUint64/uint64(linuxUserClockTick) {
		return 0, errors.New("invalid process start time")
	}
	return ticks * uint64(linuxUserClockTick), nil
}
