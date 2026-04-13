// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"unicode/utf8"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/couchbasekv"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

// CouchbaseInfo holds parsed Couchbase memcached binary protocol information.
type CouchbaseInfo struct {
	Operation  string
	Key        string
	Bucket     string
	Scope      string
	Collection string
	Statement  string
	Status     couchbasekv.Status
	IsError    bool
}

// buildCouchbaseStatement builds a Redis-style db.query.text for a KV request
// packet: "OP key [EXTRAS...] [value]". Returns "" if the key is empty.
//
// Value is appended only when non-empty, valid UTF-8, and not snappy-compressed.
// Extras are rendered per-opcode: SET-family shows TTL (if non-zero, flags are
// always skipped); INCR/DECR shows DELTA always and TTL if non-zero (INITIAL is
// skipped); TOUCH/GAT shows TTL.
func buildCouchbaseStatement(pkt couchbasekv.Packet) string {
	op := pkt.Header().Opcode()
	key := pkt.KeyString()
	if key == "" {
		return ""
	}

	var b strings.Builder
	b.WriteString(op.String())
	b.WriteByte(' ')
	b.WriteString(key)

	extras := pkt.Extras()

	switch op {
	case couchbasekv.OpcodeSet, couchbasekv.OpcodeAdd, couchbasekv.OpcodeReplace,
		couchbasekv.OpcodeSetQ, couchbasekv.OpcodeAddQ, couchbasekv.OpcodeReplaceQ:
		if len(extras) >= 8 {
			if ttl := binary.BigEndian.Uint32(extras[4:8]); ttl != 0 {
				fmt.Fprintf(&b, " TTL=%d", ttl)
			}
		}
		if val := couchbaseValueForStatement(pkt); val != "" {
			b.WriteByte(' ')
			b.WriteString(val)
		}
	case couchbasekv.OpcodeAppend, couchbasekv.OpcodePrepend,
		couchbasekv.OpcodeAppendQ, couchbasekv.OpcodePrependQ:
		if val := couchbaseValueForStatement(pkt); val != "" {
			b.WriteByte(' ')
			b.WriteString(val)
		}
	case couchbasekv.OpcodeIncrement, couchbasekv.OpcodeDecrement,
		couchbasekv.OpcodeIncrementQ, couchbasekv.OpcodeDecrementQ:
		if len(extras) >= 20 {
			delta := binary.BigEndian.Uint64(extras[0:8])
			ttl := binary.BigEndian.Uint32(extras[16:20])
			fmt.Fprintf(&b, " DELTA=%d", delta)
			if ttl != 0 {
				fmt.Fprintf(&b, " TTL=%d", ttl)
			}
		}
	case couchbasekv.OpcodeTouch, couchbasekv.OpcodeGAT, couchbasekv.OpcodeGATQ:
		if len(extras) >= 4 {
			ttl := binary.BigEndian.Uint32(extras[0:4])
			fmt.Fprintf(&b, " TTL=%d", ttl)
		}
	}

	return b.String()
}

// couchbaseValueForStatement returns the packet's value rendered for inclusion
// in a db.query.text statement, or "" if it should be omitted.
// Values are omitted when snappy-compressed or not valid UTF-8. Truncated
// values are returned as-is without a marker.
func couchbaseValueForStatement(pkt couchbasekv.Packet) string {
	if pkt.Header().DataType().HasSnappy() {
		return ""
	}
	val := pkt.Value()
	if len(val) == 0 {
		return ""
	}
	if !utf8.Valid(val) {
		return ""
	}
	return string(val)
}

// ProcessPossibleCouchbaseEvent attempts to parse the event as a Couchbase memcached binary protocol event.
// Returns a slice of CouchbaseInfo if successful, along with a boolean indicating if the event should be ignored,
// and an error if parsing failed. Multiple packets may be present in a single TCP segment due to pipelining.
func ProcessPossibleCouchbaseEvent(event *TCPRequestInfo, requestBuf *largebuf.LargeBuffer, responseBuf *largebuf.LargeBuffer, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) (*CouchbaseInfo, bool, error) {
	reqRaw := requestBuf.UnsafeView()
	respRaw := responseBuf.UnsafeView()
	info, ignore, err := processCouchbaseEvent(event.ConnInfo, reqRaw, respRaw, bucketCache)
	// If parsing failed (error or no valid packets found), try with buffers reversed
	if err != nil {
		// Try with buffers reversed - we might have captured it backwards
		info, ignore, err = processCouchbaseEvent(event.ConnInfo, respRaw, reqRaw, bucketCache)
		if err == nil {
			reverseTCPEvent(event)
			return info, false, nil
		}
	}
	return info, ignore, err
}

// handleSelectBucketWithResponse processes the SELECT_BUCKET command with an already-parsed response.
// If respPacket is nil, the response is assumed to be successful.
func handleSelectBucketWithResponse(connInfo BpfConnectionInfoT, reqPacket couchbasekv.Packet, respPacket couchbasekv.Packet, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) {
	bucketName := reqPacket.KeyString()
	if bucketCache == nil || bucketName == "" {
		return
	}

	// Check if bucket selection was successful
	// there might be cases where there is no response (e.g., truncated), we assume success
	if respPacket != nil && (!respPacket.IsResponse() || !respPacket.Header().Status().IsSuccess()) {
		return
	}

	bucketInfo, found := bucketCache.Get(connInfo)
	if !found {
		bucketInfo = CouchbaseBucketInfo{}
	}
	bucketInfo.Bucket = bucketName
	slog.Debug("Adding Couchbase bucket to cache", "bucket", bucketName, "conn", connInfo)
	bucketCache.Add(connInfo, bucketInfo)
}

// handleGetCollectionIDWithResponse processes the GET_COLLECTION_ID command with an already-parsed response.
// If respPacket is nil, the collection lookup is considered failed.
func handleGetCollectionIDWithResponse(connInfo BpfConnectionInfoT, reqPacket couchbasekv.Packet, respPacket couchbasekv.Packet, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) {
	scopeCollection := reqPacket.ValueString()
	if bucketCache == nil || scopeCollection == "" {
		return
	}

	// Check if collection lookup was successful
	if respPacket == nil || !respPacket.IsResponse() || !respPacket.Header().Status().IsSuccess() {
		return
	}

	// Parse scope.collection from the value
	parts := strings.SplitN(scopeCollection, ".", 2)
	if len(parts) != 2 {
		slog.Debug("Couchbase GET_COLLECTION_ID: invalid scope.collection format, skipping", "scope_collection", scopeCollection, "conn", connInfo)
		return
	}

	// Get existing bucket info or create new one
	bucketInfo, found := bucketCache.Get(connInfo)
	if !found {
		bucketInfo = CouchbaseBucketInfo{}
	}
	bucketInfo.Scope = parts[0]
	bucketInfo.Collection = parts[1]
	slog.Debug("Updating Couchbase bucket cache with scope and collection", "scope", bucketInfo.Scope, "collection", bucketInfo.Collection, "conn", connInfo)
	bucketCache.Add(connInfo, bucketInfo)
}

// processCouchbaseEvent parses Couchbase packets from request and response buffers.
// It handles multiple packets that may be pipelined in a single TCP segment.
func processCouchbaseEvent(connInfo BpfConnectionInfoT, requestBuf []byte, responseBuf []byte, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) (*CouchbaseInfo, bool, error) {
	// Build a map of response packets by Opaque for matching
	respByOpaque := make(map[uint32]couchbasekv.Packet)
	for pkt, err := range couchbasekv.ParsePackets(responseBuf) {
		if err != nil {
			break
		}
		if pkt.IsResponse() {
			respByOpaque[pkt.Header().Opaque()] = pkt
		}
	}

	hasPackets := false
	for reqPacket, err := range couchbasekv.ParsePackets(requestBuf) {
		if err != nil {
			if !hasPackets {
				return nil, true, errors.New("no valid Couchbase request packets found")
			}
			break
		}
		hasPackets = true

		if !reqPacket.IsRequest() {
			continue
		}

		respPacket, hasResp := respByOpaque[reqPacket.Header().Opaque()]

		if reqPacket.Header().Opcode() == couchbasekv.OpcodeSelectBucket {
			handleSelectBucketWithResponse(connInfo, reqPacket, respPacket, bucketCache)
			// Don't create a span for SELECT_BUCKET
			continue
		}

		if reqPacket.Header().Opcode() == couchbasekv.OpcodeCollectionsGetID {
			handleGetCollectionIDWithResponse(connInfo, reqPacket, respPacket, bucketCache)
			// Don't create a span for GET_COLLECTION_ID
			continue
		}

		if !reqPacket.Header().Opcode().IsKVOperation() {
			slog.Debug("Ignoring non-KV Couchbase operation", "opcode", reqPacket.Header().Opcode().String())
			continue
		}

		info := &CouchbaseInfo{
			Operation: reqPacket.Header().Opcode().String(),
			Key:       reqPacket.KeyString(),
			Statement: buildCouchbaseStatement(reqPacket),
		}

		// Get bucket info from cache
		if bucketCache != nil {
			if bucketInfo, found := bucketCache.Get(connInfo); found {
				info.Bucket = bucketInfo.Bucket
				info.Scope = bucketInfo.Scope
				info.Collection = bucketInfo.Collection
			}
		}

		if hasResp && respPacket.IsResponse() {
			info.Status = respPacket.Header().Status()
			info.IsError = respPacket.Header().Status().IsError()
		}

		return info, false, nil
	}
	if !hasPackets {
		return nil, true, errors.New("no valid Couchbase request packets found")
	}
	return nil, true, nil
}

// TCPToCouchbaseToSpan converts a TCP event with Couchbase data to a request.Span.
func TCPToCouchbaseToSpan(trace *TCPRequestInfo, data *CouchbaseInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeCouchbaseClient

	status := 0
	var dbError request.DBError
	if data.IsError {
		status = int(data.Status)
		dbError = request.DBError{
			ErrorCode:   strconv.Itoa(status),
			Description: data.Status.String(),
		}
	}

	// Build the database namespace: bucket.scope
	dbNamespace := data.Bucket

	collection := data.Scope
	if collection == "" {
		collection = data.Collection
	} else if data.Collection != "" {
		collection += "." + data.Collection
	}

	return request.Span{
		Type:          reqType,
		Method:        data.Operation,
		Path:          collection,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        status,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
		DBError:     dbError,
		DBNamespace: dbNamespace,
		Statement:   data.Statement,
	}
}
