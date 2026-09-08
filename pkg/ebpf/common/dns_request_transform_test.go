// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"
	"time"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

const testDNSPid = uint32(1234)

func newDNSParseContext() *EBPFParseContext {
	return &EBPFParseContext{
		dnsEvents: expirable.NewLRU[dnsparser.DNSId, *request.Span](1024, nil, time.Minute),
	}
}

func dnsQueryRecord(t *testing.T, id uint16, name string) *ringbuf.Record {
	t.Helper()
	return dnsRecord(t, id, dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id},
		Questions: []dnsmessage.Question{dnsQuestion(t, name)},
	})
}

func dnsAnswerRecord(t *testing.T, id uint16, name string, addr [4]byte) *ringbuf.Record {
	t.Helper()
	qname := dnsQuestion(t, name).Name
	return dnsRecord(t, id, dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{dnsQuestion(t, name)},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.AResource{A: addr},
		}},
	})
}

func dnsQuestion(t *testing.T, name string) dnsmessage.Question {
	t.Helper()
	qname, err := dnsmessage.NewName(name)
	require.NoError(t, err)
	return dnsmessage.Question{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
}

func dnsRecord(t *testing.T, id uint16, msg dnsmessage.Message) *ringbuf.Record {
	t.Helper()

	packed, err := msg.Pack()
	require.NoError(t, err)

	event := BpfDnsReqT{Id: id}
	event.Pid.HostPid = testDNSPid
	event.Len = uint32(copy(event.Buf[:], packed))

	raw := unsafe.Slice((*byte)(unsafe.Pointer(&event)), int(unsafe.Sizeof(event)))
	return &ringbuf.Record{RawSample: append([]byte(nil), raw...)}
}

// Ensure a stale (HostPID, 0) occupant with a different question name does not
// suppress this answer
func TestReadDNSEventIntoSpan_ZeroIDCollisionDoesNotSuppressAnswer(t *testing.T) {
	parseCtx := newDNSParseContext()

	_, _, err := readDNSEventIntoSpan(parseCtx, dnsQueryRecord(t, 0, "a.example.com."))
	require.NoError(t, err)

	_, _, err = readDNSEventIntoSpan(parseCtx, dnsAnswerRecord(t, 0, "a.example.com.", [4]byte{10, 0, 0, 1}))
	require.NoError(t, err)

	// a concurrent transaction for a different name, same key
	span, ignore, err := readDNSEventIntoSpan(parseCtx, dnsAnswerRecord(t, 0, "b.example.com.", [4]byte{10, 0, 0, 2}))
	require.NoError(t, err)

	assert.False(t, ignore, "answer for a different name must not be treated as a duplicate")
	assert.Equal(t, "b.example.com.", span.Path)
	assert.Equal(t, "10.0.0.2", span.Statement)
	assert.Equal(t, int(dnsparser.RCodeSuccess), span.Status)
}

func TestReadDNSEventIntoSpan_DuplicateSameNameAnswerIgnored(t *testing.T) {
	parseCtx := newDNSParseContext()

	_, _, err := readDNSEventIntoSpan(parseCtx, dnsQueryRecord(t, 42, "a.example.com."))
	require.NoError(t, err)

	span, ignore, err := readDNSEventIntoSpan(parseCtx, dnsAnswerRecord(t, 42, "a.example.com.", [4]byte{10, 0, 0, 1}))
	require.NoError(t, err)
	require.False(t, ignore)
	require.Equal(t, "10.0.0.1", span.Statement)

	dup, ignore, err := readDNSEventIntoSpan(parseCtx, dnsAnswerRecord(t, 42, "a.example.com.", [4]byte{10, 0, 0, 1}))
	require.NoError(t, err)

	assert.True(t, ignore, "a retransmitted answer for the same name is a duplicate")
	assert.Equal(t, "10.0.0.1", dup.Statement, "duplicate must not append addresses again")
}

// Concurrent A and AAAA lookups share a question name, so the name-based
// collision guard cannot separate them. They stay distinct only while the eBPF
// layer reports the real transaction id.
func TestReadDNSEventIntoSpan_SameNameDistinctIDsStayDistinct(t *testing.T) {
	parseCtx := newDNSParseContext()

	_, _, err := readDNSEventIntoSpan(parseCtx, dnsQueryRecord(t, 1, "a.example.com."))
	require.NoError(t, err)
	_, _, err = readDNSEventIntoSpan(parseCtx, dnsQueryRecord(t, 2, "a.example.com."))
	require.NoError(t, err)

	first, ignore, err := readDNSEventIntoSpan(parseCtx, dnsAnswerRecord(t, 1, "a.example.com.", [4]byte{10, 0, 0, 1}))
	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, "10.0.0.1", first.Statement)

	second, ignore, err := readDNSEventIntoSpan(parseCtx, dnsAnswerRecord(t, 2, "a.example.com.", [4]byte{10, 0, 0, 2}))
	require.NoError(t, err)

	assert.False(t, ignore, "a second transaction for the same name must not be a duplicate")
	assert.Equal(t, "10.0.0.2", second.Statement)
}

// Documents the collision the eBPF id extraction removes: with every id at 0 the
// two transactions share a key, and the name guard cannot tell them apart
// because the name matches, so the second answer is dropped.
func TestReadDNSEventIntoSpan_SameNameZeroIDsCollide(t *testing.T) {
	parseCtx := newDNSParseContext()

	_, _, err := readDNSEventIntoSpan(parseCtx, dnsQueryRecord(t, 0, "a.example.com."))
	require.NoError(t, err)

	_, ignore, err := readDNSEventIntoSpan(parseCtx, dnsAnswerRecord(t, 0, "a.example.com.", [4]byte{10, 0, 0, 1}))
	require.NoError(t, err)
	require.False(t, ignore)

	_, ignore, err = readDNSEventIntoSpan(parseCtx, dnsAnswerRecord(t, 0, "a.example.com.", [4]byte{10, 0, 0, 2}))
	require.NoError(t, err)

	assert.True(t, ignore, "the second same-name transaction is lost when both ids are 0")
}

// A colliding key whose occupant holds a different name is a collision rather
// than a retransmit, so the incoming transaction starts a fresh span.
func TestReadDNSEventIntoSpan_ZeroIDCollisionAcrossNames(t *testing.T) {
	parseCtx := newDNSParseContext()

	_, _, err := readDNSEventIntoSpan(parseCtx, dnsQueryRecord(t, 0, "a.example.com."))
	require.NoError(t, err)
	_, _, err = readDNSEventIntoSpan(parseCtx, dnsAnswerRecord(t, 0, "a.example.com.", [4]byte{10, 0, 0, 1}))
	require.NoError(t, err)

	_, _, err = readDNSEventIntoSpan(parseCtx, dnsQueryRecord(t, 0, "b.example.com."))
	require.NoError(t, err)

	span, ignore, err := readDNSEventIntoSpan(parseCtx, dnsAnswerRecord(t, 0, "b.example.com.", [4]byte{10, 0, 0, 2}))
	require.NoError(t, err)

	assert.False(t, ignore, "an answer for a different name must not be a duplicate")
	assert.Equal(t, "b.example.com.", span.Path)
	assert.Equal(t, "10.0.0.2", span.Statement)
}

func TestReadDNSEventIntoSpan_QueryThenAnswerPairs(t *testing.T) {
	parseCtx := newDNSParseContext()

	query, ignore, err := readDNSEventIntoSpan(parseCtx, dnsQueryRecord(t, 7, "a.example.com."))
	require.NoError(t, err)
	assert.True(t, ignore, "a query without a response is not emitted")
	assert.Equal(t, -1, query.Status)
	assert.Equal(t, "A", query.Method)
	assert.Equal(t, "a.example.com.", query.Path)

	answer, ignore, err := readDNSEventIntoSpan(parseCtx, dnsAnswerRecord(t, 7, "a.example.com.", [4]byte{10, 0, 0, 1}))
	require.NoError(t, err)
	assert.False(t, ignore)
	assert.Equal(t, int(dnsparser.RCodeSuccess), answer.Status)
	assert.Equal(t, "10.0.0.1", answer.Statement)
	assert.Equal(t, request.EventTypeDNS, answer.Type)
}
