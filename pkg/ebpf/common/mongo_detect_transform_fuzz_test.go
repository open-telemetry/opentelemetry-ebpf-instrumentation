// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// These fixtures are literal MongoDB wire messages. Keeping them independent
// from the production encoders makes them useful checks on parser assumptions.
var (
	mongoWireRequest = []byte{
		0x26, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0xdd, 7, 0, 0,
		0, 0, 0, 0, 0,
		0x11, 0, 0, 0, 2, 'f', 'i', 'n', 'd', 0, 2, 0, 0, 0, 'c', 0, 0,
	}
	mongoWireResponse = []byte{
		0x26, 0, 0, 0, 8, 0, 0, 0, 7, 0, 0, 0, 0xdd, 7, 0, 0,
		0, 0, 0, 0, 0,
		0x11, 0, 0, 0, 1, 'o', 'k', 0, 0, 0, 0, 0, 0, 0xf0, 0x3f, 0,
	}
	mongoWireDocumentSequence = []byte{
		0x1f, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0xdd, 7, 0, 0,
		0, 0, 0, 0, 1,
		10, 0, 0, 0, 0, 5, 0, 0, 0, 0,
	}
)

type mongoValueSnapshot struct {
	requestSections  int
	responseSections int
	startTime        int64
	endTime          int64
	flags            int32
}

type mongoParserOutcome struct {
	error          string
	moreToCome     bool
	returned       bool
	result         mongoValueSnapshot
	cacheLen       int
	pendingPresent bool
	pending        mongoValueSnapshot
}

func snapshotMongoValue(value *MongoRequestValue) mongoValueSnapshot {
	if value == nil {
		return mongoValueSnapshot{}
	}
	return mongoValueSnapshot{
		requestSections:  len(value.RequestSections),
		responseSections: len(value.ResponseSections),
		startTime:        value.StartTime,
		endTime:          value.EndTime,
		flags:            value.Flags,
	}
}

func runMongoParser(payload []byte, withPending bool) (mongoParserOutcome, mongoValueSnapshot) {
	cache := expirable.NewLRU[MongoRequestKey, *MongoRequestValue](4, nil, 0)
	conn := getConnInfo()
	pending := &MongoRequestValue{
		RequestSections: []mongoSection{{Type: sectionTypeDocumentSequence}},
		StartTime:       11,
		Flags:           0x10000,
	}
	initial := snapshotMongoValue(pending)
	key := MongoRequestKey{connInfo: conn, requestID: 7}
	if withPending {
		cache.Add(key, pending)
	}

	result, moreToCome, err := ProcessMongoEvent(payload, 100, 200, conn, cache)
	outcome := mongoParserOutcome{
		moreToCome: moreToCome,
		returned:   result != nil,
		result:     snapshotMongoValue(result),
		cacheLen:   cache.Len(),
	}
	if err != nil {
		outcome.error = err.Error()
	}
	outcome.pending, outcome.pendingPresent = func() (mongoValueSnapshot, bool) {
		value, ok := cache.Peek(key)
		return snapshotMongoValue(value), ok
	}()

	return outcome, initial
}

func checkMongoParser(t *testing.T, payload []byte, withPending bool) {
	t.Helper()
	first, initial := runMongoParser(payload, withPending)
	second, _ := runMongoParser(payload, withPending)
	if first != second {
		t.Fatalf("non-deterministic classification: first=%+v second=%+v", first, second)
	}
	if first.error != "" && withPending && (!first.pendingPresent || first.pending != initial) {
		t.Fatalf("rejected input mutated pending request: before=%+v after=%+v", initial, first.pending)
	}
	if first.error == "" {
		assertAcceptedMongoHeader(t, payload)
		if first.result.requestSections+first.result.responseSections > len(payload) {
			t.Fatalf("section count exceeds payload length: %+v", first)
		}
	}
}

func assertAcceptedMongoHeader(t *testing.T, payload []byte) {
	t.Helper()
	if len(payload) < 16 {
		t.Fatalf("accepted %d-byte MongoDB header", len(payload))
	}
	messageLength := int32(binary.LittleEndian.Uint32(payload[0:4]))
	requestID := int32(binary.LittleEndian.Uint32(payload[4:8]))
	responseTo := int32(binary.LittleEndian.Uint32(payload[8:12]))
	opcode := int32(binary.LittleEndian.Uint32(payload[12:16]))
	if messageLength < minOpMsgSize || requestID < 0 || responseTo < 0 || opcode != 2013 {
		t.Fatalf("accepted invalid MongoDB header: length=%d request=%d response=%d opcode=%d",
			messageLength, requestID, responseTo, opcode)
	}
	parsedLength := min(int(messageLength), len(payload))
	if responseTo != 0 && parsedLength == 16 {
		return
	}
	if parsedLength < 20 {
		t.Fatalf("accepted OP_MSG without complete flags: parsed length %d", parsedLength)
	}
	flags := binary.LittleEndian.Uint32(payload[16:20])
	if uint16(flags)&^uint16(3) != 0 {
		t.Fatalf("accepted invalid required flags %#x", flags)
	}
	assertAcceptedMongoSections(t, payload[20:parsedLength], int(messageLength) <= len(payload))
}

func assertAcceptedMongoSections(t *testing.T, sections []byte, completeMessage bool) {
	t.Helper()
	if len(sections) == 0 {
		t.Fatal("accepted OP_MSG without sections")
	}
	for offset := 0; offset < len(sections); {
		kind := sections[offset]
		offset++
		if len(sections)-offset < 4 {
			t.Fatalf("accepted section kind %d without a length", kind)
		}
		length := int(int32(binary.LittleEndian.Uint32(sections[offset : offset+4])))
		if length < 5 {
			t.Fatalf("accepted section kind %d with length %d", kind, length)
		}
		switch kind {
		case 0:
			if length > len(sections)-offset {
				if completeMessage {
					t.Fatalf("accepted complete message with truncated BSON of length %d", length)
				}
				return
			}
		case 1:
			if length > len(sections)-offset {
				t.Fatalf("accepted truncated document sequence of length %d", length)
			}
		default:
			t.Fatalf("accepted unsupported section kind %d", kind)
		}
		offset += length
	}
}

func TestMongoParserRejectsInvalidWireLengths(t *testing.T) {
	tests := []struct {
		name        string
		fixture     func() []byte
		withPending bool
	}{
		{name: "message ends at header", fixture: func() []byte {
			payload := append([]byte(nil), mongoWireRequest...)
			binary.LittleEndian.PutUint32(payload[0:4], 16)
			return payload
		}},
		{name: "response declares header-only message", withPending: true, fixture: func() []byte {
			payload := append([]byte(nil), mongoWireResponse...)
			binary.LittleEndian.PutUint32(payload[0:4], 16)
			return payload
		}},
		{name: "complete message has truncated BSON", fixture: func() []byte {
			payload := append([]byte(nil), mongoWireRequest...)
			binary.LittleEndian.PutUint32(payload[21:25], 100)
			return payload
		}},
		{name: "missing BSON length", fixture: func() []byte {
			return []byte{21, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xdd, 7, 0, 0, 0, 0, 0, 0, 0}
		}},
		{name: "negative BSON length", fixture: func() []byte {
			return []byte{25, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xdd, 7, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}
		}},
		{name: "document sequence exceeds packet", fixture: func() []byte {
			payload := append([]byte(nil), mongoWireDocumentSequence...)
			binary.LittleEndian.PutUint32(payload[21:25], 11)
			return payload
		}},
		{name: "negative document sequence length", fixture: func() []byte {
			payload := append([]byte(nil), mongoWireDocumentSequence...)
			binary.LittleEndian.PutUint32(payload[21:25], ^uint32(0))
			return payload
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome, initial := runMongoParser(test.fixture(), test.withPending)
			if outcome.error == "" {
				t.Fatalf("invalid wire message was accepted: %+v", outcome)
			}
			if test.withPending && (!outcome.pendingPresent || outcome.pending != initial) {
				t.Fatalf("invalid response mutated pending request: before=%+v after=%+v", initial, outcome.pending)
			}
		})
	}
}

func TestMongoParserAcceptsPartialBSONCapture(t *testing.T) {
	payload := append([]byte(nil), mongoWireRequest...)
	binary.LittleEndian.PutUint32(payload[0:4], 100)
	binary.LittleEndian.PutUint32(payload[21:25], 100)

	outcome, _ := runMongoParser(payload, false)
	if outcome.error != "" || !outcome.pendingPresent {
		t.Fatalf("partial BSON capture was rejected: %+v", outcome)
	}
}

func TestMongoParserResponseDeclaredLengthBoundary(t *testing.T) {
	for messageLength := msgHeaderSize + 1; messageLength < minOpMsgSize; messageLength++ {
		t.Run(fmt.Sprintf("length %d", messageLength), func(t *testing.T) {
			payload := append([]byte(nil), mongoWireResponse[:msgHeaderSize]...)
			binary.LittleEndian.PutUint32(payload[0:4], uint32(messageLength))

			outcome, initial := runMongoParser(payload, true)
			if outcome.error == "" || outcome.returned || outcome.cacheLen != 1 ||
				!outcome.pendingPresent || outcome.pending != initial {
				t.Fatalf("impossible partial response changed correlation: %+v", outcome)
			}
		})
	}

	payload := append([]byte(nil), mongoWireResponse[:msgHeaderSize]...)
	binary.LittleEndian.PutUint32(payload[0:4], minOpMsgSize)
	outcome, _ := runMongoParser(payload, true)
	if outcome.error != "" || !outcome.returned || outcome.cacheLen != 0 || outcome.pendingPresent {
		t.Fatalf("valid partial response was rejected: %+v", outcome)
	}
}

func TestMongoParserRejectedResponsePreservesLRUOrder(t *testing.T) {
	cache := expirable.NewLRU[MongoRequestKey, *MongoRequestValue](2, nil, 0)
	conn := getConnInfo()
	for _, requestID := range []uint32{7, 8} {
		payload := append([]byte(nil), mongoWireRequest...)
		binary.LittleEndian.PutUint32(payload[4:8], requestID)
		_, _, err := ProcessMongoEvent(payload, 100, 200, conn, cache)
		if err != nil {
			t.Fatalf("request %d was rejected: %v", requestID, err)
		}
	}

	malformed := append([]byte(nil), mongoWireResponse[:msgHeaderSize+int32Size]...)
	binary.LittleEndian.PutUint32(malformed[0:4], minOpMsgSize)
	_, _, err := ProcessMongoEvent(malformed, 100, 200, conn, cache)
	if err == nil {
		t.Fatal("malformed response was accepted")
	}

	requestC := append([]byte(nil), mongoWireRequest...)
	binary.LittleEndian.PutUint32(requestC[4:8], 9)
	_, _, err = ProcessMongoEvent(requestC, 100, 200, conn, cache)
	if err != nil {
		t.Fatalf("request C was rejected: %v", err)
	}

	oldestKey := MongoRequestKey{connInfo: conn, requestID: 7}
	untouchedKey := MongoRequestKey{connInfo: conn, requestID: 8}
	if cache.Contains(oldestKey) || !cache.Contains(untouchedKey) {
		t.Fatalf("rejected response changed eviction order: keys=%v", cache.Keys())
	}
}

func TestMongoParserWireMutationSweep(t *testing.T) {
	fixtures := [][]byte{mongoWireRequest, mongoWireResponse, mongoWireDocumentSequence}
	for fixtureIndex, fixture := range fixtures {
		for prefix := 0; prefix <= len(fixture); prefix++ {
			checkMongoParser(t, fixture[:prefix], fixtureIndex == 1)
		}
		for offset := range fixture {
			for _, value := range []byte{0, 1, 0x7f, 0x80, 0xff} {
				mutated := append([]byte(nil), fixture...)
				mutated[offset] = value
				checkMongoParser(t, mutated, fixtureIndex == 1)
			}
		}
	}
}

func FuzzMongoParser(f *testing.F) {
	for fixtureIndex, fixture := range [][]byte{mongoWireRequest, mongoWireResponse, mongoWireDocumentSequence} {
		f.Add(fixture, false)
		f.Add(fixture, true)
		for prefix := 0; prefix <= len(fixture); prefix++ {
			f.Add(fixture[:prefix], fixtureIndex == 1)
		}
	}
	f.Add([]byte(nil), false)
	f.Add([]byte{16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0}, false)
	f.Add([]byte{16, 0, 0, 0, 8, 0, 0, 0, 7, 0, 0, 0, 42, 0, 0, 0}, true)
	f.Add([]byte{25, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xdd, 7, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}, false)

	f.Fuzz(func(t *testing.T, payload []byte, withPending bool) {
		if len(payload) > 4096 {
			return
		}
		checkMongoParser(t, payload, withPending)
	})
}
