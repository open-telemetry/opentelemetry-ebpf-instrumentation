// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package xdp

import (
	"bytes"
	"encoding/binary"
	"math"
	"runtime"
	"testing"

	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

const (
	typeA     = 1
	typeCNAME = 5
	typeAAAA  = 28
)

const maxHostileCountAllocation = 32 * 1024

var (
	questionAllocationSink []*question
	recordAllocationSink   []*record
)

type responseCase struct {
	message      []byte
	questionType uint16
	recordType   uint16
	recordData   []byte
}

func compressedResponse(questionType, recordType uint16, recordData []byte) []byte {
	message := []byte{
		0x12, 0x34, 0x81, 0x80,
		0, 1, 0, 1, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm', 0,
	}
	message = binary.BigEndian.AppendUint16(message, questionType)
	message = binary.BigEndian.AppendUint16(message, 1)
	message = append(message, 0xc0, 0x0c)
	message = binary.BigEndian.AppendUint16(message, recordType)
	message = binary.BigEndian.AppendUint16(message, 1)
	message = binary.BigEndian.AppendUint32(message, 60)
	message = binary.BigEndian.AppendUint16(message, uint16(len(recordData)))
	return append(message, recordData...)
}

func compressedRecord(offset uint16, recordData []byte) []byte {
	record := []byte{0xc0 | byte(offset>>8), byte(offset)}
	record = binary.BigEndian.AppendUint16(record, typeA)
	record = binary.BigEndian.AppendUint16(record, 1)
	record = binary.BigEndian.AppendUint32(record, 60)
	record = binary.BigEndian.AppendUint16(record, uint16(len(recordData)))
	return append(record, recordData...)
}

func validResponses() map[string]responseCase {
	aData := []byte{192, 0, 2, 1}
	aaaaData := []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	cnameData := []byte{3, 'w', 'w', 'w', 0xc0, 0x0c}

	return map[string]responseCase{
		"A": {
			message:      compressedResponse(typeA, typeA, aData),
			questionType: typeA,
			recordType:   typeA,
			recordData:   aData,
		},
		"AAAA": {
			message:      compressedResponse(typeAAAA, typeAAAA, aaaaData),
			questionType: typeAAAA,
			recordType:   typeAAAA,
			recordData:   aaaaData,
		},
		"CNAME alias for A question": {
			message:      compressedResponse(typeA, typeCNAME, cnameData),
			questionType: typeA,
			recordType:   typeCNAME,
			recordData:   cnameData,
		},
	}
}

func TestParseDNSMessageCompressedResponses(t *testing.T) {
	for name, response := range validResponses() {
		t.Run(name, func(t *testing.T) {
			got := parseDNSMessage(response.message)
			if got == nil {
				t.Fatal("parseDNSMessage() = nil")
			}
			if got.id != 0x1234 || len(got.questions) != 1 {
				t.Fatalf("unexpected message header or question: %#v", got)
			}
			question := got.questions[0]
			if question.qName != "example.com" || question.qType != response.questionType || question.qClass != 1 {
				t.Fatalf("unexpected question: %#v", question)
			}
			if len(got.answers) != 1 {
				t.Fatalf("answer count = %d, want 1", len(got.answers))
			}

			answer := got.answers[0]
			if answer.name != "example.com" || answer.typ != response.recordType || answer.class != 1 ||
				answer.ttl != 60 || !bytes.Equal(answer.data, response.recordData) {
				t.Fatalf("unexpected answer: %#v", answer)
			}
		})
	}
}

func TestHandleDNSMessageIPAnswers(t *testing.T) {
	tests := map[string]struct {
		message []byte
		wantIP  string
	}{
		"IPv4 A record": {
			message: compressedResponse(typeA, typeA, []byte{192, 0, 2, 1}),
			wantIP:  "192.0.2.1",
		},
		"IPv6 AAAA record": {
			message: compressedResponse(typeAAAA, typeAAAA, []byte{
				0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			}),
			wantIP: "2001:db8::1",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := handleDNSMessage(&ringbuf.Record{RawSample: test.message})
			if got == nil {
				t.Fatal("handleDNSMessage() = nil")
			}
			if got.HostName != "example.com" {
				t.Fatalf("HostName = %q, want example.com", got.HostName)
			}
			if len(got.IPs) != 1 || got.IPs[0] != test.wantIP {
				t.Fatalf("IPs = %v, want [%s]", got.IPs, test.wantIP)
			}
		})
	}
}

func TestHandleDNSMessageRejectsNonIPAndMalformedAddresses(t *testing.T) {
	tests := map[string][]byte{
		"CNAME":          compressedResponse(typeA, typeCNAME, []byte{0}),
		"short A":        compressedResponse(typeA, typeA, []byte{192, 0, 2}),
		"oversized A":    compressedResponse(typeA, typeA, []byte{192, 0, 2, 1, 1}),
		"short AAAA":     compressedResponse(typeAAAA, typeAAAA, make([]byte, 15)),
		"oversized AAAA": compressedResponse(typeAAAA, typeAAAA, make([]byte, 17)),
	}

	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			if got := handleDNSMessage(&ringbuf.Record{RawSample: message}); got != nil {
				t.Fatalf("handleDNSMessage() = %#v, want nil", got)
			}
		})
	}
}

func TestParseDNSMessageRejectsEveryTruncation(t *testing.T) {
	for name, response := range validResponses() {
		t.Run(name, func(t *testing.T) {
			for length := range len(response.message) {
				if got := parseDNSMessage(response.message[:length]); got != nil {
					t.Fatalf("parseDNSMessage(%d-byte prefix) = %#v, want nil", length, got)
				}
			}
		})
	}
}

func allocatedBytesPerOperation(operation func()) uint64 {
	const operations = 32

	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for range operations {
		operation()
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	runtime.KeepAlive(operation)
	return (after.TotalAlloc - before.TotalAlloc) / operations
}

func TestHostileSectionCountsHaveBoundedAllocation(t *testing.T) {
	t.Run("questions", func(t *testing.T) {
		question := []byte{1, 'a', 0, 0, typeA, 0, 1}
		data := bytes.NewBuffer(make([]byte, 0, len(question)))
		allocated := allocatedBytesPerOperation(func() {
			data.Reset()
			data.Write(question)
			questionAllocationSink = parseQSections(data, math.MaxUint16)
		})
		runtime.KeepAlive(questionAllocationSink)
		t.Logf("allocated %d bytes per hostile question parse", allocated)
		if allocated >= maxHostileCountAllocation {
			t.Fatalf("allocated %d bytes per hostile question parse, want less than %d", allocated, maxHostileCountAllocation)
		}
	})

	t.Run("records", func(t *testing.T) {
		record := []byte{0, 0, typeA, 0, 1, 0, 0, 0, 0, 0, 0}
		data := bytes.NewBuffer(make([]byte, 0, len(record)))
		allocated := allocatedBytesPerOperation(func() {
			data.Reset()
			data.Write(record)
			recordAllocationSink = parseRecords(data, record, math.MaxUint16)
		})
		runtime.KeepAlive(recordAllocationSink)
		t.Logf("allocated %d bytes per hostile record parse", allocated)
		if allocated >= maxHostileCountAllocation {
			t.Fatalf("allocated %d bytes per hostile record parse, want less than %d", allocated, maxHostileCountAllocation)
		}
	})
}

func TestSectionCountsDoNotControlCapacity(t *testing.T) {
	t.Run("questions", func(t *testing.T) {
		questions := parseQSections(bytes.NewBuffer([]byte{0}), math.MaxUint16)
		if capacity := cap(questions); capacity != 0 {
			t.Fatalf("question capacity = %d, want 0", capacity)
		}
	})

	t.Run("records", func(t *testing.T) {
		records := parseRecords(bytes.NewBuffer([]byte{0}), nil, math.MaxUint16)
		if capacity := cap(records); capacity != 0 {
			t.Fatalf("record capacity = %d, want 0", capacity)
		}
	})

	t.Run("hostile message", func(t *testing.T) {
		message := []byte{0, 1, 0x81, 0x80, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}
		if got := parseDNSMessage(message); got != nil {
			t.Fatalf("parseDNSMessage() = %#v, want nil", got)
		}
	})

	t.Run("capacity is physically bounded", func(t *testing.T) {
		if got := sectionCapacity(math.MaxUint16, minQuestionLength-1, minQuestionLength); got != 0 {
			t.Fatalf("question capacity = %d, want 0", got)
		}
		if got := sectionCapacity(math.MaxUint16, 2*minRecordLength, minRecordLength); got != 2 {
			t.Fatalf("record capacity = %d, want 2", got)
		}
	})
}

func TestSectionParsersRejectPartialResults(t *testing.T) {
	t.Run("questions", func(t *testing.T) {
		question := []byte{1, 'a', 0, 0, 1, 0, 1}
		if got := parseQSections(bytes.NewBuffer(question), 2); got != nil {
			t.Fatalf("parseQSections() = %d questions, want nil", len(got))
		}
	})

	t.Run("records", func(t *testing.T) {
		record := []byte{0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0}
		if got := parseRecords(bytes.NewBuffer(record), record, 2); got != nil {
			t.Fatalf("parseRecords() = %d records, want nil", len(got))
		}
	})
}

func TestParseRecordRejectsPointerAtMessageEnd(t *testing.T) {
	base := make([]byte, 12)
	record := compressedRecord(uint16(len(base)), nil)

	if got := parseRecord(bytes.NewBuffer(record), base); got != nil {
		t.Fatalf("parseRecord() = %#v, want nil", got)
	}
}

func TestParseRecordCompressionPointerBoundaries(t *testing.T) {
	t.Run("last byte", func(t *testing.T) {
		base := []byte{1, 'a', 0}
		got := parseRecord(bytes.NewBuffer(compressedRecord(2, nil)), base)
		if got == nil || got.name != "" {
			t.Fatalf("parseRecord() = %#v, want root record", got)
		}
	})

	t.Run("largest offset", func(t *testing.T) {
		base := make([]byte, 1<<14)
		got := parseRecord(bytes.NewBuffer(compressedRecord((1<<14)-1, nil)), base)
		if got == nil {
			t.Fatal("parseRecord() = nil")
		}
	})

	t.Run("past end", func(t *testing.T) {
		base := make([]byte, 12)
		if got := parseRecord(bytes.NewBuffer(compressedRecord(13, nil)), base); got != nil {
			t.Fatalf("parseRecord() = %#v, want nil", got)
		}
	})
}

func TestLabelAndRecordTruncation(t *testing.T) {
	t.Run("partial label", func(t *testing.T) {
		if label, valid := parseSectionLabel(bytes.NewBuffer([]byte{3, 'w', 'w'})); valid {
			t.Fatalf("parseSectionLabel() = %q, true; want invalid", label)
		}
	})

	t.Run("invalid label length", func(t *testing.T) {
		label := append([]byte{maxLabelLength + 1}, make([]byte, maxLabelLength+1)...)
		label = append(label, 0)
		if got, valid := parseSectionLabel(bytes.NewBuffer(label)); valid {
			t.Fatalf("parseSectionLabel() = %q, true; want invalid", got)
		}
	})

	t.Run("overlong name", func(t *testing.T) {
		var label []byte
		for _, length := range []int{63, 63, 63, 62} {
			label = append(label, byte(length))
			label = append(label, make([]byte, length)...)
		}
		label = append(label, 0)
		if got, valid := parseSectionLabel(bytes.NewBuffer(label)); valid {
			t.Fatalf("parseSectionLabel() = %q, true; want invalid", got)
		}
	})

	t.Run("partial record", func(t *testing.T) {
		base := []byte{1, 'a', 0}
		record := compressedRecord(0, []byte{192, 0, 2, 1})
		for length := range len(record) {
			if got := parseRecord(bytes.NewBuffer(record[:length]), base); got != nil {
				t.Fatalf("parseRecord(%d-byte prefix) = %#v, want nil", length, got)
			}
		}
	})

	t.Run("partial pointer target", func(t *testing.T) {
		base := []byte{3, 'w', 'w'}
		if got := parseRecord(bytes.NewBuffer(compressedRecord(0, nil)), base); got != nil {
			t.Fatalf("parseRecord() = %#v, want nil", got)
		}
	})
}

func FuzzParseDNSMessage(f *testing.F) {
	for _, response := range validResponses() {
		f.Add(response.message)
		f.Add(response.message[:len(response.message)-1])
	}
	f.Add([]byte{0, 1, 0x81, 0x80, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0})
	f.Add([]byte{0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 63, 'a'})

	f.Fuzz(func(t *testing.T, data []byte) {
		message := parseDNSMessage(data)
		if message != nil && (len(message.questions) == 0 || len(message.answers) == 0) {
			t.Fatalf("parsed message has empty required section: %#v", message)
		}
	})
}
