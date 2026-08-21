// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func buildMongoShellFindWire(t *testing.T) []byte {
	t.Helper()

	const (
		wantLength = 300
		requestID  = 23
	)

	for commentLen := 0; commentLen < 512; commentLen++ {
		body := bson.D{
			{Key: commFind, Value: "obi_shell_test"},
			{Key: "filter", Value: bson.D{{Key: "source", Value: "strace-test"}}},
			{Key: "$db", Value: "obi_mongosh_test"},
			{Key: "comment", Value: strings.Repeat("x", commentLen)},
		}
		bodyBytes, err := bson.Marshal(body)
		require.NoError(t, err)

		if len(bodyBytes)+msgHeaderSize+int32Size+1 != wantLength {
			continue
		}

		buf := new(bytes.Buffer)
		require.NoError(t, binary.Write(buf, binary.LittleEndian, msgHeader{
			MessageLength: wantLength,
			RequestID:     requestID,
			ResponseTo:    0,
			OpCode:        opMsg,
		}))
		require.NoError(t, binary.Write(buf, binary.LittleEndian, uint32(0)))
		require.NoError(t, binary.Write(buf, binary.LittleEndian, sectionTypeBody))
		require.NoError(t, binary.Write(buf, binary.LittleEndian, bodyBytes))
		require.Len(t, buf.Bytes(), wantLength)
		return buf.Bytes()
	}

	t.Fatal("could not construct a 300-byte MongoDB OP_MSG request body")
	return nil
}

func buildMongoShellFindResponse(t *testing.T, requestID int32) []byte {
	t.Helper()

	bodyBytes, err := bson.Marshal(bson.D{{Key: "ok", Value: 1.0}})
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	require.NoError(t, binary.Write(buf, binary.LittleEndian, msgHeader{
		MessageLength: msgHeaderSize + int32Size + 1 + int32(len(bodyBytes)),
		RequestID:     requestID + 1,
		ResponseTo:    requestID,
		OpCode:        opMsg,
	}))
	require.NoError(t, binary.Write(buf, binary.LittleEndian, uint32(0)))
	require.NoError(t, binary.Write(buf, binary.LittleEndian, sectionTypeBody))
	require.NoError(t, binary.Write(buf, binary.LittleEndian, bodyBytes))
	return buf.Bytes()
}

func TestProcessMongoEventMongoShellFindExactWire(t *testing.T) {
	defer requests.Purge()

	connInfo := getConnInfo()
	requestWire := buildMongoShellFindWire(t)
	responseWire := buildMongoShellFindResponse(t, 23)

	mongoRequest, moreToCome, err := ProcessMongoEvent(requestWire, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err)
	require.True(t, moreToCome)

	mongoRequest, moreToCome, err = ProcessMongoEvent(responseWire, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err)
	require.False(t, moreToCome)
	require.NotNil(t, mongoRequest)

	info, err := getMongoInfo(mongoRequest)
	require.NoError(t, err)
	require.Equal(t, "find", info.OpName)
	require.Equal(t, "obi_shell_test", info.Collection)
	require.Equal(t, "obi_mongosh_test", info.DB)
}
