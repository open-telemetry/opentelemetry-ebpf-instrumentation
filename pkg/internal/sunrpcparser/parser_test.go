// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sunrpcparser

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func TestParse_CALL_AUTH_NULL(t *testing.T) {
	const xid = uint32(0x01020304)
	record := buildCallRecord(t, callParams{
		xid:        xid,
		prog:       ProgramNFS,
		vers:       3,
		proc:       3,
		authFlavor: authNull,
	})

	buf := largebuf.NewLargeBufferFrom(wrapTCPRecord(record))
	reader := buf.NewReader()

	res, err := Parse(&reader)
	require.NoError(t, err)
	require.True(t, res.LooksLikeSunRPC)
	require.NotNil(t, res.Call)
	assert.Equal(t, xid, res.Call.Xid)
	assert.Equal(t, uint32(ProgramNFS), res.Call.Program)
	assert.Equal(t, uint32(3), res.Call.Version)
	assert.Equal(t, uint32(3), res.Call.Procedure)
	assert.Equal(t, uint32(authNull), res.Call.AuthFlavor)
}

func TestParse_CALL_AUTH_KERB(t *testing.T) {
	record := buildCallRecord(t, callParams{
		xid:        7,
		prog:       ProgramNFS,
		vers:       3,
		proc:       1,
		authFlavor: authKerb,
		authBody:   []byte{0, 1, 2, 3},
	})

	buf := largebuf.NewLargeBufferFrom(wrapTCPRecord(record))
	reader := buf.NewReader()

	res, err := Parse(&reader)
	require.NoError(t, err)
	require.NotNil(t, res.Call)
	assert.Equal(t, uint32(authKerb), res.Call.AuthFlavor)
	assert.Equal(t, "auth_kerb", AuthFlavorName(res.Call.AuthFlavor))
}

func TestParse_CALL_RPCSEC_GSS(t *testing.T) {
	record := buildCallRecord(t, callParams{
		xid:        42,
		prog:       ProgramNFS,
		vers:       4,
		proc:       9,
		authFlavor: authRPCSECgss,
		authBody:   []byte{1, 2, 3, 4},
	})

	buf := largebuf.NewLargeBufferFrom(wrapTCPRecord(record))
	reader := buf.NewReader()

	res, err := Parse(&reader)
	require.NoError(t, err)
	require.NotNil(t, res.Call)
	assert.Equal(t, uint32(authRPCSECgss), res.Call.AuthFlavor)
	assert.Equal(t, "rpcsec_gss", AuthFlavorName(res.Call.AuthFlavor))
}

func TestParse_CALL_and_REPLY(t *testing.T) {
	const xid = uint32(99)
	call := buildCallRecord(t, callParams{
		xid:        xid,
		prog:       ProgramMount,
		vers:       3,
		proc:       1,
		authFlavor: authUnix,
		authBody:   make([]byte, 32),
	})
	reply := buildAcceptedReplyRecord(t, xid, acceptSuccess)

	payload := append(wrapTCPRecord(call), wrapTCPRecord(reply)...)
	buf := largebuf.NewLargeBufferFrom(payload)
	reader := buf.NewReader()

	res, err := Parse(&reader)
	require.NoError(t, err)
	require.NotNil(t, res.Call)
	require.NotNil(t, res.Reply)
	assert.True(t, res.Reply.MatchCallXid)
	assert.Equal(t, uint32(acceptSuccess), res.Reply.AcceptStat)
}

func TestParse_replyInvalidReplyStat(t *testing.T) {
	record := buildReplyRecord(t, 1, appendU32(nil, 2))
	buf := largebuf.NewLargeBufferFrom(wrapTCPRecord(record))
	reader := buf.NewReader()

	_, err := Parse(&reader)
	assert.ErrorIs(t, err, ErrNotSunRPC)
}

func TestParse_replyDeniedAuthError(t *testing.T) {
	body := appendU32(nil, replyDenied)
	body = appendU32(body, rejectAuthError)
	body = appendU32(body, 1)

	record := buildReplyRecord(t, 9, body)
	buf := largebuf.NewLargeBufferFrom(wrapTCPRecord(record))
	reader := buf.NewReader()

	res, err := Parse(&reader)
	require.NoError(t, err)
	require.NotNil(t, res.Reply)
	assert.True(t, res.Reply.Denied)
}

func TestParse_replyDeniedTruncated(t *testing.T) {
	body := appendU32(nil, replyDenied)
	body = appendU32(body, rejectAuthError)

	record := buildReplyRecord(t, 9, body)
	buf := largebuf.NewLargeBufferFrom(wrapTCPRecord(record))
	reader := buf.NewReader()

	_, err := Parse(&reader)
	assert.ErrorIs(t, err, ErrNotSunRPC)
}

func TestParse_replyDeniedInvalidRejectStat(t *testing.T) {
	body := appendU32(nil, replyDenied)
	body = appendU32(body, 99)

	record := buildReplyRecord(t, 9, body)
	buf := largebuf.NewLargeBufferFrom(wrapTCPRecord(record))
	reader := buf.NewReader()

	_, err := Parse(&reader)
	assert.ErrorIs(t, err, ErrNotSunRPC)
}

func TestIsLikelySunRPC_rejectsFalsePositiveReply(t *testing.T) {
	body := appendU32(nil, replyDenied)
	body = appendU32(body, 99)

	record := buildReplyRecord(t, 0x01020304, body)
	buf := largebuf.NewLargeBufferFrom(wrapTCPRecord(record))
	reader := buf.NewReader()

	assert.False(t, IsLikelySunRPC(&reader))
}

func TestIsLikelySunRPC_rejectsDeniedWithoutRejectStat(t *testing.T) {
	record := buildReplyRecord(t, 1, appendU32(nil, replyDenied))
	buf := largebuf.NewLargeBufferFrom(wrapTCPRecord(record))
	reader := buf.NewReader()

	assert.False(t, IsLikelySunRPC(&reader))
}

func TestIsLikelySunRPC_rejectsCallWithInvalidVerfFlavor(t *testing.T) {
	record := buildCallRecord(t, callParams{
		xid:        1,
		prog:       ProgramPortmapper,
		vers:       2,
		proc:       0,
		authFlavor: authNull,
		verfFlavor: 99,
	})
	buf := largebuf.NewLargeBufferFrom(wrapTCPRecord(record))
	reader := buf.NewReader()

	assert.False(t, IsLikelySunRPC(&reader))
}

func TestIsLikelySunRPC_acceptsValidCall(t *testing.T) {
	record := buildCallRecord(t, callParams{
		xid:        1,
		prog:       ProgramPortmapper,
		vers:       2,
		proc:       0,
		authFlavor: authNull,
	})
	buf := largebuf.NewLargeBufferFrom(wrapTCPRecord(record))
	reader := buf.NewReader()

	assert.True(t, IsLikelySunRPC(&reader))
}

func buildReplyRecord(t *testing.T, xid uint32, body []byte) []byte {
	t.Helper()

	msg := make([]byte, 0, 8+len(body))
	msg = appendU32(msg, xid)
	msg = appendU32(msg, msgReply)
	msg = append(msg, body...)
	return msg
}

func TestParse_notSunRPC(t *testing.T) {
	buf := largebuf.NewLargeBufferFrom([]byte("GET / HTTP/1.1\r\n"))
	reader := buf.NewReader()

	_, err := Parse(&reader)
	assert.ErrorIs(t, err, ErrNotSunRPC)
}

type callParams struct {
	xid        uint32
	prog       uint32
	vers       uint32
	proc       uint32
	authFlavor uint32
	authBody   []byte
	verfFlavor uint32
}

func buildCallRecord(t *testing.T, p callParams) []byte {
	t.Helper()

	body := make([]byte, 0, 64)
	body = appendU32(body, rpcVersion)
	body = appendU32(body, p.prog)
	body = appendU32(body, p.vers)
	body = appendU32(body, p.proc)
	body = appendOpaqueAuth(body, p.authFlavor, p.authBody)
	verfFlavor := uint32(authNull)
	if p.verfFlavor != 0 {
		verfFlavor = p.verfFlavor
	}
	body = appendOpaqueAuth(body, verfFlavor, nil)

	msg := make([]byte, 0, 8+len(body))
	msg = appendU32(msg, p.xid)
	msg = appendU32(msg, msgCall)
	msg = append(msg, body...)
	return msg
}

func buildAcceptedReplyRecord(t *testing.T, xid uint32, acceptStat uint32) []byte {
	t.Helper()

	body := make([]byte, 0, 32)
	body = appendU32(body, replyAccepted)
	body = appendOpaqueAuth(body, authNull, nil)
	body = appendU32(body, acceptStat)

	msg := make([]byte, 0, 8+len(body))
	msg = appendU32(msg, xid)
	msg = appendU32(msg, msgReply)
	msg = append(msg, body...)
	return msg
}

func wrapTCPRecord(record []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, rmLastFrag|uint32(len(record)))
	return append(hdr, record...)
}

func appendU32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func appendOpaqueAuth(b []byte, flavor uint32, data []byte) []byte {
	b = appendU32(b, flavor)
	b = appendU32(b, uint32(len(data)))
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}
