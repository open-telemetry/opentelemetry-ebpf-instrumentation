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

func TestParse_fragmentedCALL(t *testing.T) {
	record := buildCallRecord(t, callParams{
		xid:        1,
		prog:       ProgramPortmapper,
		vers:       2,
		proc:       0,
		authFlavor: authNull,
	})
	payload := wrapTCPRecordFragments(record[:8], record[8:])
	buf := largebuf.NewLargeBufferFrom(payload)
	reader := buf.NewReader()

	res, err := Parse(&reader)
	require.NoError(t, err)
	require.NotNil(t, res.Call)
	assert.Equal(t, uint32(ProgramPortmapper), res.Call.Program)
}

func TestParse_rejectsTooManyRecordFragments(t *testing.T) {
	record := buildCallRecord(t, callParams{
		xid:        1,
		prog:       ProgramPortmapper,
		vers:       2,
		proc:       0,
		authFlavor: authNull,
	})
	fragments := make([][]byte, 0, maxRecordFragments+1)
	for range maxRecordFragments {
		fragments = append(fragments, nil)
	}
	fragments = append(fragments, record)

	buf := largebuf.NewLargeBufferFrom(wrapTCPRecordFragments(fragments...))
	reader := buf.NewReader()

	_, err := Parse(&reader)
	assert.ErrorIs(t, err, ErrNotSunRPC)
}

func TestParse_acceptsEmptyNonFinalRecordFragment(t *testing.T) {
	record := buildCallRecord(t, callParams{
		xid:        1,
		prog:       ProgramPortmapper,
		vers:       2,
		proc:       0,
		authFlavor: authNull,
	})
	buf := largebuf.NewLargeBufferFrom(wrapTCPRecordFragments(nil, record))
	reader := buf.NewReader()

	res, err := Parse(&reader)
	require.NoError(t, err)
	require.NotNil(t, res.Call)
	assert.Equal(t, uint32(ProgramPortmapper), res.Call.Program)
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
	return wrapTCPRecordFragments(record)
}

// wrapTCPRecordFragments encodes one RPC-over-TCP record using RFC 5531
// record marking. Each fragment is prefixed with a 32-bit header whose high bit
// marks the final fragment and whose low 31 bits hold the fragment length.
// Empty non-final fragments are legal and are useful for exercising parser
// behavior around fragmented records without changing the reassembled payload.
func wrapTCPRecordFragments(fragments ...[]byte) []byte {
	var out []byte
	for i, fragment := range fragments {
		// Record marking has 31 length bits. Guard before converting so an
		// oversized test fixture cannot wrap, truncate, or set the final bit.
		if len(fragment) > rmFragLen {
			panic("SunRPC test fragment exceeds record-marking length")
		}
		hdr := uint32(len(fragment))
		if i == len(fragments)-1 {
			hdr |= rmLastFrag
		}
		out = appendU32(out, hdr)
		out = append(out, fragment...)
	}
	return out
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
