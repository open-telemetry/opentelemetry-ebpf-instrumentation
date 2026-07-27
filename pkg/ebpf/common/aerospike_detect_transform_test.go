// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

// The request_hex values below are real proto frames (8-byte proto header +
// AS_MSG body) captured from aerospike-server 8.1.2.3 CE driven by
// aerospike-client-go v7, with SendKey enabled so write requests carry the user
// key. scan/query requests are truncated to the first 256 bytes (the eBPF
// inline-capture prefix) since their tail is a multi-KB partition list.
var aerospikeRequestFixtures = []struct {
	name      string
	op        string
	namespace string
	set       string
	userKey   string
	hexFrame  string
}{
	{"put", "PUT", "test", "s_put", "k_put", "02030000000000711600010000000000000000000000000003e6000400020000000500746573740000000601735f707574000000150489622694e051d31aff9b8421f3431c5a3f013ca90000000702036b5f7075740000000d020300046e616d65616c6963650000000f02010003616765000000000000001e"},
	{"get", "GET", "test", "s_get", "", "02030000000000421603000000000000000000000000000003e7000300000000000500746573740000000601735f6765740000001504cb38076ffcab7692bfee20ee0c8c489bda264fad"},
	{"getbin", "GET", "test", "s_getbin", "", "020300000000004e1601000000000000000000000000000003e7000300010000000500746573740000000901735f67657462696e0000001504e7f2d43da0fdc4bea404189150398c14b7778d0b000000050100000161"},
	{"exists", "EXISTS", "test", "s_exists", "", "02030000000000451621000000000000000000000000000003e7000300000000000500746573740000000901735f6578697374730000001504a5bc5df19751f03b6c2f9a140f1fbd630b82d2bd"},
	{"touch", "TOUCH", "test", "s_touch", "k_touch", "02030000000000591600010000000000000000000000000003e7000400010000000500746573740000000801735f746f75636800000015042e6243c6ffa19b0a1809986344561e1ac48fc84c0000000902036b5f746f756368000000040b000000"},
	{"operate", "OPERATE", "test", "s_operate", "k_operate", "02030000000000811603010000000000000000000000000003e7000400030000000500746573740000000a01735f6f70657261746500000015042bf7edddd5a1f8614e732a4391fcf0189ae2312b0000000b02036b5f6f7065726174650000001305010007636f756e7465720000000000000005000000090903000474657874620000000401000000"},
	{"delete", "DELETE", "test", "s_delete", "", "02030000000000451600030000000000000000000000000003e7000300000000000500746573740000000901735f64656c6574650000001504485791d17c10a75a21d892b11ed1ca744695c868"},
	{"batch", "BATCH", "", "", "", "02030000000000851609000000000000000000000000000003e7000100000000006b2a000000030100000000971d7c1ee4b9f2f8d730e0c2e4ac2ebd713e5d0a0003000200000000000500746573740000000801735f626174636800000001f5155b25b04908c4001b53c0cd0a38751b8c642e010000000253d42f515d143c7abf3de290b23a2ae2d6c0746201"},
	{"scan", "SCAN", "test", "s_scan", "", "0203000000002045160100040000000000000000000000000000000500000000000500746573740000000701735f7363616e000020010b00000100020003000400050006000700080009000a000b000c000d000e000f0010001100120013001400150016001700180019001a001b001c001d001e001f0020002100220023002400250026002700280029002a002b002c002d002e002f0030003100320033003400350036003700380039003a003b003c003d003e003f0040004100420043004400450046004700480049004a004b004c004d004e004f0050005100520053005400550056005700580059005a005b005c005d005e005f00600061006200630064"},
	{"query", "QUERY", "test", "s_query", "", "0203000000002069160100040000000000000000000000000000000600000000000500746573740000000801735f717565727900000009079316f80c2b45fff70000001f16010376616c01000000080000000000000001000000080000000000000003000020010b00000100020003000400050006000700080009000a000b000c000d000e000f0010001100120013001400150016001700180019001a001b001c001d001e001f0020002100220023002400250026002700280029002a002b002c002d002e002f0030003100320033003400350036003700380039003a003b003c003d003e003f0040004100420043004400450046004700480049004a004b00"},
	{"udf", "UDF", "test", "s_udf", "k_udf", "02030000000000681600010000000000000000000000000003e7000700000000000500746573740000000601735f7564660000001504698b9fed790b6cb33fc05cb11e5990489ae8e1250000000702036b5f756466000000081e6361705f756466000000051f6563686f000000022090"},
}

// Real success responses: a bare write ack (just the as_msg header) and a read
// response carrying one integer bin.
const (
	aerospikeWriteOKResp = "020300000000001616000000000000000001000000000000000000000000"
	aerospikeGetOKResp   = "0203000000000027160000000000000000010000000000000000000000010000000d01010001760000000000000001"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestParseAerospikeRequest(t *testing.T) {
	for _, tc := range aerospikeRequestFixtures {
		t.Run(tc.name, func(t *testing.T) {
			buf := largebuf.NewLargeBufferFrom(mustHex(t, tc.hexFrame))

			info := parseAerospikeRequest(buf)
			require.NotNil(t, info, "request should parse as an AS_MSG data request")
			assert.Equal(t, tc.op, info.op, "operation")
			assert.Equal(t, tc.namespace, info.namespace, "namespace")
			assert.Equal(t, tc.set, info.set, "set")
			assert.Equal(t, tc.userKey, info.userKey, "user key")

			if tc.op == "BATCH" {
				assert.Positive(t, info.batchSize, "batch size should be extracted")
			}
		})
	}
}

// TestParseAerospikeRequestMultiChunk splits the same PUT frame across several
// chunks at awkward boundaries (inside the proto header, the as_msg header, and a
// field value); it must parse identically to the contiguous case.
func TestParseAerospikeRequestMultiChunk(t *testing.T) {
	full := mustHex(t, fixtureHex(t, "put"))
	lb := largebuf.NewLargeBuffer()
	lb.AppendChunk(full[:5])   // splits the 8-byte proto header
	lb.AppendChunk(full[5:35]) // splits the as_msg header and into fields
	lb.AppendChunk(full[35:])

	info := parseAerospikeRequest(lb)
	require.NotNil(t, info)
	assert.Equal(t, "PUT", info.op)
	assert.Equal(t, "test", info.namespace)
	assert.Equal(t, "s_put", info.set)
	assert.Equal(t, "k_put", info.userKey)
}

func TestAerospikeStatusSuccess(t *testing.T) {
	for _, h := range []string{aerospikeWriteOKResp, aerospikeGetOKResp} {
		status, dbErr := aerospikeStatus(largebuf.NewLargeBufferFrom(mustHex(t, h)))
		assert.Equal(t, 0, status)
		assert.Empty(t, dbErr.ErrorCode)
	}
}

func TestAerospikeStatusError(t *testing.T) {
	// Synthesize a KEY_EXISTS_ERROR (result_code 5): proto(type 3, size 22) +
	// as_msg header with result_code at body offset 5.
	body := make([]byte, 22)
	body[0] = 22 // header_sz
	body[5] = 5  // result_code = KEY_EXISTS_ERROR
	frame := append([]byte{2, 3, 0, 0, 0, 0, 0, 22}, body...)
	status, dbErr := aerospikeStatus(largebuf.NewLargeBufferFrom(frame))
	assert.Equal(t, 1, status)
	assert.Equal(t, "KEY_EXISTS_ERROR", dbErr.ErrorCode)

	// KEY_NOT_FOUND (2) is a normal miss, not an error.
	body[5] = 2
	frame = append([]byte{2, 3, 0, 0, 0, 0, 0, 22}, body...)
	status, _ = aerospikeStatus(largebuf.NewLargeBufferFrom(frame))
	assert.Equal(t, 0, status)
}

func fixtureHex(t *testing.T, name string) string {
	t.Helper()
	for _, tc := range aerospikeRequestFixtures {
		if tc.name == name {
			return tc.hexFrame
		}
	}
	t.Fatalf("fixture %q not found", name)
	return ""
}

func TestMatchAerospikeSpan(t *testing.T) {
	req := largebuf.NewLargeBufferFrom(mustHex(t, fixtureHex(t, "put")))
	resp := largebuf.NewLargeBufferFrom(mustHex(t, aerospikeWriteOKResp))

	event := &TCPRequestInfo{}
	span, ignore, matched, err := matchAerospike(event, req, resp)
	require.NoError(t, err)
	require.True(t, matched, "should match aerospike")
	assert.False(t, ignore)

	assert.Equal(t, request.EventTypeAerospikeClient, span.Type)
	assert.Equal(t, "PUT", span.Method)
	assert.Equal(t, "s_put", span.Path)
	assert.Equal(t, "test", span.DBNamespace)
	assert.Equal(t, "aerospike", span.DBSystem)
	assert.Equal(t, "k_put", span.Statement)
	assert.Equal(t, 0, span.Status)
	assert.Equal(t, "PUT test.s_put", span.TraceName())
}

func TestMatchAerospikeReversed(t *testing.T) {
	// Buffers swapped, as if OBI attached mid-connection and saw the response first.
	resp := largebuf.NewLargeBufferFrom(mustHex(t, aerospikeGetOKResp))
	req := largebuf.NewLargeBufferFrom(mustHex(t, fixtureHex(t, "get")))

	event := &TCPRequestInfo{}
	span, _, matched, err := matchAerospike(event, resp, req)
	require.NoError(t, err)
	require.True(t, matched)
	assert.Equal(t, "GET", span.Method)
	assert.Equal(t, "s_get", span.Path)
}

func TestMatchAerospikeNonAerospike(t *testing.T) {
	event := &TCPRequestInfo{}
	_, _, matched, _ := matchAerospike(event,
		largebuf.NewLargeBufferFrom([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")),
		largebuf.NewLargeBufferFrom([]byte("HTTP/1.1 200 OK\r\n\r\n")))
	assert.False(t, matched, "HTTP must not be misclassified as Aerospike")
}

// TestMatchAerospikeServerSideSkipped ensures a valid Aerospike exchange observed
// from the server process (IsServer) does not produce a span, so an operation
// instrumented on both peers is reported only once (client-side).
func TestMatchAerospikeServerSideSkipped(t *testing.T) {
	req := largebuf.NewLargeBufferFrom(mustHex(t, fixtureHex(t, "put")))
	resp := largebuf.NewLargeBufferFrom(mustHex(t, aerospikeWriteOKResp))

	_, _, matched, err := matchAerospike(&TCPRequestInfo{IsServer: true}, req, resp)
	require.NoError(t, err)
	assert.False(t, matched, "server-side Aerospike exchange must not produce a client span")

	// the same exchange on the client side still matches
	_, _, matched, err = matchAerospike(&TCPRequestInfo{IsServer: false}, req, resp)
	require.NoError(t, err)
	assert.True(t, matched, "client-side Aerospike exchange must still match")
}
