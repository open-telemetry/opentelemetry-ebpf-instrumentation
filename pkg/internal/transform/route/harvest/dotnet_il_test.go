// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"context"
	"debug/pe"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/microsoft/go-winmd/winmd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDotnetIL(t *testing.T) {
	p, md := openTestBlob(t)
	e := dotnetExtractor{ctx: context.Background(), pe: p, md: md, rs: map[string]struct{}{}}

	require.NoError(t, e.il())

	assert.Equal(t, map[string]struct{}{
		"/minimal/{id}": {},
		"/items":        {},
		"/{controller=Home}/{action=Index}/{id?}": {},
	}, e.rs)
}

func TestDotnetILWithoutRouteCalls(t *testing.T) {
	e := dotnetExtractor{
		ctx: context.Background(),
		md:  &winmd.Metadata{Tables: &winmd.Tables{}},
		rs:  map[string]struct{}{},
	}

	require.NoError(t, e.il())
	assert.Empty(t, e.rs)
}

func TestDotnetILCancelled(t *testing.T) {
	p, md := openTestBlob(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := dotnetExtractor{ctx: ctx, pe: p, md: md, rs: map[string]struct{}{}}

	require.ErrorIs(t, e.il(), context.Canceled)
	assert.Empty(t, e.rs)
}

func TestDotnetRouteCalls(t *testing.T) {
	_, md := openTestBlob(t)
	e := dotnetExtractor{ctx: context.Background(), md: md}

	calls, err := e.routeCalls()
	require.NoError(t, err)

	get := dotnetRouteMemberRef(t, &e, "MapGet")
	post := dotnetRouteMemberRef(t, &e, "MapPost")
	controller := dotnetRouteMemberRef(t, &e, "MapControllerRoute")
	assert.Contains(t, calls, get)
	assert.Contains(t, calls, post)
	assert.True(t, calls[controller].mapcontroller)

	a := dotnetAttribute(t, &e, "RouteAttribute", "api/[controller]")
	assert.NotContains(t, calls, memberRef|uint32(a.Type.Index+1))

	foundMethodDef := false
	for i := range md.Tables.MethodSpec.Indices() {
		m, err := md.Tables.MethodSpec.At(i)
		require.NoError(t, err)
		if m.Method.Tag == winmd.MethodDefOrRef_MethodDef {
			foundMethodDef = true
			assert.NotContains(t, calls, methodSpec|uint32(i+1))
		}
	}
	assert.True(t, foundMethodDef)
}

func TestDotnetRouteCallsCancelled(t *testing.T) {
	_, md := openTestBlob(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := dotnetExtractor{ctx: ctx, md: md}

	calls, err := e.routeCalls()

	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, calls)
}

func TestDotnetScanIL(t *testing.T) {
	_, base := openTestBlob(t)
	e := dotnetExtractor{md: base}
	routeCall := dotnetRouteMemberRef(t, &e, "MapGet")
	otherCall := methodDef | 1
	controllerCall := dotnetRouteMemberRef(t, &e, "MapControllerRoute")
	areaControllerCall := memberRef | 1
	h, tokens := dotnetUserHeap(
		"/api/customers", "~/health", "not/a/route", "/old", "/new",
		"default", "{controller=Home}/{action=Index}/{id?}",
		"Admin", "admin", "{area}/{controller}/{action}",
		"/route-name", "/absolute/{controller}",
		"simple", "articles/list", "en/us",
	)

	tests := []struct {
		name string
		code []byte
		want map[string]struct{}
	}{
		{
			name: "call",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, tokens[0]),
				dotnetInstruction(call, routeCall),
			),
			want: map[string]struct{}{`/api/customers`: {}},
		},
		{
			name: "callvirt",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, tokens[0]),
				dotnetInstruction(callvirt, routeCall),
			),
			want: map[string]struct{}{`/api/customers`: {}},
		},
		{
			name: "method specification call",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, tokens[0]),
				dotnetInstruction(call, methodSpec|1),
			),
			want: map[string]struct{}{`/api/customers`: {}},
		},
		{
			name: "tilde route",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, tokens[1]),
				dotnetInstruction(call, routeCall),
			),
			want: map[string]struct{}{`/health`: {}},
		},
		{
			name: "non-route string",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, tokens[2]),
				dotnetInstruction(call, routeCall),
			),
			want: map[string]struct{}{},
		},
		{
			name: "unrelated call clears route",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, tokens[3]),
				dotnetInstruction(call, otherCall),
				dotnetInstruction(call, routeCall),
			),
			want: map[string]struct{}{},
		},
		{
			name: "latest string wins",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, tokens[3]),
				dotnetInstruction(ldstr, tokens[4]),
				dotnetInstruction(call, routeCall),
			),
			want: map[string]struct{}{`/new`: {}},
		},
		{
			name: "controller route pattern",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, tokens[5]),
				dotnetInstruction(ldstr, tokens[6]),
				dotnetInstruction(call, controllerCall),
			),
			want: map[string]struct{}{`/{controller=Home}/{action=Index}/{id?}`: {}},
		},
		{
			name: "controller route absolute pattern",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, tokens[10]),
				dotnetInstruction(ldstr, tokens[11]),
				dotnetInstruction(call, controllerCall),
			),
			want: map[string]struct{}{`/absolute/{controller}`: {}},
		},
		{
			name: "area controller route pattern",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, tokens[7]),
				dotnetInstruction(ldstr, tokens[8]),
				dotnetInstruction(ldstr, tokens[9]),
				dotnetInstruction(call, areaControllerCall),
			),
			want: map[string]struct{}{`/{area}/{controller}/{action}`: {}},
		},
		{
			name: "controller route slash pattern",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, tokens[12]),
				dotnetInstruction(ldstr, tokens[13]),
				dotnetInstruction(ldstr, tokens[14]),
				dotnetInstruction(call, controllerCall),
			),
			want: map[string]struct{}{`/articles/list`: {}},
		},
		{
			name: "call clears controller route candidates",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, tokens[6]),
				dotnetInstruction(callvirt, otherCall),
				dotnetInstruction(ldstr, tokens[5]),
				dotnetInstruction(call, controllerCall),
			),
			want: map[string]struct{}{},
		},
		{
			name: "non-user-string token",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, memberRef|1),
				dotnetInstruction(call, routeCall),
			),
			want: map[string]struct{}{},
		},
		{
			name: "invalid string offset",
			code: dotnetInstructions(
				dotnetInstruction(ldstr, userString<<tokenShift|uint32(len(h))),
				dotnetInstruction(call, routeCall),
			),
			want: map[string]struct{}{},
		},
		{name: "truncated instruction", code: []byte{ldstr, 1, 0}, want: map[string]struct{}{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := *base
			md.US = h
			e := dotnetExtractor{md: &md, rs: map[string]struct{}{}}

			e.scanIL(tt.code, map[uint32]dotnetCall{
				routeCall:          {},
				methodSpec | 1:     {},
				controllerCall:     {mapcontroller: true},
				areaControllerCall: {mapcontroller: true},
			})

			assert.Equal(t, tt.want, e.rs)
		})
	}
}

func TestDotnetValidMethodToken(t *testing.T) {
	_, md := openTestBlob(t)
	e := dotnetExtractor{md: md}
	require.NotZero(t, md.Tables.MethodDef.Len())
	require.NotZero(t, md.Tables.MemberRef.Len())
	require.NotZero(t, md.Tables.MethodSpec.Len())

	tests := []struct {
		name  string
		token uint32
		want  bool
	}{
		{name: "method definition", token: methodDef | 1, want: true},
		{name: "member reference", token: memberRef | 1, want: true},
		{name: "method specification", token: methodSpec | 1, want: true},
		{name: "zero row", token: methodDef},
		{name: "method definition out of range", token: methodDef | md.Tables.MethodDef.Len() + 1},
		{name: "member reference out of range", token: memberRef | md.Tables.MemberRef.Len() + 1},
		{name: "method specification out of range", token: methodSpec | md.Tables.MethodSpec.Len() + 1},
		{name: "different table", token: userString<<tokenShift | 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, e.validMethodToken(tt.token))
		})
	}
}

func TestDotnetUserString(t *testing.T) {
	long := strings.Repeat("a", 64)
	h, tokens := dotnetUserHeap("/api", "héllo 😀", "", long)
	tests := []struct {
		name string
		heap winmd.USHeap
		off  uint32
		want string
		ok   bool
	}{
		{name: "ASCII", heap: h, off: tokens[0] & tokenMask, want: "/api", ok: true},
		{name: "Unicode", heap: h, off: tokens[1] & tokenMask, want: "héllo 😀", ok: true},
		{name: "empty", heap: h, off: tokens[2] & tokenMask, want: "", ok: true},
		{name: "two-byte length", heap: h, off: tokens[3] & tokenMask, want: long, ok: true},
		{name: "reserved offset", heap: h, off: 0},
		{name: "offset at end", heap: h, off: uint32(len(h))},
		{name: "truncated length", heap: winmd.USHeap{0, 0x80}, off: 1},
		{name: "truncated payload", heap: winmd.USHeap{0, 5, 'a', 0}, off: 1},
		{name: "odd UTF-16 payload", heap: winmd.USHeap{0, 2, 'a', 0}, off: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := dotnetUserString(tt.heap, tt.off)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDotnetMethodIL(t *testing.T) {
	raw := testBlobBytes(t)
	p := openDotnetPE(t, raw)
	md, err := winmd.New(p)
	require.NoError(t, err)
	rva := dotnetMethodRVA(t, md, "Endpoints", "Map")
	off, remaining := dotnetMethodOffset(t, p, rva)

	t.Run("compiled method", func(t *testing.T) {
		code, ok := dotnetMethodIL(p, rva)
		assert.True(t, ok)
		assert.NotEmpty(t, code)
	})

	t.Run("tiny header", func(t *testing.T) {
		body := []byte{0x00, 0x2a}
		method := append([]byte{byte(len(body)<<2) | tinyMethodFormat}, body...)
		code, ok := dotnetMethodIL(dotnetPatchedPE(t, raw, off, method), rva)
		assert.True(t, ok)
		assert.Equal(t, body, code)
	})

	t.Run("fat header", func(t *testing.T) {
		body := []byte{0x00, 0x2a}
		method := dotnetFatMethod(3, uint32(len(body)), body)
		code, ok := dotnetMethodIL(dotnetPatchedPE(t, raw, off, method), rva)
		assert.True(t, ok)
		assert.Equal(t, body, code)
	})

	t.Run("extended fat header", func(t *testing.T) {
		body := []byte{0x00, 0x2a}
		method := dotnetFatMethod(4, uint32(len(body)), body)
		code, ok := dotnetMethodIL(dotnetPatchedPE(t, raw, off, method), rva)
		assert.True(t, ok)
		assert.Equal(t, body, code)
	})

	t.Run("zero RVA", func(t *testing.T) {
		code, ok := dotnetMethodIL(p, 0)
		assert.False(t, ok)
		assert.Nil(t, code)
	})

	t.Run("RVA outside sections", func(t *testing.T) {
		code, ok := dotnetMethodIL(p, ^uint32(0))
		assert.False(t, ok)
		assert.Nil(t, code)
	})

	t.Run("unknown header", func(t *testing.T) {
		code, ok := dotnetMethodIL(dotnetPatchedPE(t, raw, off, []byte{0}), rva)
		assert.False(t, ok)
		assert.Nil(t, code)
	})

	t.Run("short fat header", func(t *testing.T) {
		method := dotnetFatMethod(2, 0, nil)
		code, ok := dotnetMethodIL(dotnetPatchedPE(t, raw, off, method), rva)
		assert.False(t, ok)
		assert.Nil(t, code)
	})

	t.Run("method too large", func(t *testing.T) {
		method := dotnetFatMethod(3, maxDotnetMethodBytes+1, nil)
		code, ok := dotnetMethodIL(dotnetPatchedPE(t, raw, off, method), rva)
		assert.False(t, ok)
		assert.Nil(t, code)
	})

	t.Run("truncated method", func(t *testing.T) {
		size := remaining - 12 + 1
		method := dotnetFatMethod(3, size, nil)
		code, ok := dotnetMethodIL(dotnetPatchedPE(t, raw, off, method), rva)
		assert.False(t, ok)
		assert.Nil(t, code)
	})
}

func dotnetRouteMemberRef(t *testing.T, e *dotnetExtractor, name string) uint32 {
	t.Helper()
	for i := range e.md.Tables.MemberRef.Indices() {
		m, err := e.md.Tables.MemberRef.At(i)
		require.NoError(t, err)
		_, ns, ok := e.memberType(m)
		if ok && ns == "Microsoft.AspNetCore.Builder" && m.Name.String() == name {
			return memberRef | uint32(i+1)
		}
	}
	t.Fatalf("route member reference %q not found", name)
	return 0
}

func dotnetUserHeap(values ...string) (winmd.USHeap, []uint32) {
	h := winmd.USHeap{0}
	tokens := make([]uint32, 0, len(values))
	for _, value := range values {
		off := uint32(len(h))
		u := utf16.Encode([]rune(value))
		h = append(h, dotnetCompressedLen(uint32(len(u)*2+1))...)
		for _, r := range u {
			h = binary.LittleEndian.AppendUint16(h, r)
		}
		h = append(h, 0)
		tokens = append(tokens, userString<<tokenShift|off)
	}
	return h, tokens
}

func dotnetCompressedLen(n uint32) []byte {
	switch {
	case n <= 0x7f:
		return []byte{byte(n)}
	case n <= 0x3fff:
		return []byte{byte(n>>8) | 0x80, byte(n)}
	default:
		return []byte{byte(n>>24) | 0xc0, byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func dotnetInstruction(op byte, token uint32) []byte {
	return binary.LittleEndian.AppendUint32([]byte{op}, token)
}

func dotnetInstructions(instructions ...[]byte) []byte {
	var code []byte
	for _, instruction := range instructions {
		code = append(code, instruction...)
	}
	return code
}

func dotnetMethodRVA(t *testing.T, md *winmd.Metadata, owner, name string) uint32 {
	t.Helper()
	i := dotnetMethod(t, md, dotnetType(t, md, owner), name)
	m, err := md.Tables.MethodDef.At(i)
	require.NoError(t, err)
	require.NotZero(t, m.RVA)
	return m.RVA
}

func dotnetMethodOffset(t *testing.T, p *pe.File, rva uint32) (int, uint32) {
	t.Helper()
	for _, s := range p.Sections {
		if rva < s.VirtualAddress || uint64(rva-s.VirtualAddress) >= uint64(s.Size) {
			continue
		}
		delta := rva - s.VirtualAddress
		return int(s.Offset + delta), s.Size - delta
	}
	t.Fatalf("RVA %#x not found", rva)
	return 0, 0
}

func dotnetPatchedPE(t *testing.T, raw []byte, off int, method []byte) *pe.File {
	t.Helper()
	require.LessOrEqual(t, off+len(method), len(raw))
	b := append([]byte(nil), raw...)
	copy(b[off:], method)
	return openDotnetPE(t, b)
}

func dotnetFatMethod(words uint16, size uint32, body []byte) []byte {
	headerSize := int(words) * 4
	b := make([]byte, headerSize+len(body))
	binary.LittleEndian.PutUint16(b, words<<12|fatMethodFormat)
	binary.LittleEndian.PutUint32(b[4:8], size)
	copy(b[headerSize:], body)
	return b
}
