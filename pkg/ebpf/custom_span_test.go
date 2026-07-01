// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
)

func twoRegArgU64(regA, regB int16) obiUSDTSpec {
	var s obiUSDTSpec
	s.ArgCount = 2
	s.Args[0] = obiUSDTArgSpec{ArgType: obiUSDTArgReg, RegOff: regA, ArgBitshift: 0}
	s.Args[1] = obiUSDTArgSpec{ArgType: obiUSDTArgReg, RegOff: regB, ArgBitshift: 0}
	return s
}

func TestCompileCustomSpanSpec_IntAndString(t *testing.T) {
	base := twoRegArgU64(112, 104)
	span := &config.CustomSpanSpec{
		Name: "order.process",
		On:   config.CustomSpanTarget{USDTSpan: "myapp:order"},
		Attrs: map[string]config.CustomSpanAttr{
			"order_id": {Arg: 0, Type: config.CustomSpanAttrU64},
			"customer": {Arg: 1, Type: config.CustomSpanAttrString},
		},
	}
	out, err := CompileCustomSpanSpec(base, span, 0xABCDEF)
	require.NoError(t, err)
	assert.Equal(t, uint64(0xABCDEF), out.Spec.Cookie)
	assert.Equal(t, obiUSDTArgReg, out.Spec.Args[0].ArgType)
	assert.Equal(t, obiUSDTArgRegDerefStr, out.Spec.Args[1].ArgType)
	assert.Equal(t, int16(104), out.Spec.Args[1].RegOff)
	assert.Equal(t, uint64(config.CustomSpanStringSize), out.Spec.Args[1].ValOff)
	assert.Equal(t, CustomSpanArgInt, out.ArgKinds[0])
	assert.Equal(t, CustomSpanArgStr, out.ArgKinds[1])
}

func TestCompileCustomSpanSpec_DriftOnArgCount(t *testing.T) {
	base := twoRegArgU64(112, 104)
	span := &config.CustomSpanSpec{
		Name: "x",
		On:   config.CustomSpanTarget{USDTNoRet: "myapp:x"},
		Attrs: map[string]config.CustomSpanAttr{
			"missing": {Arg: 5, Type: config.CustomSpanAttrU64},
		},
	}
	_, err := CompileCustomSpanSpec(base, span, 1)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCustomSpanDrift)
}

func TestCompileCustomSpanSpec_SoftDriftOnIntSizeMismatch(t *testing.T) {
	// In a paired probe the same arg index may carry different int widths
	// between start and end; the rewriter must attach the probe and let
	// userspace skip the mismatched-kind attr.
	base := twoRegArgU64(112, 104)
	span := &config.CustomSpanSpec{
		Name: "x",
		On:   config.CustomSpanTarget{USDTNoRet: "myapp:x"},
		Attrs: map[string]config.CustomSpanAttr{
			"id": {Arg: 0, Type: config.CustomSpanAttrU32},
		},
	}
	out, err := CompileCustomSpanSpec(base, span, 1)
	require.NoError(t, err)
	assert.Equal(t, obiUSDTArgReg, out.Spec.Args[0].ArgType)
}

func TestCompileCustomSpanSpec_SoftDriftOnStringWithConstArg(t *testing.T) {
	var base obiUSDTSpec
	base.ArgCount = 1
	base.Args[0] = obiUSDTArgSpec{ArgType: obiUSDTArgConst, ValOff: 0xDEADBEEF, ArgBitshift: 0}
	span := &config.CustomSpanSpec{
		Name: "x",
		On:   config.CustomSpanTarget{USDTNoRet: "myapp:x"},
		Attrs: map[string]config.CustomSpanAttr{
			"label": {Arg: 0, Type: config.CustomSpanAttrString},
		},
	}
	out, err := CompileCustomSpanSpec(base, span, 1)
	require.NoError(t, err)
	assert.Equal(t, obiUSDTArgConst, out.Spec.Args[0].ArgType)
}

func TestCompileCustomSpanSpec_IntTypeOmittedDerivesFromELF(t *testing.T) {
	// USDT int attrs may omit `type:` — wire-side sign+width comes from
	// the .note.stapsdt ArgBitshift / ArgSigned. Compile should accept
	// the attr without raising drift.
	var base obiUSDTSpec
	base.ArgCount = 1
	base.Args[0] = obiUSDTArgSpec{ArgType: obiUSDTArgReg, RegOff: 112, ArgBitshift: 32, ArgSigned: 1}
	span := &config.CustomSpanSpec{
		Name: "x",
		On:   config.CustomSpanTarget{USDTNoRet: "myapp:x"},
		Attrs: map[string]config.CustomSpanAttr{
			"id": {Arg: 0}, // no type
		},
	}
	out, err := CompileCustomSpanSpec(base, span, 1)
	require.NoError(t, err)
	assert.Equal(t, CustomSpanArgInt, out.ArgKinds[0])
}

func TestCompileCustomSpanSpec_IntSizesAllValid(t *testing.T) {
	cases := []struct {
		typ   config.CustomSpanAttrType
		shift uint8
	}{
		{config.CustomSpanAttrU8, 56},
		{config.CustomSpanAttrU16, 48},
		{config.CustomSpanAttrU32, 32},
		{config.CustomSpanAttrU64, 0},
		{config.CustomSpanAttrI8, 56},
		{config.CustomSpanAttrI16, 48},
		{config.CustomSpanAttrI32, 32},
		{config.CustomSpanAttrI64, 0},
	}
	for _, c := range cases {
		var base obiUSDTSpec
		base.ArgCount = 1
		base.Args[0] = obiUSDTArgSpec{ArgType: obiUSDTArgReg, RegOff: 112, ArgBitshift: c.shift}
		span := &config.CustomSpanSpec{
			Name:  "n",
			On:    config.CustomSpanTarget{USDTNoRet: "a:b"},
			Attrs: map[string]config.CustomSpanAttr{"x": {Arg: 0, Type: c.typ}},
		}
		_, err := CompileCustomSpanSpec(base, span, 1)
		require.NoErrorf(t, err, "type %s", c.typ)
	}
}
