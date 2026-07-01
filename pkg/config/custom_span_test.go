// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCustomSpanConfig_DisabledWhenEmpty(t *testing.T) {
	c := CustomSpanConfig{}
	assert.False(t, c.Enabled())
	require.NoError(t, c.Validate())
}

func TestCustomSpanConfig_RequiresPositiveTTL(t *testing.T) {
	c := CustomSpanConfig{
		TTL:   0,
		Spans: []CustomSpanSpec{{Name: "x", On: CustomSpanTarget{USDTNoRet: "a:b"}}},
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ttl")
}

func TestCustomSpanConfig_USDTNoRet(t *testing.T) {
	c := CustomSpanConfig{
		TTL: 5 * time.Minute,
		Spans: []CustomSpanSpec{{
			Name: "cache.hit",
			On:   CustomSpanTarget{USDTNoRet: "myapp:cache_hit"},
			Attrs: map[string]CustomSpanAttr{
				"key": {Arg: 0, Type: CustomSpanAttrString},
			},
		}},
	}
	require.NoError(t, c.Validate())
	s := &c.Spans[0]
	assert.True(t, s.IsUSDTNoRet())
	assert.False(t, s.IsUSDTSpan())
	assert.True(t, s.IsAnyUSDT())
	assert.Equal(t, "myapp:cache_hit", s.USDTNoRetProbe())
}

func TestCustomSpanConfig_USDTSpan(t *testing.T) {
	c := CustomSpanConfig{
		TTL: 5 * time.Minute,
		Spans: []CustomSpanSpec{{
			Name: "order.process",
			On:   CustomSpanTarget{USDTSpan: "myapp:order"},
			Attrs: map[string]CustomSpanAttr{
				"order_id": {Arg: 0},
				"customer": {Arg: 1, Type: CustomSpanAttrString},
			},
		}},
	}
	require.NoError(t, c.Validate())
	s := &c.Spans[0]
	assert.True(t, s.IsUSDTSpan())
	assert.Equal(t, "myapp:order_start", s.USDTStartProbe())
	assert.Equal(t, "myapp:order_end", s.USDTEndProbe())
}

func TestCustomSpanConfig_FunctionNoRet(t *testing.T) {
	c := CustomSpanConfig{
		TTL: time.Minute,
		Spans: []CustomSpanSpec{{
			Name: "init.done",
			On:   CustomSpanTarget{FunctionNoRet: "init_complete"},
			Attrs: map[string]CustomSpanAttr{
				"phase": {Arg: 0, Type: CustomSpanAttrU64},
			},
		}},
	}
	require.NoError(t, c.Validate())
	s := &c.Spans[0]
	assert.True(t, s.IsFunctionNoRet())
	assert.False(t, s.IsFunctionSpan())
	assert.Equal(t, "init_complete", s.FunctionSymbol())
}

func TestCustomSpanConfig_FunctionSpan(t *testing.T) {
	c := CustomSpanConfig{
		TTL: time.Minute,
		Spans: []CustomSpanSpec{{
			Name: "cache.func",
			On:   CustomSpanTarget{FunctionSpan: "cache_lookup"},
			Attrs: map[string]CustomSpanAttr{
				"key": {Arg: 0, Type: CustomSpanAttrString},
			},
		}},
	}
	require.NoError(t, c.Validate())
	assert.True(t, c.Spans[0].IsFunctionSpan())
	assert.Equal(t, "cache_lookup", c.Spans[0].FunctionSymbol())
}

func TestCustomSpanConfig_USDTNoRetWithMatch(t *testing.T) {
	c := CustomSpanConfig{
		TTL: time.Minute,
		Spans: []CustomSpanSpec{{
			Name: "py.proc",
			On: CustomSpanTarget{
				USDTNoRet: "python:function__entry",
				Match:     &CustomSpanMatch{Arg: 1, Value: "process_paid_order"},
			},
		}},
	}
	require.NoError(t, c.Validate())
	assert.True(t, c.Spans[0].HasMatch())
}

func TestCustomSpanConfig_FunctionRequiresType(t *testing.T) {
	c := CustomSpanConfig{
		TTL: time.Minute,
		Spans: []CustomSpanSpec{{
			Name: "x",
			On:   CustomSpanTarget{FunctionSpan: "f"},
			Attrs: map[string]CustomSpanAttr{
				"v": {Arg: 0}, // no type → invalid for function-mode
			},
		}},
	}
	require.Error(t, c.Validate())
}

func TestCustomSpanConfig_RejectsMultipleForms(t *testing.T) {
	cases := []CustomSpanSpec{
		{Name: "x", On: CustomSpanTarget{USDTNoRet: "a:b", FunctionSpan: "f"}},
		{Name: "x", On: CustomSpanTarget{USDTNoRet: "a:b", USDTSpan: "a:c"}},
		{Name: "x", On: CustomSpanTarget{FunctionNoRet: "f", FunctionSpan: "g"}},
		{Name: "x"}, // no target
	}
	for i, span := range cases {
		c := CustomSpanConfig{TTL: time.Minute, Spans: []CustomSpanSpec{span}}
		require.Errorf(t, c.Validate(), "case %d expected error", i)
	}
}

func TestCustomSpanConfig_RejectsMatchOnFunction(t *testing.T) {
	c := CustomSpanConfig{
		TTL: time.Minute,
		Spans: []CustomSpanSpec{{
			Name: "x",
			On: CustomSpanTarget{
				FunctionSpan: "f",
				Match:        &CustomSpanMatch{Arg: 0, Value: "x"},
			},
			Attrs: map[string]CustomSpanAttr{"v": {Arg: 0, Type: CustomSpanAttrU64}},
		}},
	}
	require.Error(t, c.Validate())
}

func TestCustomSpanConfig_RejectsMissingName(t *testing.T) {
	c := CustomSpanConfig{
		TTL:   time.Minute,
		Spans: []CustomSpanSpec{{On: CustomSpanTarget{USDTNoRet: "a:b"}}},
	}
	require.Error(t, c.Validate())
}

func TestCustomSpanConfig_RejectsInvalidProbeIdent(t *testing.T) {
	c := CustomSpanConfig{
		TTL:   time.Minute,
		Spans: []CustomSpanSpec{{Name: "x", On: CustomSpanTarget{USDTNoRet: "no_colon"}}},
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider:name")
}

func TestCustomSpanConfig_RejectsArgOutOfRange(t *testing.T) {
	c := CustomSpanConfig{
		TTL: time.Minute,
		Spans: []CustomSpanSpec{{
			Name: "x", On: CustomSpanTarget{USDTNoRet: "a:b"},
			Attrs: map[string]CustomSpanAttr{"bad": {Arg: CustomSpanMaxArgs, Type: CustomSpanAttrU64}},
		}},
	}
	require.Error(t, c.Validate())
}

func TestCustomSpanConfig_RejectsBadType(t *testing.T) {
	c := CustomSpanConfig{
		TTL: time.Minute,
		Spans: []CustomSpanSpec{{
			Name: "x", On: CustomSpanTarget{FunctionSpan: "f"},
			Attrs: map[string]CustomSpanAttr{"bad": {Arg: 0, Type: "float64"}},
		}},
	}
	require.Error(t, c.Validate())
}

func TestCustomSpanConfig_RejectsEmptyMatchValue(t *testing.T) {
	c := CustomSpanConfig{
		TTL: time.Minute,
		Spans: []CustomSpanSpec{{
			Name: "x",
			On: CustomSpanTarget{
				USDTNoRet: "a:b",
				Match:     &CustomSpanMatch{Arg: 0, Value: ""},
			},
		}},
	}
	require.Error(t, c.Validate())
}

func TestCustomSpanConfig_RejectsDuplicateNames(t *testing.T) {
	c := CustomSpanConfig{
		TTL: time.Minute,
		Spans: []CustomSpanSpec{
			{Name: "dup", On: CustomSpanTarget{USDTNoRet: "a:one"}},
			{Name: "dup", On: CustomSpanTarget{USDTNoRet: "a:two"}},
		},
	}
	require.Error(t, c.Validate())
}

func TestCustomSpanConfig_RejectsDuplicateProbes(t *testing.T) {
	c := CustomSpanConfig{
		TTL: time.Minute,
		Spans: []CustomSpanSpec{
			{Name: "x", On: CustomSpanTarget{USDTNoRet: "a:shared"}},
			{Name: "y", On: CustomSpanTarget{USDTNoRet: "a:shared"}},
		},
	}
	require.Error(t, c.Validate())
}

func TestCustomSpanConfig_TypeProperties(t *testing.T) {
	assert.Equal(t, uint8(1), CustomSpanAttrU8.SizeBytes())
	assert.Equal(t, uint8(8), CustomSpanAttrI64.SizeBytes())
	assert.True(t, CustomSpanAttrString.IsString())
	assert.True(t, CustomSpanAttrI32.Signed())
	assert.False(t, CustomSpanAttrU32.Signed())
	assert.True(t, CustomSpanAttrType("").Empty())
	assert.False(t, CustomSpanAttrU8.Empty())
}

func TestCustomSpanConfig_YAMLUnmarshal(t *testing.T) {
	in := []byte(`
ttl: 10m
spans:
  - name: "order.process"
    on: { usdt_span: "myapp:order" }
    attrs:
      order_id: { arg: 0 }
      customer: { arg: 1, type: string }
  - name: "cache.hit"
    on: { usdt_noret: "myapp:cache_hit" }
    attrs:
      key: { arg: 0, type: string }
  - name: "cache.func"
    on: { function_span: "cache_lookup" }
    attrs:
      key: { arg: 0, type: string }
  - name: "init.done"
    on: { function_noret: "init_complete" }
    attrs:
      phase: { arg: 0, type: u64 }
  - name: "py.proc"
    on:
      usdt_noret: "python:function__entry"
      match: { arg: 1, value: "process_paid_order" }
`)
	var c CustomSpanConfig
	require.NoError(t, yaml.Unmarshal(in, &c))
	require.NoError(t, c.Validate())
	assert.Equal(t, 10*time.Minute, c.TTL)
	assert.Len(t, c.Spans, 5)
	assert.Equal(t, "myapp:order_start", c.Spans[0].USDTStartProbe())
	assert.True(t, c.Spans[2].IsFunctionSpan())
	assert.True(t, c.Spans[3].IsFunctionNoRet())
	assert.True(t, c.Spans[4].HasMatch())
}
