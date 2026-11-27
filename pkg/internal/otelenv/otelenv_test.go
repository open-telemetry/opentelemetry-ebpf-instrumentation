// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelenv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKeyValues_RawValues(t *testing.T) {
	got := map[string]string{}
	ParseKeyValues("team=payments%20core,bad=%zz, ,novalue=,=nokey", func(k, v string) { got[k] = v })

	require.Equal(t, map[string]string{"team": "payments%20core", "bad": "%zz"}, got)
}

func TestDecodeValue(t *testing.T) {
	assert.Equal(t, "payments core", DecodeValue("payments%20core"))
	assert.Equal(t, "a+b", DecodeValue("a+b"))
	assert.Equal(t, "a%20b", DecodeValue("a%2520b"))
	assert.Equal(t, "%zz", DecodeValue("%zz"))
	assert.Equal(t, "100%", DecodeValue("100%"))
}
