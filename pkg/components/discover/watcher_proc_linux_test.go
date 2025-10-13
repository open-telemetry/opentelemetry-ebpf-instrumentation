// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProcStatField(t *testing.T) {
	// this has excessive whitespace on purpose
	const procPidStat = " 1197473 (foo bar) R   1494929 1197473 1494929 34817 1197473 4194304 91 " +
		"0 0 0 0 0 0 0 20 0 1 0 164004305 8724480 1364    18446744073709551615 93963828355072 " +
		"93963828373377 140721901331744 0 0 0 0 0 0 0 0 0    17 4 0 0 0 0 0 93963828386384 " +
		"93963828387944 93964083773440 140721901340217 140721901340237 140721901340237 " +
		"140721901342699 0"

	inParens := false

	f := func(c rune) bool {
		if c == '(' {
			inParens = true
			return true
		}

		if inParens {
			if c == ')' {
				inParens = false
				return true
			}

			return false
		}

		return c == ' '
	}

	expected := strings.FieldsFunc(procPidStat, f)

	for i := range expected {
		assert.Equal(t, expected[i], parseProcStatField(procPidStat, i+1))
	}

	// test a few fields explicitly to ensure whitespace is being handled
	// properly
	assert.Empty(t, parseProcStatField(procPidStat, 0))
	assert.Empty(t, parseProcStatField(procPidStat, 200))
	assert.Equal(t, "1197473", parseProcStatField(procPidStat, 1))
	assert.Equal(t, "foo bar", parseProcStatField(procPidStat, 2))
	assert.Equal(t, "R", parseProcStatField(procPidStat, 3))
	assert.Equal(t, "1494929", parseProcStatField(procPidStat, 4))

	// empty input
	assert.Empty(t, parseProcStatField("", 0))
	assert.Empty(t, parseProcStatField("", 1))
	assert.Empty(t, parseProcStatField("", 200))
	assert.Empty(t, parseProcStatField("", -1))
}

func TestGetProcStatField(t *testing.T) {
	r := procStatReader{}
	assert.Empty(t, r.getProcStatField(0, 0))
	assert.Empty(t, r.getProcStatField(-1, 0))

	pid := os.Getpid()

	exePath, err := os.Executable()

	require.NoError(t, err)

	exe := filepath.Base(exePath)

	assert.Equal(t, exe, r.getProcStatField(int32(pid), 2))
}

func TestNSToDuration(t *testing.T) {
	assert.Equal(t, time.Duration(math.MaxInt64), nsToDuration(math.MaxUint64))
	assert.Equal(t, time.Duration(0), nsToDuration(0))
}

func TestProcessAge(t *testing.T) {
	r := procStatReader{}

	assert.Zero(t, r.processAge(0))

	age := r.processAge(int32(os.Getpid()))

	require.NotZero(t, age)

	expected, err := time.ParseDuration("2m")

	require.NoError(t, err)

	assert.Less(t, age, expected)
}
