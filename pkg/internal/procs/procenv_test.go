// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvStrParsing(t *testing.T) {
	strs := []string{
		"ok=\"=  =\"",
		"nothing",
		"=wrong",
		"something=somethingelse",
		"something_empty=",
		"something= else",
		"weird==  =",
		"resources=a=b,c=d,e=  fg",
		"",
	}

	res := envStrsToMap(strs)
	assert.Equal(t, map[string]string{"something": "else", "ok": "\"=  =\"", "weird": "=  =", "resources": "a=b,c=d,e=  fg"}, res)
}
