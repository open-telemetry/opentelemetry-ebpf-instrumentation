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

func TestValidEnvCountIgnoresNULPadding(t *testing.T) {
	strs := make([]string, 640_000)
	strs[0] = "OTEL_SERVICE_NAME=checkout"
	strs[1] = "EMPTY="
	strs[2] = "=missing-key"

	assert.Equal(t, 1, validEnvCount(strs))
	assert.Equal(t, map[string]string{"OTEL_SERVICE_NAME": "checkout"}, envStrsToMap(strs))
}
