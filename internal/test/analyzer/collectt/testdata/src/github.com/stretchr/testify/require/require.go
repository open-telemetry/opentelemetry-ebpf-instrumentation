// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package require

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestingT interface{ Errorf(format string, args ...any) }

func NoError(t TestingT, err error, msgAndArgs ...any) {}
func Equal(t TestingT, expected, actual any, msgAndArgs ...any) {}
func Len(t TestingT, object any, length int, msgAndArgs ...any) {}
func NotEmpty(t TestingT, obj any, msgAndArgs ...any) {}
func Empty(t TestingT, obj any, msgAndArgs ...any) {}
func GreaterOrEqual(t TestingT, e1, e2 any, msgAndArgs ...any) {}

func EventuallyWithT(t *testing.T, condition func(collect *assert.CollectT), waitFor, tick any, msgAndArgs ...any) {
}
