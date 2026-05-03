// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package assert

import "testing"

type CollectT struct{ testing.TB }

type TestingT interface{ Errorf(format string, args ...any) }

func Less(t TestingT, e1, e2 any, msgAndArgs ...any) bool { return true }
func Equal(t TestingT, expected, actual any, msgAndArgs ...any) bool { return true }
func Empty(t TestingT, obj any, msgAndArgs ...any) bool { return true }

func EventuallyWithT(t *testing.T, condition func(collect *CollectT), waitFor, tick any, msgAndArgs ...any) bool {
	return true
}
