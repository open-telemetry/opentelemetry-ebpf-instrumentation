// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func TestReadNamespacedPidsNamespaceOrder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		nspid string
		want  []app.PID
	}{
		{
			name: "single namespace", nspid: "42000",
			want: []app.PID{42000},
		},
		{
			name: "outermost to innermost", nspid: "42000\t120\t1",
			want: []app.PID{42000, 120, 1},
		},
		{
			name: "proc mounted in an intermediate namespace", nspid: "120\t1",
			want: []app.PID{120, 1},
		},
		{
			name: "namespace priority differs from numeric order", nspid: "120\t900\t1",
			want: []app.PID{120, 900, 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := strings.NewReader("Name:\ttest\nNSpid:\t" + tc.nspid + "\nNSpgid:\t1\n")
			pids, err := readNamespacedPids(status)
			require.NoError(t, err)
			require.Equal(t, tc.want, pids)
		})
	}
}
