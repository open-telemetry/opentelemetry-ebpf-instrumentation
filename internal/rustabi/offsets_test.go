// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rustabi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckCompiler(t *testing.T) {
	// The database records one patch of each compiler minor for this binary's architecture.
	db := Database{Profiles: []Profile{
		{Arch: "amd64", Rustc: "1.98.1", CompilerCommit: "known"},
		{Arch: "amd64", Rustc: "1.99.1"},
		{Arch: "arm64", Rustc: "1.100.0"},
	}}

	for _, build := range []Build{
		{Arch: "amd64", Rustc: "1.98.0"},
		{Arch: "amd64", Rustc: "1.99.0"},
		{Arch: "amd64", Rustc: "1.99.2"},
		{Arch: "arm64", Rustc: "1.100.0"},
		{Arch: "amd64", CompilerCommit: "known"},
	} {
		require.NoError(t, db.CheckCompiler(build), "%+v", build)
	}

	for _, build := range []Build{
		{Arch: "amd64", Rustc: "1.96.9"},
		{Arch: "arm64", Rustc: "1.99.1"},
		{Arch: "amd64", Rustc: "1.101.0", CompilerCommit: "known"},
		{Arch: "amd64", Rustc: "1.99.0-nightly"},
		{Arch: "amd64", CompilerCommit: "unknown"},
		{Arch: "arm64", CompilerCommit: "known"},
	} {
		require.ErrorIs(t, db.CheckCompiler(build), ErrUnsupportedCompiler, "%+v", build)
	}
}
