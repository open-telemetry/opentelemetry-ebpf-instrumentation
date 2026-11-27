// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rustabi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDatabasePreservesCrateSets(t *testing.T) {
	first := CrateVersions{"hyper": {"1.7.0"}, "tokio": {"0.2.25", "1.48.0"}}
	second := CrateVersions{"hyper": {"1.8.0"}, "tokio": {"1.49.0"}}
	reordered := CrateVersions{"hyper": {"1.7.0"}, "tokio": {"1.48.0", "0.2.25"}}

	var db Database
	for _, crates := range []CrateVersions{first, second, reordered} {
		db.Add(Profile{Arch: "amd64", Rustc: "1.99.0", Config: Layouts{VecPtr: 8}, CrateSets: []CrateVersions{crates}})
	}
	require.Len(t, db.Profiles, 1)
	require.ElementsMatch(t, []CrateVersions{first, second}, db.Profiles[0].CrateSets)
}
