// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSelectorMatch(t *testing.T) {
	fbb := InclusionLists{Include: []string{"foo_bar_baz"}}
	f := InclusionLists{Include: []string{"foo"}}
	fbt := InclusionLists{Include: []string{"foo_bar_traca"}}
	pp := InclusionLists{Include: []string{"pim_pam"}}
	selection := Selection{
		"foo.bar.baz":   fbb,
		"foo.*":         f,
		"foo.bar.traca": fbt,
		"pim.pam":       pp,
	}
	assert.Equal(t,
		[]InclusionLists{f, fbb},
		selection.Matching(Name{Section: "foo.bar.baz"}))
	assert.Equal(t,
		[]InclusionLists{f, fbt},
		selection.Matching(Name{Section: "foo.bar.traca"}))
	assert.Equal(t,
		[]InclusionLists{pp},
		selection.Matching(Name{Section: "pim.pam"}))
	assert.Empty(t, selection.Matching(Name{Section: "pam.pum"}))
}

func TestSelectorMatch_NotNormalizedSections(t *testing.T) {
	ga := InclusionLists{Include: []string{"gen_ai"}}
	jt := InclusionLists{Include: []string{"jvm_thread"}}
	selection := Selection{
		"gen_ai.*":     ga,
		"jvm.thread.*": jt,
	}
	selection.Normalize()
	assert.Equal(t,
		[]InclusionLists{ga},
		selection.Matching(GenAIClientOperationDuration))
	assert.Equal(t,
		[]InclusionLists{jt},
		selection.Matching(JVMThreadCount))
}

// every metric must be selectable by its name, in dot or underscore notation
func TestSelectorMatch_AllMetrics(t *testing.T) {
	il := InclusionLists{Include: []string{"foo"}}
	for section := range getDefinitions(0, NewGroupAttributes(nil)) {
		for _, key := range []Section{section, Section(asProm(string(section)))} {
			selection := Selection{key: il}
			selection.Normalize()
			assert.Equal(t, []InclusionLists{il}, selection.Matching(Name{Section: section}), "key %q", key)
		}
	}
}
