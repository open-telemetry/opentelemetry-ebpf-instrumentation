// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func attributesAt(levels map[string]string) []resolvedAttribute {
	var out []resolvedAttribute
	for key, level := range levels {
		out = append(out, resolvedAttribute{Key: key, RequirementLevel: json.RawMessage(strconv.Quote(level))})
	}
	return out
}

func testSignal(link upstreamLink, omits, declared map[string]string) resolvedSignal {
	var s resolvedSignal
	s.Annotations.OBI.Upstream = link
	s.Annotations.OBI.UpstreamOmits = omits
	s.Attributes = attributesAt(declared)
	return s
}

// findingAttributes returns the attribute each finding names, sorted.
func findingAttributes(findings []string) []string {
	var out []string
	for _, f := range findings {
		parts := strings.SplitN(f, ": ", 3)
		out = append(out, parts[1])
	}
	slices.Sort(out)
	return out
}

func TestConformanceProblems(t *testing.T) {
	up := upstreamRegistry{
		spans: map[string]resolvedSignal{
			"db.specific.client": {Attributes: attributesAt(map[string]string{
				"db.namespace": levelRecommended,
				"db.query":     levelRequired,
			})},
			"db.client": {Attributes: attributesAt(map[string]string{
				"db.namespace":   levelConditionallyRequired,
				"db.system.name": levelRequired,
			})},
		},
		attributes: map[string]resolvedAttribute{
			"db.namespace": {}, "db.query": {}, "db.system.name": {},
			"http.route": {}, "network.peer.address": {},
		},
	}
	transport := map[string]bool{"network.peer.address": true}
	link := upstreamLink{"db.specific.client", "db.client"}
	complete := map[string]string{"db.query": levelRequired, "db.system.name": levelRequired}

	with := func(extra map[string]string) map[string]string {
		out := maps.Clone(complete)
		maps.Copy(out, extra)
		return out
	}

	tests := []struct {
		name     string
		span     bool
		omits    map[string]string
		relaxes  map[string]string
		extras   map[string]string
		declared map[string]string
		want     []string
	}{
		{name: "conforms; the first link relaxes db.namespace", span: true, declared: complete},
		{
			name: "a requirement of the first link is missing", span: true,
			declared: map[string]string{"db.system.name": levelRequired}, want: []string{"db.query"},
		},
		{
			name: "a requirement only a later link lists is missing", span: true,
			declared: map[string]string{"db.query": levelRequired}, want: []string{"db.system.name"},
		},
		{
			name: "a requirement is declared optional", span: true,
			declared: with(map[string]string{"db.query": levelRecommended}), want: []string{"db.query"},
		},
		{
			name: "a requirement is declared conditionally required", span: true,
			declared: with(map[string]string{"db.query": levelConditionallyRequired}), want: []string{"db.query"},
		},
		{
			name: "upstream_omits waives a missing requirement", span: true,
			omits:    map[string]string{"db.query": "reason"},
			declared: map[string]string{"db.system.name": levelRequired},
		},
		{
			name: "upstream_omits on an attribute upstream does not require", span: true,
			omits: map[string]string{"db.namespace": "reason"}, declared: complete, want: []string{"db.namespace"},
		},
		{
			name: "upstream_omits on an attribute OBI declares", span: true,
			omits:    map[string]string{"db.query": "reason"},
			declared: with(map[string]string{"db.query": levelRecommended}), want: []string{"db.query", "db.query"},
		},
		{
			name: "upstream_relaxes waives a requirement declared optional", span: true,
			relaxes:  map[string]string{"db.query": "reason"},
			declared: with(map[string]string{"db.query": levelRecommended}),
		},
		{
			name: "upstream_relaxes waives a requirement declared conditionally required", span: true,
			relaxes:  map[string]string{"db.query": "reason"},
			declared: with(map[string]string{"db.query": levelConditionallyRequired}),
		},
		{
			name: "upstream_relaxes on an attribute OBI does not declare", span: true,
			relaxes:  map[string]string{"db.query": "reason"},
			declared: map[string]string{"db.system.name": levelRequired}, want: []string{"db.query", "db.query"},
		},
		{
			name: "upstream_relaxes on an attribute OBI declares at upstream's level", span: true,
			relaxes: map[string]string{"db.query": "reason"}, declared: complete, want: []string{"db.query"},
		},
		{
			name: "upstream_relaxes on an attribute upstream does not require", span: true,
			relaxes:  map[string]string{"db.namespace": "reason"},
			declared: with(map[string]string{"db.namespace": levelRecommended}), want: []string{"db.namespace"},
		},
		{
			name: "an upstream attribute no link lists", span: true,
			declared: with(map[string]string{"http.route": levelRecommended}), want: []string{"http.route"},
		},
		{
			name: "OBI's own and unknown attributes are additions", span: true,
			declared: with(map[string]string{"obi.extra": levelRecommended, "custom.key": levelRecommended}),
		},
		{
			name: "a transport attribute on a span", span: true,
			declared: with(map[string]string{"network.peer.address": levelRecommended}),
		},
		{
			name: "a transport attribute on a metric", span: false,
			declared: with(map[string]string{"network.peer.address": levelRecommended}), want: []string{"network.peer.address"},
		},
		{
			name: "upstream_extras justifies an unlisted attribute", span: true,
			extras:   map[string]string{"http.route": "reason"},
			declared: with(map[string]string{"http.route": levelRecommended}),
		},
		{
			name: "upstream_extras on a listed attribute", span: true,
			extras:   map[string]string{"db.namespace": "reason"},
			declared: with(map[string]string{"db.namespace": levelRecommended}), want: []string{"db.namespace"},
		},
		{
			name: "upstream_extras on an attribute OBI does not declare", span: true,
			extras: map[string]string{"http.route": "reason"}, declared: complete, want: []string{"http.route"},
		},
		{
			name: "upstream_extras on a transport attribute of a span", span: true,
			extras:   map[string]string{"network.peer.address": "reason"},
			declared: with(map[string]string{"network.peer.address": levelRecommended}), want: []string{"network.peer.address"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signal := testSignal(link, tc.omits, tc.declared)
			signal.Annotations.OBI.UpstreamRelaxes = tc.relaxes
			signal.Annotations.OBI.UpstreamExtras = tc.extras
			s := localSignal{label: "obi.test", span: tc.span, signal: signal, known: up.spans}
			assert.Equal(t, tc.want, findingAttributes(conformanceProblems(t, s, up, transport)))
		})
	}
}

func TestLinkProblems(t *testing.T) {
	known := map[string]resolvedSignal{"http.client": {}}
	tests := []struct {
		name     string
		link     upstreamLink
		reason   string
		omits    map[string]string
		relaxes  map[string]string
		extras   map[string]string
		metric   bool
		selfLink bool
		relinked bool
		want     string
	}{
		{name: "an existing link", link: upstreamLink{"http.client"}},
		{name: "none with a reason", link: upstreamLink{upstreamNone}, reason: "reason"},
		{name: "no link", want: "names no upstream signal"},
		{name: "a metric with no link and no upstream name", metric: true, want: "is not an upstream metric"},
		{name: "a metric naming itself", link: upstreamLink{"http.client"}, metric: true, selfLink: true, want: "names itself in upstream"},
		{name: "a metric under an upstream name linking another", link: upstreamLink{"http.client"}, metric: true, relinked: true, want: "links another signal"},
		{name: "none without a reason", link: upstreamLink{upstreamNone}, want: "without an upstream_reason"},
		{
			name: "none with upstream_omits", link: upstreamLink{upstreamNone}, reason: "reason",
			omits: map[string]string{"http.route": "reason"}, want: "upstream_omits on a signal that names no upstream signal",
		},
		{
			name: "none with upstream_relaxes", link: upstreamLink{upstreamNone}, reason: "reason",
			relaxes: map[string]string{"http.route": "reason"}, want: "upstream_relaxes on a signal that names no upstream signal",
		},
		{
			name: "none with upstream_extras", link: upstreamLink{upstreamNone}, reason: "reason",
			extras: map[string]string{"http.route": "reason"}, want: "upstream_extras on a signal that names no upstream signal",
		},
		{
			name: "a reason next to a link", link: upstreamLink{"http.client"}, reason: "reason",
			want: "upstream_reason on a signal that names an upstream signal",
		},
		{
			name: "a link upstream does not define", link: upstreamLink{"http.client", "http.missing"},
			want: `upstream signal "http.missing" does not exist upstream`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signal := testSignal(tc.link, tc.omits, nil)
			signal.Annotations.OBI.UpstreamReason = tc.reason
			signal.Annotations.OBI.UpstreamRelaxes = tc.relaxes
			signal.Annotations.OBI.UpstreamExtras = tc.extras
			problems := linkProblems(localSignal{label: "obi.test", span: !tc.metric, signal: signal, known: known, selfLink: tc.selfLink, relinked: tc.relinked})
			if tc.want == "" {
				assert.Empty(t, problems)
				return
			}
			require.Len(t, problems, 1)
			assert.Contains(t, problems[0], tc.want)
		})
	}
}

func TestOverrideProblems(t *testing.T) {
	enum := func(members string) json.RawMessage {
		return json.RawMessage(`{"members":[` + members + `]}`)
	}
	const (
		a       = `{"id":"a","value":"a","stability":"stable"}`
		b       = `{"id":"b","value":"b","stability":"development"}`
		extra   = `{"id":"x","value":"x","stability":"development"}`
		aUnstab = `{"id":"a","value":"a","stability":"development"}`
	)
	upstream := resolvedAttribute{Type: enum(a + "," + b), Brief: "The thing.", Stability: "stable"}
	override := func(typ json.RawMessage, reason string) resolvedAttribute {
		o := resolvedAttribute{Type: typ, Brief: "The  thing.", Stability: "stable"}
		o.Annotations.OBI.UpstreamDeviation = reason
		return o
	}
	tests := []struct {
		name     string
		obi      resolvedAttribute
		upstream resolvedAttribute
		want     []string
	}{
		{name: "adds a member", obi: override(enum(a+","+b+","+extra), ""), upstream: upstream},
		{name: "drops a member", obi: override(enum(a), ""), upstream: upstream, want: []string{`upstream member "b"`}},
		{name: "changes a member", obi: override(enum(aUnstab+","+b), ""), upstream: upstream, want: []string{`upstream member "a"`}},
		{name: "retypes an enum with a reason", obi: override(json.RawMessage(`"string"`), "reason"), upstream: upstream},
		{
			name: "retypes an enum without a reason", obi: override(json.RawMessage(`"string"`), ""), upstream: upstream,
			want: []string{"without an upstream_deviation reason"},
		},
		{
			name: "gives a reason without a retype", obi: override(enum(a+","+b), "reason"), upstream: upstream,
			want: []string{"keeps the upstream type"},
		},
		{
			name: "changes a primitive type", obi: override(json.RawMessage(`"int"`), ""),
			upstream: resolvedAttribute{Type: json.RawMessage(`"string"`), Brief: "The thing.", Stability: "stable"},
			want:     []string{`type "int" differs`},
		},
		{name: "changes the brief", obi: func() resolvedAttribute {
			o := override(enum(a+","+b), "")
			o.Brief = "Another thing."
			return o
		}(), upstream: upstream, want: []string{"brief differs"}},
		{name: "changes the stability", obi: func() resolvedAttribute {
			o := override(enum(a+","+b), "")
			o.Stability = "development"
			return o
		}(), upstream: upstream, want: []string{"stability"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			problems := overrideProblems(t, tc.obi, tc.upstream)
			require.Len(t, problems, len(tc.want), "%v", problems)
			for i, want := range tc.want {
				assert.Contains(t, problems[i], want)
			}
		})
	}
}

func TestApplyUpstreamGroup(t *testing.T) {
	groups := map[string]upstreamGroup{
		"base":  {levels: map[string]string{"a": levelRequired, "b": levelRequired, "c": levelConditionallyRequired}},
		"child": {extends: "base", levels: map[string]string{"b": levelRecommended, "c": "", "d": ""}},
		"loop1": {extends: "loop2"},
		"loop2": {extends: "loop1"},
	}

	levels := map[string]string{}
	require.NoError(t, applyUpstreamGroup(groups, "child", levels, map[string]bool{}))
	assert.Equal(t, map[string]string{"a": levelRequired, "b": levelRecommended, "c": levelConditionallyRequired, "d": ""}, levels)

	assert.ErrorContains(t, applyUpstreamGroup(groups, "loop1", map[string]string{}, map[string]bool{}), "extends itself")
}
