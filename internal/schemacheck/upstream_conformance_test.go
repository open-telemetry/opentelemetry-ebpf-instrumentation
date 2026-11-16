// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	upstreamNone   = "none"
	obiNamespace   = "obi"
	transportGroup = "attributes.obi.transport"

	levelRequired              = "required"
	levelConditionallyRequired = "conditionally_required"
	levelRecommended           = "recommended"
)

// upstreamLink names the upstream signals an OBI signal implements: one id, a
// list of ids, or `none`. The first id is the signal OBI implements; any
// further id is a convention whose attributes the signal also carries.
type upstreamLink []string

func (l *upstreamLink) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*l = upstreamLink{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*l = many
	return nil
}

func (l *upstreamLink) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*l = upstreamLink{n.Value}
		return nil
	}
	var many []string
	if err := n.Decode(&many); err != nil {
		return err
	}
	*l = many
	return nil
}

func (l upstreamLink) none() bool {
	return len(l) == 1 && l[0] == upstreamNone
}

func namespaceOf(key string) string {
	ns, _, _ := strings.Cut(key, ".")
	return ns
}

func requirementLevel(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var level string
	if json.Unmarshal(raw, &level) == nil {
		return level
	}
	var conditional map[string]json.RawMessage
	require.NoErrorf(t, json.Unmarshal(raw, &conditional), "requirement level %s", raw)
	for level := range conditional {
		return level
	}
	return ""
}

func mandatory(level string) bool {
	return level == levelRequired || level == levelConditionallyRequired
}

// meets reports whether OBI's level keeps upstream's requirement: a required
// attribute must stay required, and a conditionally required one must stay
// mandatory.
func meets(obiLevel, upstreamLevel string) bool {
	if upstreamLevel == levelRequired {
		return obiLevel == levelRequired
	}
	return mandatory(obiLevel)
}

type upstreamRegistry struct {
	spans      map[string]resolvedSignal
	metrics    map[string]resolvedSignal
	attributes map[string]resolvedAttribute
	renamed    map[string]string
	namespaces map[string]bool
}

var registryPathRE = regexp.MustCompile(`^(.+)\[(.+)\]$`)

// pinnedUpstreamModel returns the model directory of the upstream registry the
// manifest depends on, relative to the registry.
func pinnedUpstreamModel(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(registryDir, "manifest.yaml"))
	require.NoError(t, err)
	var manifest struct {
		Dependencies []struct {
			RegistryPath string `yaml:"registry_path"`
		} `yaml:"dependencies"`
	}
	require.NoError(t, yaml.Unmarshal(body, &manifest))
	require.Len(t, manifest.Dependencies, 1, "the manifest should depend on one upstream registry")
	m := registryPathRE.FindStringSubmatch(manifest.Dependencies[0].RegistryPath)
	require.Lenf(t, m, 3, "registry_path %q does not name a local model directory", manifest.Dependencies[0].RegistryPath)
	return filepath.Join(m[1], m[2])
}

func resolveUpstreamRegistry(t *testing.T) upstreamRegistry {
	t.Helper()
	model := pinnedUpstreamModel(t)
	res := resolveRegistryAt(t, "/obi-registry/"+filepath.ToSlash(model))

	reg := upstreamRegistry{
		spans:      map[string]resolvedSignal{},
		metrics:    map[string]resolvedSignal{},
		attributes: map[string]resolvedAttribute{},
		renamed:    map[string]string{},
		namespaces: map[string]bool{},
	}
	for _, a := range res.Registry.Attributes {
		reg.attributes[a.Key] = a
		reg.namespaces[namespaceOf(a.Key)] = true
		if a.Deprecated != nil && a.Deprecated.RenamedTo != "" {
			reg.renamed[a.Key] = a.Deprecated.RenamedTo
		}
	}
	for _, s := range res.Registry.Spans {
		reg.spans[s.Type] = s
	}
	for _, s := range res.Refinements.Spans {
		if _, ok := reg.spans[s.ID]; !ok {
			reg.spans[s.ID] = s
		}
	}
	for _, m := range res.Registry.Metrics {
		reg.metrics[m.metricName(t)] = m
	}
	for id, g := range upstreamAttributeGroups(t, filepath.Join(registryDir, model)) {
		if _, ok := reg.spans[id]; !ok {
			reg.spans[id] = g
		}
	}
	return reg
}

type upstreamGroupsFile struct {
	Groups []struct {
		ID         string `yaml:"id"`
		Type       string `yaml:"type"`
		Extends    string `yaml:"extends"`
		Attributes []struct {
			Ref              string    `yaml:"ref"`
			RequirementLevel yaml.Node `yaml:"requirement_level"`
		} `yaml:"attributes"`
	} `yaml:"groups"`
}

type upstreamGroup struct {
	extends string
	levels  map[string]string
}

// upstreamAttributeGroups returns the attribute groups of the upstream model
// with their `extends` chain applied. Some conventions, such as the messaging
// ones in semconv v1.41.0, are defined only as attribute groups, which weaver
// drops from the resolved registry, so they are read from the model files.
func upstreamAttributeGroups(t *testing.T, model string) map[string]resolvedSignal {
	t.Helper()
	groups := map[string]upstreamGroup{}
	require.NoError(t, filepath.WalkDir(model, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yaml" {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var f upstreamGroupsFile
		if err := yaml.Unmarshal(body, &f); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		for _, g := range f.Groups {
			if g.Type != "attribute_group" {
				continue
			}
			group := upstreamGroup{extends: g.Extends, levels: map[string]string{}}
			for _, a := range g.Attributes {
				if a.Ref != "" {
					group.levels[a.Ref] = levelWord(a.RequirementLevel)
				}
			}
			groups[g.ID] = group
		}
		return nil
	}))

	out := map[string]resolvedSignal{}
	for id := range groups {
		levels := map[string]string{}
		require.NoError(t, applyUpstreamGroup(groups, id, levels, map[string]bool{}))
		var signal resolvedSignal
		signal.ID = id
		for _, key := range slices.Sorted(maps.Keys(levels)) {
			level, err := json.Marshal(cmp.Or(levels[key], levelRecommended))
			require.NoError(t, err)
			signal.Attributes = append(signal.Attributes, resolvedAttribute{Key: key, RequirementLevel: level})
		}
		out[id] = signal
	}
	return out
}

// applyUpstreamGroup writes a group's attribute levels over those of the group
// it extends. A group that references an attribute without a level keeps the
// level it inherits, as weaver does; one no group in the chain sets defaults
// to recommended.
func applyUpstreamGroup(groups map[string]upstreamGroup, id string, levels map[string]string, seen map[string]bool) error {
	g, ok := groups[id]
	if !ok {
		return nil
	}
	if seen[id] {
		return fmt.Errorf("upstream attribute group %s extends itself", id)
	}
	seen[id] = true
	if g.extends != "" {
		if err := applyUpstreamGroup(groups, g.extends, levels, seen); err != nil {
			return err
		}
	}
	for key, level := range g.levels {
		if _, inherited := levels[key]; level != "" || !inherited {
			levels[key] = level
		}
	}
	return nil
}

func (reg upstreamRegistry) key(attribute string) string {
	if renamed, ok := reg.renamed[attribute]; ok {
		return renamed
	}
	return attribute
}

// localSignal is a span or metric this registry defines, with the upstream
// signals its link names.
type localSignal struct {
	label    string
	span     bool
	signal   resolvedSignal
	known    map[string]resolvedSignal
	selfLink bool
	relinked bool
}

func localSignals(t *testing.T, obi resolveOutput, up upstreamRegistry) []localSignal {
	t.Helper()
	var out []localSignal
	for _, s := range obi.Registry.Spans {
		if s.Provenance.local() {
			out = append(out, localSignal{s.Type, true, s, up.spans, false, false})
		}
	}
	for _, m := range obi.Registry.Metrics {
		name := m.metricName(t)
		if !m.Provenance.local() {
			continue
		}
		link := m.Annotations.OBI.Upstream
		if namespaceOf(name) == obiNamespace && len(link) == 0 {
			continue
		}
		selfLink := slices.Contains(link, name)
		_, upstreamName := up.metrics[name]
		relinked := upstreamName && len(link) > 0 && !link.none() && !selfLink
		if upstreamName && len(link) == 0 {
			m.Annotations.OBI.Upstream = upstreamLink{name}
		}
		out = append(out, localSignal{name, false, m, up.metrics, selfLink, relinked})
	}
	return out
}

// TestEverySignalNamesItsUpstreamSignal asserts that every span and every
// metric outside the obi namespace names, in annotations.obi.upstream, the
// upstream signals it implements, or `none` with an upstream_reason, and that
// every named signal exists in the pinned upstream registry. A metric whose
// name is an upstream metric implements it without an annotation.
func TestEverySignalNamesItsUpstreamSignal(t *testing.T) {
	obi := resolveRegistry(t)
	up := resolveUpstreamRegistry(t)

	var problems []string
	for _, s := range localSignals(t, obi, up) {
		problems = append(problems, linkProblems(s)...)
	}
	slices.Sort(problems)
	assert.Emptyf(t, problems, "every span and metric must name the upstream signals it implements:\n%s",
		strings.Join(problems, "\n"))
}

func linkProblems(s localSignal) []string {
	annotations := s.signal.Annotations.OBI
	link := annotations.Upstream
	switch {
	case s.selfLink:
		return []string{s.label + ": names itself in upstream; a metric with an upstream name implements it without an annotation"}
	case s.relinked:
		return []string{s.label + ": is declared under an upstream metric's name but links another signal; drop the annotation"}
	case len(link) == 0 && !s.span:
		return []string{s.label + ": is not an upstream metric; set upstream: none with an upstream_reason"}
	case len(link) == 0:
		return []string{s.label + ": names no upstream signal"}
	case link.none() && annotations.UpstreamReason == "":
		return []string{s.label + ": upstream is none without an upstream_reason"}
	case link.none() && len(annotations.UpstreamOmits) > 0:
		return []string{s.label + ": upstream_omits on a signal that names no upstream signal"}
	case link.none() && len(annotations.UpstreamRelaxes) > 0:
		return []string{s.label + ": upstream_relaxes on a signal that names no upstream signal"}
	case link.none() && len(annotations.UpstreamExtras) > 0:
		return []string{s.label + ": upstream_extras on a signal that names no upstream signal"}
	case link.none():
		return nil
	case annotations.UpstreamReason != "":
		return []string{s.label + ": upstream_reason on a signal that names an upstream signal"}
	}
	var problems []string
	for _, id := range link {
		if _, ok := s.known[id]; !ok {
			problems = append(problems, fmt.Sprintf("%s: upstream signal %q does not exist upstream", s.label, id))
		}
	}
	return problems
}

// transportAttributes returns the attributes of the transport group, which any
// span may carry with the group's reason.
func transportAttributes(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range registryFiles(t) {
		for _, g := range f.AttributeGroups {
			if g.ID != transportGroup {
				continue
			}
			for _, a := range g.Attributes {
				require.NotEmptyf(t, a.Annotations.OBI.UpstreamDeviation, "%s references %s without a reason", transportGroup, a.Ref)
				out[a.Ref] = true
			}
		}
	}
	require.NotEmptyf(t, out, "%s is not defined", transportGroup)
	return out
}

// upstreamLevels returns the requirement level of every attribute the linked
// upstream signals list. A signal listed earlier wins, so the signal OBI
// implements keeps the levels it sets for an attribute a broader convention
// also lists; Elasticsearch, for one, relaxes the database client's
// conditionally required `db.namespace` to recommended.
func upstreamLevels(t *testing.T, s localSignal, up upstreamRegistry) map[string]string {
	t.Helper()
	levels := map[string]string{}
	for _, id := range s.signal.Annotations.OBI.Upstream {
		for _, a := range s.known[id].Attributes {
			if _, ok := levels[up.key(a.Key)]; !ok {
				levels[up.key(a.Key)] = requirementLevel(t, a.RequirementLevel)
			}
		}
	}
	return levels
}

func conformanceProblems(t *testing.T, s localSignal, up upstreamRegistry, transport map[string]bool) []string {
	t.Helper()
	link := s.signal.Annotations.OBI.Upstream
	if len(link) == 0 || link.none() {
		return nil
	}
	omits := s.signal.Annotations.OBI.UpstreamOmits
	relaxes := s.signal.Annotations.OBI.UpstreamRelaxes
	extras := s.signal.Annotations.OBI.UpstreamExtras

	declared := map[string]string{}
	for _, a := range s.signal.Attributes {
		declared[a.Key] = requirementLevel(t, a.RequirementLevel)
	}
	levels := upstreamLevels(t, s, up)

	var problems []string
	report := func(attribute, problem string) {
		problems = append(problems, fmt.Sprintf("%s (upstream %s): %s: %s", s.label, link[0], attribute, problem))
	}
	for key, level := range levels {
		obiLevel, ok := declared[key]
		switch {
		case !mandatory(level), ok && meets(obiLevel, level):
		case !ok && omits[key] != "", ok && relaxes[key] != "":
		case !ok:
			report(key, "upstream makes it "+level+", OBI does not declare it")
		default:
			report(key, "upstream makes it "+level+", OBI declares it "+obiLevel)
		}
	}
	for key := range omits {
		if _, ok := declared[key]; !mandatory(levels[key]) || ok {
			report(key, "upstream_omits names an attribute upstream does not require or OBI declares")
		}
	}
	for key := range relaxes {
		if obiLevel, ok := declared[key]; !mandatory(levels[key]) || !ok || meets(obiLevel, levels[key]) {
			report(key, "upstream_relaxes names an attribute OBI does not declare below upstream's level")
		}
	}
	unlisted := func(key string) bool {
		_, isDeclared := declared[key]
		_, upstream := up.attributes[key]
		_, listed := levels[key]
		if !isDeclared || !upstream || listed || namespaceOf(key) == obiNamespace {
			return false
		}
		return !s.span || !transport[key]
	}
	for key := range declared {
		if unlisted(key) && extras[key] == "" {
			report(key, "an upstream attribute that no linked upstream signal lists")
		}
	}
	for key := range extras {
		if !unlisted(key) {
			report(key, "upstream_extras names an attribute that needs no reason or OBI does not declare")
		}
	}
	return problems
}

// TestSignalsConformToUpstream compares every linked span and metric with the
// upstream signals it names. It fails when OBI does not declare, or declares
// at a lower level, an attribute the named signals require or conditionally
// require (a required attribute declared conditionally required counts),
// unless the signal's upstream_omits or upstream_relaxes gives a reason; and
// when OBI
// declares an upstream attribute that none of the named signals lists, unless
// it is a transport attribute on a span or the signal's upstream_extras gives
// a reason.
func TestSignalsConformToUpstream(t *testing.T) {
	obi := resolveRegistry(t)
	up := resolveUpstreamRegistry(t)
	transport := transportAttributes(t)

	var problems []string
	for _, s := range localSignals(t, obi, up) {
		problems = append(problems, conformanceProblems(t, s, up, transport)...)
	}
	slices.Sort(problems)
	assert.Emptyf(t, problems, "signals diverge from the upstream signals they implement:\n%s",
		strings.Join(problems, "\n"))
}

type attributeType struct {
	primitive string
	members   map[string]enumMember
}

type enumMember struct {
	ID        string `json:"id"`
	Value     any    `json:"value"`
	Stability string `json:"stability"`
}

func parseAttributeType(t *testing.T, raw json.RawMessage) attributeType {
	t.Helper()
	var primitive string
	if json.Unmarshal(raw, &primitive) == nil {
		return attributeType{primitive: primitive}
	}
	var enum struct {
		Members []enumMember `json:"members"`
	}
	require.NoErrorf(t, json.Unmarshal(raw, &enum), "attribute type %s", raw)
	members := map[string]enumMember{}
	for _, m := range enum.Members {
		members[fmt.Sprint(m.Value)] = m
	}
	return attributeType{members: members}
}

func overrideProblems(t *testing.T, obi, upstream resolvedAttribute) []string {
	t.Helper()
	obiType := parseAttributeType(t, obi.Type)
	upType := parseAttributeType(t, upstream.Type)
	reason := obi.Annotations.OBI.UpstreamDeviation

	retyped := upType.members != nil && obiType.members == nil

	var problems []string
	switch {
	case retyped && reason == "":
		problems = append(problems, "retypes the upstream enum as "+obiType.primitive+" without an upstream_deviation reason")
	case !retyped && reason != "":
		problems = append(problems, "upstream_deviation on a definition that keeps the upstream type")
	}
	switch {
	case retyped:
	case upType.primitive != obiType.primitive:
		problems = append(problems, fmt.Sprintf("type %q differs from upstream %q", obiType.primitive, upType.primitive))
	case upType.members != nil:
		for value, m := range upType.members {
			if got, ok := obiType.members[value]; !ok || got.ID != m.ID || got.Stability != m.Stability {
				problems = append(problems, fmt.Sprintf("does not carry upstream member %q as upstream declares it", value))
			}
		}
	}
	if strings.Join(strings.Fields(obi.Brief), " ") != strings.Join(strings.Fields(upstream.Brief), " ") {
		problems = append(problems, "brief differs from upstream")
	}
	if obi.Stability != upstream.Stability {
		problems = append(problems, fmt.Sprintf("stability %q differs from upstream %q", obi.Stability, upstream.Stability))
	}
	return problems
}

// TestAttributeDefinitionsConformToUpstream checks every attribute this
// registry defines. A definition of an upstream key must keep the upstream
// type, brief and stability and every upstream enum member, and may only add members or
// retype an enum as a primitive with a reason. A new attribute outside the obi
// namespace, in a namespace upstream owns, must give a reason.
func TestAttributeDefinitionsConformToUpstream(t *testing.T) {
	obi := resolveRegistry(t)
	up := resolveUpstreamRegistry(t)

	var problems []string
	for _, a := range obi.Registry.Attributes {
		if !a.Provenance.local() {
			continue
		}
		upstream, ok := up.attributes[a.Key]
		if ok {
			for _, p := range overrideProblems(t, a, upstream) {
				problems = append(problems, a.Key+": "+p)
			}
			continue
		}
		ns := namespaceOf(a.Key)
		if ns == a.Key || ns == obiNamespace || !up.namespaces[ns] {
			continue
		}
		if a.Annotations.OBI.UpstreamDeviation == "" {
			problems = append(problems, fmt.Sprintf("%s: defined in the upstream %s namespace without an upstream_deviation reason", a.Key, ns))
		}
	}
	slices.Sort(problems)
	assert.Emptyf(t, problems, "attribute definitions diverge from upstream:\n%s", strings.Join(problems, "\n"))
}
