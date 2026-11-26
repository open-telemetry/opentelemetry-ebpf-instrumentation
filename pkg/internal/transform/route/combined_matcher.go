// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package route

// CombinedRouteMatcher matches complete routes before attempting
// to combine partial routes.
type CombinedRouteMatcher struct {
	complete *CompleteRouteMatcher
	partial  *PartialRouteMatcher
}

// NewCombinedRouteMatcher creates a matcher for complete and partial routes.
func NewCombinedRouteMatcher(complete, partial []string) *CombinedRouteMatcher {
	m := &CombinedRouteMatcher{}

	if len(complete) > 0 {
		m.complete = NewMatcher(complete)
	}

	if len(partial) > 0 {
		m.partial = NewPartialRouteMatcher(partial)
	}

	return m
}

// Find tokenizes the incoming path once and reuses the tokens.
func (m *CombinedRouteMatcher) Find(path string) string {
	if m == nil || (m.complete == nil && m.partial == nil) {
		return ""
	}

	tokens := tokenize(path)

	// Complete routes take precedence over partial routes.
	if m.complete != nil {
		if found := find(tokens, m.complete.root); found != "" {
			return found
		}
	}

	if m.partial != nil {
		return m.partial.findTokens(path, tokens)
	}

	return ""
}
