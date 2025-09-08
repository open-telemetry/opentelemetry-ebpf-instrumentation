// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package route

import "strings"

// Matcher allows matching a given URL path towards a set of framework-like provided
// patterns.
type PartialRouteMatcher struct {
	roots           []*node
	hasAbsoluteRoot bool
}

// NewMatcher creates a new Matcher that would allow validating given URL paths towards
// the provided set of routes
func NewPartialRouteMatcher(routes []string) *PartialRouteMatcher {
	m := PartialRouteMatcher{roots: []*node{}}
	for _, route := range routes {
		if route == "/" {
			m.hasAbsoluteRoot = true
			continue
		}
		n := &node{Child: map[string]*node{}}
		m.roots = append(m.roots, n)
		appendRoute(route, tokenize(route), n)
	}
	return &m
}

// Find the router pattern that would match a given URL path, or empty if no pattern
// matches it. Uses partial matching across multiple root trees.
func (rm *PartialRouteMatcher) Find(path string) string {
	if path == "/" && rm.hasAbsoluteRoot {
		return path
	}

	tokens := tokenize(path)
	return rm.findCombined(tokens, 0, []string{})
}

// findCombined tries to match the full path using combinations of partial matches from different roots
func (rm *PartialRouteMatcher) findCombined(tokens []string, startIdx int, matchedParts []string) string {
	// If we've consumed all tokens, we found a complete match
	if startIdx >= len(tokens) {
		if len(matchedParts) > 0 {
			return strings.Join(matchedParts, "")
		}
		return ""
	}

	// Try each root tree for partial matching from current position
	for _, root := range rm.roots {
		if partialMatch, consumed := rm.findPartial(tokens[startIdx:], root); partialMatch != "" && consumed > 0 {
			// Found a partial match, try to match the rest
			newMatchedParts := append(matchedParts, partialMatch)
			if result := rm.findCombined(tokens, startIdx+consumed, newMatchedParts); result != "" {
				return result
			}
		}
	}

	return ""
}

// findPartial attempts to match as many tokens as possible from a single root, returns the matched route and tokens consumed
func (rm *PartialRouteMatcher) findPartial(tokens []string, root *node) (string, int) {
	return rm.findPartialRecursive(tokens, root, 0)
}

func (rm *PartialRouteMatcher) findPartialRecursive(tokens []string, node *node, consumed int) (string, int) {
	// If we have a valid route at this point, it's a potential partial match
	if node.FullRoute != "" {
		// Return this match and how many tokens we consumed
		return node.FullRoute, consumed
	}

	// If no more tokens to consume, return empty
	if consumed >= len(tokens) {
		return "", 0
	}

	currentToken := tokens[consumed]

	// Try exact match first
	if child, ok := node.Child[currentToken]; ok {
		return rm.findPartialRecursive(tokens, child, consumed+1)
	}

	// Try wildcard match
	if node.Wildcard != nil {
		return rm.findPartialRecursive(tokens, node.Wildcard, consumed+1)
	}

	// No match found
	return "", 0
}
