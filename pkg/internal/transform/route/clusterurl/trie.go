// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clusterurl

import (
	"strings"
	"sync"
)

// PathNode represents a node in the path trie
type PathNode struct {
	// segment is the path component (e.g., "test", "files")
	segment string

	// children maps segment values to their nodes
	// e.g., children["bar-attach-generic-product-apjkmyp"] = &PathNode{...}
	children map[string]*PathNode

	// collapsed indicates if this node has been collapsed to "*"
	collapsed bool

	// cardinality tracks how many unique children this node has
	cardinality int

	// isWildcard indicates if this represents a "*" wildcard
	isWildcard bool
}

// PathTrie manages the dynamic collapsing trie structure
type PathTrie struct {
	root           *PathNode
	maxCardinality int
	mu             sync.RWMutex
}

// NewPathTrie creates a new path trie with the given max cardinality
func NewPathTrie(maxCardinality int) *PathTrie {
	return &PathTrie{
		root: &PathNode{
			segment:  "",
			children: make(map[string]*PathNode),
		},
		maxCardinality: maxCardinality,
	}
}

// Insert adds a path to the trie and returns the normalized path
// If a segment exceeds maxCardinality, it collapses to "*"
func (pt *PathTrie) Insert(path string) string {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) == 0 || (len(segments) == 1 && segments[0] == "") {
		return path
	}

	return pt.insertSegments(segments)
}

func (pt *PathTrie) insertSegments(segments []string) string {
	current := pt.root
	result := make([]string, 0, len(segments))

	for _, segment := range segments {
		if segment == "" {
			result = append(result, segment)
			continue
		}

		// If current node is already collapsed, all children become wildcards
		if current.collapsed {
			result = append(result, "*")
			// Continue with the wildcard child
			if current.children["*"] == nil {
				current.children["*"] = &PathNode{
					segment:    "*",
					children:   make(map[string]*PathNode),
					isWildcard: true,
				}
			}
			current = current.children["*"]
			continue
		}

		// Check if this segment already exists
		child, exists := current.children[segment]

		if !exists {
			// New segment - check if we need to collapse
			if current.cardinality >= pt.maxCardinality {
				// Collapse this level
				pt.collapseNode(current)
				result = append(result, "*")
				current = current.children["*"]
				continue
			}

			// Create new child
			child = &PathNode{
				segment:  segment,
				children: make(map[string]*PathNode),
			}
			current.children[segment] = child
			current.cardinality++

			// Check if we just hit the threshold
			if current.cardinality > pt.maxCardinality {
				pt.collapseNode(current)
				result = append(result, "*")
				current = current.children["*"]
				continue
			}
		}

		result = append(result, segment)
		current = child
	}

	return "/" + strings.Join(result, "/")
}

// collapseNode collapses a node by replacing all children with a single wildcard
// and merging their children into the wildcard node
func (pt *PathTrie) collapseNode(node *PathNode) {
	if node.collapsed {
		return
	}

	node.collapsed = true

	// Create or get wildcard node
	wildcardNode, hasWildcard := node.children["*"]
	if !hasWildcard {
		wildcardNode = &PathNode{
			segment:    "*",
			children:   make(map[string]*PathNode),
			isWildcard: true,
		}
	}

	// Merge all children into the wildcard node
	for segment, child := range node.children {
		if segment == "*" {
			continue // Skip the wildcard itself
		}
		pt.mergeChildren(wildcardNode, child)
	}

	// Replace all children with just the wildcard
	node.children = map[string]*PathNode{
		"*": wildcardNode,
	}
	node.cardinality = 1

	// Recursively check if wildcard node needs collapsing
	if wildcardNode.cardinality > pt.maxCardinality {
		pt.collapseNode(wildcardNode)
	}
}

// mergeChildren merges children from source into target
// This is called during collapse to combine all child paths
func (pt *PathTrie) mergeChildren(target, source *PathNode) {
	for segment, child := range source.children {
		if existing, exists := target.children[segment]; exists {
			// Child already exists, recursively merge their children
			pt.mergeChildren(existing, child)
		} else {
			// New child, add it
			target.children[segment] = child
			if segment == "*" {
				target.cardinality = pt.maxCardinality
			}
			target.cardinality++
		}
	}
}

// Lookup returns the normalized path for a given input path
// This is used to query existing paths without modifying the trie
func (pt *PathTrie) Lookup(path string) string {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) == 0 || (len(segments) == 1 && segments[0] == "") {
		return path
	}

	return pt.lookupSegments(segments)
}

func (pt *PathTrie) lookupSegments(segments []string) string {
	current := pt.root
	result := make([]string, 0, len(segments))

	for _, segment := range segments {
		if segment == "" {
			result = append(result, segment)
			continue
		}

		// If node is collapsed, use wildcard
		if current.collapsed {
			result = append(result, "*")
			current = current.children["*"]
			continue
		}

		// Try to find exact match
		child, exists := current.children[segment]
		if !exists {
			// No exact match, check for wildcard
			if wildcardChild, hasWildcard := current.children["*"]; hasWildcard {
				result = append(result, "*")
				current = wildcardChild
				continue
			}
			// Not found at all, return segment as-is and stop traversing
			result = append(result, segment)
			// Can't traverse further, append remaining segments
			result = append(result, segments[len(result):]...)
			break
		}

		result = append(result, segment)
		current = child
	}

	return "/" + strings.Join(result, "/")
}
