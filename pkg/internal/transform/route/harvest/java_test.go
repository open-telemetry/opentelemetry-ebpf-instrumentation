// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package harvest

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJavaRoutesHarvester(t *testing.T) {
	harvester := NewJavaRoutesHarvester()
	assert.NotNil(t, harvester)
	assert.NotNil(t, harvester.log)
}

func TestHasAlphanumeric(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "only special characters",
			input:    "!@#$%^&*()",
			expected: false,
		},
		{
			name:     "only spaces",
			input:    "   ",
			expected: false,
		},
		{
			name:     "has letters",
			input:    "abc",
			expected: true,
		},
		{
			name:     "has digits",
			input:    "123",
			expected: true,
		},
		{
			name:     "mixed with special chars",
			input:    "!@#abc123",
			expected: true,
		},
		{
			name:     "unicode letters",
			input:    "café",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasAlphanumeric(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeParams(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no curly braces",
			input:    "/api/users",
			expected: "/api/users",
		},
		{
			name:     "simple param",
			input:    "/api/users/{id}",
			expected: "/api/users/{id}",
		},
		{
			name:     "param with regex",
			input:    "/api/users/{id:\\d+}",
			expected: "/api/users/{id}",
		},
		{
			name:     "param with special chars",
			input:    "/api/users/{user-id_123}",
			expected: "/api/users/{user}",
		},
		{
			name:     "param starts with non-alphanumeric",
			input:    "/api/users/{_id}",
			expected: "/api/users/{_id}",
		},
		{
			name:     "multiple params",
			input:    "/api/{version}/users/{id:\\d+}",
			expected: "/api/{version}/users/{id}",
		},
		{
			name:     "empty braces",
			input:    "/api/users/{}",
			expected: "/api/users/{}",
		},
		{
			name:     "param with colon but no alphanumeric start",
			input:    "/api/users/{:pattern}",
			expected: "/api/users/{}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeParams(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJavaRoutes_parseAndAdd(t *testing.T) {
	harvester := NewJavaRoutesHarvester()

	tests := []struct {
		name        string
		accumulator []string
		line        string
		pos         int
		dLen        int
		expected    []string
	}{
		{
			name:        "valid route",
			accumulator: []string{"/existing"},
			line:        "17: /api/users",
			pos:         2,
			dLen:        3,
			expected:    []string{"/existing", "/api/users"},
		},
		{
			name:        "WEB-INF route should be filtered",
			accumulator: []string{"/existing"},
			line:        "17: /WEB-INF/classes",
			pos:         2,
			dLen:        3,
			expected:    []string{"/existing"},
		},
		{
			name:        "META-INF route should be filtered",
			accumulator: []string{"/existing"},
			line:        "17: /META-INF/resources",
			pos:         2,
			dLen:        3,
			expected:    []string{"/existing"},
		},
		{
			name:        "invalid URL characters",
			accumulator: []string{"/existing"},
			line:        "17: /api users",
			pos:         2,
			dLen:        3,
			expected:    []string{"/existing"},
		},
		{
			name:        "no alphanumeric characters",
			accumulator: []string{"/existing"},
			line:        "17: /!!!",
			pos:         2,
			dLen:        3,
			expected:    []string{"/existing"},
		},
		{
			name:        "pos beyond line length",
			accumulator: []string{"/existing"},
			line:        "17:",
			pos:         2,
			dLen:        5,
			expected:    []string{"/existing"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := harvester.parseAndAdd(tt.accumulator, tt.line, tt.pos, tt.dLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJavaRoutes_sortRoutes(t *testing.T) {
	harvester := NewJavaRoutesHarvester()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "single route",
			input:    []string{"/api"},
			expected: []string{"/api"},
		},
		{
			name:     "routes without params sorted by length",
			input:    []string{"/api", "/api/users/profile", "/api/users"},
			expected: []string{"/api/users/profile", "/api/users", "/api"},
		},
		{
			name:     "routes with params come last",
			input:    []string{"/api/{id}", "/api/users", "/api/users/{id}"},
			expected: []string{"/api/users", "/api/users/{id}", "/api/{id}"},
		},
		{
			name:     "params sorted by length within group",
			input:    []string{"/api/{id}", "/api/users/{id}/profile/{type}", "/api/users/{id}"},
			expected: []string{"/api/users/{id}/profile/{type}", "/api/users/{id}", "/api/{id}"},
		},
		{
			name:     "mixed routes",
			input:    []string{"/short", "/api/{id}", "/very/long/static/route", "/api/users/{id}"},
			expected: []string{"/very/long/static/route", "/short", "/api/users/{id}", "/api/{id}"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy since sortRoutes modifies in place
			input := make([]string, len(tt.input))
			copy(input, tt.input)

			result := harvester.sortRoutes(input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJavaRoutes_validLine(t *testing.T) {
	harvester := NewJavaRoutesHarvester()

	tests := []struct {
		name         string
		input        string
		expectedLine string
		expectedOk   bool
	}{
		{
			name:         "valid line",
			input:        "1 17: /api/users/{id}",
			expectedLine: "1 17: /api/users/{id}",
			expectedOk:   true,
		},
		{
			name:         "line with system symbol",
			input:        "17 65535: /system/internal",
			expectedLine: "",
			expectedOk:   false,
		},
		{
			name:         "line that sanitizes to empty",
			input:        "17: /api/users/{:}",
			expectedLine: "17: /api/users/{}",
			expectedOk:   true,
		},
		{
			name:         "line with regex params",
			input:        "17: /api/users/{id:\\d+}",
			expectedLine: "17: /api/users/{id}",
			expectedOk:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, ok := harvester.validLine(tt.input)
			assert.Equal(t, tt.expectedLine, line)
			assert.Equal(t, tt.expectedOk, ok)
		})
	}
}

func TestJavaRoutes_addRouteIfValid(t *testing.T) {
	harvester := NewJavaRoutesHarvester()

	tests := []struct {
		name     string
		line     string
		routes   []string
		expected []string
	}{
		{
			name:     "valid route line",
			line:     "17: /api/users",
			routes:   []string{"/existing"},
			expected: []string{"/existing", "/api/users"},
		},
		{
			name:     "line without delimiter",
			line:     "17 /api/users",
			routes:   []string{"/existing"},
			expected: []string{"/existing"},
		},
		{
			name:     "line with delimiter at end",
			line:     "17: /",
			routes:   []string{"/existing"},
			expected: []string{"/existing"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := harvester.addRouteIfValid(tt.line, tt.routes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJavaRoutes_ExtractRoutes(t *testing.T) {
	harvester := NewJavaRoutesHarvester()

	tests := []struct {
		name           string
		pid            int32
		mockOutput     string
		mockError      error
		expectedRoutes []string
		expectedKind   RouteHarvesterResultKind
		expectedError  bool
	}{
		{
			name: "successful extraction",
			pid:  1234,
			mockOutput: `Symbol table:
17: /api/users
25: /api/users/{id}
33: /health
44: /api/products/{id}/reviews
`,
			mockError:      nil,
			expectedRoutes: []string{"/api/users", "/health", "/api/products/{id}/reviews", "/api/users/{id}"},
			expectedKind:   PartialRoutes,
			expectedError:  false,
		},
		{
			name: "extraction with system symbols filtered",
			pid:  1234,
			mockOutput: `Symbol table:
17: /api/users
25 65535: /system/internal
33: /health
`,
			mockError:      nil,
			expectedRoutes: []string{"/api/users", "/health"},
			expectedKind:   PartialRoutes,
			expectedError:  false,
		},
		{
			name: "extraction with WEB-INF filtered",
			pid:  1234,
			mockOutput: `Symbol table:
17: /api/users
25: /WEB-INF/classes
33: /META-INF/resources
44: /health
`,
			mockError:      nil,
			expectedRoutes: []string{"/api/users", "/health"},
			expectedKind:   PartialRoutes,
			expectedError:  false,
		},
		{
			name:          "jattach error",
			pid:           1234,
			mockOutput:    "",
			mockError:     assert.AnError,
			expectedError: true,
		},
		{
			name: "no valid routes",
			pid:  1234,
			mockOutput: `Symbol table:
17 65535: /system/internal
25: /WEB-INF/classes
`,
			mockError:      nil,
			expectedRoutes: []string{},
			expectedKind:   PartialRoutes,
			expectedError:  false,
		},
	}

	// This test simulates the entire flow without mocking
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harvester.Attacher = FakeJavaAttacher{attachFunc: func(pid int, argv []string, _ bool) (io.ReadCloser, error) {
				assert.Equal(t, int(tt.pid), pid)
				assert.Equal(t, []string{"jcmd", "VM.symboltable -verbose"}, argv)

				if tt.mockError != nil {
					return nil, tt.mockError
				}

				return NewReaderCloser(strings.NewReader(tt.mockOutput)), nil
			}}

			result, err := harvester.ExtractRoutes(tt.pid)

			if tt.expectedError {
				require.Error(t, err)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.expectedKind, result.Kind)
				assert.Equal(t, tt.expectedRoutes, result.Routes)
			}
		})
	}
}

func TestJavaRoutes_ExtractRoutes_Integration(t *testing.T) {
	harvester := NewJavaRoutesHarvester()

	// This test simulates the entire flow without mocking
	harvester.Attacher = FakeJavaAttacher{attachFunc: func(_ int, _ []string, _ bool) (io.ReadCloser, error) {
		symbolTableOutput := `Symbol table:
Header: ...
17: /api/users
25: /api/users/{id:\\d+}
33: /health/live
44: /health/ready
55: /api/products
66: /api/products/{productId}/reviews/{reviewId}
77 65535: /system/metrics
88: /WEB-INF/classes
99: /META-INF/resources
110: /static/{filename}
`
		return NewReaderCloser(strings.NewReader(symbolTableOutput)), nil
	}}

	result, err := harvester.ExtractRoutes(1234)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, PartialRoutes, result.Kind)

	// Expected routes: sorted with non-param routes first (by length desc), then param routes (by length desc)
	expectedRoutes := []string{
		"/health/ready", // longest static
		"/api/products", // shorter static
		"/health/live",  // shorter static
		"/api/users",    // shortest static
		"/api/products/{productId}/reviews/{reviewId}", // longest with params
		"/static/{filename}",                           // with params
		"/api/users/{id}",                              // shortest with params
	}

	assert.Equal(t, expectedRoutes, result.Routes)
}

func TestRegexPatterns(t *testing.T) {
	t.Run("validURLPath regex", func(t *testing.T) {
		validPaths := []string{
			"/api/users",
			"/api/users_123",
			"/api/users-profile",
			"/api/{id}",
			"/api/users/profile.json",
			"/v1_2/api",
		}

		invalidPaths := []string{
			"/api users",             // space
			"/api/users!",            // exclamation
			"/api/users@123",         // at symbol
			"/api/users#tag",         // hash
			"/api/users?param=value", // query params
		}

		for _, path := range validPaths {
			assert.True(t, validURLPath.MatchString(path), "Path should be valid: %s", path)
		}

		for _, path := range invalidPaths {
			assert.False(t, validURLPath.MatchString(path), "Path should be invalid: %s", path)
		}
	})

	t.Run("curlyBracesRegexp regex", func(t *testing.T) {
		tests := []struct {
			input    string
			expected [][]string // [full_match, captured_group]
		}{
			{
				input:    "/api/{id}",
				expected: [][]string{{"{id}", "id"}},
			},
			{
				input:    "/api/{id:\\d+}",
				expected: [][]string{{"{id:\\d+}", "id:\\d+"}},
			},
			{
				input:    "/api/{user}/posts/{id}",
				expected: [][]string{{"{user}", "user"}, {"{id}", "id"}},
			},
			{
				input:    "/api/users",
				expected: nil,
			},
			{
				input:    "/api/{}",
				expected: [][]string{{"{}", ""}},
			},
		}

		for _, tt := range tests {
			matches := curlyBracesRegexp.FindAllStringSubmatch(tt.input, -1)
			assert.Equal(t, tt.expected, matches, "Input: %s", tt.input)
		}
	})
}

func TestConstants(t *testing.T) {
	assert.Equal(t, ": /", jvmAnnotationDelimiter)
	assert.Equal(t, " 65535: ", jvmSystemSymbol)
}

// Benchmark tests
func BenchmarkHasAlphanumeric(b *testing.B) {
	testStrings := []string{
		"",
		"abc123",
		"!@#$%^&*()",
		"test-string_with123numbers",
		"очень длинная строка с unicode символами",
	}

	for b.Loop() {
		for _, s := range testStrings {
			hasAlphanumeric(s)
		}
	}
}

func BenchmarkSanitizeParams(b *testing.B) {
	testPaths := []string{
		"/api/users/{id}",
		"/api/{version}/users/{id:\\d+}/profile/{type}",
		"/static/files",
		"/api/complex/{param1:pattern1}/sub/{param2:pattern2}/final/{param3}",
	}

	for b.Loop() {
		for _, path := range testPaths {
			sanitizeParams(path)
		}
	}
}

func BenchmarkSortRoutes(b *testing.B) {
	harvester := NewJavaRoutesHarvester()
	routes := []string{
		"/api/users",
		"/api/users/{id}",
		"/api/products",
		"/api/products/{id}/reviews",
		"/health",
		"/api/{version}/users/{id}",
		"/static/assets",
		"/api/orders/{orderId}/items/{itemId}",
	}

	for b.Loop() {
		// Make a copy for each iteration
		routesCopy := make([]string, len(routes))
		copy(routesCopy, routes)
		harvester.sortRoutes(routesCopy)
	}
}

type ReaderCloser struct {
	io.Reader
}

func (rc *ReaderCloser) Close() error {
	return nil
}

func NewReaderCloser(r io.Reader) *ReaderCloser {
	return &ReaderCloser{Reader: r}
}

type FakeJavaAttacher struct {
	JavaAttacher
	attachFunc func(int, []string, bool) (io.ReadCloser, error)
}

func (j FakeJavaAttacher) Init() {
}

func (j FakeJavaAttacher) Cleanup() {
}

func (j FakeJavaAttacher) Attach(pid int, argv []string, ignoreOnJ9 bool) (io.ReadCloser, error) {
	return j.attachFunc(pid, argv, ignoreOnJ9)
}
