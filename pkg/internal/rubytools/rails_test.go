// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadRailsApplicationName(t *testing.T) {
	t.Run("missing file yields empty result", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "application.rb")

		assert.Empty(t, readRailsApplicationName(path))
	})

	t.Run("empty file yields empty result", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "application.rb")
		writeRubyFile(t, path, nil)

		assert.Empty(t, readRailsApplicationName(path))
	})

	t.Run("directory yields empty result", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "application.rb")
		require.NoError(t, os.Mkdir(path, 0o755))

		assert.Empty(t, readRailsApplicationName(path))
	})

	t.Run("symlink yields empty result", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.rb")
		writeRubyFile(t, target, []byte("class WrongApp < Rails::Application\nend\n"))
		path := filepath.Join(dir, "application.rb")
		require.NoError(t, os.Symlink(target, path))

		assert.Empty(t, readRailsApplicationName(path))
	})

	t.Run("file at size limit is read", func(t *testing.T) {
		data := []byte("class MyApp < Rails::Application\nend\n#")
		data = append(data, bytes.Repeat([]byte("x"), int(maxRubyMetadataBytes)-len(data))...)
		path := filepath.Join(t.TempDir(), "application.rb")
		writeRubyFile(t, path, data)

		assert.Equal(t, "my-app", readRailsApplicationName(path))
	})

	t.Run("oversized file yields empty result", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "application.rb")
		writeRubyFile(t, path, make([]byte, maxRubyMetadataBytes+1))

		assert.Empty(t, readRailsApplicationName(path))
	})

	t.Run("well-formed declaration is read from disk", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "application.rb")
		writeRubyFile(t, path, []byte("class MyApp < Rails::Application\nend\n"))

		assert.Equal(t, "my-app", readRailsApplicationName(path))
	})
}

func TestParseRailsApplicationName(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected string
	}{
		{
			name:     "simple top-level class",
			source:   "class MyApp < Rails::Application\nend\n",
			expected: "my-app",
		},
		{
			name: "end method references are not unmatched block terminators",
			source: `lifecycle.end
module StoreFront
  class Application < Rails::Application
  end
end`,
			expected: "store-front",
		},
		{
			name: "two levels of nested modules",
			source: `
module Acme
  module Orders
    class Application < Rails::Application
    end
  end
end
`,
			expected: "acme/orders",
		},
		{
			name: "three levels of nested modules",
			source: `
module A
  module B
    module C
      class Application < Rails::Application
      end
    end
  end
end
`,
			expected: "a/b/c",
		},
		{
			name: "absolute leading double colon ignores enclosing module",
			source: `
module Foo
  class ::BillingService < ::Rails::Application
  end
end
`,
			expected: "billing-service",
		},
		{
			name: "relative qualified name inside a module is ambiguous",
			source: `
module Foo
  class Foo::Bar < Rails::Application
  end
end
`,
			expected: "",
		},
		{
			name: "two well-formed declarations have no unambiguous answer",
			source: `
class FirstApp < Rails::Application
end
class SecondApp < Rails::Application
end
`,
			expected: "",
		},
		{
			name: "a second ambiguous mention also stops the scan",
			source: `
class FirstApp < Rails::Application
end
class Weird < SomeModule::Rails::Application
end
`,
			expected: "",
		},
		{
			name:     "text containing Rails::Application without the strict shape bails out",
			source:   "class Weird < SomeModule::Rails::Application\n",
			expected: "",
		},
		{
			name: "declaration inside an if block cannot be trusted",
			source: `
if ENV["USE_APP"]
  class ConditionalApp < Rails::Application
  end
end
`,
			expected: "",
		},
		{
			name: "declaration inside a do block cannot be trusted",
			source: `
[1].each do |item|
  class ConditionalApp < Rails::Application
  end
end
`,
			expected: "",
		},
		{
			name: "declaration inside a brace block cannot be trusted",
			source: `
[1].each { |item|
  class ConditionalApp < Rails::Application
  end
}
`,
			expected: "",
		},
		{
			name: "closed sibling blocks are forgotten before the real declaration",
			source: `
module Helpers
  module Nested
  end
end
module RealApp
  class Application < Rails::Application
  end
end
`,
			expected: "real-app",
		},
		{
			name:     "a stray end with no open block returns empty immediately",
			source:   "end\n",
			expected: "",
		},
		{
			name:     "an unclosed application class is rejected",
			source:   "class MyApp < Rails::Application\n",
			expected: "",
		},
		{
			name: "an unclosed enclosing module is rejected",
			source: `
module Acme
  class Application < Rails::Application
  end
`,
			expected: "",
		},
		{
			name: "a stray end after an application class is rejected",
			source: `
class MyApp < Rails::Application
end
end
`,
			expected: "",
		},
		{
			name: "a module nested inside an ambiguous qualified enclosing context",
			source: `
module Foo
  module Foo::Bar
  end
end
`,
			expected: "",
		},
		{
			name:     "a trailing comment on the declaration line is ignored",
			source:   "class MyApp < Rails::Application # top-level app\nend\n",
			expected: "my-app",
		},
		{
			name:     "no declaration at all",
			source:   "puts 'hello world'\n",
			expected: "",
		},
		{
			name:     "empty input",
			source:   "",
			expected: "",
		},
		{
			name: "ambiguous Ruby syntax fails closed",
			source: `items = []
item = 1
items <<item
class MyApp < Rails::Application
end
`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseRailsApplicationName([]byte(tt.source)))
		})
	}
}

func TestScanRailsApplication(t *testing.T) {
	tests := []struct {
		name      string
		source    string
		namespace string
		dynamic   bool
		want      railsApplicationScan
	}{
		{
			name:   "top-level application",
			source: "class Orders < Rails::Application\nend",
			want:   railsApplicationScan{candidates: []string{"Orders"}},
		},
		{
			name:      "application inherits supplied namespace",
			source:    "class Application < Rails::Application\nend",
			namespace: "Orders",
			want:      railsApplicationScan{candidates: []string{"Orders::Application"}},
		},
		{
			name:   "module supplies namespace",
			source: "module Orders\n  class Application < Rails::Application\n  end\nend",
			want:   railsApplicationScan{candidates: []string{"Orders::Application"}},
		},
		{
			name:    "dynamic context is ambiguous",
			source:  "class Orders < Rails::Application\nend",
			dynamic: true,
			want:    railsApplicationScan{ambiguous: true},
		},
		{
			name:   "conditional context is ambiguous",
			source: "if enabled\n  class Orders < Rails::Application\n  end\nend",
			want:   railsApplicationScan{ambiguous: true},
		},
		{
			name:      "qualified module below a namespace is ambiguous",
			source:    "module Existing::Orders\nend",
			namespace: "Outer",
			want:      railsApplicationScan{ambiguous: true},
		},
		{
			name:   "similar superclass is ambiguous",
			source: "class Orders < Other::Rails::Application\nend",
			want:   railsApplicationScan{ambiguous: true},
		},
		{
			name: "multiple applications are collected",
			source: `class Orders < Rails::Application
end
class Billing < Rails::Application
end`,
			want: railsApplicationScan{candidates: []string{"Orders", "Billing"}},
		},
		{name: "unrelated Ruby", source: `puts "hello"`, want: railsApplicationScan{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := parseRubyTestTree(t, test.source)
			got := railsApplicationScan{}

			scanRailsApplication(tree, tree.root(), test.namespace, test.dynamic, &got)

			assert.Equal(t, test.want, got)
		})
	}

	t.Run("nil node is ignored", func(t *testing.T) {
		tree := parseRubyTestTree(t, "nil")
		scan := railsApplicationScan{}

		scanRailsApplication(tree, nil, "", false, &scan)

		assert.Empty(t, scan.candidates)
		assert.False(t, scan.ambiguous)
	})

	t.Run("ambiguous scan stops immediately", func(t *testing.T) {
		tree := parseRubyTestTree(t, "class Billing < Rails::Application\nend")
		scan := railsApplicationScan{candidates: []string{"Orders"}, ambiguous: true}

		scanRailsApplication(tree, tree.root(), "", false, &scan)

		assert.Equal(t, railsApplicationScan{candidates: []string{"Orders"}, ambiguous: true}, scan)
	})
}

func TestRailsSuperclass(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
		ok     bool
	}{
		{
			name:   "qualified constant",
			source: "class Orders < Rails::Application\nend",
			want:   "Rails::Application",
			ok:     true,
		},
		{
			name:   "root-qualified constant",
			source: "class Orders < ::Rails::Application\nend",
			want:   "::Rails::Application",
			ok:     true,
		},
		{
			name:   "dynamic expression",
			source: "class Orders < build_superclass\nend",
		},
		{
			name:   "no superclass",
			source: "class Orders\nend",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := parseRubyTestTree(t, test.source)
			class := firstRubyTestNode(tree, tree.root(), "class")
			require.NotNil(t, class)

			got, ok := railsSuperclass(tree, tree.child(class, "superclass"))
			assert.Equal(t, test.ok, ok)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestAmbiguousQualifiedConstant(t *testing.T) {
	tests := []struct {
		name      string
		className string
		enclosing string
		expected  bool
	}{
		{name: "no enclosing module is never ambiguous", className: "Foo::Bar", enclosing: "", expected: false},
		{name: "qualified name with an enclosing module is ambiguous", className: "Foo::Bar", enclosing: "Mod", expected: true},
		{name: "leading double colon is never ambiguous", className: "::Foo::Bar", enclosing: "Mod", expected: false},
		{name: "unqualified name with an enclosing module is not ambiguous", className: "Foo", enclosing: "Mod", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ambiguousQualifiedConstant(tt.className, tt.enclosing))
		})
	}
}

func TestQualifiedRubyConstant(t *testing.T) {
	tests := []struct {
		name      string
		className string
		enclosing string
		expected  string
	}{
		{name: "leading double colon strips the prefix and ignores enclosing", className: "::Foo", enclosing: "Mod", expected: "Foo"},
		{name: "bare top-level name with no enclosing module is unchanged", className: "Foo", enclosing: "", expected: "Foo"},
		{name: "name is qualified by the enclosing module", className: "Foo", enclosing: "Mod", expected: "Mod::Foo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, qualifiedRubyConstant(tt.className, tt.enclosing))
		})
	}
}

func TestRailsServiceName(t *testing.T) {
	tests := []struct {
		name      string
		className string
		expected  string
	}{
		{name: "empty class name yields empty service name", className: "", expected: ""},
		{name: "acronym boundary before a capitalized word", className: "HTTPServer", expected: "http-server"},
		{name: "ordinary camelCase boundary", className: "OrdersWorker", expected: "orders-worker"},
		{name: "Application suffix stripped only as a trailing segment", className: "Acme::Application", expected: "acme"},
		{name: "Application as a substring is not stripped", className: "Acme::OrdersApplication", expected: "acme/orders-application"},
		{name: "each segment is dasherized independently", className: "Acme::OrdersApp::BillingService", expected: "acme/orders-app/billing-service"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, railsServiceName(tt.className))
		})
	}
}
