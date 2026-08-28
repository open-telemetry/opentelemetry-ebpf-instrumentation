// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func TestReadGemspecAcceptsStaticIdentity(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		source string
		want   serviceMetadata
	}{
		{
			name: "canonical assignments",
			source: `Gem::Specification.new do |spec|
  spec.name = "orders"
  spec.version = "1.2.3"
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name:   "CRLF source",
			source: "Gem::Specification.new do |spec|\r\n  spec.name = \"orders\"\r\n  spec.version = \"1.2.3\"\r\nend\r\n",
			want:   serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "parenthesized no argument constructor",
			source: `Gem::Specification.new() do |spec|
  spec.name = "orders"
  spec.version = "1.2.3"
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "spaced parenthesized no argument constructor",
			source: `Gem::Specification.new( ) do |spec|
  spec.name = "orders"
  spec.version = "1.2.3"
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "single quoted frozen assignments",
			source: `Gem::Specification.new do |s|
  s.name = 'orders-api'.freeze
  s.version = '1.2.3.pre.1'.freeze
end`,
			want: serviceMetadata{Name: "orders-api", Version: "1.2.3.pre.1"},
		},
		{
			name:   "constructor arguments",
			source: `Gem::Specification.new "orders", "1.2.3" do |spec|` + "\nend",
			want:   serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name:   "parenthesized constructor arguments",
			source: `Gem::Specification.new("orders", "1.2.3") do |spec|` + "\nend",
			want:   serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name:   "root qualified constructor",
			source: `::Gem::Specification.new("orders", "1.2.3") do |spec|` + "\nend",
			want:   serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name:   "name only constructor",
			source: `Gem::Specification.new("orders") do |spec|` + "\nend",
			want:   serviceMetadata{Name: "orders"},
		},
		{
			name: "name only constructor with version assignment",
			source: `Gem::Specification.new("orders") do |spec|
  spec.version = "1.2.3"
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "name only constructor with dynamic version",
			source: `Gem::Specification.new("orders") do |spec|
  spec.version = Orders::VERSION
end`,
			want: serviceMetadata{Name: "orders"},
		},
		{
			name: "alternate block variable",
			source: `Gem::Specification.new do |gem_spec2|
  gem_spec2.name = "orders"
  gem_spec2.version = "1.2.3"
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "comments and unrelated fields",
			source: `# generated gemspec
Gem::Specification.new do |spec| # identity
  spec.name = "orders" # package name
  spec.summary = "Order service"
  spec.files = ["lib/orders.rb"]
  spec.add_dependency "rack", ">= 3"
  spec.version = "1.2.3" # package version
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "balanced preamble",
			source: `if false
end
module BuildMetadata
end
Gem::Specification.new("orders", "1.2.3") do |spec|
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "end method references are not unmatched block terminators",
			source: `lifecycle.end
Gem::Specification.new("orders", "1.2.3") do |spec|
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "unrelated similarly named fields",
			source: `Gem::Specification.new do |spec|
  spec.name = "orders"
  spec.name_suffix = "api"
  other_spec.name = "unrelated"
  spec.version = "1.2.3"
  spec.version_requirement = ">= 1"
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "identity references inside literals",
			source: `Gem::Specification.new do |spec|
  spec.name = "orders"
  spec.version = "1.2.3"
  description = %q{spec.name and spec.version}
  pattern = %r{spec.name|spec.version}
  other_pattern = /spec.name|spec.version/
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "lowercase heredoc hides identity-looking text",
			source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  items = []
  item = "other"
  items <<item
  spec.name = item
item
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "puts heredoc hides identity-looking text",
			source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  puts <<SOURCE
  spec.name = "other"
SOURCE
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "custom command heredoc hides identity-looking text",
			source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  render <<SOURCE
  spec.name = "other"
SOURCE
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.want, readGemspecSource(t, testCase.source))
		})
	}
}

func TestReadGemspecValidatesRubyGemsNames(t *testing.T) {
	for _, name := range []string{
		"orders",
		"orders-api",
		"orders_api",
		"orders.api",
		"Orders2",
		"2orders",
		"a",
		"a.",
		"a-",
		"a_",
		"a..b",
	} {
		t.Run("accepts "+strconv.Quote(name), func(t *testing.T) {
			source := "Gem::Specification.new do |spec|\n" +
				"  spec.name = \"" + name + "\"\n" +
				"  spec.version = \"1.2.3\"\nend\n"

			assert.Equal(t, serviceMetadata{Name: name, Version: "1.2.3"}, readGemspecSource(t, source))
		})
	}

	for _, name := range []string{
		"",
		"123",
		".orders",
		"-orders",
		"_orders",
		".",
		"-",
		"_",
		"..",
		"orders service",
		"orders/api",
		"orders:api",
		"orders+api",
		"orders\x00api",
		"café",
	} {
		t.Run("rejects "+strconv.Quote(name), func(t *testing.T) {
			source := "Gem::Specification.new do |spec|\n" +
				"  spec.name = \"" + name + "\"\n" +
				"  spec.version = \"1.2.3\"\nend\n"

			assert.Empty(t, readGemspecSource(t, source))
		})
	}
}

func TestReadGemspecValidatesSupportedVersionLiterals(t *testing.T) {
	for _, version := range []string{
		"0",
		"1",
		"01.002",
		"1.2.3",
		"1.0.0.pre.1",
		"1.0.a10",
		"1.0.RC1",
		"1.0-rc1",
		"1.0-rc.1",
		"1.0--rc",
	} {
		t.Run("accepts "+strconv.Quote(version), func(t *testing.T) {
			source := "Gem::Specification.new do |spec|\n" +
				"  spec.name = \"orders\"\n" +
				"  spec.version = \"" + version + "\"\nend\n"

			assert.Equal(t, serviceMetadata{Name: "orders", Version: version}, readGemspecSource(t, source))
		})
	}

	for _, version := range []string{
		"",
		" ",
		"v1.0",
		".1",
		"1.",
		"1..0",
		"1_0",
		"1.0+build",
		"1 0",
		"1/2",
		"١.٢.٣",
	} {
		t.Run("omits "+strconv.Quote(version), func(t *testing.T) {
			source := "Gem::Specification.new do |spec|\n" +
				"  spec.name = \"orders\"\n" +
				"  spec.version = \"" + version + "\"\nend\n"

			assert.Equal(t, serviceMetadata{Name: "orders"}, readGemspecSource(t, source))
		})
	}
}

func TestReadGemspecRejectsUnsupportedOrAmbiguousIdentity(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		source string
	}{
		{name: "no specification", source: `ORDERS = "1.2.3"`},
		{name: "wrong specification constant", source: `Other::Specification.new("orders", "1.2.3")`},
		{name: "specification nested in conditional", source: `if production?
  Gem::Specification.new("orders", "1.2.3") do |spec|
  end
end`},
		{name: "unmatched end before specification", source: `end
Gem::Specification.new("orders", "1.2.3") do |spec|
end`},
		{name: "two specification blocks", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
end
Gem::Specification.new("other", "2.0.0") do |spec|
end`},
		{name: "second specification in expression", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
end
true && Gem::Specification.new("other", "2.0.0")`},
		{name: "additional specification before semicolon", source: `Gem::Specification.new; nil
Gem::Specification.new("orders", "1.2.3") do |spec|
end`},
		{name: "additional specification with brace block", source: `Gem::Specification.new{ |other| other.name = "other" }
Gem::Specification.new("orders", "1.2.3") do |spec|
end`},
		{name: "additional chained specification", source: `Gem::Specification.new.tap { |other| other.name = "other" }
Gem::Specification.new("orders", "1.2.3") do |spec|
end`},
		{name: "two specifications on one line", source: `Gem::Specification.new("orders", "1.2.3"); Gem::Specification.new("other", "2.0.0")`},
		{name: "additional specification after percent literal comment marker", source: `marker = %q{#}; Gem::Specification.new("other", "2.0.0")
Gem::Specification.new("orders", "1.2.3") do |spec|
end`},
		{name: "additional specification after slash literal comment marker", source: `marker = /#/; Gem::Specification.new("other", "2.0.0")
Gem::Specification.new("orders", "1.2.3") do |spec|
end`},
		{name: "dynamic constructor name", source: `Gem::Specification.new(Orders::NAME, "1.2.3") do |spec|
end`},
		{name: "dynamic constructor version", source: `Gem::Specification.new("orders", Orders::VERSION) do |spec|
end`},
		{name: "constructor with too many arguments", source: `Gem::Specification.new("orders", "1.2.3", :extra) do |spec|
end`},
		{name: "constructor arguments without comma", source: `Gem::Specification.new("orders" "1.2.3") do |spec|
end`},
		{name: "constructor without block", source: `Gem::Specification.new("orders", "1.2.3")`},
		{name: "constructor with brace block", source: `Gem::Specification.new("orders", "1.2.3") { |spec| spec }`},
		{name: "block without variable", source: `Gem::Specification.new("orders", "1.2.3") do
end`},
		{name: "multiline constructor", source: `Gem::Specification.new(
  "orders",
  "1.2.3"
) do |spec|
end`},
		{name: "percent name literal", source: `Gem::Specification.new do |spec|
  spec.name = %q{orders}
  spec.version = "1.2.3"
end`},
		{name: "interpolated name", source: `Gem::Specification.new do |spec|
  spec.name = "orders#{suffix}"
  spec.version = "1.2.3"
end`},
		{name: "escaped name", source: `Gem::Specification.new do |spec|
  spec.name = "orders\-api"
  spec.version = "1.2.3"
end`},
		{name: "unterminated name", source: `Gem::Specification.new do |spec|
  spec.name = "orders
  spec.version = "1.2.3"
end`},
		{name: "freeze call with parentheses", source: `Gem::Specification.new do |spec|
  spec.name = "orders".freeze()
  spec.version = "1.2.3"
end`},
		{name: "chained freeze calls", source: `Gem::Specification.new do |spec|
  spec.name = "orders".freeze.freeze
  spec.version = "1.2.3"
end`},
		{name: "adjacent name strings", source: `Gem::Specification.new do |spec|
  spec.name = "orders" "-api"
  spec.version = "1.2.3"
end`},
		{name: "multiple assignments on one line", source: `Gem::Specification.new do |spec|
  spec.name = "orders"; spec.version = "1.2.3"
end`},
		{name: "assignment with trailing semicolon", source: `Gem::Specification.new do |spec|
  spec.name = "orders";
  spec.version = "1.2.3"
end`},
		{name: "duplicate name", source: `Gem::Specification.new do |spec|
  spec.name = "orders"
  spec.name = "other"
end`},
		{name: "duplicate version", source: `Gem::Specification.new do |spec|
  spec.name = "orders"
  spec.version = "1.2.3"
  spec.version = "2.0.0"
end`},
		{name: "compound name mutation", source: `Gem::Specification.new do |spec|
  spec.name = "orders"
  spec.name += "-api"
  spec.version = "1.2.3"
end`},
		{name: "constructor and name assignment", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec.name = "other"
end`},
		{name: "constructor and version assignment", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec.version = "2.0.0"
end`},
		{name: "name only constructor and name assignment", source: `Gem::Specification.new("orders") do |spec|
  spec.name = "other"
end`},
		{name: "safe navigation name mutation", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec&.name = "other"
end`},
		{name: "safe navigation version mutation", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec&.version = "2.0.0"
end`},
		{name: "embedded field assignment", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  log_event; spec.name = "other"
end`},
		{name: "field assignment after percent literal comment marker", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  marker = %q!#!; spec.name = "other"
end`},
		{name: "field assignment after slash literal comment marker", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  marker = /#/; spec.name = "other"
end`},
		{name: "field assignment after command percent literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  logger.info %q!#!; spec.name = "other"
end`},
		{name: "field assignment after command slash literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  logger.info /#/; spec.name = "other"
end`},
		{name: "field assignment after bare command percent literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  p %q!#!; spec.name = "other"
end`},
		{name: "field assignment after bare command slash literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  p /#/; spec.name = "other"
end`},
		{name: "field assignment after custom command percent literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  render %q!#!; spec.name = "other"
end`},
		{name: "field assignment after custom command slash literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  render /#/; spec.name = "other"
end`},
		{name: "field assignment after nested command percent literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  ignored = logger.info %q!#!; spec.name = "other"
end`},
		{name: "field assignment after nested command slash literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  ignored = logger.info /#/; spec.name = "other"
end`},
		{name: "field assignment after hash rocket regex", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  mapping = { "key" => /#/ }; spec.name = "other"
end`},
		{name: "field assignment after range regex", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  range = 1.. /#/; spec.name = "other"
end`},
		{name: "field assignment after custom command untyped percent literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  render %!#!; spec.name = "other"
end`},
		{name: "field assignment after spaced receiver percent literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  logger .info %q!#!; spec.name = "other"
end`},
		{name: "field assignment after modulo expression", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  value = 5%+2
  spec.name += "-service"
end`},
		{name: "field assignment after spaced modulo expression", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  value = 10
  value %+2
  spec.name += "-service"; other = 1+2
end`},
		{name: "field assignment inside a same-line modulo ambiguity", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  value = 10
  value %+2; spec.name = "other"; +2
end`},
		{name: "field assignment after float division", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  value = 1.0 / 2
  spec.name += "-service"; other = 4 / 2
end`},
		{name: "field assignment after shadowed command division", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  p = 10
  p / x
  spec.name += "-service"; other = 4 / 2
end`},
		{name: "slash inside percent literal does not hide mutation", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  marker = %q{/}
  spec.name += "-service"; value = 8/2
end`},
		{name: "percent inside slash literal does not hide mutation", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  marker = /%!/
  spec.name += "-service" # !
end`},
		{name: "field assignment before multiline percent literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  log_event; spec.name = "other"; marker = %q{
  }
end`},
		{name: "field assignment before multiline slash literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  log_event; spec.name = "other"; marker = /
  hidden
  /
end`},
		{name: "field assignment after multiline percent literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  marker = %q{
# hidden text
}; spec.name = "other"
end`},
		{name: "field assignment after multiline slash literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  marker = /
# hidden text
/; spec.name = "other"
end`},
		{name: "field assignment after multiline quoted literal", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  marker = "
# hidden text
"; spec.name = "other"
end`},
		{name: "quote inside multiline percent literal does not hide mutation", source: `other = "other"
Gem::Specification.new("orders", "1.2.3") do |spec|
  marker = %q{"
  }
  spec.name = other # "
end`},
		{name: "nested interpolation cannot hide a field mutation", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  message = "#{foo("#")}"; spec.name = "other"
end`},
		{name: "character literal cannot hide a field mutation", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  marker = ?#; spec.name = "other"
end`},
		{name: "command character literal cannot hide a field mutation", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  puts ?#; spec.name = "other"
end`},
		{name: "escaped character literal cannot hide a field mutation", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  marker = ?\#; spec.name = "other"
end`},
		{name: "single quote character literal cannot hide a field mutation", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  marker = ?'; spec.name = "other"
end`},
		{name: "double quote character literal cannot hide a field mutation", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  marker = ?"; spec.name = "other"
end`},
		{name: "spaced field assignment", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec .name = "other"
end`},
		{name: "field assignment spaced after dot", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec. name = "other"
end`},
		{name: "field assignment spaced around dot", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec . name = "other"
end`},
		{name: "safe navigation field assignment spaced after dot", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec&. name = "other"
end`},
		{name: "double colon field assignment", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec::name = "other"
end`},
		{name: "parenthesized receiver field assignment", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  (spec).name = "other"
end`},
		{name: "continued field assignment", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec
    .name = "other"
end`},
		{name: "field assignment after continued dot", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec.
    name = "other"
end`},
		{name: "field assignment after continued dot and explicit continuation", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec. \
    name = "other"
end`},
		{name: "field assignment after explicit line continuation", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec \
    .name = "other"
end`},
		{name: "field assignment after continued dot and comment", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec.
    # continued receiver
    name = "other"
end`},
		{name: "nested field mutation", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  enabled ? spec.name.replace("other") : nil
end`},
		{name: "name comparison", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  valid = spec.name == "orders"
end`},
		{name: "direct name comparison", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  spec.name == "orders"
end`},
		{name: "version regular expression match", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
  valid = spec.version =~ /^1/
end`},
		{name: "assignment outside block", source: `Gem::Specification.new do |spec|
end
spec.name = "orders"
spec.version = "1.2.3"`},
		{name: "version assignment outside block", source: `Gem::Specification.new("orders") do |spec|
end
spec.version = "1.2.3"`},
		{name: "assignment in nested block", source: `Gem::Specification.new do |spec|
  [true].each do |enabled|
    spec.name = "orders"
    spec.version = "1.2.3"
  end
end`},
		{name: "assignment in brace block", source: `Gem::Specification.new do |spec|
  [true].each { |enabled|
    spec.name = "orders"
    spec.version = "1.2.3"
  }
end`},
		{name: "assignment in assigned conditional", source: `Gem::Specification.new do |spec|
  spec.version = "1.2.3"
  guard = if production?
    spec.name = "orders"
  end
end`},
		{name: "assignment in parenthesized conditional", source: `Gem::Specification.new do |spec|
  spec.version = "1.2.3"
  consume(if production?
    spec.name = "orders"
  end)
end`},
		{name: "assignment in boolean begin block", source: `Gem::Specification.new do |spec|
  spec.version = "1.2.3"
  condition && begin
    spec.name = "orders"
  end
end`},
		{name: "assignment in and begin block", source: `Gem::Specification.new do |spec|
  spec.version = "1.2.3"
  condition and begin
    spec.name = "orders"
  end
end`},
		{name: "assignment in or begin block", source: `Gem::Specification.new do |spec|
  spec.version = "1.2.3"
  condition or begin
    spec.name = "orders"
  end
end`},
		{name: "unclosed specification block", source: `Gem::Specification.new do |spec|
  spec.name = "orders"
  spec.version = "1.2.3"`},
		{name: "conditional specification close", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
end if enabled`},
		{name: "chained specification close", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
end.name`},
		{name: "executable postamble", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
end
nil`},
		{name: "literal postamble", source: `Gem::Specification.new("orders", "1.2.3") do |spec|
end
%q!not-a-specification!`},
		{name: "unclosed block before specification", source: `begin
Gem::Specification.new do |spec|
  spec.name = "orders"
  spec.version = "1.2.3"
end`},
		{name: "ambiguous lowercase left shift fails closed", source: `items = []
item = 1
items <<item
Gem::Specification.new("orders", "1.2.3") do |spec|
end`},
		{name: "version without name", source: `Gem::Specification.new do |spec|
  spec.version = "1.2.3"
end`},
		{name: "dynamic name with static version", source: `Gem::Specification.new do |spec|
  spec.name = Orders::NAME
  spec.version = "1.2.3"
end`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Empty(t, readGemspecSource(t, testCase.source))
		})
	}
}

func TestReadGemspecKeepsStaticNameWithoutStaticVersion(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		version string
	}{
		{name: "missing version"},
		{name: "dynamic version", version: `  spec.version = Orders::VERSION`},
		{name: "interpolated version", version: `  spec.version = "1.#{minor}.0"`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			source := "Gem::Specification.new do |spec|\n" +
				"  spec.name = \"orders\"\n" + testCase.version + "\nend\n"

			assert.Equal(t, serviceMetadata{Name: "orders"}, readGemspecSource(t, source))
		})
	}
}

func TestReadGemspecIgnoresNonExecutableSpecificationText(t *testing.T) {
	const realSpecification = `Gem::Specification.new("orders", "1.2.3") do |spec|
end`
	for _, testCase := range []struct {
		name   string
		source string
	}{
		{name: "line comment", source: `# Gem::Specification.new("fake", "9.9.9")` + "\n" + realSpecification},
		{name: "block comment", source: `=begin
Gem::Specification.new("fake", "9.9.9")
=end
` + realSpecification},
		{name: "single quoted string", source: `EXAMPLE = 'Gem::Specification.new("fake", "9.9.9")'` + "\n" + realSpecification},
		{name: "multiline string", source: `EXAMPLE = "
Gem::Specification.new('fake', '9.9.9')
"
` + realSpecification},
		{name: "backtick string", source: "EXAMPLE = `\nGem::Specification.new('fake', '9.9.9')\n`\n" + realSpecification},
		{name: "single line percent string", source: `EXAMPLE = %q{Gem::Specification.new("fake", "9.9.9")}` + "\n" + realSpecification},
		{name: "multiline percent string", source: `EXAMPLE = %Q{
Gem::Specification.new("fake", "9.9.9")
}
` + realSpecification},
		{name: "single line percent regex", source: `EXAMPLE = %r{Gem::Specification.new\("fake", "9.9.9"\)}` + "\n" + realSpecification},
		{name: "heredoc marker inside percent regex", source: `PATTERN = %r{<<SOURCE}` + "\n" + realSpecification},
		{name: "multiline slash regex", source: `EXAMPLE = /
Gem::Specification.new\("fake", "9.9.9"\)
/
` + realSpecification},
		{name: "assigned heredoc", source: `EXAMPLE = <<~SOURCE
Gem::Specification.new("fake", "9.9.9")
SOURCE
` + realSpecification},
		{name: "quoted heredoc delimiter containing spaces", source: `EXAMPLE = <<'END DOC'
Gem::Specification.new("fake", "9.9.9")
END DOC
` + realSpecification},
		{name: "multiple heredocs", source: `FIRST = <<~FIRST_SOURCE; SECOND = <<~SECOND_SOURCE
Gem::Specification.new("fake-one", "9.9.9")
FIRST_SOURCE
Gem::Specification.new("fake-two", "9.9.9")
SECOND_SOURCE
` + realSpecification},
		{name: "data section", source: realSpecification + `
__END__
Gem::Specification.new("fake", "9.9.9")`},
		{name: "different constant", source: `Other::Gem::Specification.new("fake", "9.9.9")` + "\n" + realSpecification},
		{name: "longer method name", source: `Gem::Specification.newer("fake", "9.9.9")` + "\n" + realSpecification},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(
				t,
				serviceMetadata{Name: "orders", Version: "1.2.3"},
				readGemspecSource(t, testCase.source),
			)
		})
	}
}

func TestReadGemspecFileSafety(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		assert.Empty(t, readGemspec(filepath.Join(t.TempDir(), "missing.gemspec")))
	})

	t.Run("empty file", func(t *testing.T) {
		assert.Empty(t, readGemspecSource(t, ""))
	})

	t.Run("directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "service.gemspec")
		require.NoError(t, os.Mkdir(path, 0o755))

		assert.Empty(t, readGemspec(path))
	})

	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.gemspec")
		writeRubyFile(t, target, []byte(`Gem::Specification.new("outside", "9.9.9") do |spec|
end`))
		path := filepath.Join(dir, "service.gemspec")
		require.NoError(t, os.Symlink(target, path))

		assert.Empty(t, readGemspec(path))
	})

	t.Run("exact size limit", func(t *testing.T) {
		data := []byte(`Gem::Specification.new("orders", "1.2.3") do |spec|
end
#`)
		data = append(data, bytes.Repeat([]byte("x"), int(maxRubyMetadataBytes)-len(data))...)
		path := filepath.Join(t.TempDir(), "service.gemspec")
		writeRubyFile(t, path, data)

		assert.Equal(t, serviceMetadata{Name: "orders", Version: "1.2.3"}, readGemspec(path))
	})

	t.Run("over size limit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "service.gemspec")
		writeRubyFile(t, path, bytes.Repeat([]byte("x"), int(maxRubyMetadataBytes)+1))

		assert.Empty(t, readGemspec(path))
	})
}

func TestResolveServiceMetadataFromGemspec(t *testing.T) {
	t.Run("nearest gemspec wins over an outer gemspec", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "outer.gemspec"), []byte(`
Gem::Specification.new("outer", "9.9.9") do |spec|
end
`))
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new("orders", "1.2.3") do |spec|
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
	})

	t.Run("BUNDLE_GEMFILE project", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "Gemfile.custom"), nil)
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new("orders", "1.2.3") do |spec|
end
`))
		fileInfo := mockRubyProcess(t, root, "/unrelated", "puma", nil, map[string]string{
			bundleGemfile: "/app/Gemfile.custom",
		})

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
		assert.True(t, service.AutoName())
	})

	t.Run("relative BUNDLE_GEMFILE project", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "Gemfile.custom"), nil)
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new("orders", "1.2.3") do |spec|
end
`))
		fileInfo := mockRubyProcess(t, root, "/work", "puma", nil, map[string]string{
			bundleGemfile: "../app/Gemfile.custom",
		})

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
	})

	t.Run("unusable nearest gemspec prevents BUNDLE_GEMFILE fallback", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "server.rb"), nil)
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new { dynamic_metadata }
`))
		writeRubyFile(t, filepath.Join(root, "bundle", "Gemfile"), nil)
		writeRubyFile(t, filepath.Join(root, "bundle", "other.gemspec"), []byte(`
Gem::Specification.new("other", "9.9.9") do |spec|
end
`))
		fileInfo := mockRubyProcess(t, root, "/", "ruby", []string{"/app/server.rb"}, map[string]string{
			bundleGemfile: "/bundle/Gemfile",
		})

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "server", service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
	})

	t.Run("dependency gemspec cannot leak identity or version", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "bundle", "gems", "puma", "puma.gemspec"), []byte(`
Gem::Specification.new("puma", "6.0.0") do |spec|
end
`))
		writeRubyFile(t, filepath.Join(root, "app", "Gemfile.custom"), nil)
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new("orders", "1.2.3") do |spec|
end
`))
		fileInfo := mockRubyProcess(t, root, "/bundle/gems/puma", "puma", nil, map[string]string{
			gemHome:       "/bundle",
			bundleGemfile: "/app/Gemfile.custom",
		})

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
	})

	t.Run("dependency entrypoint falls through to cwd before BUNDLE_GEMFILE", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "bundle", "gems", "puma", "server.rb"), nil)
		writeRubyFile(t, filepath.Join(root, "bundle", "gems", "puma", "puma.gemspec"), []byte(`
Gem::Specification.new("puma", "6.0.0") do |spec|
end
`))
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new("orders", "1.2.3") do |spec|
end
`))
		writeRubyFile(t, filepath.Join(root, "other", "Gemfile"), nil)
		writeRubyFile(t, filepath.Join(root, "other", "other.gemspec"), []byte(`
Gem::Specification.new("other", "9.9.9") do |spec|
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "ruby", []string{
			"/bundle/gems/puma/server.rb",
		}, map[string]string{
			gemHome:       "/bundle",
			bundleGemfile: "/other/Gemfile",
		})

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
	})

	t.Run("configured name does not inherit a dependency version", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "bundle", "gems", "puma", "puma.gemspec"), []byte(`
Gem::Specification.new("puma", "6.0.0") do |spec|
end
`))
		fileInfo := mockRubyProcess(t, root, "/bundle/gems/puma", "puma", nil, map[string]string{
			gemHome: "/bundle",
		})
		fileInfo.SetUID(svc.UID{Name: "configured"})

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "configured", service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
		assert.False(t, service.AutoName())
	})

	t.Run("ambiguous source uses project directory without version", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new("orders", "1.2.3") do |spec|
end
true && Gem::Specification.new("other", "2.0.0")
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "app", service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
	})

	t.Run("invalid package name uses project directory", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new("123", "1.2.3") do |spec|
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "app", service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
	})

	t.Run("directory named gemspec is a local boundary", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "outer.gemspec"), []byte(`
Gem::Specification.new("outer", "9.9.9") do |spec|
end
`))
		require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "orders.gemspec"), 0o755))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "app", service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
	})

	t.Run("exact directory entry limit still discovers gemspec", func(t *testing.T) {
		root := t.TempDir()
		project := filepath.Join(root, "app")
		writeRubyFile(t, filepath.Join(project, "orders.gemspec"), []byte(`
Gem::Specification.new("orders", "1.2.3") do |spec|
end
`))
		for index := 1; index < maxProjectEntries; index++ {
			writeRubyFile(t, filepath.Join(project, "entry-"+strconv.Itoa(index)), nil)
		}
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
	})
}

func readGemspecSource(t *testing.T, source string) serviceMetadata {
	t.Helper()
	path := filepath.Join(t.TempDir(), "service.gemspec")
	writeRubyFile(t, path, []byte(source))
	return readGemspec(path)
}
