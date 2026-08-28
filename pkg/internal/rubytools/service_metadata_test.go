// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestResolveServiceMetadata(t *testing.T) {
	t.Run("Rails application supplies its canonical name", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
module Acme
  module Orders
    class Application < Rails::Application
    end
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)
		fileInfo.SetUID(svc.UID{Namespace: "production"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "acme/orders", service.UID.Name)
		assert.Equal(t, "production", service.UID.Namespace)
		assert.True(t, service.AutoName())
		assert.False(t, service.AutoNamespace())
	})

	t.Run("direct Rails application class is normalized", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
class BillingService < ::Rails::Application
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "billing-service", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("dynamic Rails declaration falls back to the project directory", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "Orders-Service", "config", "application.rb"), []byte(`
ApplicationClass = Class.new(Rails::Application)
`))
		fileInfo := mockRubyProcess(t, root, "/Orders-Service", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "Orders-Service", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("unparseable Rails application falls back to the direct script", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
class Application < Rails::Application
`))
		writeRubyFile(t, filepath.Join(root, "app", "bin", "worker.rb"), nil)
		fileInfo := mockRubyProcess(t, root, "/app", "ruby", []string{"/app/bin/worker.rb"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "worker", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Rails never takes a version from a colocated gemspec", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
module Orders
  class Application < Rails::Application
  end
end
`))
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new do |spec|
  spec.name = "orders-gem"
  spec.version = "1.2.3"
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
	})

	t.Run("Rails declarations in comments strings and heredocs are ignored", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
# class CommentedApp < Rails::Application
EXAMPLE = "class StringApp < Rails::Application"
EXAMPLE_SOURCE = <<~RUBY
class HeredocApp < Rails::Application
RUBY
module RealApp
  class Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "real-app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Rails declarations in block comments are ignored", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
=begin
class BlockCommentApp < Rails::Application
end
=end
module RealApp
  class Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "real-app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Rails declarations in multiline strings are ignored", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
EXAMPLE = "source:
class StringApp < Rails::Application
end"
module RealApp
  class Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "real-app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Rails declarations in multiline regex literals are ignored", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
EXAMPLE = /
class RegexApp < Rails::Application
/
module RealApp
  class Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "real-app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Rails declarations in quoted heredocs are ignored", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
EXAMPLE = <<~'SOURCE'
class HeredocApp < Rails::Application
end
SOURCE
module RealApp
  class Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "real-app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Rails declarations in a second heredoc body are ignored", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
EXAMPLES = [<<~FIRST, <<~SECOND]
plain text
FIRST
class HeredocApp < Rails::Application
SECOND
module RealApp
  class Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "real-app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("plain heredoc requires an unindented terminator", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
EXAMPLE = <<PLAIN
  PLAIN
class HeredocApp < Rails::Application
PLAIN
module RealApp
  class Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "real-app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Rails declarations in percent strings are ignored", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
EXAMPLE = %q{
class PercentStringApp < Rails::Application
end
}
module RealApp
  class Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "real-app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("heredoc-like text inside percent regex does not hide Rails metadata", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
PATTERN = %r{<<SOURCE}
module RealApp
  class Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "real-app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("left shift operator does not hide Rails metadata", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
VALUES = []
VALUES << IDENT
module RealApp
  class Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "real-app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Rails declarations after the data marker are ignored", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
module RealApp
  class Application < Rails::Application
  end
end
__END__
class DataApp < Rails::Application
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "real-app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("conditional Rails declarations use the directory fallback", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
if ENV["USE_APP"]
  class ConditionalApp < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Rails declaration in a boolean control expression uses the directory fallback", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
ENV["USE_APP"] and begin
  class ConditionalApp < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Rails declaration in a brace block uses the directory fallback", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
[true].each { |enabled|
  class ConditionalApp < Rails::Application
  end
}
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Rails declaration in an assigned conditional uses the directory fallback", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
guard = if ENV["USE_APP"]
  class ConditionalApp < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Rails declaration in a boolean begin block uses the directory fallback", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
ENV["USE_APP"] && begin
  class ConditionalApp < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("relative qualified Rails class inside a module is ambiguous", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
module Acme
  class Acme::Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("symlinked Rails application is a local boundary but is not read", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "outer.gemspec"), []byte(`
Gem::Specification.new "outer", "1.0.0" do |spec|
end
`))
		target := filepath.Join(root, "outside-application.rb")
		writeRubyFile(t, target, []byte(`class OutsideApp < Rails::Application; end`))
		applicationPath := filepath.Join(root, "app", "config", "application.rb")
		require.NoError(t, os.MkdirAll(filepath.Dir(applicationPath), 0o755))
		require.NoError(t, os.Symlink(target, applicationPath))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "app", service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
	})

	t.Run("multiple Rails application classes use the directory fallback", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
class FirstApp < Rails::Application
end
class SecondApp < Rails::Application
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("static gemspec supplies name and RubyGems version", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "bin", "server"), nil)
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new do |spec|
  spec.name = 'orders_service'.freeze
  spec.version = "1.2.0.pre.1"
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "ruby", []string{"bin/server"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders_service", service.UID.Name)
		assert.Equal(t, "1.2.0.pre.1", service.Metadata[serviceVersion])
	})

	t.Run("gemspec constructor literals are supported", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new "orders-api", "2025.08.21" do |spec|
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders-api", service.UID.Name)
		assert.Equal(t, "2025.08.21", service.Metadata[serviceVersion])
	})

	t.Run("dynamic gemspec version does not discard a static name", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new do |spec|
  spec.name = "orders-api"
  spec.version = Orders::VERSION
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders-api", service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
	})

	t.Run("ambiguous gemspecs stop lookup and use the direct script", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "outer.gemspec"), []byte(`
Gem::Specification.new "outer", "1.0.0" do |spec|
end
`))
		writeRubyFile(t, filepath.Join(root, "services", "orders", "one.gemspec"), nil)
		writeRubyFile(t, filepath.Join(root, "services", "orders", "two.gemspec"), nil)
		writeRubyFile(t, filepath.Join(root, "services", "orders", "bin", "worker.rb"), nil)
		fileInfo := mockRubyProcess(t, root, "/", "ruby", []string{"/services/orders/bin/worker.rb"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "worker", service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
	})

	for _, testCase := range []struct {
		name    string
		prepare func(*testing.T, string)
	}{
		{
			name: "malformed gemspec",
			prepare: func(t *testing.T, path string) {
				writeRubyFile(t, path, []byte(`Gem::Specification.new { dynamic_metadata }`))
			},
		},
		{
			name: "conditional gemspec",
			prepare: func(t *testing.T, path string) {
				writeRubyFile(t, path, []byte(`
Gem::Specification.new do |spec|
  if production?
    spec.name = "conditional"
    spec.version = "2.0.0"
  end
end
`))
			},
		},
		{
			name: "oversized gemspec",
			prepare: func(t *testing.T, path string) {
				writeRubyFile(t, path, make([]byte, maxRubyMetadataBytes+1))
			},
		},
		{
			name: "symlinked gemspec",
			prepare: func(t *testing.T, path string) {
				target := filepath.Join(filepath.Dir(filepath.Dir(path)), "target.gemspec")
				writeRubyFile(t, target, []byte(`
Gem::Specification.new "outside", "9.9.9" do |spec|
end
`))
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
				require.NoError(t, os.Symlink(target, path))
			},
		},
	} {
		t.Run(testCase.name+" is a nearest project boundary", func(t *testing.T) {
			root := t.TempDir()
			writeRubyFile(t, filepath.Join(root, "outer.gemspec"), []byte(`
Gem::Specification.new "outer", "1.0.0" do |spec|
end
`))
			testCase.prepare(t, filepath.Join(root, "services", "orders", "orders.gemspec"))
			writeRubyFile(t, filepath.Join(root, "services", "orders", "bin", "worker.rb"), nil)
			fileInfo := mockRubyProcess(t, root, "/", "ruby", []string{"/services/orders/bin/worker.rb"}, nil)

			err := ResolveServiceMetadata(fileInfo)

			require.NoError(t, err)
			service := fileInfo.ServiceAttrs()
			assert.Equal(t, "worker", service.UID.Name)
			assert.Empty(t, service.Metadata[serviceVersion])
		})
	}

	t.Run("directory enumeration cap prevents borrowing outer metadata", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "outer.gemspec"), []byte(`
Gem::Specification.new "outer", "1.0.0" do |spec|
end
`))
		project := filepath.Join(root, "services", "orders")
		writeRubyFile(t, filepath.Join(project, "server.rb"), nil)
		for index := range maxProjectEntries {
			writeRubyFile(t, filepath.Join(project, "entry-"+strconv.Itoa(index)), nil)
		}
		fileInfo := mockRubyProcess(t, root, "/", "ruby", []string{"/services/orders/server.rb"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "server", service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
	})

	for _, marker := range []string{"Gemfile", "Gemfile.lock", "config.ru"} {
		t.Run(marker+" is a boundary but direct script remains the fallback", func(t *testing.T) {
			root := t.TempDir()
			writeRubyFile(t, filepath.Join(root, "outer.gemspec"), []byte(`
Gem::Specification.new "outer", "9.9.9" do |spec|
end
`))
			writeRubyFile(t, filepath.Join(root, "app", marker), nil)
			writeRubyFile(t, filepath.Join(root, "app", "bin", "order_worker.rb"), nil)
			fileInfo := mockRubyProcess(t, root, "/app", "ruby", []string{"bin/order_worker.rb"}, nil)

			err := ResolveServiceMetadata(fileInfo)

			require.NoError(t, err)
			service := fileInfo.ServiceAttrs()
			assert.Equal(t, "order_worker", service.UID.Name)
			assert.Empty(t, service.Metadata[serviceVersion])
		})
	}

	for _, testCase := range []struct {
		name    string
		marker  string
		prepare func(*testing.T, string)
	}{
		{
			name:   "symlinked Gemfile",
			marker: "Gemfile",
			prepare: func(t *testing.T, path string) {
				target := filepath.Join(filepath.Dir(filepath.Dir(path)), "target-Gemfile")
				writeRubyFile(t, target, nil)
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
				require.NoError(t, os.Symlink(target, path))
			},
		},
		{
			name:   "directory Gemfile lock",
			marker: "Gemfile.lock",
			prepare: func(t *testing.T, path string) {
				require.NoError(t, os.MkdirAll(path, 0o755))
			},
		},
		{
			name:   "directory config ru",
			marker: "config.ru",
			prepare: func(t *testing.T, path string) {
				require.NoError(t, os.MkdirAll(path, 0o755))
			},
		},
	} {
		t.Run(testCase.name+" remains a local boundary", func(t *testing.T) {
			root := t.TempDir()
			writeRubyFile(t, filepath.Join(root, "outer.gemspec"), []byte(`
Gem::Specification.new "outer", "1.0.0" do |spec|
end
`))
			project := filepath.Join(root, "orders")
			testCase.prepare(t, filepath.Join(project, testCase.marker))
			fileInfo := mockRubyProcess(t, root, "/orders", "puma", nil, nil)

			err := ResolveServiceMetadata(fileInfo)

			require.NoError(t, err)
			service := fileInfo.ServiceAttrs()
			assert.Equal(t, "orders", service.UID.Name)
			assert.Empty(t, service.Metadata[serviceVersion])
		})
	}

	t.Run("cwd takes precedence over BUNDLE_GEMFILE", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "Gemfile"), nil)
		writeRubyFile(t, filepath.Join(root, "other", "Gemfile"), nil)
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, map[string]string{
			bundleGemfile: "/other/Gemfile",
		})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("explicit entrypoint project takes precedence over cwd and BUNDLE_GEMFILE", func(t *testing.T) {
		root := t.TempDir()
		for path, name := range map[string]string{
			"direct": "direct-service",
			"cwd":    "cwd-service",
			"bundle": "bundle-service",
		} {
			writeRubyFile(t, filepath.Join(root, path, name+".gemspec"), []byte(
				"Gem::Specification.new \""+name+"\", \"1.0.0\" do |spec|\nend\n",
			))
		}
		writeRubyFile(t, filepath.Join(root, "direct", "server.rb"), nil)
		writeRubyFile(t, filepath.Join(root, "bundle", "Gemfile"), nil)
		fileInfo := mockRubyProcess(t, root, "/cwd", "ruby", []string{"/direct/server.rb"}, map[string]string{
			bundleGemfile: "/bundle/Gemfile",
		})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "direct-service", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("hint-only Puma config continues discovery from cwd", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "etc", "puma", "orders.rb"), nil)
		writeRubyFile(t, filepath.Join(root, "app", "Gemfile"), nil)
		fileInfo := mockRubyProcess(t, root, "/app", "puma", []string{
			"--config", "/etc/puma/orders.rb",
		}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("authoritative Passenger application directory supplies a fallback", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "srv", "orders"), 0o755))
		fileInfo := mockRubyProcess(t, root, "/", "passenger", []string{"start", "/srv/orders"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("missing authoritative Passenger path does not fall through to cwd", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "Gemfile"), nil)
		fileInfo := mockRubyProcess(t, root, "/app", "passenger", []string{
			"start", "/missing/orders",
		}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("authoritative path inside GEM_HOME falls through to cwd", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "bundle", "orders"), 0o755))
		writeRubyFile(t, filepath.Join(root, "app", "Gemfile"), nil)
		fileInfo := mockRubyProcess(t, root, "/app", "passenger", []string{
			"start", "/bundle/orders",
		}, map[string]string{gemHome: "/bundle"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("authoritative path inside GEM_HOME can recover through BUNDLE_GEMFILE", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "bundle", "orders"), 0o755))
		writeRubyFile(t, filepath.Join(root, "app", "Gemfile.custom"), nil)
		fileInfo := mockRubyProcess(t, root, "/unrelated", "passenger", []string{
			"start", "/bundle/orders",
		}, map[string]string{
			gemHome:       "/bundle",
			bundleGemfile: "/app/Gemfile.custom",
		})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("config ru uses its project directory", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "opt", "orders", "config.ru"), nil)
		fileInfo := mockRubyProcess(t, root, "/", "rackup", []string{"/opt/orders/config.ru"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Sidekiq require path resolves the Rails project above config", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "opt", "orders", "config", "environment.rb"), nil)
		writeRubyFile(t, filepath.Join(root, "opt", "orders", "config", "application.rb"), []byte(`
module Orders
  class Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/", "sidekiq", []string{
			"--require", "/opt/orders/config/environment.rb",
		}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Sidekiq require file searches ancestor projects", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "opt", "orders", "config", "jobs.rb"), nil)
		writeRubyFile(t, filepath.Join(root, "opt", "orders", "config", "application.rb"), []byte(`
module Orders
  class Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/", "sidekiq", []string{
			"--require", "/opt/orders/config/jobs.rb",
		}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Sidekiq require inside GEM_HOME falls through to cwd Rails project", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "bundle", "gems", "worker", "environment.rb"), nil)
		writeRubyFile(t, filepath.Join(root, "app", "config", "application.rb"), []byte(`
module Orders
  class Application < Rails::Application
  end
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "sidekiq", []string{
			"--require", "/bundle/gems/worker/environment.rb",
		}, map[string]string{gemHome: "/bundle"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("BUNDLE_GEMFILE recovers a process inside GEM_HOME", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "bundle", "gems", "puma", "puma.gemspec"), []byte(`
Gem::Specification.new "puma", "6.0.0" do |spec|
end
`))
		writeRubyFile(t, filepath.Join(root, "app", "Gemfile.custom"), nil)
		fileInfo := mockRubyProcess(t, root, "/bundle/gems/puma", "puma", nil, map[string]string{
			gemHome:       "/bundle",
			bundleGemfile: "/app/Gemfile.custom",
		})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("GEM_PATH dependency roots are also suppressed", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "vendor", "gems", "tool", "tool.gemspec"), []byte(`
Gem::Specification.new "dependency", "6.0.0" do |spec|
end
`))
		writeRubyFile(t, filepath.Join(root, "vendor", "gems", "tool", "server.rb"), nil)
		writeRubyFile(t, filepath.Join(root, "app", "Gemfile.custom"), nil)
		fileInfo := mockRubyProcess(t, root, "/vendor/gems/tool", "ruby", []string{"server.rb"}, map[string]string{
			gemPath:       "/other:/vendor/gems",
			bundleGemfile: "/app/Gemfile.custom",
		})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	for _, envKey := range []string{gemHome, gemPath} {
		t.Run("relative "+envKey+" dependency root is suppressed", func(t *testing.T) {
			root := t.TempDir()
			writeRubyFile(t, filepath.Join(root, "app", "vendor", "bundle", "gems", "tool", "tool.gemspec"), []byte(`
Gem::Specification.new "dependency", "6.0.0" do |spec|
end
`))
			writeRubyFile(t, filepath.Join(root, "app", "vendor", "bundle", "gems", "tool", "server.rb"), nil)
			writeRubyFile(t, filepath.Join(root, "app", "Gemfile.custom"), nil)
			fileInfo := mockRubyProcess(t, root, "/app", "ruby", []string{
				"/app/vendor/bundle/gems/tool/server.rb",
			}, map[string]string{
				envKey:        "vendor/bundle",
				bundleGemfile: "/app/Gemfile.custom",
			})

			err := ResolveServiceMetadata(fileInfo)

			require.NoError(t, err)
			assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
		})
	}

	t.Run("deleted direct script retains its basename fallback", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "opt", "orders", ".keep"), nil)
		fileInfo := mockRubyProcess(t, root, "/", "ruby", []string{"/opt/orders/server.rb"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "server", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("process root is never used as a directory fallback", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "Gemfile"), nil)
		fileInfo := mockRubyProcess(t, root, "/", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("explicit name is preserved while a gemspec supplies version", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new "orders-api", "3.4.5" do |spec|
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)
		fileInfo.SetUID(svc.UID{Name: "configured", Namespace: "production"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "configured", service.UID.Name)
		assert.Equal(t, "production", service.UID.Namespace)
		assert.Equal(t, "3.4.5", service.Metadata[serviceVersion])
		assert.False(t, service.AutoName())
	})

	t.Run("explicit service version is preserved", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "app", "orders.gemspec"), []byte(`
Gem::Specification.new "orders-api", "3.4.5" do |spec|
end
`))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)
		fileInfo.SetMetadata(map[attr.Name]string{serviceVersion: "configured-version"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders-api", service.UID.Name)
		assert.Equal(t, "configured-version", service.Metadata[serviceVersion])
	})

	t.Run("project lookup never walks outside the process root", func(t *testing.T) {
		outer := t.TempDir()
		root := filepath.Join(outer, "process-root")
		writeRubyFile(t, filepath.Join(outer, "outer.gemspec"), []byte(`
Gem::Specification.new "host-project", "1.0.0" do |spec|
end
`))
		writeRubyFile(t, filepath.Join(root, "app", "server.rb"), nil)
		fileInfo := mockRubyProcess(t, root, "/app", "ruby", []string{"server.rb"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "server", fileInfo.ServiceAttrs().UID.Name)
		assert.Empty(t, fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("process lookup errors are returned", func(t *testing.T) {
		root := t.TempDir()
		expectedErr := errors.New("process disappeared")
		fileInfo := mockRubyProcessWithErrors(t, root, "/app", nil, nil, expectedErr, expectedErr)

		err := ResolveServiceMetadata(fileInfo)

		require.ErrorIs(t, err, expectedErr)
	})

	t.Run("project directory read errors are returned", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "not-a-directory"), nil)
		fileInfo := mockRubyProcess(t, root, "/not-a-directory", "puma", nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.Error(t, err)
		require.ErrorContains(t, err, "reading Ruby project directory")
	})
}

func TestPathEntryExistsDistinguishesFilesystemErrors(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "Gemfile")
	writeRubyFile(t, existing, nil)
	exists, err := pathEntryExists(existing)
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = pathEntryExists(filepath.Join(root, "missing"))
	require.NoError(t, err)
	assert.False(t, exists)

	invalid := filepath.Join(existing, "Gemfile.lock")
	exists, err = pathEntryExists(invalid)
	assert.False(t, exists)
	require.Error(t, err)
	require.ErrorContains(t, err, "checking Ruby project marker")
	require.ErrorContains(t, err, invalid)
}

func TestRootGemspecsReturnsDirectoryErrors(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	paths, boundary, err := rootGemspecs(missing)
	assert.Empty(t, paths)
	assert.False(t, boundary)
	require.Error(t, err)
	require.ErrorContains(t, err, "opening Ruby project directory")
	require.ErrorContains(t, err, missing)

	file := filepath.Join(root, "not-a-directory")
	writeRubyFile(t, file, nil)
	paths, boundary, err = rootGemspecs(file)
	assert.Empty(t, paths)
	assert.False(t, boundary)
	require.Error(t, err)
	require.ErrorContains(t, err, "reading Ruby project directory")
	require.ErrorContains(t, err, file)
}

func mockRubyProcess(
	t *testing.T,
	root, cwd, command string,
	args []string,
	env map[string]string,
) *exec.FileInfo {
	t.Helper()
	return mockRubyProcessWithErrors(t, root, cwd, env, []string{command}, nil, nil, args...)
}

func mockRubyProcessWithErrors(
	t *testing.T,
	root, cwd string,
	env map[string]string,
	command []string,
	cmdlineErr, cwdErr error,
	args ...string,
) *exec.FileInfo {
	t.Helper()

	oldRootDirForPID := rootDirForPID
	oldCmdlineForPID := cmdlineForPID
	oldCwdForPID := cwdForPID
	rootDirForPID = func(app.PID) string { return root }
	cmdlineForPID = func(app.PID) (string, []string, error) {
		var executable string
		if len(command) != 0 {
			executable = command[0]
		}
		return executable, args, cmdlineErr
	}
	cwdForPID = func(app.PID) (string, error) { return cwd, cwdErr }
	t.Cleanup(func() {
		rootDirForPID = oldRootDirForPID
		cmdlineForPID = oldCmdlineForPID
		cwdForPID = oldCwdForPID
	})

	return exec.New(exec.Init{
		Service: svc.Attrs{EnvVars: env},
		Pid:     123,
	})
}

func writeRubyFile(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, data, 0o644))
}
