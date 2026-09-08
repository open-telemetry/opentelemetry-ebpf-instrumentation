// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadRailsApplicationName(t *testing.T) {
	t.Run("reads a conventional Rails declaration", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "application.rb")
		writeRubyFile(t, path, []byte(`
module OrdersAPI
  class Application < Rails::Application
  end
end
`))

		assert.Equal(t, "orders-api", readRailsApplicationName(path))
	})

	t.Run("missing file yields empty result", func(t *testing.T) {
		assert.Empty(t, readRailsApplicationName(filepath.Join(t.TempDir(), "application.rb")))
	})

	t.Run("directory yields empty result", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "application.rb")
		require.NoError(t, os.Mkdir(path, 0o755))

		assert.Empty(t, readRailsApplicationName(path))
	})

	t.Run("symlink yields empty result", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.rb")
		writeRubyFile(t, target, []byte("class WrongApp < Rails::Application\n"))
		path := filepath.Join(dir, "application.rb")
		require.NoError(t, os.Symlink(target, path))

		assert.Empty(t, readRailsApplicationName(path))
	})

	t.Run("oversized file yields empty result", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "application.rb")
		writeRubyFile(t, path, make([]byte, maxRailsApplicationBytes+1))

		assert.Empty(t, readRailsApplicationName(path))
	})
}

func TestScanRailsApplicationName(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected string
	}{
		{
			name: "generated Rails layout",
			source: `require "rails/all"
module StoreFront
  class Application < Rails::Application
  end
end`,
			expected: "store-front",
		},
		{
			name: "qualified module",
			source: `module Acme::Orders
  class Application < ::Rails::Application
  end
end`,
			expected: "acme/orders",
		},
		{
			name:     "direct application class",
			source:   "class BillingService < Rails::Application\nend",
			expected: "billing-service",
		},
		{
			name:     "qualified application class",
			source:   "class Billing::Application < Rails::Application # app\nend",
			expected: "billing",
		},
		{
			name: "nearest module is used",
			source: `module Helper
end
module Orders
  class Application < Rails::Application
  end
end`,
			expected: "orders",
		},
		{
			name: "commented declarations are ignored",
			source: `# module Wrong
# class Application < Rails::Application
module Right
  class Application < Rails::Application
  end
end`,
			expected: "right",
		},
		{
			name:     "application without a module falls back",
			source:   "class Application < Rails::Application\nend",
			expected: "",
		},
		{
			name:     "dynamic application falls back",
			source:   "Application = Class.new(Rails::Application)",
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanner := bufio.NewScanner(bytes.NewBufferString(test.source))
			assert.Equal(t, test.expected, scanRailsApplicationName(scanner))
		})
	}
}

func TestRailsServiceName(t *testing.T) {
	assert.Equal(t, "my-http/app", railsServiceName("MyHTTP::App::Application"))
}
