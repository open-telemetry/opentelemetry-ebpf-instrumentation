// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPHPFPM(t *testing.T) {
	tests := []struct {
		name       string
		executable string
		want       bool
	}{
		{name: "standard name", executable: "/usr/sbin/php-fpm", want: true},
		{name: "versioned name", executable: "/usr/sbin/php-fpm8.3", want: true},
		{name: "case insensitive", executable: `/opt/PHP-FPM.EXE`, want: true},
		{name: "directory is ignored", executable: "/php-fpm/php", want: false},
		{name: "CLI", executable: "/usr/bin/php", want: false},
		{name: "empty", executable: "", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, isPHPFPM(test.executable))
		})
	}
}

func TestPHPScriptArgument(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "no arguments"},
		{name: "first positional", args: []string{"bin/console", "arg"}, want: "bin/console"},
		{name: "unknown options", args: []string{"-n", "--quiet", "index.php"}, want: "index.php"},
		{name: "separator", args: []string{"--", "-script.php"}, want: "-script.php"},
		{name: "separator without script", args: []string{"--"}},
		{name: "short file", args: []string{"-f", "index.php"}, want: "index.php"},
		{name: "long file", args: []string{"--file", "index.php"}, want: "index.php"},
		{name: "short process file", args: []string{"-F", "index.php"}, want: "index.php"},
		{name: "long process file", args: []string{"--process-file", "index.php"}, want: "index.php"},
		{name: "inline file", args: []string{"--file=index.php"}, want: "index.php"},
		{name: "inline process file", args: []string{"--process-file=index.php"}, want: "index.php"},
		{name: "empty inline file", args: []string{"--file="}},
		{name: "file option without value", args: []string{"-f"}},
		{name: "options with values are skipped", args: []string{"-c", "php.ini", "-d", "display_errors=1", "index.php"}, want: "index.php"},
		{name: "option without value", args: []string{"--docroot"}},
		{name: "short run code", args: []string{"-r", "echo 1;", "not-a-script.php"}},
		{name: "long run code", args: []string{"--run", "echo 1;", "not-a-script.php"}},
		{name: "process begin", args: []string{"-B", "begin();", "not-a-script.php"}},
		{name: "process code", args: []string{"-R", "run();", "not-a-script.php"}},
		{name: "process end", args: []string{"-E", "end();", "not-a-script.php"}},
		{name: "long process code", args: []string{"--process-code", "run();", "not-a-script.php"}},
		{name: "code option without value", args: []string{"-r"}},
		{name: "separator after code mode", args: []string{"-r", "echo 1;", "--", "not-a-script.php"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, phpScriptArgument(test.args))
		})
	}
}

func TestOptionTakesNextArgument(t *testing.T) {
	for _, option := range []string{
		"-c", "--php-ini", "-d", "--define", "-S", "--server", "-t", "--docroot", "-z", "--zend-extension",
	} {
		t.Run(option, func(t *testing.T) {
			assert.True(t, optionTakesNextArgument(option))
		})
	}

	for _, option := range []string{"", "-n", "--file", "--define=value", "index.php"} {
		t.Run("other "+option, func(t *testing.T) {
			assert.False(t, optionTakesNextArgument(option))
		})
	}
}
