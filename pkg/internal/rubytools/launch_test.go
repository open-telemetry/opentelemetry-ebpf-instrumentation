// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRubyLaunchFindsDirectScript(t *testing.T) {
	assert.Equal(t, RubyLaunch{EntryPoint: "/opt/orders/server.rb"},
		ParseRubyLaunch("/usr/bin/ruby3.4", []string{"/opt/orders/server.rb", "--config", "worker.rb"}))
}

func TestParseRubyLaunchUsesApplicationArgvZero(t *testing.T) {
	assert.Equal(t, RubyLaunch{EntryPoint: "/opt/orders/bin/server"},
		ParseRubyLaunch("/opt/orders/bin/server", []string{"--config", "worker.rb"}))
}

func TestParseRubyLaunchRejectsUnknownRewrittenTitle(t *testing.T) {
	for _, command := range []string{
		"orders worker 2",
		"orders worker /srv/orders",
		"puma 6.4.2 (tcp://0.0.0.0:3000)",
		"/usr/bin/ruby: puma worker /srv/orders",
	} {
		t.Run(command, func(t *testing.T) {
			assert.Equal(t, RubyLaunch{}, ParseRubyLaunch(command, nil))
		})
	}
}

func TestParseRubyLaunchDoesNotNameOtherRubyInterpreters(t *testing.T) {
	for _, command := range []string{
		"/usr/bin/jruby",
		"/opt/truffleruby/bin/truffleruby",
	} {
		t.Run(command, func(t *testing.T) {
			assert.Equal(t, RubyLaunch{}, ParseRubyLaunch(command, []string{"app.rb"}))
		})
	}
}

func TestParseRubyLaunchDoesNotNameKnownTooling(t *testing.T) {
	for _, command := range []string{
		"bundle", "bundler", "rails", "rake", "rackup", "puma", "unicorn", "passenger", "sidekiq", "irb", "gem",
	} {
		t.Run(command, func(t *testing.T) {
			assert.Empty(t, ParseRubyLaunch("/usr/local/bin/"+command, nil).EntryPoint)
		})
	}
}

func TestParseRubyLaunchSkipsLongOptions(t *testing.T) {
	assert.Equal(t, RubyLaunch{EntryPoint: "/opt/orders/server"}, ParseRubyLaunch("ruby", []string{
		"--debug", "--backtrace-limit", "20", "--enable=frozen-string-literal", "--parser=prism", "/opt/orders/server",
	}))
}

func TestParseRubyLaunchSupportsDocumentedCRubyLongOptions(t *testing.T) {
	tests := [][]string{
		{"--disable", "gems", "app.rb"},
		{"--encoding=UTF-8", "app.rb"},
		{"--external-encoding", "UTF-8", "app.rb"},
		{"--internal-encoding=UTF-8", "app.rb"},
		{"--source-encoding=UTF-8", "app.rb"},
		{"--crash-report=crash.%p", "app.rb"},
		{"--verbose", "app.rb"},
		{"--yydebug", "app.rb"},
		{"--jit", "app.rb"},
		{"--jit-debug", "app.rb"},
		{"--jit-max-cache=100", "app.rb"},
		{"--jit-min-calls=10", "app.rb"},
		{"--jit-save-temps", "app.rb"},
		{"--jit-verbose=2", "app.rb"},
		{"--jit-wait", "app.rb"},
		{"--jit-warnings", "app.rb"},
		{"--mjit", "app.rb"},
		{"--mjit-debug", "app.rb"},
		{"--mjit-max-cache=100", "app.rb"},
		{"--mjit-min-calls=10", "app.rb"},
		{"--mjit-save-temps", "app.rb"},
		{"--mjit-verbose=2", "app.rb"},
		{"--mjit-wait", "app.rb"},
		{"--mjit-warnings", "app.rb"},
		{"--rjit", "app.rb"},
		{"--rjit-exec-mem-size=64", "app.rb"},
		{"--rjit-call-threshold=10", "app.rb"},
		{"--rjit-stats", "app.rb"},
		{"--rjit-disable", "app.rb"},
		{"--rjit-trace", "app.rb"},
		{"--rjit-trace-exits", "app.rb"},
		{"--rjit-dump-disasm", "app.rb"},
		{"--yjit", "app.rb"},
		{"--yjit-mem-size=128", "app.rb"},
		{"--yjit-exec-mem-size=64", "app.rb"},
		{"--yjit-call-threshold=10", "app.rb"},
		{"--yjit-cold-threshold=200000", "app.rb"},
		{"--yjit-max-versions=4", "app.rb"},
		{"--yjit-greedy-versioning", "app.rb"},
		{"--yjit-stats", "app.rb"},
		{"--yjit-log=/tmp/yjit.log", "app.rb"},
		{"--yjit-disable", "app.rb"},
		{"--yjit-code-gc", "app.rb"},
		{"--yjit-perf", "app.rb"},
		{"--yjit-trace-exits", "app.rb"},
		{"--yjit-trace-exits-sample-rate=10", "app.rb"},
		{"--zjit", "app.rb"},
		{"--zjit-mem-size=128", "app.rb"},
		{"--zjit-call-threshold=10", "app.rb"},
		{"--zjit-num-profiles=5", "app.rb"},
		{"--zjit-stats-quiet", "app.rb"},
		{"--zjit-stats=/tmp/zjit.json", "app.rb"},
		{"--zjit-disable", "app.rb"},
		{"--zjit-perf", "app.rb"},
		{"--zjit-log-compiled-iseqs=/tmp/zjit.log", "app.rb"},
		{"--zjit-trace-exits=send", "app.rb"},
		{"--zjit-trace-exits-sample-rate=10", "app.rb"},
	}

	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			assert.Equal(t, "app.rb", ParseRubyLaunch("ruby", args).EntryPoint)
		})
	}
}

func TestParseRubyLaunchStopsForTerminalLongModes(t *testing.T) {
	for _, args := range [][]string{
		{"--copyright", "app.rb"},
		{"--help", "app.rb"},
		{"--version", "app.rb"},
		{"--dump=version", "app.rb"},
		{"--dump=CoPy", "app.rb"},
		{"--dump", "u", "app.rb"},
		{"--dump=H", "app.rb"},
	} {
		t.Run(args[0], func(t *testing.T) {
			assert.Equal(t, RubyLaunch{}, ParseRubyLaunch("ruby", args))
		})
	}
}

func TestParseRubyLaunchKeepsProgramsForFileDumpModes(t *testing.T) {
	for _, option := range []string{
		"--dump=syntax",
		"--dump=PARSE",
		"--dump=insns",
		"--dump=yydebug",
		"--dump=parsetree_with_comment",
		"--dump=insns_without_opt",
		"--dump=syntax yydebug",
		"--dump=bogus",
	} {
		t.Run(option, func(t *testing.T) {
			assert.Equal(t, "app.rb", ParseRubyLaunch("ruby", []string{option, "app.rb"}).EntryPoint)
		})
	}
}

func TestParseRubyLaunchLogsUnknownDumpValue(t *testing.T) {
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	launch := ParseRubyLaunch("ruby", []string{"--dump=secret", "app.rb"})

	assert.Equal(t, "app.rb", launch.EntryPoint)
	assert.Contains(t, logs.String(), "unknown dump")
	assert.NotContains(t, logs.String(), "secret")
}

func TestParseRubyLaunchLogsSanitizedUnknownOption(t *testing.T) {
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	launch := ParseRubyLaunch("ruby", []string{"--future-option=secret", "app.rb"})

	assert.Empty(t, launch.EntryPoint)
	assert.Contains(t, logs.String(), "unknown option")
	assert.Contains(t, logs.String(), "--future-option")
	assert.NotContains(t, logs.String(), "secret")

	logs.Reset()
	launch = ParseRubyLaunch("ruby", []string{"-qsecret", "app.rb"})

	assert.Empty(t, launch.EntryPoint)
	assert.Contains(t, logs.String(), "option=-q")
	assert.NotContains(t, logs.String(), "secret")
}

func TestParseRubyLaunchRejectsUnknownRubyOptions(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "unknown long option with a separate config-looking operand",
			args: []string{"--quantum-gc", "/tmp/decoy/config.ru", "/srv/orders/app.rb"},
		},
		{
			name: "unknown long option with an attached config-looking operand",
			args: []string{"--teleport-bytecode=/tmp/decoy/config.ru", "/srv/orders/app.rb"},
		},
		{
			name: "unknown short option",
			args: []string{"-Q", "/tmp/decoy/config.ru", "/srv/orders/app.rb"},
		},
		{
			name: "unknown short option after a valid clustered option",
			args: []string{"-wQ", "/tmp/decoy/config.ru", "/srv/orders/app.rb"},
		},
		{
			name: "misspelled known option",
			args: []string{"--verbsoe", "/tmp/decoy/config.ru", "/srv/orders/app.rb"},
		},
		{
			name: "triple dash option",
			args: []string{"---crystal-ball", "/tmp/decoy/config.ru", "/srv/orders/app.rb"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, RubyLaunch{}, ParseRubyLaunch("ruby", test.args))
		})
	}
}

func TestParseRubyLaunchTreatsUnknownOptionsAfterTheProgramAsApplicationArguments(t *testing.T) {
	assert.Equal(t, RubyLaunch{EntryPoint: "/srv/orders/app.rb"}, ParseRubyLaunch("ruby", []string{
		"/srv/orders/app.rb", "--quantum-gc", "/tmp/decoy/config.ru",
	}))
}

func TestParseRubyLaunchDoesNotDeriveProjectPathsFromUnknownFrameworkOptions(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
	}{
		{
			name:    "Rails",
			command: "rails",
			args:    []string{"server", "--warp-drive=/tmp/decoy/config.ru"},
		},
		{
			name:    "Rake",
			command: "rake",
			args:    []string{"--parallel-universe", "/tmp/decoy/config.ru"},
		},
		{
			name:    "Bundler",
			command: "bundle",
			args:    []string{"--crystal-ball=/tmp/decoy/config.ru"},
		},
		{
			name:    "Bundler executable",
			command: "bundler",
			args:    []string{"--time-machine", "/tmp/decoy/config.ru"},
		},
		{
			name:    "Rackup",
			command: "rackup",
			args:    []string{"--quantum-mode", "/tmp/decoy/config.ru", "/srv/orders/config.ru"},
		},
		{
			name:    "Puma",
			command: "puma",
			args:    []string{"--warp-drive=/tmp/decoy/config.ru", "/srv/orders/config.ru"},
		},
		{
			name:    "Unicorn",
			command: "unicorn",
			args:    []string{"--teleport", "/tmp/decoy/config.ru", "/srv/orders/config.ru"},
		},
		{
			name:    "Unicorn Rails",
			command: "unicorn_rails",
			args:    []string{"-Q", "/tmp/decoy/config.ru", "/srv/orders/config.ru"},
		},
		{
			name:    "Sidekiq",
			command: "sidekiq",
			args:    []string{"--time-machine=/tmp/decoy/config.ru"},
		},
		{
			name:    "Passenger",
			command: "passenger",
			args:    []string{"--hovercraft", "/tmp/decoy/config.ru"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, RubyLaunch{}, ParseRubyLaunch(test.command, test.args))
		})
	}
}

func TestParseRubyLaunchKeepsRailsBinstubDespiteUnknownApplicationOptions(t *testing.T) {
	assert.Equal(t, RubyLaunch{ProjectPath: "/srv/orders/bin/rails"}, ParseRubyLaunch("ruby", []string{
		"/srv/orders/bin/rails", "server", "--warp-drive=/tmp/decoy/config.ru",
	}))
}

func TestParseRubyLaunchSupportsCRubyShortOptionGrammar(t *testing.T) {
	tests := [][]string{
		{"-acdnpslvwyU", "app.rb"},
		{"-0777w", "app.rb"},
		{"-W1w", "app.rb"},
		{"-W:no-experimental", "app.rb"},
		{"-KUw", "app.rb"},
		{"-C/opt/orders", "app.rb"},
		{"-C", "/opt/orders", "app.rb"},
		{"-X/opt/orders", "app.rb"},
		{"-EUTF-8", "app.rb"},
		{"-E", "UTF-8", "app.rb"},
		{"-Ilib", "app.rb"},
		{"-I", "lib", "app.rb"},
		{"-rjson", "app.rb"},
		{"-r", "json", "app.rb"},
		{"-F,", "app.rb"},
		{"-F", "app.rb"},
		{"-i.bak", "app.rb"},
		{"-x/tmp", "app.rb"},
	}

	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			assert.Equal(t, "app.rb", ParseRubyLaunch("ruby", args).EntryPoint)
		})
	}
}

func TestParseRubyLaunchLimitsOctalRecordSeparator(t *testing.T) {
	assert.Equal(t, "app.rb", ParseRubyLaunch("ruby", []string{"-0400w", "app.rb"}).EntryPoint)
	assert.Equal(t, RubyLaunch{}, ParseRubyLaunch("ruby", []string{"-01234w", "app.rb"}))
}

func TestParseRubyLaunchIgnoresNoFileModes(t *testing.T) {
	for _, args := range [][]string{
		{"-e", "run_server()", "app.rb"},
		{"-erun_server()", "app.rb"},
		{"-pe", "run_server()", "app.rb"},
		{"-h", "app.rb"},
		{"-", "app.rb"},
	} {
		t.Run(args[0], func(t *testing.T) {
			assert.Equal(t, RubyLaunch{}, ParseRubyLaunch("ruby", args))
		})
	}
}

func TestParseRubyLaunchSupportsPathSearch(t *testing.T) {
	for _, args := range [][]string{
		{"-S", "app.rb"},
		{"-wS", "app.rb"},
	} {
		t.Run(args[0], func(t *testing.T) {
			assert.Equal(t, "app.rb", ParseRubyLaunch("ruby", args).EntryPoint)
		})
	}
}

func TestParseRubyLaunchHonorsOptionTerminator(t *testing.T) {
	assert.Equal(t, "--server", ParseRubyLaunch("ruby", []string{"--", "--server", "worker.rb"}).EntryPoint)
}

func TestParseRubyLaunchSupportsAttachedFeatureOptions(t *testing.T) {
	for _, option := range []string{
		"--debug-frozen-string-literal",
		"--disable-gems",
		"--enable-frozen-string-literal",
		"--crash-report-crash.%p",
	} {
		t.Run(option, func(t *testing.T) {
			assert.Equal(t, "app.rb", ParseRubyLaunch("ruby", []string{option, "app.rb"}).EntryPoint)
		})
	}
}

func TestParseRubyLaunchRejectsValuesForBareLongOptions(t *testing.T) {
	for _, option := range []string{
		"--copyright=secret",
		"--help=secret",
		"--verbose=secret",
		"--version=secret",
		"--yydebug=secret",
	} {
		t.Run(option, func(t *testing.T) {
			var logs bytes.Buffer
			oldLogger := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
			t.Cleanup(func() { slog.SetDefault(oldLogger) })

			assert.Equal(t, RubyLaunch{}, ParseRubyLaunch("ruby", []string{option, "app.rb"}))
			assert.Contains(t, logs.String(), "unknown option")
			assert.NotContains(t, logs.String(), "secret")
		})
	}
}

func TestParseRubyLaunchFindsAuthoritativeRackProjectPaths(t *testing.T) {
	for _, tt := range []struct {
		name    string
		command string
		args    []string
		path    string
	}{
		{name: "rackup", command: "rackup", args: []string{"/opt/orders/config.ru"}, path: "/opt/orders/config.ru"},
		{name: "passenger start", command: "passenger", args: []string{"start", "/srv/orders"}, path: "/srv/orders"},
		{name: "passenger rackup", command: "passenger", args: []string{"--rackup", "/srv/orders/config.ru"}, path: "/srv/orders/config.ru"},
		{name: "passenger startup file", command: "passenger", args: []string{"--startup-file=/srv/orders/config.ru"}, path: "/srv/orders/config.ru"},
		{name: "passenger title", command: "Passenger RubyApp: /srv/orders", path: "/srv/orders"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			launch := ParseRubyLaunch(tt.command, tt.args)
			assert.Equal(t, tt.path, launch.ProjectPath)
			assert.True(t, launch.projectPathAuthoritative)
			assert.Empty(t, launch.EntryPoint)
		})
	}
}

func TestParseRubyLaunchIgnoresPassengerAppStartCommand(t *testing.T) {
	assert.Equal(t, RubyLaunch{}, ParseRubyLaunch("passenger", []string{
		"--app-start-command", "--startup-file=/srv/wrong/config.ru",
	}))
}

func TestParseRubyLaunchClassifiesRubyProgram(t *testing.T) {
	t.Run("config.ru", func(t *testing.T) {
		launch := ParseRubyLaunch("ruby", []string{"/opt/orders/config.ru"})
		assert.Equal(t, "/opt/orders/config.ru", launch.ProjectPath)
		assert.True(t, launch.projectPathAuthoritative)
		assert.Empty(t, launch.EntryPoint)
	})

	t.Run("application rails binstub", func(t *testing.T) {
		launch := ParseRubyLaunch("ruby", []string{"/opt/orders/bin/rails", "server"})
		assert.Equal(t, "/opt/orders/bin/rails", launch.ProjectPath)
		assert.False(t, launch.projectPathAuthoritative)
		assert.Empty(t, launch.EntryPoint)
	})
}

func TestParseRubyLaunchFindsFrameworkProjectHints(t *testing.T) {
	for _, tt := range []struct {
		name          string
		command       string
		args          []string
		path          string
		authoritative bool
	}{
		{name: "Puma short config", command: "puma", args: []string{"-C", "/opt/orders/config/puma.rb"}, path: "/opt/orders/config/puma.rb"},
		{name: "Puma config named config.ru", command: "puma", args: []string{"-C", "/etc/puma/config.ru"}, path: "/etc/puma/config.ru"},
		{name: "Puma attached config", command: "puma", args: []string{"--config=/opt/orders/config/puma.rb"}, path: "/opt/orders/config/puma.rb"},
		{name: "Puma application binstub", command: "/opt/orders/bin/puma", path: "/opt/orders/bin/puma"},
		{name: "Puma last config", command: "puma", args: []string{"-Cfirst.rb", "--config", "second.rb"}, path: "second.rb"},
		{name: "Puma rackup", command: "puma", args: []string{"-C", "/etc/puma/orders.rb", "/opt/orders/config.ru"}, path: "/opt/orders/config.ru", authoritative: true},
		{name: "Unicorn config", command: "unicorn", args: []string{"-c", "/opt/orders/config/unicorn.rb"}, path: "/opt/orders/config/unicorn.rb"},
		{name: "Unicorn config named config.ru", command: "unicorn", args: []string{"-c", "/etc/unicorn/config.ru"}, path: "/etc/unicorn/config.ru"},
		{name: "Unicorn attached config", command: "unicorn", args: []string{"--config-file=/opt/orders/config/unicorn.rb"}, path: "/opt/orders/config/unicorn.rb"},
		{name: "Unicorn rackup", command: "unicorn", args: []string{"-c", "/etc/unicorn/orders.rb", "/opt/orders/config.ru"}, path: "/opt/orders/config.ru", authoritative: true},
		{name: "Unicorn Rails config", command: "unicorn_rails", args: []string{"-c", "/opt/orders/config/unicorn.rb"}, path: "/opt/orders/config/unicorn.rb"},
		{name: "Ruby Unicorn Rails config", command: "/usr/bin/ruby", args: []string{"/usr/local/bin/unicorn_rails", "-c", "/opt/orders/config/unicorn.rb"}, path: "/opt/orders/config/unicorn.rb"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			launch := ParseRubyLaunch(tt.command, tt.args)
			assert.Equal(t, tt.path, launch.ProjectPath)
			assert.Equal(t, tt.authoritative, launch.projectPathAuthoritative)
			assert.Empty(t, launch.EntryPoint)
		})
	}
}

func TestParseRubyLaunchRedispatchesBundlerExec(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
	}{
		{
			name:    "bundle",
			command: "/usr/local/bin/bundle",
			args:    []string{"exec", "puma", "-C", "config/puma.rb"},
		},
		{
			name:    "bundler",
			command: "bundler",
			args:    []string{"exec", "puma", "--config=config/puma.rb"},
		},
		{
			name:    "Ruby bundle binstub",
			command: "ruby",
			args:    []string{"/usr/local/bin/bundle", "exec", "puma", "-Cconfig/puma.rb"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, RubyLaunch{ProjectPath: "config/puma.rb"}, ParseRubyLaunch(tt.command, tt.args))
		})
	}
}

func TestParseRubyLaunchFindsSidekiqEntryPoint(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		path string
	}{
		{name: "short require", args: []string{"-r", "/opt/orders/config/environment.rb"}, path: "/opt/orders/config/environment.rb"},
		{name: "attached require", args: []string{"--require=/opt/orders/config/environment.rb"}, path: "/opt/orders/config/environment.rb"},
		{name: "last require", args: []string{"-rfirst.rb", "--require", "second.rb"}, path: "second.rb"},
		{name: "option terminator", args: []string{"-r", "/srv/correct", "--", "--require", "/srv/wrong"}, path: "/srv/correct"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			launch := ParseRubyLaunch("sidekiq", tt.args)
			assert.Equal(t, tt.path, launch.EntryPoint)
			assert.Empty(t, launch.ProjectPath)
			assert.False(t, launch.projectPathAuthoritative)
		})
	}
}

func TestParseRubyLaunchOnlyUsesPositionalRackupFiles(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		args     []string
		expected RubyLaunch
	}{
		{
			name:    "Rackup PID option value",
			command: "rackup",
			args:    []string{"--pid", "/tmp/config.ru", "/srv/orders/app.ru"},
		},
		{
			name:    "Rackup attached PID option value",
			command: "rackup",
			args:    []string{"--pid=/tmp/config.ru", "/srv/orders/app.ru"},
		},
		{
			name:    "Rackup last positional",
			command: "rackup",
			args:    []string{"/tmp/config.ru", "/srv/orders/app.ru"},
		},
		{
			name:    "Puma tag option value",
			command: "puma",
			args:    []string{"--tag", "config.ru"},
		},
		{
			name:    "Puma attached tag option value",
			command: "puma",
			args:    []string{"--tag=config.ru"},
		},
		{
			name:    "Puma config option inside option value",
			command: "puma",
			args:    []string{"--tag", "-C/tmp/config.ru"},
		},
		{
			name:    "Puma attached short option value",
			command: "puma",
			args:    []string{"-pconfig.ru", "/srv/orders/config.ru"},
			expected: RubyLaunch{
				ProjectPath:              "/srv/orders/config.ru",
				projectPathAuthoritative: true,
			},
		},
		{
			name:    "Puma optional option value",
			command: "puma",
			args:    []string{"--bind-to-activated-sockets", "config.ru"},
		},
		{
			name:    "Puma attached-only long option",
			command: "puma",
			args:    []string{"--fork-worker", "config.ru"},
			expected: RubyLaunch{
				ProjectPath:              "config.ru",
				projectPathAuthoritative: true,
			},
		},
		{
			name:    "Puma attached-only short option",
			command: "puma",
			args:    []string{"-f", "config.ru"},
			expected: RubyLaunch{
				ProjectPath:              "config.ru",
				projectPathAuthoritative: true,
			},
		},
		{
			name:    "Puma bundled config option",
			command: "puma",
			args:    []string{"-qC", "/etc/puma.rb", "/srv/orders/config.ru"},
			expected: RubyLaunch{
				ProjectPath:              "/srv/orders/config.ru",
				projectPathAuthoritative: true,
			},
		},
		{
			name:    "Puma positional after option",
			command: "puma",
			args:    []string{"--tag", "orders", "/srv/orders/config.ru"},
			expected: RubyLaunch{
				ProjectPath:              "/srv/orders/config.ru",
				projectPathAuthoritative: true,
			},
		},
		{
			name:    "Puma first positional",
			command: "puma",
			args:    []string{"/srv/orders/config.ru", "/tmp/other/config.ru"},
			expected: RubyLaunch{
				ProjectPath:              "/srv/orders/config.ru",
				projectPathAuthoritative: true,
			},
		},
		{
			name:    "Unicorn PID option value",
			command: "unicorn",
			args:    []string{"--pid", "/tmp/config.ru", "/srv/orders/config.ru"},
			expected: RubyLaunch{
				ProjectPath:              "/srv/orders/config.ru",
				projectPathAuthoritative: true,
			},
		},
		{
			name:    "Unicorn config option inside option value",
			command: "unicorn",
			args:    []string{"--pid", "-c/tmp/config.ru"},
		},
		{
			name:    "unknown option",
			command: "puma",
			args:    []string{"/srv/orders/config.ru", "--future-option", "value"},
		},
		{
			name:    "option terminator",
			command: "puma",
			args:    []string{"--tag", "orders", "--", "/srv/orders/config.ru"},
			expected: RubyLaunch{
				ProjectPath:              "/srv/orders/config.ru",
				projectPathAuthoritative: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, ParseRubyLaunch(test.command, test.args))
		})
	}
}

func TestParseRubyLaunchPassengerTitleWithoutPath(t *testing.T) {
	for _, command := range []string{
		"Passenger RubyApp: ",
		"Passenger RubyApp:    ",
	} {
		t.Run(command, func(t *testing.T) {
			assert.Equal(t, RubyLaunch{}, ParseRubyLaunch(command, nil))
		})
	}
}

func TestParseRubyLaunchBareRubyCommandWithoutArgs(t *testing.T) {
	assert.Equal(t, RubyLaunch{}, ParseRubyLaunch("ruby", nil))
	assert.Equal(t, RubyLaunch{}, ParseRubyLaunch("ruby", []string{}))
}

func TestParseRubyLaunchOptionTerminatorWithoutProgram(t *testing.T) {
	for _, args := range [][]string{
		{"--"},
		{"--", "-"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			assert.Equal(t, RubyLaunch{}, ParseRubyLaunch("ruby", args))
		})
	}
}

func TestParseRubyLaunchLongOptionMissingValue(t *testing.T) {
	for _, args := range [][]string{
		{"--encoding"},
		{"--dump"},
	} {
		t.Run(args[0], func(t *testing.T) {
			assert.Equal(t, RubyLaunch{}, ParseRubyLaunch("ruby", args))
		})
	}
}

func TestParseRubyLaunchNoProgramFound(t *testing.T) {
	assert.Equal(t, RubyLaunch{}, ParseRubyLaunch("ruby", []string{"--debug", "--verbose", "-w"}))
}

func TestIsCommandPath(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{name: "URI is not a path", command: "http://example.com/app.rb", want: false},
		{name: "space rules out a path even without a separator", command: "orders worker", want: false},
		{name: "absolute path", command: "/opt/orders/server", want: true},
		{name: "relative script by extension", command: "server.rb", want: true},
		{name: "bare tool name is not a path", command: "puma", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isCommandPath(tt.command))
		})
	}
}

func TestParseToolLaunch(t *testing.T) {
	tests := []struct {
		name    string
		tool    string
		command string
		args    []string
		want    RubyLaunch
	}{
		{
			name: "rackup positional config.ru is authoritative",
			tool: "rackup", command: "rackup", args: []string{"/opt/orders/config.ru"},
			want: RubyLaunch{ProjectPath: "/opt/orders/config.ru", projectPathAuthoritative: true},
		},
		{
			name: "rackup without a config.ru falls back to the command path",
			tool: "rackup", command: "/usr/bin/rackup", args: []string{"--pid", "1"},
			want: RubyLaunch{ProjectPath: "/usr/bin/rackup"},
		},
		{
			name: "puma short config option",
			tool: "puma", command: "puma", args: []string{"-C", "/etc/puma.rb"},
			want: RubyLaunch{ProjectPath: "/etc/puma.rb"},
		},
		{
			name: "puma positional config.ru overrides the config option",
			tool: "puma", command: "puma", args: []string{"-C", "/etc/puma.rb", "/opt/config.ru"},
			want: RubyLaunch{ProjectPath: "/opt/config.ru", projectPathAuthoritative: true},
		},
		{
			name: "unicorn config option",
			tool: "unicorn", command: "unicorn", args: []string{"-c", "/etc/unicorn.rb"},
			want: RubyLaunch{ProjectPath: "/etc/unicorn.rb"},
		},
		{
			name: "unicorn_rails shares the unicorn option table",
			tool: "unicorn_rails", command: "unicorn_rails", args: []string{"-c", "/etc/unicorn.rb"},
			want: RubyLaunch{ProjectPath: "/etc/unicorn.rb"},
		},
		{
			name: "sidekiq require path is an entrypoint",
			tool: "sidekiq", command: "sidekiq", args: []string{"-r", "/opt/env.rb"},
			want: RubyLaunch{EntryPoint: "/opt/env.rb"},
		},
		{
			name: "sidekiq without require yields nothing",
			tool: "sidekiq", command: "sidekiq", args: nil,
			want: RubyLaunch{},
		},
		{
			name: "passenger start",
			tool: "passenger", command: "passenger", args: []string{"start", "/srv/orders"},
			want: RubyLaunch{ProjectPath: "/srv/orders", projectPathAuthoritative: true},
		},
		{
			name: "passenger attached app-start-command is skipped",
			tool: "passenger", command: "passenger", args: []string{"--app-start-command=run"},
			want: RubyLaunch{},
		},
		{
			name: "passenger separate app-start-command value is skipped without affecting later options",
			tool: "passenger", command: "passenger", args: []string{"--app-start-command", "run", "--rackup", "/srv/config.ru"},
			want: RubyLaunch{ProjectPath: "/srv/config.ru", projectPathAuthoritative: true},
		},
		{
			name: "passenger dangling --rackup with nothing after it",
			tool: "passenger", command: "passenger", args: []string{"--rackup"},
			want: RubyLaunch{},
		},
		{
			name: "passenger dangling --startup-file with nothing after it",
			tool: "passenger", command: "passenger", args: []string{"--startup-file"},
			want: RubyLaunch{},
		},
		{
			name: "Bundler exec of a tool without a project hint yields nothing",
			tool: "bundle", command: "bundle", args: []string{"exec", "rails"},
			want: RubyLaunch{},
		},
		{
			name: "unknown tool with a path command keeps the command path",
			tool: "bundle", command: "/usr/bin/bundle", args: nil,
			want: RubyLaunch{ProjectPath: "/usr/bin/bundle"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseToolLaunch(tt.tool, tt.command, tt.args))
		})
	}
}

func TestLastLauncherOption(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		short string
		long  string
		want  string
	}{
		{name: "no arguments", args: nil, short: "-r", long: "--require", want: ""},
		{name: "attached short value", args: []string{"-rjson"}, short: "-r", long: "--require", want: "json"},
		{name: "separate short value", args: []string{"-r", "json"}, short: "-r", long: "--require", want: "json"},
		{name: "attached long value", args: []string{"--require=json"}, short: "-r", long: "--require", want: "json"},
		{name: "separate long value", args: []string{"--require", "json"}, short: "-r", long: "--require", want: "json"},
		{name: "last occurrence wins", args: []string{"-rfirst", "--require", "second"}, short: "-r", long: "--require", want: "second"},
		{name: "terminator stops scanning", args: []string{"-r", "correct", "--", "--require", "wrong"}, short: "-r", long: "--require", want: "correct"},
		{name: "short flag as last argument has no value", args: []string{"-r"}, short: "-r", long: "--require", want: ""},
		{name: "unrelated arguments are ignored", args: []string{"foo", "-x"}, short: "-r", long: "--require", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, lastLauncherOption(tt.args, tt.short, tt.long))
		})
	}
}

func TestParseLauncherArguments(t *testing.T) {
	options := map[string]optionArity{
		"-a":      launcherNoValue,
		"-b":      launcherRequiredValue,
		"-c":      launcherPlacedOptionalValue,
		"-d":      launcherAttachedOptionalValue,
		"--alpha": launcherNoValue,
		"--beta":  launcherRequiredValue,
		"--gamma": launcherPlacedOptionalValue,
		"--delta": launcherAttachedOptionalValue,
	}

	tests := []struct {
		name        string
		args        []string
		configShort string
		configLong  string
		want        launcherArguments
	}{
		{name: "no arguments", args: nil, want: launcherArguments{positionalsKnown: true}},
		{
			name: "collects first and last positional",
			args: []string{"pos1", "pos2", "pos3"},
			want: launcherArguments{firstPositional: "pos1", lastPositional: "pos3", positionalsKnown: true},
		},
		{
			name: "lone dash is a positional",
			args: []string{"-"},
			want: launcherArguments{firstPositional: "-", lastPositional: "-", positionalsKnown: true},
		},
		{
			name: "terminator collects everything after it as positional",
			args: []string{"--alpha", "--", "-x", "pos"},
			want: launcherArguments{firstPositional: "-x", lastPositional: "pos", positionalsKnown: true},
		},
		{
			name: "unknown long option stops parsing",
			args: []string{"--unknown", "pos"},
			want: launcherArguments{positionalsKnown: false},
		},
		{
			name: "attached value on a no-value long option is unknown",
			args: []string{"--alpha=x"},
			want: launcherArguments{positionalsKnown: false},
		},
		{
			name: "long required value attached sets the config path", args: []string{"--beta=foo"}, configLong: "--beta",
			want: launcherArguments{configPath: "foo", positionalsKnown: true},
		},
		{
			name: "long required value from the next argument", args: []string{"--beta", "foo"}, configLong: "--beta",
			want: launcherArguments{configPath: "foo", positionalsKnown: true},
		},
		{
			name: "long required value missing at the end of arguments",
			args: []string{"--beta"},
			want: launcherArguments{positionalsKnown: false},
		},
		{
			name: "long placed-optional value attached", args: []string{"--gamma=foo"}, configLong: "--gamma",
			want: launcherArguments{configPath: "foo", positionalsKnown: true},
		},
		{
			name: "long placed-optional value from a following non-option argument", args: []string{"--gamma", "foo"}, configLong: "--gamma",
			want: launcherArguments{configPath: "foo", positionalsKnown: true},
		},
		{
			name: "long placed-optional value is not taken when the next argument looks like an option",
			args: []string{"--gamma", "-a", "pos"}, configLong: "--gamma",
			want: launcherArguments{firstPositional: "pos", lastPositional: "pos", positionalsKnown: true},
		},
		{
			name: "long placed-optional value missing at the end of arguments",
			args: []string{"--gamma"},
			want: launcherArguments{positionalsKnown: true},
		},
		{
			name: "long attached-optional value stays empty without an attachment",
			args: []string{"--delta"},
			want: launcherArguments{positionalsKnown: true},
		},
		{
			name: "long attached-optional value uses the attached value", args: []string{"--delta=foo"}, configLong: "--delta",
			want: launcherArguments{configPath: "foo", positionalsKnown: true},
		},
		{
			name: "short cluster with an unknown flag stops parsing",
			args: []string{"-z"},
			want: launcherArguments{positionalsKnown: false},
		},
		{
			name: "short no-value flags cluster together",
			args: []string{"-aa"},
			want: launcherArguments{positionalsKnown: true},
		},
		{
			name: "short required value attached", args: []string{"-bfoo"}, configShort: "-b",
			want: launcherArguments{configPath: "foo", positionalsKnown: true},
		},
		{
			name: "short required value from the next argument", args: []string{"-b", "foo"}, configShort: "-b",
			want: launcherArguments{configPath: "foo", positionalsKnown: true},
		},
		{
			name: "short required value missing at the end of the cluster",
			args: []string{"-b"},
			want: launcherArguments{positionalsKnown: false},
		},
		{
			name: "short placed-optional value attached", args: []string{"-cfoo"}, configShort: "-c",
			want: launcherArguments{configPath: "foo", positionalsKnown: true},
		},
		{
			name: "short placed-optional value from a following non-option argument", args: []string{"-c", "foo"}, configShort: "-c",
			want: launcherArguments{configPath: "foo", positionalsKnown: true},
		},
		{
			name: "short placed-optional value is not taken when the next argument looks like an option",
			args: []string{"-c", "-a"},
			want: launcherArguments{positionalsKnown: true},
		},
		{
			name: "short placed-optional value missing at the end of the cluster",
			args: []string{"-c"},
			want: launcherArguments{positionalsKnown: true},
		},
		{
			name: "short attached-optional value uses the cluster remainder", args: []string{"-dfoo"}, configShort: "-d",
			want: launcherArguments{configPath: "foo", positionalsKnown: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseLauncherArguments(tt.args, options, tt.configShort, tt.configLong))
		})
	}
}

func TestLauncherArgumentsAddPositional(t *testing.T) {
	var args launcherArguments

	args.addPositional("first")
	assert.Equal(t, "first", args.firstPositional)
	assert.Equal(t, "first", args.lastPositional)

	args.addPositional("second")
	assert.Equal(t, "first", args.firstPositional)
	assert.Equal(t, "second", args.lastPositional)

	args.addPositional("third")
	assert.Equal(t, "first", args.firstPositional)
	assert.Equal(t, "third", args.lastPositional)
}

func TestAllowsAttachedLongValue(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "--debug", want: true},
		{name: "--jit", want: true},
		{name: "--jit-verbose", want: true},
		{name: "--mjit-wait", want: true},
		{name: "--rjit-trace-exits", want: true},
		{name: "--yjit-stats", want: true},
		{name: "--zjit-perf", want: true},
		{name: "--disable", want: false},
		{name: "--enable", want: false},
		{name: "--verbose", want: false},
		{name: "--help", want: false},
		{name: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, allowsAttachedLongValue(tt.name))
		})
	}
}

func TestLaunchFromProgram(t *testing.T) {
	tests := []struct {
		name    string
		program string
		args    []string
		want    RubyLaunch
	}{
		{
			name:    "config.ru is an authoritative project path",
			program: "/opt/orders/config.ru",
			want:    RubyLaunch{ProjectPath: "/opt/orders/config.ru", projectPathAuthoritative: true},
		},
		{
			name:    "known tool basename delegates to parseToolLaunch",
			program: "/usr/local/bin/puma", args: []string{"-C", "/etc/puma.rb"},
			want: RubyLaunch{ProjectPath: "/etc/puma.rb"},
		},
		{
			name:    "plain ruby script becomes the entry point",
			program: "/opt/orders/server.rb",
			want:    RubyLaunch{EntryPoint: "/opt/orders/server.rb"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, launchFromProgram(tt.program, tt.args))
		})
	}
}

func TestSplitLongOption(t *testing.T) {
	tests := []struct {
		option       string
		wantName     string
		wantValue    string
		wantAttached bool
	}{
		{option: "--verbose", wantName: "--verbose", wantValue: "", wantAttached: false},
		{option: "--debug=verbose", wantName: "--debug", wantValue: "verbose", wantAttached: true},
		{option: "--enable=frozen", wantName: "--enable", wantValue: "frozen", wantAttached: true},
		{option: "--enable-frozen-string-literal", wantName: "--enable", wantValue: "frozen-string-literal", wantAttached: true},
		{option: "--disable-gems", wantName: "--disable", wantValue: "gems", wantAttached: true},
		{option: "--crash-report-crash.%p", wantName: "--crash-report", wantValue: "crash.%p", wantAttached: true},
		{option: "--jit-verbose", wantName: "--jit-verbose", wantValue: "", wantAttached: false},
		{option: "--debug-", wantName: "--debug", wantValue: "", wantAttached: true},
	}

	for _, tt := range tests {
		t.Run(tt.option, func(t *testing.T) {
			name, value, attached := splitLongOption(tt.option)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantValue, value)
			assert.Equal(t, tt.wantAttached, attached)
		})
	}
}

func TestScanShortOption(t *testing.T) {
	tests := []struct {
		name            string
		option          string
		wantConsumeNext bool
		wantTerminal    bool
		wantValid       bool
	}{
		{name: "single no-value flag", option: "-a", wantValid: true},
		{name: "all no-value flags clustered", option: "-acdlnpsUvwy", wantValid: true},
		{name: "help is terminal", option: "-h", wantTerminal: true, wantValid: true},
		{name: "capital S is a no-value flag", option: "-S", wantValid: true},
		{name: "e is terminal", option: "-e", wantTerminal: true, wantValid: true},
		{name: "C as the last char in the cluster consumes the next argument", option: "-C", wantConsumeNext: true, wantValid: true},
		{name: "C not last in the cluster does not consume the next argument", option: "-Cx", wantValid: true},
		{name: "E as the last char consumes the next argument", option: "-E", wantConsumeNext: true, wantValid: true},
		{name: "I not last in the cluster", option: "-Ix", wantValid: true},
		{name: "X as the last char consumes the next argument", option: "-X", wantConsumeNext: true, wantValid: true},
		{name: "r as the last char consumes the next argument", option: "-r", wantConsumeNext: true, wantValid: true},
		{name: "r not last in the cluster", option: "-rx", wantValid: true},
		{name: "F is a non-terminal value flag", option: "-F", wantValid: true},
		{name: "F ignores trailing characters", option: "-Fx", wantValid: true},
		{name: "i is a non-terminal value flag", option: "-i", wantValid: true},
		{name: "x is a non-terminal value flag", option: "-x", wantValid: true},
		{name: "0 with nothing following", option: "-0", wantValid: true},
		{name: "0 consumes up to three octal digits", option: "-0777", wantValid: true},
		{name: "0 stops after three octal digits and rejects a fourth", option: "-01234", wantValid: false},
		{name: "0 stops at a non-octal character", option: "-0w", wantValid: true},
		{name: "K with nothing following", option: "-K", wantValid: true},
		{name: "K consumes exactly one following character", option: "-K5x", wantValid: true},
		{name: "K consumes its only following character", option: "-Kx", wantValid: true},
		{name: "W followed by a colon", option: "-W:", wantValid: true},
		{name: "W followed by an octal digit", option: "-W7", wantValid: true},
		{name: "W followed by neither a colon nor an octal digit", option: "-Wz", wantValid: false},
		{name: "W with nothing following", option: "-W", wantValid: true},
		{name: "unrecognized character is invalid", option: "-z", wantValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			consumeNext, terminal, valid := scanShortOption(tt.option)
			assert.Equal(t, tt.wantConsumeNext, consumeNext, "consumeNext")
			assert.Equal(t, tt.wantTerminal, terminal, "terminal")
			assert.Equal(t, tt.wantValid, valid, "valid")
		})
	}
}

func TestLogUnknownOption(t *testing.T) {
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	logUnknownOption("--future-option=secret")
	assert.Contains(t, logs.String(), "can't reliably discover Ruby entrypoint after unknown option")
	assert.Contains(t, logs.String(), "option=--future-option")
	assert.NotContains(t, logs.String(), "secret")

	logs.Reset()
	logUnknownOption("-qsecret")
	assert.Contains(t, logs.String(), "option=-q")
	assert.NotContains(t, logs.String(), "secret")
}

func TestSanitizedOptionName(t *testing.T) {
	tests := []struct {
		option string
		want   string
	}{
		{option: "--future-option=secret", want: "--future-option"},
		{option: "-qsecret", want: "-q"},
		{option: "-q", want: "-q"},
		{option: "--help", want: "--help"},
		{option: "-", want: "-"},
		{option: "value", want: "value"},
	}

	for _, tt := range tests {
		t.Run(tt.option, func(t *testing.T) {
			assert.Equal(t, tt.want, sanitizedOptionName(tt.option))
		})
	}
}

func TestClassifyDumpValue(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		wantTerminal bool
		wantKnown    bool
	}{
		{name: "exact terminal target", value: "version", wantTerminal: true, wantKnown: true},
		{name: "another exact terminal target", value: "copyright", wantTerminal: true, wantKnown: true},
		{name: "case-insensitive prefix of a terminal target", value: "VER", wantTerminal: true, wantKnown: true},
		{name: "exact non-terminal target", value: "yydebug", wantTerminal: false, wantKnown: true},
		{name: "prefix of a non-terminal target", value: "syn", wantTerminal: false, wantKnown: true},
		{name: "list of non-terminal targets", value: "syntax,insns yydebug", wantTerminal: false, wantKnown: true},
		{name: "list with one unknown item stays unknown", value: "syntax,bogus", wantTerminal: false, wantKnown: false},
		{name: "empty value has no items", value: "", wantTerminal: false, wantKnown: false},
		{name: "whitespace-only value has no items", value: "   ", wantTerminal: false, wantKnown: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			terminal, known := classifyDumpValue(tt.value)
			assert.Equal(t, tt.wantTerminal, terminal, "terminal")
			assert.Equal(t, tt.wantKnown, known, "known")
		})
	}
}
