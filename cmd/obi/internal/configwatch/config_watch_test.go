// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configwatch

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/discover"
)

func watcherConfig(port int) []byte {
	return fmt.Appendf(nil, `file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: exclude
      rules:
        - action: include
          match:
            process:
              open_ports: %d
    daemon:
      logging:
        debug_trace_output: text
`, port)
}

type configWatchLog struct {
	records chan slog.Record
}

func (l configWatchLog) Enabled(context.Context, slog.Level) bool { return true }
func (l configWatchLog) Handle(_ context.Context, record slog.Record) error {
	l.records <- record.Clone()
	return nil
}

func TestConfigFileWatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obi.yml")
	initial := watcherConfig(8080)
	require.NoError(t, os.WriteFile(path, initial, 0o600))
	cfg, err := loadConfig(initial)
	require.NoError(t, err)
	updater := discover.NewCriteriaUpdater(cfg)
	updates := updater.Updates()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Matcher reconciliation is covered in discover; acknowledge its boundary here.
	go func() {
		defer updates.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case update := <-updates.Requests():
				updates.Complete(update, nil)
			}
		}
	}()
	ticks := make(chan time.Time)
	records := make(chan slog.Record, 10)
	logger := slog.New(configWatchLog{records: records})
	done := make(chan struct{})
	go func() { defer close(done); watchConfigFile(ctx, path, updater.Update, logger, ticks) }()
	require.Equal(t, slog.LevelInfo, readConfigLog(t, records).Level)

	replacement := path + ".new"
	require.NoError(t, os.WriteFile(replacement, watcherConfig(9090), 0o600))
	require.NoError(t, os.Rename(replacement, path))
	ticks <- time.Now()
	require.Equal(t, slog.LevelInfo, readConfigLog(t, records).Level)
	criteria, _ := updates.Current()
	require.True(t, criteria[0].GetOpenPorts().Matches(9090))
	require.False(t, criteria[0].GetOpenPorts().Matches(8080))

	incompatible := strings.ReplaceAll(string(watcherConfig(9090)), "debug_trace_output: text", "debug_trace_output: json")
	require.NoError(t, os.WriteFile(path, []byte(incompatible), 0o600))
	ticks <- time.Now()
	failure := readConfigLog(t, records)
	require.Equal(t, slog.LevelError, failure.Level)
	require.Contains(t, failure.Message, "can't refresh configuration")
	require.Contains(t, failure.Message, "restart OBI")
	criteria, _ = updates.Current()
	require.True(t, criteria[0].GetOpenPorts().Matches(9090))

	require.NoError(t, os.WriteFile(path, []byte("extensions: ["), 0o600))
	ticks <- time.Now()
	require.Equal(t, slog.LevelError, readConfigLog(t, records).Level)

	// A valid edit after rejection still refreshes from the last accepted criteria.
	require.NoError(t, os.WriteFile(path, initial, 0o600))
	ticks <- time.Now()
	require.Equal(t, slog.LevelInfo, readConfigLog(t, records).Level)
	criteria, _ = updates.Current()
	require.True(t, criteria[0].GetOpenPorts().Matches(8080))

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("config watcher did not stop")
	}
}

func readConfigLog(t *testing.T, records <-chan slog.Record) slog.Record {
	t.Helper()
	select {
	case record := <-records:
		return record
	case <-time.After(time.Second):
		t.Fatal("config watcher did not log a result")
		return slog.Record{}
	}
}

func (l configWatchLog) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l configWatchLog) WithGroup(string) slog.Handler      { return l }
