// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configwatch

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/obi"
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

func TestConfigFileWatcherStartup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		port    int
		refresh bool
	}{
		{name: "unchanged startup file", port: 8080},
		{name: "file changed before watcher starts", port: 9090, refresh: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "obi.yml")
			initial := watcherConfig(8080)
			require.NoError(t, os.WriteFile(path, initial, 0o600))
			if tc.refresh {
				require.NoError(t, os.WriteFile(path, watcherConfig(tc.port), 0o600))
			}
			// A change applies once a second poll reads it unchanged.
			ticks := make(chan time.Time, 1)
			ticks <- time.Now()
			close(ticks)
			records := make(chan slog.Record, 10)
			logger := slog.New(configWatchLog{records: records})
			var refreshed []*obi.Config
			watchConfigFile(t.Context(), path, initial, func(_ context.Context, cfg *obi.Config) error {
				refreshed = append(refreshed, cfg)
				return nil
			}, logger, ticks)

			if tc.refresh {
				require.Len(t, refreshed, 1)
				criteria := discover.FindingCriteria(refreshed[0])
				require.True(t, criteria[0].GetOpenPorts().Matches(tc.port))
				require.Equal(t, slog.LevelInfo, readConfigLog(t, records).Level)
			} else {
				require.Empty(t, refreshed, "startup configuration must not trigger a refresh")
			}
			require.Empty(t, records)
		})
	}
}

func TestConfigFileWatcherRetriesRejectedUpdate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		pids      []int
		errorLogs int
	}{
		{name: "same rejection", pids: []int{10, 10}, errorLogs: 1},
		{name: "different rejection", pids: []int{10, 20}, errorLogs: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "obi.yml")
			initial := watcherConfig(8080)
			require.NoError(t, os.WriteFile(path, watcherConfig(9090), 0o600))
			// One poll waits for the change to settle and one confirms the accepted file is skipped.
			ticks := make(chan time.Time, len(tc.pids)+2)
			for range cap(ticks) {
				ticks <- time.Now()
			}
			close(ticks)
			records := make(chan slog.Record, 10)
			logger := slog.New(configWatchLog{records: records})
			attempts := 0
			var applied *obi.Config
			watchConfigFile(t.Context(), path, initial, func(_ context.Context, cfg *obi.Config) error {
				attempts++
				criteria := discover.FindingCriteria(cfg)
				require.True(t, criteria[0].GetOpenPorts().Matches(9090))
				if attempts <= len(tc.pids) {
					return fmt.Errorf("service settings would change for PID %d; restart OBI to apply this configuration", tc.pids[attempts-1])
				}
				// The blocking processes have exited; the unchanged file can now apply.
				applied = cfg
				return nil
			}, logger, ticks)

			require.Equal(t, len(tc.pids)+1, attempts, "retry until accepted, then skip the unchanged file")
			require.NotNil(t, applied)
			for range tc.errorLogs {
				require.Equal(t, slog.LevelError, readConfigLog(t, records).Level)
			}
			require.Equal(t, slog.LevelInfo, readConfigLog(t, records).Level)
			require.Empty(t, records)
		})
	}
}

func TestConfigFileWatcherSkipsPartialWrite(t *testing.T) {
	complete := []byte(`file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    daemon:
      logging:
        debug_trace_output: text
    capture:
      policy:
        default_action: exclude
      rules:
        - action: include
          match:
            process:
              open_ports: 8080
        - action: include
          match:
            process:
              open_ports: 9090
`)
	// The first rule alone is still a valid configuration.
	partial := complete[:bytes.LastIndex(complete, []byte("        - action"))]
	_, err := loadConfig(partial)
	require.NoError(t, err)

	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "obi.yml")
		initial := watcherConfig(7070)
		require.NoError(t, os.WriteFile(path, initial, 0o600))
		ticks := make(chan time.Time)
		records := make(chan slog.Record, 10)
		logger := slog.New(configWatchLog{records: records})
		refreshed := make(chan *obi.Config, 10)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			watchConfigFile(ctx, path, initial, func(_ context.Context, cfg *obi.Config) error {
				refreshed <- cfg
				return nil
			}, logger, ticks)
		}()

		// Waiting for the watcher to block between polls makes each write visible to exactly one poll.
		for _, contents := range [][]byte{partial, complete, complete} {
			synctest.Wait()
			require.NoError(t, os.WriteFile(path, contents, 0o600))
			ticks <- time.Now()
		}
		synctest.Wait()
		cancel()
		<-done

		require.Len(t, refreshed, 1)
		criteria := discover.FindingCriteria(<-refreshed)
		require.Len(t, criteria, 2)
		require.Equal(t, slog.LevelInfo, readConfigLog(t, records).Level)
		require.Empty(t, records)
	})
}

func TestConfigFileWatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obi.yml")
	initial := watcherConfig(8080)
	require.NoError(t, os.WriteFile(path, initial, 0o600))
	cfg, err := loadConfig(initial)
	require.NoError(t, err)
	require.True(t, cfg.Enabled(obi.FeatureAppO11y))
	require.False(t, cfg.Enabled(obi.FeatureNetO11y))
	require.False(t, cfg.Enabled(obi.FeatureStatsO11y))
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
	go func() { defer close(done); watchConfigFile(ctx, path, initial, updater.Update, logger, ticks) }()
	// A change applies once a second poll reads it unchanged.
	pollChange := func() {
		ticks <- time.Now()
		ticks <- time.Now()
	}
	for range 2 {
		select {
		case ticks <- time.Now():
		case <-time.After(time.Second):
			t.Fatal("config watcher did not finish the unchanged poll")
		}
		require.Empty(t, records)
		require.Empty(t, updates.Changed(), "unchanged configuration must not trigger a rescan")
	}

	replacement := path + ".new"
	require.NoError(t, os.WriteFile(replacement, watcherConfig(9090), 0o600))
	require.NoError(t, os.Rename(replacement, path))
	pollChange()
	require.Equal(t, slog.LevelInfo, readConfigLog(t, records).Level)
	criteria, _ := updates.Current()
	require.True(t, criteria[0].GetOpenPorts().Matches(9090))
	require.False(t, criteria[0].GetOpenPorts().Matches(8080))

	incompatible := strings.ReplaceAll(string(watcherConfig(9090)), "debug_trace_output: text", "debug_trace_output: json")
	require.NoError(t, os.WriteFile(path, []byte(incompatible), 0o600))
	pollChange()
	failure := readConfigLog(t, records)
	require.Equal(t, slog.LevelError, failure.Level)
	require.Contains(t, failure.Message, "can't refresh configuration")
	require.Contains(t, failure.Message, "retrying")
	criteria, _ = updates.Current()
	require.True(t, criteria[0].GetOpenPorts().Matches(9090))

	require.NoError(t, os.WriteFile(path, []byte("extensions: ["), 0o600))
	pollChange()
	require.Equal(t, slog.LevelError, readConfigLog(t, records).Level)

	// Removing the final include rule must reach the updater even with no other active features.
	idle := []byte(`file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: exclude
      rules: []
    daemon:
      logging:
        debug_trace_output: text
`)
	require.NoError(t, os.WriteFile(path, idle, 0o600))
	pollChange()
	result := readConfigLog(t, records)
	require.Equal(t, slog.LevelInfo, result.Level, "%v", result)
	criteria, _ = updates.Current()
	require.Empty(t, criteria)

	// Adding an include rule resumes selection after the pipeline became idle.
	require.NoError(t, os.WriteFile(path, initial, 0o600))
	pollChange()
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
