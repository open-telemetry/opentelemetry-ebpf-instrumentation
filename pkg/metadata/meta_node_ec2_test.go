// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/aws/smithy-go/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEC2SDKLoggerLevels(t *testing.T) {
	for _, tc := range []struct {
		name    string
		min     slog.Level
		class   logging.Classification
		format  string
		args    []any
		want    []string
		wantLog bool
	}{
		{
			name:    "warn",
			min:     slog.LevelInfo,
			class:   logging.Warn,
			format:  "falling back to IMDSv1: %s",
			args:    []any{"403"},
			want:    []string{"level=WARN", "falling back to IMDSv1: 403", "component=meta.NodeMeta.ec2"},
			wantLog: true,
		},
		{
			name:   "debug suppressed at info",
			min:    slog.LevelInfo,
			class:  logging.Debug,
			format: "request %s",
			args:   []any{"PUT"},
		},
		{
			name:    "debug kept",
			min:     slog.LevelDebug,
			class:   logging.Debug,
			format:  "request %s",
			args:    []any{"PUT"},
			want:    []string{"level=DEBUG", "request PUT", "component=meta.NodeMeta.ec2"},
			wantLog: true,
		},
		{
			name:    "other classification is info",
			min:     slog.LevelInfo,
			class:   "INFO",
			format:  "other %d",
			args:    []any{1},
			want:    []string{"level=INFO", "other 1"},
			wantLog: true,
		},
		{
			name:   "warn suppressed at error",
			min:    slog.LevelError,
			class:  logging.Warn,
			format: "falling back to IMDSv1: %s",
			args:   []any{"403"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: tc.min}))
			ec2SDKLogger(logger.With("component", "meta.NodeMeta.ec2")).Logf(tc.class, tc.format, tc.args...)
			got := buf.String()
			if !tc.wantLog {
				assert.Empty(t, got)
				return
			}
			for _, want := range tc.want {
				assert.Contains(t, got, want)
			}
		})
	}
}

func TestEC2SDKLoggerContext(t *testing.T) {
	handler := &ctxRecordHandler{level: slog.LevelInfo}
	logger := ec2SDKLogger(slog.New(handler))

	logger.Logf(logging.Warn, "without operation context")
	require.Equal(t, context.Background(), handler.ctx)

	cancelCtx, cancel := context.WithCancel(t.Context())
	child := context.WithValue(cancelCtx, ec2LogCtxKey{}, "detect")
	cancel()
	logging.WithContext(child, logger).Logf(logging.Warn, "from detect")
	require.Equal(t, "detect", handler.ctx.Value(ec2LogCtxKey{}))
	require.ErrorIs(t, handler.ctx.Err(), context.Canceled)

	logger.Logf(logging.Warn, "still without operation context")
	require.Equal(t, context.Background(), handler.ctx)
}

type ec2LogCtxKey struct{}

type ctxRecordHandler struct {
	level slog.Level
	ctx   context.Context
}

func (h *ctxRecordHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *ctxRecordHandler) Handle(ctx context.Context, _ slog.Record) error {
	h.ctx = ctx
	return nil
}

func (h *ctxRecordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *ctxRecordHandler) WithGroup(string) slog.Handler { return h }

func TestEC2VPCID(t *testing.T) {
	t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", t.TempDir()+"/credentials")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	for _, tc := range []struct {
		name      string
		macStatus int
		vpcStatus int
		disabled  bool
		wantError bool
	}{
		{name: "primary interface", macStatus: http.StatusOK, vpcStatus: http.StatusOK},
		{name: "MAC unavailable", macStatus: http.StatusNotFound, wantError: true},
		{name: "VPC unavailable", macStatus: http.StatusOK, vpcStatus: http.StatusNotFound, wantError: true},
		{name: "IMDS disabled", disabled: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.False(t, tc.disabled)
				switch r.URL.Path {
				case "/latest/api/token":
					assert.Equal(t, http.MethodPut, r.Method)
					w.Header().Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
					fmt.Fprint(w, "token")
				case "/latest/meta-data/mac":
					assert.Equal(t, "token", r.Header.Get("X-aws-ec2-metadata-token"))
					w.WriteHeader(tc.macStatus)
					fmt.Fprint(w, " 0e:49:61:0f:c3:11\n")
				case "/latest/meta-data/network/interfaces/macs/0e:49:61:0f:c3:11/vpc-id":
					w.WriteHeader(tc.vpcStatus)
					fmt.Fprint(w, " vpc-local\n")
				default:
					t.Errorf("unexpected metadata path %q", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(server.Close)
			t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
			t.Setenv("AWS_EC2_METADATA_DISABLED", strconv.FormatBool(tc.disabled))
			id, err := ec2VPCID(t.Context())
			if tc.wantError {
				require.Error(t, err)
				require.Empty(t, id)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "vpc-local", id)
			var node NodeMeta
			node.merge(NodeMeta{EC2VPCID: id})
			node.merge(NodeMeta{HostID: "overridden"})
			require.Equal(t, id, node.EC2VPCID)
		})
	}
}
