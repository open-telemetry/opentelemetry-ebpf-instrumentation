// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func newTestDecorator(ignoredPaths []string) *languageDecorator {
	return &languageDecorator{
		log:          slog.With("component", "LanguageDecorator"),
		ignoredPaths: ignoredPaths,
	}
}

func TestIsIgnoredPath(t *testing.T) {
	ld := newTestDecorator([]string{
		"/lib/systemd/",
		"/usr/lib/systemd/",
		"/usr/libexec/",
		"/sbin/",
		"/usr/sbin/",
	})

	tests := []struct {
		name     string
		exePath  string
		expected bool
	}{
		{
			name:     "systemd unit",
			exePath:  "/lib/systemd/systemd-journald",
			expected: true,
		},
		{
			name:     "usr systemd unit",
			exePath:  "/usr/lib/systemd/systemd-logind",
			expected: true,
		},
		{
			name:     "libexec helper",
			exePath:  "/usr/libexec/polkitd",
			expected: true,
		},
		{
			name:     "sbin binary",
			exePath:  "/sbin/init",
			expected: true,
		},
		{
			name:     "usr sbin binary",
			exePath:  "/usr/sbin/sshd",
			expected: true,
		},
		{
			name:     "user application in /usr/bin",
			exePath:  "/usr/bin/myapp",
			expected: false,
		},
		{
			name:     "user application in /home",
			exePath:  "/home/user/app/server",
			expected: false,
		},
		{
			name:     "empty path",
			exePath:  "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ld.isIgnoredPath(tt.exePath))
		})
	}
}

func TestIsIgnoredPathEmptyList(t *testing.T) {
	ld := newTestDecorator(nil)
	assert.False(t, ld.isIgnoredPath("/sbin/init"))
	assert.False(t, ld.isIgnoredPath("/usr/bin/myapp"))
}

func TestDecorateEventIgnoredPath(t *testing.T) {
	ld := newTestDecorator([]string{"/sbin/", "/usr/sbin/"})

	_executableReady = func(pid app.PID) (string, bool) {
		if pid == 1 {
			return "/sbin/init", true
		}

		return "", false
	}
	defer func() {
		_executableReady = ExecutableReady
	}()

	ev := Event[ProcessAttrs]{
		Type: EventCreated,
		Obj:  ProcessAttrs{pid: 1, detectedType: svc.InstrumentableUnknown},
	}

	ld.decorateEvent(&ev)

	assert.Equal(t, svc.InstrumentableUnknown, ev.Obj.detectedType)
}

func TestDecorateEventChecksEachPID(t *testing.T) {
	ld := newTestDecorator(nil)
	_executableReady = func(app.PID) (string, bool) { return "/usr/bin/apphost", true }
	t.Cleanup(func() {
		_executableReady = ExecutableReady
		_findProcLanguage = procs.FindProcLanguage
	})

	want := []svc.InstrumentableType{svc.InstrumentableGeneric, svc.InstrumentableDotnet}
	_findProcLanguage = func(pid app.PID) (svc.InstrumentableType, error) {
		return want[int(pid)-1], nil
	}
	for i, lang := range want {
		ev := Event[ProcessAttrs]{Type: EventCreated, Obj: ProcessAttrs{pid: app.PID(i + 1)}}
		ld.decorateEvent(&ev)
		assert.Equal(t, lang, ev.Obj.detectedType)
	}
}
