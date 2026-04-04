// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"log/slog"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func newTestDecorator(ignoredPaths []string) *languageDecorator {
	cache, _ := lru.New[cacheKey, svc.InstrumentableType](100)
	return &languageDecorator{
		typeCache:    cache,
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

	ev := Event[ProcessAttrs]{
		Type: EventCreated,
		Obj:  ProcessAttrs{pid: 1, detectedType: svc.InstrumentableUnknown},
	}

	ld.decorateEvent(&ev)

	assert.Equal(t, svc.InstrumentableUnknown, ev.Obj.detectedType)
}

func TestDecorateEventCachesResult(t *testing.T) {
	ld := newTestDecorator(nil)

	_findInodeForPID = func(pid app.PID) (uint64, uint64, error) {
		if pid == 1 {
			return 1, 12345, nil
		}

		return 0, 0, nil
	}

	_executableReady = func(pid app.PID) (string, bool) {
		if pid == 1 {
			return "/usr/bin/node", true
		}

		return "", false
	}

	defer func() {
		_findInodeForPID = FindINodeForPID
		_executableReady = ExecutableReady
	}()

	// Pre-populate the cache with a known dev:inode -> type mapping
	ld.typeCache.Add(cacheKey{Dev: 1, Ino: 12345}, svc.InstrumentablePython)

	ev := Event[ProcessAttrs]{
		Type: EventCreated,
		Obj:  ProcessAttrs{pid: 1, detectedType: svc.InstrumentableUnknown},
	}

	ld.decorateEvent(&ev)

	assert.Equal(t, svc.InstrumentablePython, ev.Obj.detectedType)
}

func TestDecorateEventFirstTime(t *testing.T) {
	ld := newTestDecorator(nil)

	_findInodeForPID = func(pid app.PID) (uint64, uint64, error) {
		if pid == 1 {
			return 1, 12345, nil
		}

		return 0, 0, nil
	}

	_executableReady = func(pid app.PID) (string, bool) {
		if pid == 1 {
			return "/usr/bin/node", true
		}

		return "", false
	}

	_findProcLanguage = func(pid app.PID) svc.InstrumentableType {
		if pid == 1 {
			return svc.InstrumentablePython
		}

		return svc.InstrumentableUnknown
	}

	defer func() {
		_findInodeForPID = FindINodeForPID
		_executableReady = ExecutableReady
	}()

	ev := Event[ProcessAttrs]{
		Type: EventCreated,
		Obj:  ProcessAttrs{pid: 1, detectedType: svc.InstrumentableUnknown},
	}

	ld.decorateEvent(&ev)

	assert.Equal(t, svc.InstrumentablePython, ev.Obj.detectedType)
	// check that we cached the result
	_, ok := ld.typeCache.Get(cacheKey{Dev: 1, Ino: 12345})
	assert.True(t, ok)
}
