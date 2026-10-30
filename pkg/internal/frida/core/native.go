// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_frida && linux && (amd64 || arm64)

package core // import "go.opentelemetry.io/obi/pkg/internal/frida/core"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// Session owns a script and its native signal subscriptions.
type Session struct {
	sessionState
	id                            uintptr
	handle                        uintptr
	messageHandler, detachHandler uint64
	detached                      sync.Once
}

var (
	sessionIDs atomic.Uint64
	sessions   sync.Map
)

type nativeError struct {
	_       uint32
	code    int32
	message *byte
}

// Engine owns Frida's device manager and the GLib loop dispatching signals.
// Only one engine lifetime is supported per process; its library stays mapped.
type Engine struct {
	handle                                         uintptr
	manager, device, loop                          uintptr
	loopDone                                       chan struct{}
	init, shutdown, deinit                         func()
	newManager                                     func() uintptr
	getDevice                                      func(uintptr, int32, int32, uintptr, **nativeError) uintptr
	attach                                         func(uintptr, uint32, uintptr, uintptr, **nativeError) uintptr
	create                                         func(uintptr, string, uintptr, uintptr, **nativeError) uintptr
	load, unload, eternalize, detach, closeManager func(uintptr, uintptr, **nativeError)
	post                                           func(uintptr, string, uintptr)
	isDetached                                     func(uintptr) int32
	unref                                          func(uintptr)
	errorFree                                      func(*nativeError)
	connect                                        func(uintptr, string, uintptr, uintptr, uintptr, int32) uint64
	disconnect                                     func(uintptr, uint64)
	newLoop                                        func(uintptr, int32) uintptr
	runLoop, quitLoop, unrefLoop                   func(uintptr)
	loopRunning                                    func(uintptr) int32
	newCancellable                                 func() uintptr
	cancel                                         func(uintptr)
}

var engineLifetime struct {
	sync.Mutex
	used bool
}
var callbacks struct {
	sync.Once
	message, detached uintptr
}

func Open(ctx context.Context, path string) (*Engine, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	engineLifetime.Lock()
	defer engineLifetime.Unlock()
	if engineLifetime.used {
		return nil, errors.New("frida Core has already been initialized in this process")
	}
	if path == "" {
		return nil, fmt.Errorf("%w: library path is required", ErrUnavailable)
	}
	handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("%w: loading Frida Core: %w", ErrUnavailable, err)
	}
	initialized := false
	defer func() {
		if !initialized {
			_ = purego.Dlclose(handle)
		}
	}()
	e := &Engine{handle: handle, loopDone: make(chan struct{})}
	bindings := []struct {
		target any
		name   string
	}{
		{&e.init, "frida_init"},
		{&e.shutdown, "frida_shutdown"},
		{&e.deinit, "frida_deinit"},
		{&e.newManager, "frida_device_manager_new"},
		{&e.getDevice, "frida_device_manager_get_device_by_type_sync"},
		{&e.attach, "frida_device_attach_sync"},
		{&e.create, "frida_session_create_script_sync"},
		{&e.load, "frida_script_load_sync"},
		{&e.unload, "frida_script_unload_sync"},
		{&e.eternalize, "frida_script_eternalize_sync"},
		{&e.detach, "frida_session_detach_sync"},
		{&e.closeManager, "frida_device_manager_close_sync"},
		{&e.post, "frida_script_post"},
		{&e.isDetached, "frida_session_is_detached"},
		{&e.unref, "frida_unref"},
		{&e.errorFree, "_frida_g_error_free"},
		{&e.connect, "_frida_g_signal_connect_data"},
		{&e.disconnect, "_frida_g_signal_handler_disconnect"},
		{&e.newLoop, "_frida_g_main_loop_new"},
		{&e.runLoop, "_frida_g_main_loop_run"},
		{&e.quitLoop, "_frida_g_main_loop_quit"},
		{&e.unrefLoop, "_frida_g_main_loop_unref"},
		{&e.loopRunning, "_frida_g_main_loop_is_running"},
		{&e.newCancellable, "_frida_g_cancellable_new"},
		{&e.cancel, "_frida_g_cancellable_cancel"},
	}
	for _, b := range bindings {
		symbol, lookupErr := purego.Dlsym(handle, b.name)
		if lookupErr != nil {
			return nil, fmt.Errorf("%w: library %q is missing required symbol %s: %w", ErrUnavailable, path, b.name, lookupErr)
		}
		purego.RegisterFunc(b.target, symbol)
	}
	callbacks.Do(func() {
		callbacks.message = purego.NewCallback(func(_ uintptr, message *byte, _ uintptr, id uintptr) {
			if value, ok := sessions.Load(id); ok {
				value.(*Session).receive([]byte(unix.BytePtrToString(message)))
			}
		})
		callbacks.detached = purego.NewCallback(func(_ uintptr, _ int32, _ uintptr, id uintptr) {
			if value, ok := sessions.Load(id); ok {
				s := value.(*Session)
				s.detached.Do(func() { close(s.Detached) })
			}
		})
	})
	engineLifetime.used = true
	initialized = true
	e.init()
	e.loop = e.newLoop(0, 0)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		e.runLoop(e.loop)
		close(e.loopDone)
	}()
	for e.loopRunning(e.loop) == 0 {
		runtime.Gosched()
	}
	e.manager = e.newManager()
	cancel, finish := e.cancellable(ctx)
	var failure *nativeError
	e.device = e.getDevice(e.manager, 0, 0, cancel, &failure)
	finish()
	if err = e.takeError(&failure); err != nil {
		_ = e.Close()
		return nil, err
	}
	return e, nil
}

func (e *Engine) takeError(slot **nativeError) error {
	failure := *slot
	*slot = nil
	if failure == nil {
		return nil
	}
	err := fmt.Errorf("frida error %d: %s", failure.code, unix.BytePtrToString(failure.message))
	e.errorFree(failure)
	return err
}

func (e *Engine) cancellable(ctx context.Context) (uintptr, func()) {
	native := e.newCancellable()
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { e.cancel(native); close(done) })
	return native, func() {
		if !stop() {
			<-done
		}
		e.unref(native)
	}
}

func (e *Engine) Attach(ctx context.Context, pid uint32, source string) (s *Session, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	s = &Session{
		id: uintptr(sessionIDs.Add(1)),
		sessionState: sessionState{
			engine:   e,
			Messages: make(chan json.RawMessage, 64),
			Detached: make(chan struct{}),
			Failed:   make(chan struct{}),
			replies:  make(map[uint64]chan reply),
		},
	}
	cancel, finish := e.cancellable(ctx)
	defer finish()
	var failure *nativeError
	s.handle = e.attach(e.device, pid, 0, cancel, &failure)
	if err = e.takeError(&failure); err != nil {
		return nil, err
	}
	sessions.Store(s.id, s)
	s.detachHandler = e.connect(s.handle, "detached", callbacks.detached, s.id, 0, 0)
	defer func() {
		if err != nil {
			_ = s.Close(false)
		}
	}()
	if e.isDetached(s.handle) != 0 {
		return s, errors.New("frida target detached during attachment")
	}
	s.script = e.create(s.handle, source, 0, cancel, &failure)
	if err = e.takeError(&failure); err != nil {
		return s, err
	}
	s.messageHandler = e.connect(s.script, "message", callbacks.message, s.id, 0, 0)
	e.load(s.script, cancel, &failure)
	return s, e.takeError(&failure)
}

// Close eternalizes the script before detaching when drain is true.
func (s *Session) Close(drain bool) error {
	e := s.engine
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cancellable, finish := e.cancellable(ctx)
	defer finish()
	var result error
	var failure *nativeError
	detached := e.isDetached(s.handle) != 0
	if s.script != 0 && !detached {
		if drain {
			e.eternalize(s.script, cancellable, &failure)
		} else {
			e.unload(s.script, cancellable, &failure)
		}
		result = errors.Join(result, e.takeError(&failure))
	}
	if s.script != 0 {
		e.disconnect(s.script, s.messageHandler)
		e.unref(s.script)
	}
	if !detached {
		e.detach(s.handle, cancellable, &failure)
		result = errors.Join(result, e.takeError(&failure))
	}
	e.disconnect(s.handle, s.detachHandler)
	e.unref(s.handle)
	sessions.Delete(s.id)
	return result
}

func (e *Engine) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cancellable, finish := e.cancellable(ctx)
	var failure *nativeError
	e.closeManager(e.manager, cancellable, &failure)
	finish()
	err := e.takeError(&failure)
	if e.device != 0 {
		e.unref(e.device)
	}
	e.unref(e.manager)
	e.quitLoop(e.loop)
	<-e.loopDone
	e.unrefLoop(e.loop)
	e.shutdown()
	e.deinit()
	// Native TLS destructors may outlive shutdown. dlclose caused an exit crash.
	runtime.KeepAlive(e.handle)
	return err
}
