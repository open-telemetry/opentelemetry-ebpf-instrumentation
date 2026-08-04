// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tcmanager

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"go.opentelemetry.io/obi/pkg/internal/netolly/ifaces"
)

const lifecycleTestTimeout = time.Second

func TestManagersDeliverUnconsumedCallbackErrors(t *testing.T) {
	for name, newManager := range managerFactories() {
		t.Run(name, func(t *testing.T) {
			manager := newManager()
			interfaces := NewInterfaceManager()
			manager.SetInterfaceManager(interfaces)

			callbackErr := errors.New("callback failed")
			requireCompletes(t, func() { interfaces.emitError(callbackErr) })

			select {
			case err := <-manager.Errors():
				require.ErrorContains(t, err, callbackErr.Error())
			case <-time.After(lifecycleTestTimeout):
				t.Fatal("callback error was not delivered")
			}

			manager.Shutdown()
		})
	}
}

func TestManagerAddRemoveDoesNotWaitForErrorConsumer(t *testing.T) {
	for name, newManager := range managerFactories() {
		t.Run(name, func(t *testing.T) {
			manager := newManager()
			interfaces := prepareInvalidAttachment(manager)

			requireCompletes(t, func() {
				manager.AddProgram("invalid", nil, AttachmentType(255))
			})
			assertNextErrorContains(t, manager.Errors(), "invalid attachment type")
			requireCompletes(t, func() { manager.RemoveProgram("invalid") })

			manager.Shutdown()
			assertCallbacksEmpty(t, interfaces)
		})
	}
}

func TestManagersReportProgramCloseFailures(t *testing.T) {
	for name, newManager := range managerFactories() {
		t.Run(name, func(t *testing.T) {
			manager := newManager()
			manager.AddProgram("close-fails", nil, AttachmentIngress)

			closeErr := errors.New("closing program failed")
			switch typedManager := manager.(type) {
			case *netlinkManager:
				typedManager.programs[0].closeFn = func() error { return closeErr }
			case *tcxManager:
				typedManager.programs[0].closeFn = func() error { return closeErr }
			}

			requireCompletes(t, func() { manager.RemoveProgram("close-fails") })
			assertNextErrorContains(t, manager.Errors(), closeErr.Error())
			assertProgramsEmpty(t, manager)
			manager.Shutdown()
		})
	}
}

func TestInterfaceRemovalReleasesResources(t *testing.T) {
	for name, newManager := range managerFactories() {
		t.Run(name, func(t *testing.T) {
			manager := newManager()
			interfaces := NewInterfaceManager()
			manager.SetInterfaceManager(interfaces)
			iface := &ifaces.Interface{Index: 42, Name: "test"}

			var linkCloses atomic.Int32
			switch typedManager := manager.(type) {
			case *netlinkManager:
				typedManager.interfaces[iface.Index] = &netlinkIface{Interface: iface}
			case *tcxManager:
				typedManager.links = append(typedManager.links, &ifaceLink{
					progName: "test",
					iface:    iface.Index,
					closeFn: func() error {
						linkCloses.Add(1)
						return nil
					},
				})
			}

			requireCompletes(t, func() { interfaces.onInterfaceRemoved(iface) })
			switch typedManager := manager.(type) {
			case *netlinkManager:
				assert.NotContains(t, typedManager.interfaces, iface.Index)
			case *tcxManager:
				assert.Empty(t, typedManager.links)
				assert.EqualValues(t, 1, linkCloses.Load())
			}

			manager.Shutdown()
		})
	}
}

func TestTCXInterfaceRemovalReportsLinkCloseFailure(t *testing.T) {
	manager := NewTCXManager().(*tcxManager)
	interfaces := NewInterfaceManager()
	manager.SetInterfaceManager(interfaces)
	iface := &ifaces.Interface{Index: 42, Name: "test"}
	closeErr := errors.New("closing link failed")
	manager.links = append(manager.links, &ifaceLink{
		progName: "test",
		iface:    iface.Index,
		closeFn:  func() error { return closeErr },
	})

	requireCompletes(t, func() { interfaces.onInterfaceRemoved(iface) })
	assertNextErrorContains(t, manager.Errors(), closeErr.Error())
	assert.Empty(t, manager.links)
	manager.Shutdown()
}

func TestShutdownUnregistersCallbacksBeforeCleanup(t *testing.T) {
	for name, newManager := range managerFactories() {
		t.Run(name, func(t *testing.T) {
			manager := newManager()
			interfaces := NewInterfaceManager()
			manager.SetInterfaceManager(interfaces)
			callbacks := snapshotCallbacks(t, manager, interfaces)

			checkedOrder := false
			checkOrder := func() error {
				assertCallbacksEmpty(t, interfaces)
				checkedOrder = true
				return nil
			}
			switch typedManager := manager.(type) {
			case *netlinkManager:
				typedManager.programs = append(typedManager.programs, &netlinkProg{
					name: "test", closeFn: checkOrder,
				})
			case *tcxManager:
				typedManager.links = append(typedManager.links, &ifaceLink{
					progName: "test", iface: 42, closeFn: checkOrder,
				})
			}

			requireCompletes(t, manager.Shutdown)
			assert.True(t, checkedOrder)
			assertCallbacksEmpty(t, interfaces)

			lateIface := &ifaces.Interface{Index: 43, Name: "late"}
			assertLateStateCallbacksAreNoOps(t, manager, callbacks, lateIface)
			requireCompletes(t, func() { callbacks.failed(errors.New("late callback")) })
			assertErrorChannelClosed(t, manager.Errors())
		})
	}
}

func assertLateStateCallbacksAreNoOps(
	t *testing.T, manager TCManager, callbacks savedCallbacks, lateIface *ifaces.Interface,
) {
	t.Helper()

	var addedCalls atomic.Int32
	var linkCloses atomic.Int32

	switch typedManager := manager.(type) {
	case *netlinkManager:
		sentinel := &netlinkIface{Interface: lateIface}
		typedManager.interfaces[lateIface.Index] = sentinel
		typedManager.installQdiscFn = func(*ifaces.Interface) *netlink.GenericQdisc {
			addedCalls.Add(1)
			return &netlink.GenericQdisc{}
		}

		requireCompletes(t, func() { callbacks.added(lateIface) })
		assert.Zero(t, addedCalls.Load())
		assert.Same(t, sentinel, typedManager.interfaces[lateIface.Index])

		requireCompletes(t, func() { callbacks.removed(lateIface) })
		assert.Same(t, sentinel, typedManager.interfaces[lateIface.Index])
	case *tcxManager:
		typedManager.programs = append(typedManager.programs, &attachedProg{name: "late"})
		typedManager.attachProgramFn = func(*attachedProg, int) { addedCalls.Add(1) }
		sentinel := &ifaceLink{
			progName: "late",
			iface:    lateIface.Index,
			closeFn:  func() error { linkCloses.Add(1); return nil },
		}
		typedManager.links = append(typedManager.links, sentinel)

		requireCompletes(t, func() { callbacks.added(lateIface) })
		assert.Zero(t, addedCalls.Load())
		assert.Equal(t, []*ifaceLink{sentinel}, typedManager.links)

		requireCompletes(t, func() { callbacks.removed(lateIface) })
		assert.Zero(t, linkCloses.Load())
		assert.Equal(t, []*ifaceLink{sentinel}, typedManager.links)
	}
}

func TestConcurrentShutdownIsSafe(t *testing.T) {
	for name, newManager := range managerFactories() {
		t.Run(name, func(t *testing.T) {
			manager := newManager()
			interfaces := NewInterfaceManager()
			manager.SetInterfaceManager(interfaces)

			operations := make([]func(), 32)
			for i := range operations {
				operations[i] = manager.Shutdown
			}
			requireConcurrentOperations(t, operations...)
			requireCompletes(t, manager.Shutdown)

			assertCallbacksEmpty(t, interfaces)
			assertErrorChannelClosed(t, manager.Errors())
		})
	}
}

func TestConcurrentLifecycleOperationsAreSafe(t *testing.T) {
	for name, newManager := range managerFactories() {
		t.Run(name, func(t *testing.T) {
			manager := newManager()
			interfaces := prepareInvalidAttachment(manager)
			iface := &ifaces.Interface{Index: 42, Name: "test"}

			operations := make([]func(), 0, 64)
			for i := 0; i < 16; i++ {
				programName := fmt.Sprintf("program-%d", i)
				operations = append(operations,
					func() { manager.AddProgram(programName, nil, AttachmentType(255)) },
					func() { manager.RemoveProgram(programName) },
					func() { interfaces.emitError(errors.New("callback failed")) },
					func() { interfaces.onInterfaceRemoved(iface) },
				)
			}
			operations = append(operations, manager.Shutdown, manager.Shutdown)

			requireConcurrentOperations(t, operations...)
			manager.Shutdown()
			assertCallbacksEmpty(t, interfaces)
			assertErrorChannelClosed(t, manager.Errors())
		})
	}
}

func TestManagersLogCleanupErrorsWhenErrorChannelIsFull(t *testing.T) {
	for name, newManager := range managerFactories() {
		t.Run(name, func(t *testing.T) {
			manager := newManager()
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			closeErr := errors.New("cleanup close failed")

			switch typedManager := manager.(type) {
			case *netlinkManager:
				typedManager.log = logger
				typedManager.programs = append(typedManager.programs, &netlinkProg{
					name: "test", closeFn: func() error { return closeErr },
				})
			case *tcxManager:
				typedManager.log = logger
				typedManager.links = append(typedManager.links, &ifaceLink{
					progName: "test", iface: 42, closeFn: func() error { return closeErr },
				})
			}

			for i := 0; i < cap(manager.Errors()); i++ {
				manager.Errors() <- fmt.Errorf("queued error %d", i)
			}
			requireCompletes(t, manager.Shutdown)

			assert.Contains(t, logs.String(), closeErr.Error())
			assertErrorChannelClosed(t, manager.Errors())
		})
	}
}

type savedCallbacks struct {
	added   InterfaceManagerCB
	removed InterfaceManagerCB
	failed  InterfaceManagerErrorCB
}

func managerFactories() map[string]func() TCManager {
	return map[string]func() TCManager{
		"netlink": NewNetlinkManager,
		"tcx":     NewTCXManager,
	}
}

func prepareInvalidAttachment(manager TCManager) *InterfaceManager {
	interfaces := NewInterfaceManager()
	iface := &ifaces.Interface{Index: 42, Name: "test"}
	interfaces.interfaces[iface.Index] = iface
	manager.SetInterfaceManager(interfaces)

	if typedManager, ok := manager.(*netlinkManager); ok {
		typedManager.interfaces[iface.Index] = &netlinkIface{Interface: iface}
	}

	return interfaces
}

func snapshotCallbacks(t *testing.T, manager TCManager, interfaces *InterfaceManager) savedCallbacks {
	t.Helper()

	interfaces.mutex.Lock()
	defer interfaces.mutex.Unlock()

	var addedID, removedID, errorID uint64
	switch typedManager := manager.(type) {
	case *netlinkManager:
		addedID = typedManager.addedCallbackID
		removedID = typedManager.removedCallbackID
		errorID = typedManager.errorCallbackID
	case *tcxManager:
		addedID = typedManager.addedCallbackID
		removedID = typedManager.removedCallbackID
		errorID = typedManager.errorCallbackID
	}

	return savedCallbacks{
		added:   requireCallback(t, interfaces.ifaceAddedCallbacks, addedID),
		removed: requireCallback(t, interfaces.ifaceRemovedCallbacks, removedID),
		failed:  requireCallback(t, interfaces.ifaceErrorCallbacks, errorID),
	}
}

func requireCallback[T any](t *testing.T, callbacks map[uint64]T, id uint64) T {
	t.Helper()
	callback, ok := callbacks[id]
	require.True(t, ok)
	return callback
}

func assertCallbacksEmpty(t *testing.T, interfaces *InterfaceManager) {
	t.Helper()

	interfaces.mutex.Lock()
	defer interfaces.mutex.Unlock()
	assert.Empty(t, interfaces.ifaceAddedCallbacks)
	assert.Empty(t, interfaces.ifaceRemovedCallbacks)
	assert.Empty(t, interfaces.ifaceErrorCallbacks)
}

func assertProgramsEmpty(t *testing.T, manager TCManager) {
	t.Helper()
	switch typedManager := manager.(type) {
	case *netlinkManager:
		assert.Empty(t, typedManager.programs)
	case *tcxManager:
		assert.Empty(t, typedManager.programs)
	}
}

func assertNextErrorContains(t *testing.T, errors <-chan error, substring string) {
	t.Helper()
	select {
	case err := <-errors:
		require.ErrorContains(t, err, substring)
	case <-time.After(lifecycleTestTimeout):
		t.Fatalf("error containing %q was not delivered", substring)
	}
}

func assertErrorChannelClosed(t *testing.T, errors <-chan error) {
	t.Helper()
	timer := time.NewTimer(lifecycleTestTimeout)
	defer timer.Stop()

	for {
		select {
		case _, ok := <-errors:
			if !ok {
				return
			}
		case <-timer.C:
			t.Fatal("error channel did not close")
		}
	}
}

func requireConcurrentOperations(t *testing.T, operations ...func()) {
	t.Helper()

	start := make(chan struct{})
	results := make(chan any, len(operations))
	var ready sync.WaitGroup
	ready.Add(len(operations))
	for _, operation := range operations {
		go func() {
			ready.Done()
			<-start
			defer func() { results <- recover() }()
			operation()
		}()
	}
	ready.Wait()
	close(start)

	timer := time.NewTimer(lifecycleTestTimeout)
	defer timer.Stop()
	for range operations {
		select {
		case panicValue := <-results:
			require.Nil(t, panicValue, "operation panicked: %v", panicValue)
		case <-timer.C:
			t.Fatalf("operations did not complete within %s", lifecycleTestTimeout)
		}
	}
}

func requireCompletes(t *testing.T, operation func()) {
	t.Helper()

	result := make(chan any, 1)
	go func() {
		defer func() { result <- recover() }()
		operation()
	}()

	select {
	case panicValue := <-result:
		require.Nil(t, panicValue, "operation panicked: %v", panicValue)
	case <-time.After(lifecycleTestTimeout):
		t.Fatalf("operation did not complete within %s", lifecycleTestTimeout)
	}
}
