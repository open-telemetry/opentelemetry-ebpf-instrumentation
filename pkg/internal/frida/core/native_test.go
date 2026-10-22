// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_frida && linux && (amd64 || arm64)

package core

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNativeLifecycle(t *testing.T) {
	library := os.Getenv("OBI_FRIDA_LIBRARY")
	if library == "" {
		t.Skip("set OBI_FRIDA_LIBRARY to run the live Frida feasibility test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	engine, err := Open(ctx, library)
	require.NoError(t, err)
	defer func() { require.NoError(t, engine.Close()) }()
	child := exec.Command("sleep", "60")
	require.NoError(t, child.Start())
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	source := `send({phase:'immediate'});setTimeout(()=>send({phase:'delayed'}),20);rpc.exports={ping(){return 'pong';},stop(){return true;}};`
	for range 12 {
		session, attachErr := engine.Attach(ctx, uint32(child.Process.Pid), source)
		require.NoError(t, attachErr)
		runtime.GC()
		for _, phase := range []string{"immediate", "delayed"} {
			select {
			case event := <-session.Messages:
				require.Contains(t, string(event), phase)
			case <-ctx.Done():
				t.Fatal("native callback timed out")
			}
		}
		result, callErr := session.Call(ctx, "ping")
		require.NoError(t, callErr)
		require.JSONEq(t, `"pong"`, string(result))
		_, callErr = session.Call(ctx, "missing")
		require.Error(t, callErr)
		require.NoError(t, session.Close(false))
	}
	_, err = engine.Attach(ctx, uint32(child.Process.Pid), "invalid javascript {")
	require.Error(t, err)
	cancelled, stop := context.WithCancel(ctx)
	stop()
	_, err = engine.Attach(cancelled, uint32(child.Process.Pid), source)
	require.Error(t, err)
	session, err := engine.Attach(ctx, uint32(child.Process.Pid), source)
	require.NoError(t, err)
	require.NoError(t, child.Process.Kill())
	select {
	case <-session.Detached:
	case <-ctx.Done():
		t.Fatal("missing target-exit callback")
	}
	_ = session.Close(false)
	_, ok := sessions.Load(session.id)
	require.False(t, ok, "native user-data registry retained a released session")
	t.Log("PASS CGO-free attach, immediate/delayed callbacks, GC, RPC, errors, repeated detach, cancellation and target exit")
}
