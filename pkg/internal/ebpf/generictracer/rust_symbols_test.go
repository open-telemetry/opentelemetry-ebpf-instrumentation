// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRustSymbolSelection(t *testing.T) {
	for name, kind := range map[string]rustProbeKind{
		"<tokio::runtime::scheduler::multi_thread::handle::Handle>::schedule_local":                               rustTaskScheduleLocal,
		"tokio::runtime::task::raw::poll::<T, S>":                                                                 rustTaskPoll,
		"<tokio::runtime::task::core::Cell<T, S>>::new":                                                           rustTaskNew,
		"<tokio::runtime::Runtime>::spawn::<F>":                                                                   rustTaskSpawn,
		"<tokio::runtime::thread_pool::Spawner>::spawn::<F>":                                                      rustTaskSpawn,
		"<tokio::runtime::basic_scheduler::Spawner>::spawn::<F>":                                                  rustTaskSpawn,
		"tokio::task::spawn::spawn::<F>":                                                                          rustTaskSpawnPublic,
		"<tokio::runtime::task::list::OwnedTasks<S>>::bind_inner":                                                 rustTaskBind,
		"<tokio::runtime::thread_pool::worker::Shared>::schedule":                                                 rustTaskSchedule,
		"<alloc::sync::Arc<tokio::runtime::basic_scheduler::Shared> as tokio::runtime::task::Schedule>::schedule": rustTaskSchedule,
		"<tokio::runtime::scheduler::multi_thread::handle::Handle>::schedule_option_task_without_yield":           rustTaskPublish,
	} {
		actual, ok := rustSymbolKind(name)
		assert.True(t, ok, name)
		assert.Equal(t, kind, actual, name)
	}
	for _, name := range []string{
		"core::ptr::drop_glue::<tokio::runtime::task::raw::RawTask>",
		"<tokio::runtime::task::raw::RawTask>::poll",
		"<tokio::runtime::task::core::Cell<T, S>>::new::{closure#0}",
		"<tokio::runtime::Runtime>::spawn::<F>::{closure#0}",
		"<tokio::runtime::thread_pool::Spawner>::spawn::<F>::{closure#0}",
		"tokio::task::spawn::spawn::<F>::{closure#0}",
		"<tokio::runtime::scheduler::multi_thread::handle::Handle>::schedule_local::{closure#0}",
		"<tokio::runtime::task::list::OwnedTasks<S>>::bind::<F>",
		"<tokio::runtime::task::list::OwnedTasks<S>>::bind",
		"<tokio::runtime::task::list::OwnedTasks<S>>::bind_inner::{closure#0}",
		"<tokio::runtime::thread_pool::worker::Shared>::schedule::{closure#0}",
	} {
		_, ok := rustSymbolKind(name)
		assert.False(t, ok, name)
	}
}
