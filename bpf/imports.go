//go:build beyla_bpf

package bpf

import (
	_ "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/bpf/bpfcore"
	_ "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/bpf/common"
	_ "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/bpf/generictracer"
	_ "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/bpf/gotracer"
	_ "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/bpf/gpuevent"
	_ "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/bpf/logger"
	_ "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/bpf/maps"
	_ "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/bpf/netolly"
	_ "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/bpf/pid"
	_ "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/bpf/rdns"
	_ "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/bpf/tctracer"
	_ "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/bpf/watcher"
)
