// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

const (
	customSpanCPort      = "8390"
	customSpanPythonPort = "8392"
	customSpanRubyPort   = "8393"
	customSpanGoPort     = "8394"
	customSpanJavaPort   = "8395"
	customSpanNodejsPort = "8396"
	customSpanCppPort    = "8397"
	customSpanRustPort   = "8398"
)

// TestCustomSpan asserts OBI emits user-declared spans for every supported
// language flavor:
//   - C (static .note.stapsdt via <sys/sdt.h>) — paired, single, function-mode (both shapes), match-filter
//   - Python (libstapsdt-backed runtime probes via python-stapsdt)
//   - Ruby (libstapsdt via ruby-stapsdt)
//   - Go (salp runtime-registered USDT). Go binaries route to gotracer;
//     finder.newGoTracersGroup additionally attaches generictracer when
//     custom_span is configured so probes register, and gotracer routes
//     EVENT_CUSTOM_SPAN records via EBPFEventContext.CustomSpanHandler.
//   - Java (JNI bridge to libstapsdt). HotSpot's built-in
//     hotspot:method__entry requires DTraceMethodProbes which is develop-only
//     in distro JDKs; the JNI path mirrors python-stapsdt / ruby-stapsdt /
//     salp and registers custom_span_java:order probes at runtime.
//   - Node.js (Node-API addon over libstapsdt). dtrace-provider relies on
//     libusdt which has no arm64 path; the N-API addon reuses our vendored
//     libstapsdt-arm64 fork the same way the JNI bridge does.
//   - C++ with folly's FOLLY_SDT_WITH_SEMAPHORE macro. The only sample that
//     exercises the semaphore-gated probe path — OBI bumps a u16 semaphore
//     via link.UprobeOptions.RefCtrOffset at attach time so the probe's
//     inline-asm body skips its body when no consumer is attached.
//   - Rust via the `usdt` crate (oxidecomputer). Stable inline-asm-emitted
//     .note.stapsdt notes in the binary; covers usdt_span + usdt_noret.
func TestCustomSpan(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-custom-span.yml", path.Join(pathOutput, "test-suite-custom-span.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Cleanup(func() { require.NoError(t, compose.Close()) })

	waitForCustomSpanServices(t)

	// bpf_get_attach_cookie landed in 5.15 (RHEL 8 / 4.18 backport lacks
	// it). Below 5.15 OBI skips match-filter custom_span probes — see
	// customSpanProbes — so the test must not require them.
	cookieKernel := kernelSupportsAttachCookie()
	refCtrKernel := ebpfcommon.HasUprobeRefCtrOffset()
	tracesPath := path.Join(pathOutput, "custom-span-traces.json")
	flavors := []struct {
		port, customer, cachePrefix string
		idBase                      int
	}{
		{customSpanCPort, "alice", "user", 0},
		{customSpanPythonPort, "bob", "cart", 100},
		{customSpanRubyPort, "carol", "stock", 200},
		{customSpanGoPort, "dave", "sku", 300},
		{customSpanJavaPort, "eve", "jdk", 400},
		{customSpanNodejsPort, "frank", "node", 500},
		{customSpanCppPort, "grace", "cpp", 600},
		{customSpanRustPort, "heidi", "rust", 700},
	}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for i := 1; i <= 5; i++ {
			for _, f := range flavors {
				ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/order?id=%d&customer=%s%d", f.port, f.idBase+i, f.customer, i), http.StatusOK)
				ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/cache?key=%s:%d", f.port, f.cachePrefix, i), http.StatusOK)
			}
		}
		spans := readCustomSpanSpecs(ct, tracesPath)
		assert.NotEmpty(ct, spansByName(spans, "order.process"), "expected C paired spans")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit"), "expected C single-shot spans")
		assert.NotEmpty(ct, spansByName(spans, "order.process.py"), "expected Python paired spans")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit.py"), "expected Python single-shot spans")
		assert.NotEmpty(ct, spansByName(spans, "order.process.rb"), "expected Ruby paired spans")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit.rb"), "expected Ruby single-shot spans")
		assert.NotEmpty(ct, spansByName(spans, "order.process.go"), "expected Go paired spans")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit.go"), "expected Go single-shot spans")
		assert.NotEmpty(ct, spansByName(spans, "order.process.java"), "expected Java paired spans (libstapsdt via JNI)")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit.java"), "expected Java single-shot spans (libstapsdt via JNI)")
		assert.NotEmpty(ct, spansByName(spans, "order.process.nodejs"), "expected Node.js paired spans (libstapsdt via N-API)")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit.nodejs"), "expected Node.js single-shot spans (libstapsdt via N-API)")
		// FOLLY_SDT_WITH_SEMAPHORE and the Rust `usdt` crate gate their
		// inline probe body on a non-zero semaphore. The kernel only
		// bumps that counter when the uprobe is attached with the
		// `ref_ctr_offset` PMU attr (kernel ≥4.20). Older kernels —
		// notably RHEL 8 / 4.18 backports — accept the attach with
		// RefCtrOffset=0 but the probe body skips itself, so no events
		// land. See refCtrOffsetForAttach in pkg/ebpf/instrumenter.go.
		if refCtrKernel {
			assert.NotEmpty(ct, spansByName(spans, "order.process.cpp"), "expected C++ folly SDT paired spans (semaphored)")
			assert.NotEmpty(ct, spansByName(spans, "cache.hit.cpp"), "expected C++ folly SDT single-shot spans (semaphored)")
			assert.NotEmpty(ct, spansByName(spans, "order.process.rust"), "expected Rust paired spans (usdt crate)")
			assert.NotEmpty(ct, spansByName(spans, "cache.hit.rust"), "expected Rust single-shot spans (usdt crate)")
		}
		assert.NotEmpty(ct, spansByName(spans, "order.func.go"), "expected Go function-mode paired spans (per-RET uprobes)")
		// Match-filter probes require bpf_get_attach_cookie to disambiguate
		// multiple specs at the same USDT probe IP. Kernels older than 5.15
		// fall back to the IP-keyed spec map (last-write-wins), and OBI
		// skips match-filter registrations there — see customSpanProbes.
		if cookieKernel {
			goMatch := spansByName(spans, "cache.match.go")
			assert.NotEmpty(ct, goMatch, "expected Go match-filter span on key=sku:3")
			for _, s := range goMatch {
				for _, a := range s.Attributes {
					if a.Key == "key" {
						assert.Equal(ct, "sku:3", a.Value.StringValue, "Go match-filter should only emit for sku:3")
					}
				}
			}
			pyMatch := spansByName(spans, "cache.match.py")
			assert.NotEmpty(ct, pyMatch, "expected Python match-filter span on key=cart:3")
			for _, s := range pyMatch {
				for _, a := range s.Attributes {
					if a.Key == "key" {
						assert.Equal(ct, "cart:3", a.Value.StringValue, "Python match-filter should only emit for cart:3")
					}
				}
			}
			matchSpans := spansByName(spans, "cache.match.c")
			assert.NotEmpty(ct, matchSpans, "expected C match-filter spans to emit on user:3")
			for _, s := range matchSpans {
				for _, a := range s.Attributes {
					if a.Key == "key" {
						assert.Equal(ct, "user:3", a.Value.StringValue, "match-filter span should only emit for user:3")
					}
				}
			}
		}
		assert.NotEmpty(ct, spansByName(spans, "order.func.c"), "expected C function-mode spans")
		assert.NotEmpty(ct, spansByName(spans, "cache.func.c"), "expected C paired function spans")
		// order.process.cpp / .rust use semaphore-gated USDT bodies that
		// can't fire on kernels without uprobe ref_ctr_offset support.
		attrNames := []string{"order.process", "order.process.py", "order.process.rb", "order.process.go", "order.process.java", "order.process.nodejs", "order.func.c", "order.func.go"}
		if refCtrKernel {
			attrNames = append(attrNames, "order.process.cpp", "order.process.rust")
		}
		for _, n := range attrNames {
			assertAnyAttr(ct, spansByName(spans, n), "order_id")
			assertAnyAttr(ct, spansByName(spans, n), "customer")
		}
	}, 120*time.Second, 2*time.Second)
}

// kernelSupportsAttachCookie returns true when the running kernel is
// ≥5.15 (where bpf_get_attach_cookie became available). Pre-5.15
// kernels — including RHEL 8 / 4.18 backports — fall back to OBI's
// IP-keyed spec map, which can't disambiguate two custom_spans that
// target the same USDT probe. The match-filter assertions below are
// gated on this signal.
func kernelSupportsAttachCookie() bool {
	major, minor := ebpfcommon.KernelVersion()
	return major > 5 || (major == 5 && minor >= 15)
}

func waitForCustomSpanServices(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, port := range []string{customSpanCPort, customSpanPythonPort, customSpanRubyPort, customSpanGoPort, customSpanJavaPort, customSpanNodejsPort, customSpanCppPort, customSpanRustPort} {
			ti.DoHTTPGet(ct, "http://localhost:"+port+"/smoke", http.StatusOK)
		}
	}, testTimeout, time.Second)
}

type otlpSpan struct {
	Name       string     `json:"name"`
	Attributes []otlpAttr `json:"attributes"`
	StartUnix  string     `json:"startTimeUnixNano"`
	EndUnix    string     `json:"endTimeUnixNano"`
	Parent     string     `json:"parentSpanId"`
	TraceID    string     `json:"traceId"`
	SpanID     string     `json:"spanId"`
}

type otlpAttr struct {
	Key   string `json:"key"`
	Value struct {
		StringValue string `json:"stringValue,omitempty"`
		IntValue    string `json:"intValue,omitempty"`
	} `json:"value"`
}

func readCustomSpanSpecs(t assert.TestingT, p string) []otlpSpan {
	raw, err := os.ReadFile(p)
	if err != nil {
		assert.NoError(t, err, "trace export file not present yet")
		return nil
	}
	var spans []otlpSpan
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var batch struct {
			ResourceSpans []struct {
				ScopeSpans []struct {
					Spans []otlpSpan `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		if err := json.Unmarshal([]byte(line), &batch); err != nil {
			continue
		}
		for _, rs := range batch.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				spans = append(spans, ss.Spans...)
			}
		}
	}
	return spans
}

func spansByName(all []otlpSpan, name string) []otlpSpan {
	var out []otlpSpan
	for _, s := range all {
		if s.Name == name {
			out = append(out, s)
		}
	}
	return out
}

func assertAnyAttr(t assert.TestingT, spans []otlpSpan, key string) {
	for _, s := range spans {
		for _, a := range s.Attributes {
			if a.Key == key && (a.Value.StringValue != "" || a.Value.IntValue != "") {
				return
			}
		}
	}
	assert.Failf(t, "missing attribute", "expected at least one span with attribute %q across %d spans", key, len(spans))
}
