// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube // import "go.opentelemetry.io/obi/internal/test/integration/components/kube"

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	"go.opentelemetry.io/obi/internal/test/weavercheck"
)

const (
	// WeaverK8sAdminHostPort is the host port the kind clusters map weaver's
	// admin port (4320) to, via the extraPortMapping in manifests/00-kind*.yml.
	WeaverK8sAdminHostPort = 32320

	// Host ports the kind clusters map the weavercol and suite-otelcol telemetry
	// endpoints to (00-kind*.yml); validateWeaver scrapes both for tap drops.
	WeaverColMetricsHostPort     = 32888
	OtelcolWeaverMetricsHostPort = 32889

	// weaverK8sTimeout bounds the wait-for-weaver + /stop + report-read
	// sequence. Report generation scales with the number of unique samples
	// weaver received; the interval processor in
	// otelcol-config-k8s-weavercol.yml keeps that bounded, but
	// high-cardinality suites (netolly) still need a generous margin.
	weaverK8sTimeout = 6 * time.Minute

	// weaverK8sDrainWindow is how long validateWeaver waits after weaver is
	// reachable before stopping it: it must cover the weavercol `interval`
	// processor tick (10s, see otelcol-config-k8s-weavercol.yml) plus gRPC
	// reconnect backoff, so at least one aggregated batch arrives.
	weaverK8sDrainWindow = 25 * time.Second

	// weaverK8sEmptyReportAttempts is how many /stop + read cycles to try
	// when the report comes back with zero samples (each cycle restarts the
	// weaver pod and drains again).
	weaverK8sEmptyReportAttempts = 3

	// weaverK8sReadyTimeout bounds the pre-test wait for the weaver tap to come
	// up (see waitForWeaverReady). It is generous because weaver and weavercol
	// pull their images from the network on a cold CI node.
	weaverK8sReadyTimeout = 5 * time.Minute
)

// weaverRecorder adapts weavercheck.TestingT to the suite-teardown context,
// where no *testing.T exists (e2e-framework Finish funcs run after m.Run()
// has returned). Failures are recorded and logged at default slog verbosity —
// deliberately NOT relying on the framework's handling of Finish errors,
// which are logged at klog V(2) only and dropped from the exit code.
type weaverRecorder struct {
	failed bool
}

func (r *weaverRecorder) Helper() {}

// Logf/Errorf are the single place a "weaver(k8s):" prefix is applied, so the
// shared weavercheck.Validate output (which is prefix-less, being reused by the
// non-k8s compose/OATS suites) is tagged consistently. validateWeaver's own
// messages therefore must NOT repeat the prefix, or it would double up.
func (r *weaverRecorder) Logf(format string, args ...any) {
	log().Info("weaver(k8s): " + fmt.Sprintf(format, args...))
}

func (r *weaverRecorder) Errorf(format string, args ...any) {
	r.failed = true
	log().Error("weaver(k8s): " + fmt.Sprintf(format, args...))
}

// FailNow mirrors testing.T.FailNow for the require calls inside
// weavercheck.Validate: validateWeaverFinish runs the validation on a
// dedicated goroutine precisely so this Goexit aborts only the validation.
func (r *weaverRecorder) FailNow() {
	r.failed = true
	runtime.Goexit()
}

// waitForWeaverReady is a setup func (registered before the suite's tests run,
// see Kind.Run) that blocks until the weaver tap is reachable. Spans are bursty
// — OBI emits them only while the tests drive traffic — so if weaver is still
// pulling its image when the tests start, every span is dropped before it and
// the teardown report degrades to the continuously-emitted metrics only. The
// metric stream would still make the report non-empty, hiding the gap, so the
// readiness gate is what actually lets validateWeaver observe spans. Waits on
// both the weaver admin port and weavercol's telemetry endpoint (the two
// host-mapped hops of the tap); the suite otelcol comes up from a local image
// well before either.
func (k *Kind) waitForWeaverReady() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		wctx, cancel := context.WithTimeout(ctx, weaverK8sReadyTimeout)
		defer cancel()
		weaverURL := fmt.Sprintf("http://127.0.0.1:%d/", WeaverK8sAdminHostPort)
		if err := waitForHTTP(wctx, weaverURL); err != nil {
			return ctx, fmt.Errorf("weaver admin port not ready before tests: %w", err)
		}
		weavercolURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", WeaverColMetricsHostPort)
		if err := waitForHTTP(wctx, weavercolURL); err != nil {
			return ctx, fmt.Errorf("weavercol not ready before tests: %w", err)
		}
		otelcolURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", OtelcolWeaverMetricsHostPort)
		if err := waitForHTTP(wctx, otelcolURL); err != nil {
			return ctx, fmt.Errorf("suite otelcol telemetry not ready before tests: %w", err)
		}
		// Baseline for validateWeaver's teardown drop check (before any traffic).
		k.tapDropsBaseline, k.tapDropsBaselineErr = k.tapDropCount(wctx)
		log().Info("weaver(k8s): tap ready, starting tests")
		return ctx, nil
	}
}

// validateWeaverFinish is the Finish func registered — first, while the
// cluster is still up — when a suite opts in via the WeaverValidation option.
// e2e-framework gives Finish funcs no way to fail the suite, so enforcement
// happens out of band: the failure is recorded on the Kind and Run turns it
// into a non-zero exit.
func (k *Kind) validateWeaverFinish() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		rec := &weaverRecorder{}
		done := make(chan struct{})
		go func() {
			defer close(done)
			k.validateWeaver(ctx, rec)
		}()
		<-done
		// Record only — never return an error: every func registered in the
		// single .Finish() call of Kind.Run belongs to one e2e-framework
		// action, and an action stops at its first failing func, which would
		// skip log export, the OBI coverage flush and DestroyCluster.
		// Enforcement happens via Kind.Run's exit code instead.
		k.weaverFailed = rec.failed
		return ctx, nil
	}
}

// validateWeaver stops the in-cluster weaver pod (HTTP POST /stop on its
// host-exposed admin port) and validates the live-check report weaver returns
// in the /stop response body (weaver runs with --output http). It runs at suite
// teardown (see validateWeaverFinish), after every test but before the cluster
// is destroyed.
//
// Requirements (wired in the suite's manifests):
//   - a weaver pod (manifests/08-weaver*.yml) mounting /obi-registry from the
//     kind `obi-registry` extraMount;
//   - an OTLP-exporting otelcol that taps weaver (03-otelcol-weaver*.yml);
//   - the kind config (00-kind*.yml) with the weaver admin extraPortMapping
//     4320 -> WeaverK8sAdminHostPort.
func (k *Kind) validateWeaver(parent context.Context, t weavercheck.TestingT) {
	t.Helper()

	// Derive from the Finish context so an aborted suite cancels validation
	// instead of blocking up to weaverK8sTimeout.
	ctx, cancel := context.WithTimeout(parent, weaverK8sTimeout)
	defer cancel()

	// The weaver pod is deployed with the rest of the suite but pulls its
	// image from the network, so on a cold node it may become Ready only
	// after the suite's tests have already started (nothing in the suite
	// depends on it before this point). Wait for its host-mapped admin port
	// to answer, then leave a drain window covering the weavercol `interval`
	// processor tick plus gRPC reconnect backoff, so at least one aggregated
	// batch reaches weaver before we stop it.
	addr := fmt.Sprintf("127.0.0.1:%d", WeaverK8sAdminHostPort)
	if err := waitForHTTP(ctx, "http://"+addr+"/"); err != nil {
		t.Errorf("admin port %s never became reachable (weaver pod not running?): %v", addr, err)
		return
	}

	// Lifetime counters at end of tests, before the /stop loop restarts weaver.
	finalDrops, finalDropsErr := k.tapDropCount(ctx)

	// A weaver that came up mid-suite may still produce an empty report on
	// the first /stop (the tap was reconnecting / the interval tick had not
	// flushed). Stopping weaver makes its pod restart (default restartPolicy),
	// and OBI keeps emitting until teardown, so simply draining again and
	// re-fetching from the restarted instance recovers — retry a couple of
	// times before declaring the tap pipeline broken.
	adminURL := fmt.Sprintf("http://%s/stop", addr)
	var report *weavercheck.Report
	for attempt := 1; ; attempt++ {
		select {
		case <-time.After(weaverK8sDrainWindow):
		case <-ctx.Done():
		}

		var err error
		report, err = weavercheck.FetchReport(ctx, adminURL)
		if err != nil {
			t.Errorf("%v", err)
			return
		}
		if report.Statistics.TotalEntities > 0 {
			break
		}
		if attempt >= weaverK8sEmptyReportAttempts {
			t.Errorf("live-check report has no entities after %d attempts — weaver received "+
				"no telemetry (is the otelcol weaver tap pipeline broken?)", attempt)
			return
		}
		t.Logf("empty report on attempt %d/%d, waiting for the restarted weaver to receive telemetry",
			attempt, weaverK8sEmptyReportAttempts)
		// The restarted weaver pod needs to be answering again before the
		// next /stop.
		if err := waitForHTTP(ctx, "http://"+addr+"/"); err != nil {
			t.Errorf("restarted weaver never became reachable: %v", err)
			return
		}
	}

	// A dropped export may have carried the sole sample of a violating shape, so
	// any drop during the suite — or an unreadable counter — makes the report
	// untrustworthy.
	if k.tapDropsBaselineErr != nil || finalDropsErr != nil {
		t.Errorf("could not read the tap's export-failure counters (baseline: %v, teardown: %v) — "+
			"cannot confirm weaver saw every emitted shape, so the report is untrustworthy",
			k.tapDropsBaselineErr, finalDropsErr)
	} else if dropped := finalDrops - k.tapDropsBaseline; dropped > 0 {
		t.Errorf("the weaver tap dropped %.0f export item(s) during the suite "+
			"(otelcol_exporter_{send,enqueue}_failed_* across the suite otelcol and weavercol) — "+
			"weaver may have missed a telemetry shape, so the report cannot be trusted; reduce "+
			"OBI's emission rate or raise the tap queue sizes", dropped)
	}

	if k.weaverRequireSpans && report.Statistics.TotalEntitiesByType["span"] == 0 {
		t.Errorf("weaver report has no span entities — OBI's trace export is not reaching weaver " +
			"(is OTEL_EXPORTER_OTLP_TRACES_ENDPOINT pointed at the tapped otelcol rather than " +
			"straight at jaeger?); span semconv violations would otherwise go unvalidated")
	}

	weavercheck.Validate(t, report)
}

// tapDropCount sums the export failures of both tap hops (suite otelcol ->
// weavercol -> weaver), erroring if either endpoint can't be scraped.
func (k *Kind) tapDropCount(ctx context.Context) (float64, error) {
	var total float64
	for _, port := range []int{OtelcolWeaverMetricsHostPort, WeaverColMetricsHostPort} {
		n, err := exporterFailedCount(ctx, port)
		if err != nil {
			return 0, fmt.Errorf("scraping exporter counters on host port %d: %w", port, err)
		}
		total += n
	}
	return total, nil
}

// exporterFailedCount sums otelcol_exporter_{send,enqueue}_failed_* from a
// collector's telemetry endpoint on the given host port.
func exporterFailedCount(ctx context.Context, hostPort int) (float64, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", hostPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	var total float64
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "otelcol_exporter_send_failed_") &&
			!strings.HasPrefix(line, "otelcol_exporter_enqueue_failed_") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			continue
		}
		total += v
	}
	return total, nil
}

// waitForHTTP polls url until the server produces any HTTP response (status
// irrelevant) or ctx expires. A plain TCP dial is not enough: the kind
// extraPortMapping accepts connections even while the target hostPort has no
// running backend and only resets them on use, so readiness requires an
// HTTP-level round trip.
func waitForHTTP(ctx context.Context, url string) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var lastErr error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (last probe error: %w)", ctx.Err(), lastErr)
		case <-ticker.C:
		}
	}
}
