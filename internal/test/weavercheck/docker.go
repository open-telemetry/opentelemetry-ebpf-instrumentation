// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package weavercheck // import "go.opentelemetry.io/obi/internal/test/weavercheck"

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/obi/internal/test/tools"
)

const (
	dockerDrainWindow            = 5 * time.Second
	dockerCollectorDrainTimeout  = time.Minute
	dockerDiscoveryTimeout       = time.Minute
	dockerTapPoll                = 500 * time.Millisecond
	weaverTapExporter            = "otlp/weaver"
	weaverImage                  = "otel/weaver"
	collectorImage               = "otel/opentelemetry-collector-contrib"
	localRegistryHost            = "localhost"
	defaultCollectorTelemetryURL = "http://127.0.0.1:8888/metrics"
	busyboxDependencyStage       = "busybox-musl"
	telemetryURLLabel            = "io.opentelemetry.obi.weaver-tap.telemetry-url"
	dockerPSFormat               = `{{.ID}}	{{.Image}}	{{.Networks}}	{{.Label "` + telemetryURLLabel + `"}}`
	dockerPSFields               = 4
)

type runningContainer struct {
	id           string
	image        string
	networks     []string
	telemetryURL string
}

var errTapNotSettled = errors.New("the weaver tap never settled")

type tapCollector struct {
	runningContainer
	scraper string
}

func DrainDockerTap(ctx context.Context, warnf func(format string, args ...any)) error {
	discoveryCtx, cancel := context.WithTimeout(ctx, dockerDiscoveryTimeout)
	defer cancel()

	containers, err := runningContainers(discoveryCtx)
	if err != nil {
		return fmt.Errorf("cannot confirm the weaver tap delivered everything: %w", err)
	}
	if !weaverRunning(containers) {
		return nil
	}

	collectors, err := weaverTapCollectors(discoveryCtx, containers)
	if err != nil {
		return fmt.Errorf("cannot confirm the weaver tap delivered everything: %w", err)
	}
	if len(collectors) == 0 {
		warnf("weaver: no collector with an %s exporter shares a network with weaver, so the tap was not drained", weaverTapExporter)
		return nil
	}

	select {
	case <-time.After(dockerDrainWindow):
	case <-ctx.Done():
		return ctx.Err()
	}

	for _, collector := range collectors {
		if err := drainCollector(ctx, collector, warnf); err != nil {
			return err
		}
	}
	return nil
}

func runningContainers(ctx context.Context) ([]runningContainer, error) {
	out, err := exec.CommandContext(ctx, "docker", "ps", "--format", dockerPSFormat).Output()
	if err != nil {
		return nil, fmt.Errorf("listing running containers: %w", err)
	}
	return parseDockerPS(string(out)), nil
}

func weaverRunning(containers []runningContainer) bool {
	return slices.ContainsFunc(containers, func(container runningContainer) bool {
		return strings.HasPrefix(container.image, weaverImage)
	})
}

func weaverTapCollectors(ctx context.Context, containers []runningContainer) ([]tapCollector, error) {
	scraper, err := dependencyImage(busyboxDependencyStage)
	if err != nil {
		return nil, err
	}

	var collectors []tapCollector
	for _, container := range collectorsBesideWeaver(containers) {
		collector := tapCollector{runningContainer: container, scraper: scraper}
		stats, err := scrapeCollectorTelemetry(ctx, collector)
		if err != nil {
			return nil, err
		}
		if stats.Found {
			collectors = append(collectors, collector)
		}
	}
	return collectors, nil
}

func parseDockerPS(out string) []runningContainer {
	var containers []runningContainer
	for line := range strings.SplitSeq(strings.TrimRight(out, "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != dockerPSFields {
			continue
		}

		telemetryURL := fields[3]
		if telemetryURL == "" {
			telemetryURL = defaultCollectorTelemetryURL
		}
		containers = append(containers, runningContainer{
			id:           fields[0],
			image:        withoutRegistryHost(fields[1]),
			networks:     strings.Split(fields[2], ","),
			telemetryURL: telemetryURL,
		})
	}
	return containers
}

func withoutRegistryHost(image string) string {
	host, repository, found := strings.Cut(image, "/")
	if found && (strings.ContainsAny(host, ".:") || host == localRegistryHost) {
		return repository
	}
	return image
}

func collectorsBesideWeaver(containers []runningContainer) []runningContainer {
	var weaverNetworks []string
	for _, container := range containers {
		if strings.HasPrefix(container.image, weaverImage) {
			weaverNetworks = append(weaverNetworks, container.networks...)
		}
	}

	var collectors []runningContainer
	for _, container := range containers {
		if !strings.HasPrefix(container.image, collectorImage) {
			continue
		}
		if slices.ContainsFunc(container.networks, func(network string) bool {
			return slices.Contains(weaverNetworks, network)
		}) {
			collectors = append(collectors, container)
		}
	}
	return collectors
}

func drainCollector(parent context.Context, collector tapCollector, warnf func(format string, args ...any)) error {
	ctx, cancel := context.WithTimeout(parent, dockerCollectorDrainTimeout)
	defer cancel()

	stats, err := waitForSettledTap(ctx, collector)
	switch {
	case errors.Is(err, errTapNotSettled):
		warnf("weaver: %v", err)
	case err != nil:
		return fmt.Errorf("reading the weaver tap's exporter telemetry: %w", err)
	}
	if stats.Failed > 0 {
		warnf("weaver: the weaver tap failed to deliver %.0f item(s) (otelcol_exporter_{send,enqueue}_failed_*), "+
			"so weaver may have missed a telemetry shape", stats.Failed)
	}
	return nil
}

func waitForSettledTap(ctx context.Context, collector tapCollector) (TapStats, error) {
	ticker := time.NewTicker(dockerTapPoll)
	defer ticker.Stop()

	previous, err := scrapeCollectorTelemetry(ctx, collector)
	if err != nil {
		return previous, err
	}
	for {
		select {
		case <-ctx.Done():
			return previous, fmt.Errorf("%w within %s (%.0f item(s) still queued)", errTapNotSettled, dockerCollectorDrainTimeout, previous.Queued)
		case <-ticker.C:
		}

		current, err := scrapeCollectorTelemetry(ctx, collector)
		if err != nil && ctx.Err() != nil {
			return previous, fmt.Errorf("%w within %s (%.0f item(s) still queued)", errTapNotSettled, dockerCollectorDrainTimeout, previous.Queued)
		}
		if err != nil {
			return current, err
		}
		if current.Settled(previous) {
			return current, nil
		}
		previous = current
	}
}

func scrapeCollectorTelemetry(ctx context.Context, collector tapCollector) (TapStats, error) {
	out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "container:"+collector.id,
		collector.scraper, "wget", "-q", "-O", "-", collector.telemetryURL).Output()
	if err != nil {
		return TapStats{}, fmt.Errorf("scraping the telemetry of collector %s at %s: %w", collector.id, collector.telemetryURL, err)
	}
	return ParseTapStats(bytes.NewReader(out), weaverTapExporter)
}

func dependencyImage(stage string) (string, error) {
	dockerfile := filepath.Join(tools.ProjectDir(), "dependencies.Dockerfile")
	content, err := os.ReadFile(dockerfile)
	if err != nil {
		return "", err
	}
	image, ok := dependencyImageIn(string(content), stage)
	if !ok {
		return "", fmt.Errorf("no %s stage in %s", stage, dockerfile)
	}
	return image, nil
}

func dependencyImageIn(dockerfile, stage string) (string, bool) {
	for line := range strings.SplitSeq(dockerfile, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 4 && fields[0] == "FROM" && fields[2] == "AS" && fields[3] == stage {
			return fields[1], true
		}
	}
	return "", false
}
