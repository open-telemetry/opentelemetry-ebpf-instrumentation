// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

const (
	serverURL     = "http://localhost:8381"
	smokeEndpoint = "/smoke"
	jsonEndpoint  = "/json_logger"

	containerImage = "hatest-testserver-logenricher"
)

func containerLogs(t require.TestingT, cl *client.Client, containerID string) []string {
	reader, err := cl.ContainerLogs(context.TODO(), containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	require.NoError(t, err)
	defer reader.Close()

	var stdout, stderr strings.Builder
	_, err = stdcopy.StdCopy(&stdout, &stderr, reader)
	require.NoError(t, err)

	combined := stdout.String() + stderr.String()

	scanner := bufio.NewScanner(strings.NewReader(combined))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	require.NoError(t, scanner.Err())

	return lines
}

func testContainerID(t require.TestingT, cl *client.Client, image string) string {
	containers, err := cl.ContainerList(context.TODO(), container.ListOptions{All: true})
	require.NoError(t, err)

	for _, c := range containers {
		if c.Image == image {
			return c.ID
		}
	}

	return ""
}

func testLogEnricher(t *testing.T) {
	waitForTestComponentsNoMetrics(t, serverURL+smokeEndpoint)

	cl, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cl.Close()

	require.Eventually(t, func() bool {
		ti.DoHTTPGet(t, serverURL+jsonEndpoint, 200)

		containerID := testContainerID(require.New(t), cl, containerImage)
		if containerID == "" {
			return false
		}
		logs := containerLogs(require.New(t), cl, containerID)
		if len(logs) == 0 {
			return false
		}

		var logIdx int
		// Loop from the end -- it might be possible that OBI wasn't ready to inject
		// context when the test started, so get the latest request logs every time.
		for i := len(logs) - 1; i >= 0; i-- {
			if strings.Contains(logs[i], "span_id") {
				logIdx = i
				break
			}
		}

		var logFields map[string]string
		if err := json.Unmarshal([]byte(logs[logIdx]), &logFields); err != nil {
			return false
		}

		if logFields["message"] != "this is a json log" {
			return false
		}
		if logFields["level"] != "INFO" {
			return false
		}
		if _, ok := logFields["trace_id"]; !ok {
			return false
		}
		if _, ok := logFields["span_id"]; !ok {
			return false
		}
		return true
	}, testTimeout, 500*time.Millisecond, "Log enricher validation failed")
}
