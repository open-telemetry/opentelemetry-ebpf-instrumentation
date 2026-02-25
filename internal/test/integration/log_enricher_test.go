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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

type testServerConstants struct {
	url            string
	smokeEndpoint  string
	logEndpoint    string
	containerImage string
	message        string
}

var (
	logEnricherHTTPConstants = testServerConstants{
		url:            "http://localhost:8381",
		smokeEndpoint:  "/smoke",
		logEndpoint:    "/json_logger",
		containerImage: "hatest-testserver-logenricher-http",
		message:        "this is a json log",
	}
	logEnricherGoGRPCConstants = testServerConstants{
		url:            "http://localhost:8382",
		smokeEndpoint:  "/smoke",
		logEndpoint:    "/log",
		containerImage: "hatest-testserver-logenricher-grpc-go",
		message:        "hello!",
	}
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

func testLogEnricher(t *testing.T, constants testServerConstants) {
	waitForTestComponentsNoMetrics(t, constants.url+constants.smokeEndpoint)

	cl, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cl.Close()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, constants.url+constants.logEndpoint, 200)

		containerID := testContainerID(ct, cl, constants.containerImage)
		require.NotEmpty(ct, containerID, "could not find test container ID")
		logs := containerLogs(ct, cl, containerID)
		require.NotEmpty(ct, logs)

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
		require.NoError(ct, json.Unmarshal([]byte(logs[logIdx]), &logFields))

		assert.Equal(ct, constants.message, logFields["message"])
		assert.Equal(ct, "INFO", logFields["level"])
		assert.Contains(ct, logFields, "trace_id")
		assert.Contains(ct, logFields, "span_id")
	}, testTimeout, 100*time.Millisecond)
}
