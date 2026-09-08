// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

type executableIdentity struct {
	device uint64
	inode  uint64
}

type inodeReuseService struct {
	container string
	name      string
	url       string
	path      string
}

func TestSuite_GoExecutableInodeReuse(t *testing.T) {
	compose, err := docker.ComposeSuite(
		"docker-compose-go-inode-reuse.yml",
		path.Join(pathOutput, "test-suite-go-inode-reuse.log"),
	)
	require.NoError(t, err)

	if !KernelLockdownMode() {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		if err := compose.Close(); err != nil {
			t.Logf("compose.Close(): %v", err)
		}
	})

	services := []inodeReuseService{
		{container: "testserver-a", name: "inode-reuse-a", url: "http://localhost:18080", path: "/from-a"},
		{container: "testserver-b", name: "inode-reuse-b", url: "http://localhost:18180", path: "/from-b"},
	}

	first := readExecutableIdentity(t, compose, services[0].container)
	second := readExecutableIdentity(t, compose, services[1].container)
	require.NotZero(t, first.device)
	require.NotZero(t, first.inode)
	require.NotZero(t, second.device)
	require.NotZero(t, second.inode)
	require.Equal(t, first.inode, second.inode, "reproduction requires matching inode numbers")
	require.NotEqual(t, first.device, second.device, "reproduction requires different filesystems")

	for _, service := range services {
		waitForTestComponentsNoMetrics(t, service.url+"/smoke")
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, service := range services {
			resp, err := http.Get(service.url + service.path)
			require.NoError(ct, err)
			if resp != nil {
				resp.Body.Close()
				require.Equal(ct, http.StatusOK, resp.StatusCode)
			}

			require.Truef(
				ct,
				hasHTTPSpan(service.name, service.path),
				"service %s returned HTTP 200 but emitted no span (dev/inode: %d/%d and %d/%d)",
				service.name,
				first.device,
				first.inode,
				second.device,
				second.inode,
			)
		}
	}, testTimeout, time.Second)
}

func readExecutableIdentity(t *testing.T, compose *docker.Compose, service string) executableIdentity {
	t.Helper()

	output, err := compose.ExecOutput(service, "stat", "-Lc", "%d %i", "/collision/testserver")
	require.NoError(t, err)

	fields := strings.Fields(output)
	require.Len(t, fields, 2)

	device, err := strconv.ParseUint(fields[0], 10, 64)
	require.NoError(t, err)
	inode, err := strconv.ParseUint(fields[1], 10, 64)
	require.NoError(t, err)

	return executableIdentity{device: device, inode: inode}
}

func hasHTTPSpan(service, requestPath string) bool {
	query := url.Values{
		"service":   {service},
		"operation": {"GET " + requestPath},
		"lookback":  {"5m"},
	}
	resp, err := http.Get(jaegerQueryURL + "?" + query.Encode())
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}

	var traces jaeger.TracesQuery
	if err := json.NewDecoder(resp.Body).Decode(&traces); err != nil {
		return false
	}

	return len(traces.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: requestPath})) > 0
}
