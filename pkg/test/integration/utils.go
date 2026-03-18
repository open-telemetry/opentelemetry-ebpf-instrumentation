// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/pkg/test/integration"

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"github.com/stretchr/testify/require"
)

type loopbackTarget struct {
	containerName string
	containerPort int
}

var loopbackTargetsByPort = map[string]loopbackTarget{
	"3034":  {containerName: "integration-ntestserverssl-1", containerPort: 3033},
	"3041":  {containerName: "integration-utestserver-1", containerPort: 3040},
	"3044":  {containerName: "integration-utestserverssl-1", containerPort: 3043},
	"38080": {containerName: "integration-testserver-unused-1", containerPort: 8080},
	"7773":  {containerName: "integration-pytestserver-1", containerPort: 7773},
	"8080":  {containerName: "integration-testserver-1", containerPort: 8080},
	"8086":  {containerName: "integration-jtestserver-1", containerPort: 8085},
	"8088":  {containerName: "integration-testserver-1", containerPort: 8088},
	"8091":  {containerName: "integration-rtestserver-1", containerPort: 8090},
	"8900":  {containerName: "integration-testserver1-1", containerPort: 8900},
	"8381":  {containerName: "integration-pytestserverssl-1", containerPort: 8380},
	"8491":  {containerName: "integration-rtestserverssl-1", containerPort: 8490},
	"18080": {containerName: "integration-testserver-duplicate-1", containerPort: 18080},
	"18090": {containerName: "integration-testserver-duplicate-1", containerPort: 18090},
	"33031": {containerName: "integration-ntestserver-1", containerPort: 3030},
}

func resolveContainerAddr(target loopbackTarget) string {
	cmd := exec.Command("docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", target.containerName)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return ""
	}

	return net.JoinHostPort(ip, strconv.Itoa(target.containerPort))
}

// HTTP client for testing
var testHTTPClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer

			host, port, err := net.SplitHostPort(addr)
			if err == nil && host == "localhost" {
				loopbackAddr := net.JoinHostPort("127.0.0.1", port)
				if target, ok := loopbackTargetsByPort[port]; ok {
					conn, loopbackErr := d.DialContext(ctx, network, loopbackAddr)
					if loopbackErr == nil {
						return conn, nil
					}
					if resolved := resolveContainerAddr(target); resolved != "" {
						return d.DialContext(ctx, network, resolved)
					}
				}
				addr = loopbackAddr
			}

			return d.DialContext(ctx, network, addr)
		},
	},
}

func DoHTTPGet(t require.TestingT, path string, status int) {
	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"productId": 123456, "quantity": 100}`)

	req, err := http.NewRequest(http.MethodGet, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	r, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
}
