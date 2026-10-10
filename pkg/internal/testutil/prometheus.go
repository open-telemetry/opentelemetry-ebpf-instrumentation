// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package testutil // import "go.opentelemetry.io/obi/pkg/internal/testutil"

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/connector"
)

type PrometheusServer struct {
	Manager *connector.PrometheusManager
	Port    int
	URL     string
}

func NewPrometheusServer(t *testing.T) *PrometheusServer {
	t.Helper()
	server := &PrometheusServer{Manager: &connector.PrometheusManager{}, Port: FreeTCPPort(t)}
	server.URL = fmt.Sprintf("http://localhost:%d/metrics", server.Port)
	server.Manager.Register(server.Port, "/metrics")
	server.Manager.StartHTTP(t.Context())
	require.Eventually(t, func() bool {
		resp, err := http.Get(server.URL)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 10*time.Millisecond)
	return server
}

func (s *PrometheusServer) Gather() ([]*dto.MetricFamily, error) {
	req, err := http.NewRequest(http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", string(expfmt.NewFormat(expfmt.TypeProtoDelim)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scraping Prometheus: HTTP %d", resp.StatusCode)
	}
	decoder := expfmt.NewDecoder(resp.Body, expfmt.ResponseFormat(resp.Header))
	var families []*dto.MetricFamily
	for {
		family := &dto.MetricFamily{}
		if err := decoder.Decode(family); err != nil {
			if errors.Is(err, io.EOF) {
				return families, nil
			}
			return nil, err
		}
		families = append(families, family)
	}
}
