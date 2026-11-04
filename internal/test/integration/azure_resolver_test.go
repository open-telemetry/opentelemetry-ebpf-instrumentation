// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func TestAzureServiceResolution(t *testing.T) {
	for _, mode := range []string{"Uniform", "Flexible"} {
		t.Run(mode, func(t *testing.T) {
			t.Run("explicit scope", func(t *testing.T) { testAzureServiceResolution(t, false, mode) })
			t.Run("detected scope", func(t *testing.T) { testAzureServiceResolution(t, true, mode) })
		})
	}
}

func testAzureServiceResolution(t *testing.T, detected bool, mode string) {
	t.Helper()
	const computeBase = "/subscriptions/test-subscription/resourceGroups/test-group/providers/Microsoft.Compute"
	const prefix = computeBase + "/virtualMachineScaleSets"
	const nicBase = "/subscriptions/test-subscription/resourceGroups/networking/providers/Microsoft.Network/networkInterfaces"
	network := setupIMDSSubnet(t)
	if mode == "Flexible" {
		data, err := os.ReadFile(pathRoot + "/internal/test/integration/components/azure-imds/azure-metadata-mock.json")
		require.NoError(t, err)
		var metadata map[string]any
		require.NoError(t, json.Unmarshal(data, &metadata))
		metadata["resourceId"] = computeBase + "/virtualMachines/storefront-0"
		data, err = json.Marshal(metadata)
		require.NoError(t, err)
		metadataFile := filepath.Join(t.TempDir(), "azure-metadata-mock.json")
		require.NoError(t, os.WriteFile(metadataFile, data, 0o644))
		setupMockAzureIMDSWithFile(t, network, metadataFile)
	} else {
		setupMockAzureIMDS(t, network)
	}
	setupContainerPrometheus(t, network, "prometheus-config-perapp.yml")
	setupContainerJaeger(t, network)
	setupContainerCollector(t, network, "otelcol-config.yml")
	_, backendIP := setupAWSResolverApplication(t, network, "ecs-backend", false)
	_, frontendIP := setupAWSResolverApplication(t, network, "ecs-frontend", true)
	var available atomic.Bool
	var denied atomic.Int64
	proxy, certificate := azureARMProxy(t, network, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "Bearer azure-integration-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		if !available.Load() {
			denied.Add(1)
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":{"code":"AuthorizationFailed","message":"inventory not ready"}}`)
			return
		}
		var response any
		if strings.EqualFold(r.URL.Path, prefix) {
			response = map[string]any{"value": []any{map[string]any{"id": prefix + "/storefront", "name": "storefront", "properties": map[string]any{"orchestrationMode": mode}}, map[string]any{"id": prefix + "/checkout", "name": "checkout", "properties": map[string]any{"orchestrationMode": mode}}}}
		} else {
			group := "checkout"
			uuid := "backend-vm"
			ip := backendIP
			if strings.HasPrefix(strings.ToLower(r.URL.Path), strings.ToLower(prefix+"/storefront/")) ||
				(mode == "Flexible" && (strings.EqualFold(r.URL.Path, nicBase+"/storefront") || r.URL.Query().Get("$filter") == "'virtualMachineScaleSet/id' eq '"+prefix+"/storefront'")) {
				group = "storefront"
				uuid = "02aab8a4-74ef-476e-8182-f6d2ba4166a6"
				ip = frontendIP
			}
			vmPath := prefix + "/" + group + "/virtualMachines"
			nicPath := prefix + "/" + group + "/networkInterfaces"
			vmID := vmPath + "/0"
			if mode == "Flexible" {
				vmPath = computeBase + "/virtualMachines"
				vmID = vmPath + "/" + group + "-0"
				nicPath = nicBase + "/" + group
			}
			switch {
			case strings.EqualFold(r.URL.Path, vmPath):
				assert.Equal(t, "instanceView", r.URL.Query().Get("$expand"))
				properties := map[string]any{"vmId": uuid, "instanceView": map[string]any{"statuses": []any{map[string]string{"code": "PowerState/running"}}}}
				if mode == "Flexible" {
					assert.Equal(t, "'virtualMachineScaleSet/id' eq '"+prefix+"/"+group+"'", r.URL.Query().Get("$filter"))
					properties["virtualMachineScaleSet"] = map[string]string{"id": prefix + "/" + group}
					properties["networkProfile"] = map[string]any{"networkInterfaces": []any{map[string]string{"id": nicPath}}}
				}
				response = map[string]any{"value": []any{map[string]any{"id": vmID, "properties": properties}}}
			case strings.EqualFold(r.URL.Path, nicPath):
				response = map[string]any{"properties": map[string]any{"virtualMachine": map[string]string{"id": vmID}, "ipConfigurations": []any{map[string]any{"properties": map[string]string{"privateIPAddress": ip}}}}}
				if mode == "Uniform" {
					response = map[string]any{"value": []any{response}}
				}
			default:
				t.Errorf("unexpected ARM request %s", r.URL)
				http.NotFound(w, r)
				return
			}
		}
		assert.NoError(t, json.NewEncoder(w).Encode(response))
	}))
	o := obi{Env: []string{"HTTPS_PROXY=" + proxy, "NO_PROXY=169.254.169.254,otelcol,prometheus,localhost,127.0.0.1", "SSL_CERT_FILE=" + certificate, "AZURE_TOKEN_CREDENTIALS=ManagedIdentityCredential"}, Logs: createLogOutput(t, "azure-resolver")}
	if !detected {
		o.Env = append(o.Env, "AZURE_TEST_SUBSCRIPTION_ID=test-subscription", "AZURE_TEST_RESOURCE_GROUP=test-group")
	}
	if !KernelLockdownMode() {
		o.SecurityConfigSuffix = "_none"
	}
	o.instrument(t, network, "obi-config-azure-v2.yml")
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Positive(ct, denied.Load())
		results, err := pq.Query(`target_info{exported="prometheus",service_name="nginx"}`)
		require.NoError(ct, err)
		assert.NotEmpty(ct, results)
	}, testTimeout, 100*time.Millisecond)
	available.Store(true)
	// Recovery must rename discovered processes before any application traffic.
	for _, exporter := range []string{"prometheus", "otel"} {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(fmt.Sprintf(`target_info{exported=%q,service_name="storefront",host_id="custom-exported-host"}`, exporter))
			require.NoError(ct, err)
			assert.NotEmpty(ct, results, "renamed target_info from %s exporter", exporter)
		}, testTimeout, 100*time.Millisecond)
	}
	httpClient := &http.Client{Timeout: time.Second}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := httpClient.Get("http://localhost:8080/")
		require.NoError(ct, err)
		require.NoError(ct, resp.Body.Close())
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		for _, exporter := range []string{"prometheus", "otel"} {
			for _, query := range []string{fmt.Sprintf(`traces_service_graph_request_total{exported=%q,client="storefront",server="checkout"}`, exporter), fmt.Sprintf(`http_server_request_duration_seconds_count{exported=%q,service_name="storefront"}`, exporter)} {
				results, err := pq.Query(query)
				require.NoError(ct, err)
				assert.NotEmpty(ct, results)
			}
		}
	}, testTimeout, 100*time.Millisecond)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger(jaegerQueryURL + "?service=storefront")
		require.NoError(ct, err)
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var traces jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&traces))
		assert.NotEmpty(ct, traces.Data)
	}, testTimeout, 100*time.Millisecond)
	for _, exporter := range []string{"prometheus", "otel"} {
		results, err := pq.Query(fmt.Sprintf(`target_info{exported=%q,service_name="checkout"}`, exporter))
		require.NoError(t, err)
		assert.Empty(t, results, "backend must remain uninstrumented")
	}
}
