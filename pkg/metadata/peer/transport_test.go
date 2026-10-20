// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMetadataEndpoint(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Token = "shared-secret"
	store := newStore("host", cfg)
	api, idle := Service{Name: "api"}, Service{Name: "idle"}
	store.setInventory([]Service{api, idle}, []Listener{
		{Endpoint: Endpoint{IP: "0.0.0.0", Port: 8080}, Service: api},
	})
	store.observe(Endpoint{IP: "10.1.0.2", Port: 9090}, api, time.Now())
	handler := metadataHandler(store, cfg)
	for _, test := range []struct {
		path, method, token string
		status              int
	}{
		{MetadataPath, http.MethodGet, "", http.StatusUnauthorized},
		{MetadataPath, http.MethodPost, cfg.Token, http.StatusMethodNotAllowed},
		{MetadataPath + "?port=bad", http.MethodGet, cfg.Token, http.StatusBadRequest},
		{MetadataPath + "?target=hostname", http.MethodGet, cfg.Token, http.StatusBadRequest},
		{MetadataPath + "?ip=bad", http.MethodGet, cfg.Token, http.StatusBadRequest},
		{MetadataPath, http.MethodGet, cfg.Token, http.StatusOK},
	} {
		r := httptest.NewRequest(test.method, test.path, nil)
		r.Header.Set("Authorization", "Bearer "+test.token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		require.Equal(t, test.status, w.Code, test.path)
	}
	r := httptest.NewRequest(http.MethodGet, MetadataPath+"?port=8080&ip=10.1.0.1&target=10.1.0.2", nil)
	r.Header.Set("Authorization", "Bearer "+cfg.Token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var snapshot Snapshot
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &snapshot))
	require.Equal(t, "host", snapshot.Hostname)
	require.ElementsMatch(t, []Service{api}, snapshot.Services)
	require.Len(t, snapshot.Callers, 1)
	cfg.MaxResponseBytes = 1
	w = httptest.NewRecorder()
	metadataHandler(store, cfg).ServeHTTP(w, r)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestSnapshotValidation(t *testing.T) {
	snapshot := Snapshot{Version: 1, Hostname: "host", Callers: []Caller{
		{Destination: Endpoint{IP: "::ffff:10.1.0.2", Port: 8080}, Services: []CallerService{
			{Service: Service{Name: "api"}, RemainingMillis: 120000},
		}},
	}}
	require.NoError(t, validateSnapshot(&snapshot, time.Minute))
	require.Equal(t, "10.1.0.2", snapshot.Callers[0].Destination.IP)
	require.EqualValues(t, 60000, snapshot.Callers[0].Services[0].RemainingMillis)
	snapshot.Callers[0].Services[0].RemainingMillis = -1
	require.Error(t, validateSnapshot(&snapshot, time.Minute))
	snapshot.Version = 2
	require.Error(t, validateSnapshot(&snapshot, time.Minute))
}

func TestHTTPFailuresAndResponseLimits(t *testing.T) {
	cfg := DefaultConfig()
	for _, test := range []struct {
		name, body, redirect string
		status, maxBytes     int
	}{
		{name: "wrong version", body: `{"version":2,"hostname":"host"}`, status: 200, maxBytes: 1000},
		{name: "invalid JSON", body: `{`, status: 200, maxBytes: 1000},
		{name: "oversized", body: `{"version":1,"hostname":"host"}`, status: 200, maxBytes: 5},
		{name: "unavailable", body: "unavailable", status: 503, maxBytes: 1000},
		{name: "redirect", redirect: "http://127.0.0.1:1", status: 302, maxBytes: 1000},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", test.redirect)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			cfg.Port = server.Listener.Addr().(*net.TCPAddr).Port
			cfg.MaxResponseBytes = test.maxBytes
			client := newHTTPClient(cfg, nil)
			defer client.CloseIdleConnections()
			_, _, err := fetchSnapshot(t.Context(), client, cfg, netip.MustParseAddr("127.0.0.1"), nil)
			require.Error(t, err)
		})
	}
}

func TestTLSVerification(t *testing.T) {
	cfg := DefaultConfig()
	store := newStore("host", cfg)
	server := httptest.NewTLSServer(metadataHandler(store, cfg))
	defer server.Close()
	dir := t.TempDir()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	key, err := x509.MarshalPKCS8PrivateKey(server.TLS.Certificates[0].PrivateKey)
	require.NoError(t, err)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, certificate, 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600))
	cfg.Port = server.Listener.Addr().(*net.TCPAddr).Port
	cfg.TLS = TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile}
	for _, trusted := range []bool{false, true} {
		if trusted {
			cfg.TLS.CAFile = certFile
		}
		_, clientTLS, err := tlsConfigs(cfg.TLS)
		require.NoError(t, err)
		client := newHTTPClient(cfg, clientTLS)
		snapshot, _, err := fetchSnapshot(t.Context(), client, cfg, netip.MustParseAddr("127.0.0.1"), nil)
		client.CloseIdleConnections()
		if trusted {
			require.NoError(t, err)
			require.Equal(t, "host", snapshot.Hostname)
		} else {
			require.Error(t, err)
		}
	}
}

func TestBearerTokenAuthorization(t *testing.T) {
	for _, test := range []struct {
		name, token, authorization string
		status                     int
	}{
		{"valid token", "shared-secret", "Bearer shared-secret", http.StatusOK},
		{"missing header", "shared-secret", "", http.StatusUnauthorized},
		{"empty token", "shared-secret", "Bearer ", http.StatusUnauthorized},
		{"wrong token", "shared-secret", "Bearer different-secret", http.StatusUnauthorized},
		{"truncated token", "shared-secret", "Bearer shared", http.StatusUnauthorized},
		{"missing scheme", "shared-secret", "shared-secret", http.StatusUnauthorized},
		{"wrong scheme", "shared-secret", "Basic shared-secret", http.StatusUnauthorized},
		{"authentication disabled", "", "", http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Token = test.token
			r := httptest.NewRequest(http.MethodGet, MetadataPath, nil)
			if test.authorization != "" {
				r.Header.Set("Authorization", test.authorization)
			}
			w := httptest.NewRecorder()
			metadataHandler(newStore("host", cfg), cfg).ServeHTTP(w, r)
			require.Equal(t, test.status, w.Code)
			if test.status == http.StatusUnauthorized {
				require.NotContains(t, w.Body.String(), test.token)
				require.NotContains(t, w.Body.String(), `"hostname"`)
			}
		})
	}
}
