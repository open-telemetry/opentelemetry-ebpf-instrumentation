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

var testLoopbackNetwork = network{allowed: []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"),
}}

func TestMetadataEndpoint(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Token = "shared-secret"
	cfg.PeerCIDRs = []string{"10.1.0.0/16"}
	store := newStore("host", cfg)
	api, idle := Service{Name: "api"}, Service{Name: "idle"}
	store.setInventory([]Service{api, idle}, []Listener{
		{Endpoint: Endpoint{IP: "0.0.0.0", Port: 8080}, Service: api},
	})
	store.observe(Endpoint{IP: "10.1.0.2", Port: 9090}, api, time.Now())
	peers, err := makeNetwork(nil, cfg.PeerCIDRs)
	require.NoError(t, err)
	handler := metadataHandler(store, cfg, peers, nil)
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
		r.RemoteAddr = "10.1.0.2:1234"
		r.Header.Set("Authorization", "Bearer "+test.token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		require.Equal(t, test.status, w.Code, test.path)
	}
	r := httptest.NewRequest(http.MethodGet, MetadataPath+"?port=8080&ip=10.1.0.1&target=10.1.0.2", nil)
	r.RemoteAddr = "10.1.0.2:1234"
	r.Header.Set("Authorization", "Bearer "+cfg.Token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var snapshot Snapshot
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &snapshot))
	require.Equal(t, "host", snapshot.Hostname)
	require.ElementsMatch(t, []Service{api}, snapshot.Services)
	require.Len(t, snapshot.Callers, 1)
	t.Run("IPv6 query excludes IPv4 wildcard", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, MetadataPath+"?ip=fd12::2&port=8080", nil)
		r.RemoteAddr = "10.1.0.2:1234"
		r.Header.Set("Authorization", "Bearer "+cfg.Token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		require.Equal(t, http.StatusOK, w.Code)
		var snapshot Snapshot
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &snapshot))
		require.Empty(t, snapshot.Listeners)
		require.Empty(t, snapshot.Services)
	})
	cfg.MaxResponseBytes = 1
	w = httptest.NewRecorder()
	metadataHandler(store, cfg, peers, nil).ServeHTTP(w, r)
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

func TestSnapshotValidatesKnownCallers(t *testing.T) {
	snapshot := Snapshot{Version: ProtocolVersion, Hostname: "host", KnownCallers: []Caller{
		{Destination: Endpoint{IP: "::ffff:10.1.0.2", Port: 8080}, Services: []CallerService{
			{Service: Service{Name: "frontend"}, RemainingMillis: 120000},
		}},
	}}
	require.NoError(t, validateSnapshot(&snapshot, time.Minute))
	require.Equal(t, "10.1.0.2", snapshot.KnownCallers[0].Destination.IP)
	require.EqualValues(t, 60000, snapshot.KnownCallers[0].Services[0].RemainingMillis)
	snapshot.KnownCallers[0].Services[0].RemainingMillis = -1
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
			_, _, err := fetchSnapshot(t.Context(), client, cfg, netip.MustParseAddr("127.0.0.1"))
			require.Error(t, err)
		})
	}
}

func TestTLSVerification(t *testing.T) {
	cfg := DefaultConfig()
	store := newStore("host", cfg)
	server := httptest.NewTLSServer(metadataHandler(store, cfg, testLoopbackNetwork, nil))
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
		snapshot, _, err := fetchSnapshot(t.Context(), client, cfg, netip.MustParseAddr("127.0.0.1"))
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
			r.RemoteAddr = "127.0.0.1:1234"
			if test.authorization != "" {
				r.Header.Set("Authorization", test.authorization)
			}
			w := httptest.NewRecorder()
			metadataHandler(newStore("host", cfg), cfg, testLoopbackNetwork, nil).ServeHTTP(w, r)
			require.Equal(t, test.status, w.Code)
			if test.status == http.StatusUnauthorized {
				require.NotContains(t, w.Body.String(), test.token)
				require.NotContains(t, w.Body.String(), `"hostname"`)
			}
		})
	}
}

func TestMetadataEndpointRestrictsRequesterCIDRs(t *testing.T) {
	for _, test := range []struct {
		name      string
		remote    string
		automatic bool
		token     string
		status    int
	}{
		{name: "allowed IPv4", remote: "10.1.0.2:1234", status: http.StatusOK},
		{name: "outside IPv4 CIDR", remote: "10.2.0.2:1234", status: http.StatusForbidden},
		{name: "IPv4-mapped IPv6", remote: "[::ffff:10.1.0.2]:1234", status: http.StatusOK},
		{name: "allowed IPv6", remote: "[fd12::2]:1234", status: http.StatusOK},
		{name: "outside IPv6 CIDR", remote: "[fd13::2]:1234", status: http.StatusForbidden},
		{name: "loopback excluded by explicit CIDRs", remote: "127.0.0.1:1234", status: http.StatusForbidden},
		{name: "malformed source", remote: "invalid", status: http.StatusForbidden},
		{name: "valid token cannot bypass CIDRs", remote: "10.2.0.2:1234", token: "shared-secret", status: http.StatusForbidden},
		{name: "automatic private block", remote: "10.200.0.2:1234", automatic: true, status: http.StatusOK},
		{name: "outside automatic private blocks", remote: "172.16.0.2:1234", automatic: true, status: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.PeerCIDRs = []string{"10.1.0.0/16", "fd12::/64"}
			if test.automatic {
				cfg.PeerCIDRs = nil
			}
			cfg.Token = test.token
			peers, err := makeNetwork([]netip.Addr{netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("fd12::1")}, cfg.PeerCIDRs)
			require.NoError(t, err)
			store := newStore("private-host", cfg)
			store.setInventory([]Service{{Name: "private-api"}}, nil)
			r := httptest.NewRequest(http.MethodGet, MetadataPath, nil)
			r.RemoteAddr = test.remote
			r.Header.Set("X-Forwarded-For", "10.1.0.2")
			r.Header.Set("Forwarded", "for=10.1.0.2")
			if test.token != "" {
				r.Header.Set("Authorization", "Bearer "+test.token)
			}
			w := httptest.NewRecorder()
			metadataHandler(store, cfg, peers, nil).ServeHTTP(w, r)
			require.Equal(t, test.status, w.Code)
			if test.status == http.StatusForbidden {
				require.NotContains(t, w.Body.String(), "private-host")
				require.NotContains(t, w.Body.String(), "private-api")
			}
		})
	}
}

func TestMetadataEndpointRestrictsCallerTargets(t *testing.T) {
	cfg := DefaultConfig()
	peers, err := makeNetwork(nil, []string{"10.1.0.0/16", "fd12::/64"})
	require.NoError(t, err)
	store := newStore("host", cfg)
	for _, ip := range []string{"10.1.0.2", "10.1.0.3", "fd12::2", "fd12::3"} {
		store.observe(Endpoint{IP: ip, Port: 8080}, Service{Name: "caller"}, time.Now())
	}
	handler := metadataHandler(store, cfg, peers, nil)
	for _, test := range []struct {
		name, remote, query string
		status              int
	}{
		{name: "default source", remote: "10.1.0.2:1234", status: http.StatusOK},
		{name: "matching target", remote: "10.1.0.2:1234", query: "?target=10.1.0.2", status: http.StatusOK},
		{name: "different target", remote: "10.1.0.2:1234", query: "?target=10.1.0.3", status: http.StatusBadRequest},
		{name: "mixed targets", remote: "10.1.0.2:1234", query: "?target=10.1.0.2&target=10.1.0.3", status: http.StatusBadRequest},
		{name: "repeated matching target", remote: "10.1.0.2:1234", query: "?target=10.1.0.2&target=10.1.0.2", status: http.StatusOK},
		{name: "IPv4-mapped target", remote: "10.1.0.2:1234", query: "?target=::ffff:10.1.0.2", status: http.StatusOK},
		{name: "IPv4-mapped source", remote: "[::ffff:10.1.0.2]:1234", query: "?target=10.1.0.2", status: http.StatusOK},
		{name: "IPv6 source", remote: "[fd12::2]:1234", status: http.StatusOK},
		{name: "IPv6 target", remote: "[fd12::2]:1234", query: "?target=fd12:0:0:0:0:0:0:2", status: http.StatusOK},
		{name: "different IPv6 target", remote: "[fd12::2]:1234", query: "?target=fd12::3", status: http.StatusBadRequest},
		{name: "invalid target", remote: "10.1.0.2:1234", query: "?target=hostname", status: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, MetadataPath+test.query, nil)
			r.RemoteAddr = test.remote
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			require.Equal(t, test.status, w.Code)
			if test.status != http.StatusOK {
				require.NotContains(t, w.Body.String(), `"hostname"`)
				return
			}
			var snapshot Snapshot
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &snapshot))
			require.Len(t, snapshot.Callers, 1)
			expected := netip.MustParseAddrPort(test.remote).Addr().Unmap().String()
			require.Equal(t, expected, snapshot.Callers[0].Destination.IP)
		})
	}
}

func TestFetchSnapshotDefaultsToRequesterAddress(t *testing.T) {
	cfg := DefaultConfig()
	store := newStore("host", cfg)
	self := Endpoint{IP: "127.0.0.1", Port: 8080}
	store.observe(self, Service{Name: "caller"}, time.Now())
	store.observe(Endpoint{IP: "10.1.0.2", Port: 8080}, Service{Name: "unrelated"}, time.Now())
	server := httptest.NewServer(metadataHandler(store, cfg, testLoopbackNetwork, nil))
	defer server.Close()
	cfg.Port = server.Listener.Addr().(*net.TCPAddr).Port
	client := newHTTPClient(cfg, nil)
	defer client.CloseIdleConnections()
	snapshot, _, err := fetchSnapshot(t.Context(), client, cfg, netip.MustParseAddr("127.0.0.1"))
	require.NoError(t, err)
	require.Len(t, snapshot.Callers, 1)
	require.Equal(t, self, snapshot.Callers[0].Destination)
}

func TestKnownCallersAreScopedToRequester(t *testing.T) {
	cfg := DefaultConfig()
	peers, err := makeNetwork(nil, []string{"10.1.0.0/16"})
	require.NoError(t, err)
	cache := newPeerCache(cfg)
	target := Endpoint{IP: "10.1.0.2", Port: 8080}
	now := time.Now()
	for _, caller := range []struct{ ip, name string }{
		{ip: "10.1.0.1", name: "frontend"}, {ip: "10.1.0.3", name: "other"},
	} {
		address := netip.MustParseAddr(caller.ip)
		snapshot := indexSnapshot(&Snapshot{Hostname: "host", Callers: []Caller{{
			Destination: target,
			Services:    []CallerService{{Service: Service{Name: caller.name}, RemainingMillis: cfg.CallerTTL.Milliseconds()}},
		}}})
		cache.lookup(address, now)
		cache.complete(cache.due(now, 1)[0], snapshot, 1, now, now)
	}
	before := cache.peers.Keys()
	handler := metadataHandler(newStore("server-host", cfg), cfg, peers, cache)
	for _, test := range []struct{ source, caller string }{
		{source: "10.1.0.1", caller: "frontend"}, {source: "10.1.0.3", caller: "other"}, {source: "10.1.0.4"},
	} {
		r := httptest.NewRequest(http.MethodGet, MetadataPath, nil)
		r.RemoteAddr = net.JoinHostPort(test.source, "1234")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		require.Equal(t, http.StatusOK, w.Code)
		var snapshot Snapshot
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &snapshot))
		if test.caller == "" {
			require.Empty(t, snapshot.KnownCallers)
			continue
		}
		require.Len(t, snapshot.KnownCallers, 1)
		require.Equal(t, target, snapshot.KnownCallers[0].Destination)
		require.Len(t, snapshot.KnownCallers[0].Services, 1)
		require.Equal(t, test.caller, snapshot.KnownCallers[0].Services[0].Service.Name)
	}
	require.Equal(t, before, cache.peers.Keys(), "metadata requests must not register peers or alter eviction order")
}
