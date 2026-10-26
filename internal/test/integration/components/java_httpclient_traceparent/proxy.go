// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type observation struct {
	Headers     []string `json:"headers"`
	Protocol    int      `json:"protocol"`
	Connection  string   `json:"connection"`
	Body        string   `json:"body"`
	Application string   `json:"application"`
	Tracestate  string   `json:"tracestate"`
	BodyError   string   `json:"body_error,omitempty"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "certificate" {
		certificate()
		return
	}
	var mu sync.Mutex
	records := make(map[string][]observation)
	downstream := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := strings.CutPrefix(r.URL.Path, "/records"); ok {
			mu.Lock()
			defer mu.Unlock()
			if _, exists := records[id]; !exists {
				w.WriteHeader(http.StatusNotFound)
			}
			_ = json.NewEncoder(w).Encode(records[id])
			return
		}
		headers := r.Header.Values("Traceparent")
		mu.Lock()
		records[r.URL.Path] = append(records[r.URL.Path], observation{
			Headers: headers, Protocol: r.ProtoMajor, Connection: r.RemoteAddr,
			Application: r.Header.Get("X-Application"), Tracestate: r.Header.Get("Tracestate"),
		})
		attempt := len(records[r.URL.Path])
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "-expect-reject") {
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusExpectationFailed)
			_, _ = w.Write([]byte("expectation rejected"))
			w.(http.Flusher).Flush()
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			mu.Lock()
			records[r.URL.Path][attempt-1].BodyError = err.Error()
			mu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		records[r.URL.Path][attempt-1].Body = string(body)
		mu.Unlock()
		log.Printf("TRACEPARENT %s protocol=%s values=%q", r.URL.Path, r.Proto, headers)
		keepAlive := strings.HasSuffix(r.URL.Path, "-pool-first") || strings.Contains(r.URL.Path, "-reuse") && attempt == 1
		if r.ProtoMajor == 1 && !keepAlive {
			w.Header().Set("Connection", "close")
		}
		if strings.Contains(r.URL.Path, "-retry") && attempt == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		if strings.HasSuffix(r.URL.Path, "-redirect") {
			http.Redirect(w, r, r.URL.Path+"-target", http.StatusFound)
			return
		}
		if strings.Contains(r.URL.Path, "-auth") && r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "-timeout") || strings.HasSuffix(r.URL.Path, "-cancel-transport") {
			<-r.Context().Done()
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, "http://downstream:8086"+r.URL.Path, strings.NewReader(string(body)))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		for _, header := range headers {
			req.Header.Add("Traceparent", header)
		}
		for _, state := range r.Header.Values("Tracestate") {
			req.Header.Add("Tracestate", state)
		}
		response, err := downstream.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})
	go func() { log.Fatal(http.ListenAndServe(":8082", handler)) }()
	go func() {
		server := &http.Server{
			Addr: ":8445", Handler: handler, ReadHeaderTimeout: 10 * time.Second,
			TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
		log.Fatal(server.ListenAndServeTLS("proxy.crt", "proxy.key"))
	}()
	server := &http.Server{
		Addr: ":8443", Handler: handler,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	log.Fatal(server.ListenAndServeTLS("proxy.crt", "proxy.key"))
}

func certificate() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "proxy"},
		DNSNames: []string{"proxy"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("proxy.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("proxy.key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		log.Fatal(err)
	}
}
