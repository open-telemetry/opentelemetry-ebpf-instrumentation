// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const (
	ownedTraceparent = "00-11111111111111111111111111111111-2222222222222222-01"
	muxTraceparent   = "00-33333333333333333333333333333333-4444444444444444-01"
)

type headerObservation struct {
	Traceparents []string `json:"traceparents"`
	RemoteAddr   string   `json:"remote_addr"`
	Protocol     string   `json:"protocol"`
}

type ownershipResult struct {
	Transport string              `json:"transport"`
	Repeated  []headerObservation `json:"repeated"`
	Controls  []headerObservation `json:"controls"`
	MuxOwned  headerObservation   `json:"mux_owned"`
	MuxPlain  headerObservation   `json:"mux_plain"`
	Error     string              `json:"error,omitempty"`
}

func checkErr(err error, msg string) {
	if err == nil {
		return
	}
	fmt.Printf("ERROR: %s: %s\n", msg, err)
}

func main() {
	go serveOwnershipTrigger()

	for {
		HttpClientExample()
		RoundTripExample()
		HttpClientDoExample()

		time.Sleep(time.Second)
	}
}

func serveOwnershipTrigger() {
	mux := http.NewServeMux()
	mux.HandleFunc("/run", func(w http.ResponseWriter, _ *http.Request) {
		runOwnershipSuites()
		w.WriteHeader(http.StatusNoContent)
	})
	checkErr(http.ListenAndServe("0.0.0.0:7575", mux), "while serving ownership trigger")
}

func init() {
	if os.Getenv("TEST_HTTP2_PROTOCOLS") == "1" {
		newHTTP2Transport = newHTTP2TransportThroughProtocols
		newOwnershipTLSRoundTripper = newHTTP2TransportThroughProtocols
		newOwnershipPlaintextRoundTripper = newHTTP2PlaintextTransportThroughProtocols
	}
}

func newHTTP2TransportThroughProtocols() http.RoundTripper {
	protocols := &http.Protocols{}
	protocols.SetHTTP2(true)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Protocols = protocols
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return tr
}

var newHTTP2Transport = func() http.RoundTripper {
	return &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

var newOwnershipTLSRoundTripper = func() http.RoundTripper {
	return &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

var newOwnershipPlaintextRoundTripper = func() http.RoundTripper {
	return &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
}

func newHTTP2PlaintextTransportThroughProtocols() http.RoundTripper {
	protocols := &http.Protocols{}
	protocols.SetUnencryptedHTTP2(true)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Protocols = protocols
	return tr
}

func runOwnershipSuites() {
	target := os.Getenv("TARGET_URL")
	runOwnershipSuite("tls", target, newOwnershipTLSRoundTripper())
	runOwnershipSuite(
		"plaintext",
		"http://testserver:7374",
		newOwnershipPlaintextRoundTripper(),
	)
}

func runOwnershipSuite(name, target string, transport http.RoundTripper) {
	result := ownershipResult{Transport: name}
	client := &http.Client{Transport: transport}

	for range 4 {
		observation, err := observeHeaders(client, target+"/ownership/repeated", ownedTraceparent)
		if err != nil {
			result.Error = err.Error()
			writeOwnershipResult(result)
			return
		}
		result.Repeated = append(result.Repeated, observation)
	}

	for range 2 {
		observation, err := observeHeaders(client, target+"/ownership/control", "")
		if err != nil {
			result.Error = err.Error()
			writeOwnershipResult(result)
			return
		}
		result.Controls = append(result.Controls, observation)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})
	var ownedErr, plainErr error
	go func() {
		defer wg.Done()
		<-start
		result.MuxOwned, ownedErr =
			observeHeaders(client, target+"/ownership/multiplex", muxTraceparent)
	}()
	go func() {
		defer wg.Done()
		<-start
		result.MuxPlain, plainErr = observeHeaders(client, target+"/ownership/multiplex", "")
	}()
	close(start)
	wg.Wait()
	if ownedErr != nil {
		result.Error = ownedErr.Error()
	} else if plainErr != nil {
		result.Error = plainErr.Error()
	}

	writeOwnershipResult(result)
}

func observeHeaders(client *http.Client, url, traceparent string) (headerObservation, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return headerObservation{}, err
	}
	if traceparent != "" {
		req.Header.Set("TrAcEpArEnT", traceparent)
	}

	resp, err := client.Do(req)
	if err != nil {
		return headerObservation{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return headerObservation{}, fmt.Errorf("unexpected status %s", resp.Status)
	}

	var observation headerObservation
	if err := json.NewDecoder(resp.Body).Decode(&observation); err != nil {
		return headerObservation{}, err
	}
	return observation, nil
}

func writeOwnershipResult(result ownershipResult) {
	encoded, err := json.Marshal(result)
	if err != nil {
		fmt.Printf("ERROR: encoding ownership result: %s\n", err)
		return
	}
	fmt.Printf("HTTP2_OWNERSHIP_RESULT %s\n", encoded)
}

func RoundTripExample() {
	req, err := http.NewRequestWithContext(context.Background(), "GET", os.Getenv("TARGET_URL")+"/pingrt", nil)
	checkErr(err, "during new request")

	tr := newHTTP2Transport()
	resp, err := tr.RoundTrip(req)
	checkErr(err, "during roundtrip")

	if err == nil {
		fmt.Printf("RoundTrip Proto: %d\n", resp.ProtoMajor)
	}
}

func HttpClientExample() {
	client := http.Client{
		Transport: newHTTP2Transport(),
	}

	resp, err := client.Get(os.Getenv("TARGET_URL") + "/ping")
	checkErr(err, "during get")

	if err == nil {
		fmt.Printf("Client Proto: %d\n", resp.ProtoMajor)
	}
}

func HttpClientDoExample() {
	client := http.Client{
		Transport: newHTTP2Transport(),
	}

	req, err := http.NewRequestWithContext(context.Background(), "GET", os.Getenv("TARGET_URL")+"/pingdo", nil)
	checkErr(err, "during new request")

	resp, err := client.Do(req)
	checkErr(err, "during get")

	if err == nil {
		fmt.Printf("Client.Do Proto: %d\n", resp.ProtoMajor)
	}
}
