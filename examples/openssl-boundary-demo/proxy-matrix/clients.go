// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const existingContext = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"

type scenario struct {
	Name       string
	Service    string
	Port       int
	Mode       string
	Prefix     string
	Proxies    []string
	Requests   int
	Concurrent bool
	Reuse      bool
	Existing   bool
	Split      bool
	Body       int
	MutualTLS  bool
	Fragment   int
}

func cases() []scenario {
	return []scenario{
		{Name: "direct-tls", Service: "backend", Port: 8443, Prefix: "/direct/"},
		{Name: "nginx-tls-passthrough", Service: "nginx", Port: 9443, Prefix: "/passthrough/"},
		{Name: "apache-connect", Service: "apache", Port: 8080, Mode: "connect", Prefix: "/connect/"},
		{Name: "apache-authenticated-connect", Service: "apache", Port: 8081, Mode: "connect-auth", Prefix: "/connect/"},
		{Name: "unobserved-reverse-proxy", Service: "unobserved", Port: 8443, Prefix: "/tls/"},
		{Name: "nginx-mutual-tls-client", Service: "nginx", Port: 8444, Prefix: "/tls/", Proxies: []string{"nginx"}, MutualTLS: true},
		{Name: "direct-mutual-tls", Service: "backend", Port: 9444, Prefix: "/mtls/", MutualTLS: true},
		{Name: "nginx-tls-to-http", Service: "nginx", Port: 8443, Prefix: "/plain/", Proxies: []string{"nginx"}},
		{Name: "nginx-tls-to-tls", Service: "nginx", Port: 8443, Prefix: "/tls/", Proxies: []string{"nginx"}},
		{Name: "nginx-mutual-tls-upstream", Service: "nginx", Port: 8443, Prefix: "/mtls/", Proxies: []string{"nginx"}},
		{Name: "apache-tls-to-http", Service: "apache", Port: 8443, Prefix: "/plain/", Proxies: []string{"apache"}},
		{Name: "apache-tls-to-tls", Service: "apache", Port: 8443, Prefix: "/tls/", Proxies: []string{"apache"}},
		{Name: "apache-forward-http", Service: "apache", Port: 8080, Mode: "forward-http", Prefix: "/forward/", Proxies: []string{"apache"}},
		{Name: "apache-forward-https-origin", Service: "apache", Port: 8443, Mode: "absolute", Prefix: "/forward/", Proxies: []string{"apache"}},
		{Name: "apache-https-connect", Service: "apache", Port: 8443, Mode: "https-proxy", Prefix: "/nested/"},
		{Name: "nginx-preserve-existing", Service: "nginx", Port: 8443, Prefix: "/tls/", Proxies: []string{"nginx"}, Existing: true},
		{Name: "nginx-strip-header", Service: "nginx", Port: 8443, Prefix: "/strip/", Proxies: []string{"nginx"}},
		{Name: "nginx-replace-header", Service: "nginx", Port: 8443, Prefix: "/replace/", Proxies: []string{"nginx"}},
		{Name: "nginx-upstream-pool", Service: "nginx", Port: 8443, Prefix: "/pool/", Proxies: []string{"nginx"}, Requests: 4, Reuse: true},
		{Name: "nginx-concurrent", Service: "nginx", Port: 8443, Prefix: "/pool/", Proxies: []string{"nginx"}, Requests: 6, Concurrent: true},
		{Name: "nginx-load-balance", Service: "nginx", Port: 8443, Prefix: "/balance/", Proxies: []string{"nginx"}, Requests: 4},
		{Name: "nginx-retry-503", Service: "nginx", Port: 8443, Prefix: "/retry/", Proxies: []string{"nginx"}},
		{Name: "nginx-apache-chain", Service: "nginx", Port: 8443, Prefix: "/chain/", Proxies: []string{"nginx", "apache"}},
		{Name: "nginx-cache", Service: "nginx", Port: 8443, Prefix: "/cache/", Proxies: []string{"nginx"}, Requests: 2},
		{Name: "h2-client-nginx-h1-origin", Service: "nginx", Port: 8443, Mode: "h2", Prefix: "/tls/", Proxies: []string{"nginx"}},
		{Name: "h1-client-apache-h2-origin", Service: "apache", Port: 8443, Prefix: "/h2/", Proxies: []string{"apache"}},
		{Name: "h2-client-apache-h2-origin", Service: "apache", Port: 8443, Mode: "h2", Prefix: "/h2/", Proxies: []string{"apache"}},
		{Name: "h3-client-nginx-h1-origin", Service: "nginx", Port: 8443, Mode: "h3", Prefix: "/tls/", Proxies: []string{"nginx"}},
		{Name: "h3-existing-context-through-nginx", Service: "nginx", Port: 8443, Mode: "h3", Prefix: "/tls/", Proxies: []string{"nginx"}, Existing: true},
		{Name: "split-headers-through-proxy", Service: "nginx", Port: 8443, Prefix: "/tls/", Proxies: []string{"nginx"}, Split: true},
		{Name: "tls-record-fragments-through-proxy", Service: "nginx", Port: 8443, Prefix: "/tls/", Proxies: []string{"nginx"}, Body: 32768, Fragment: 512},
	}
}

type observation struct {
	EchoID       string `json:"id"`
	ClientVerify string `json:"client_verify,omitempty"`
	RequestID    string `json:"request_id"`
	Path         string `json:"path"`
	Traceparent  string `json:"traceparent"`
	Connection   string `json:"connection"`
	Requests     int    `json:"requests"`
	Protocol     string `json:"protocol"`
	Backend      string `json:"backend"`
	ClientPID    int    `json:"client_pid"`
	Cache        string `json:"cache,omitempty"`
	HTTPVersion  string `json:"client_http_version"`
}

type opensslClient struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	reader *bufio.Reader
	log    *os.File
}

func (m *matrix) openClient(ctx context.Context, test scenario, index int) (*opensslClient, error) {
	address, err := m.port(test.Service, test.Port)
	if err != nil {
		return nil, err
	}
	args := []string{"s_client", "-quiet", "-nocommands", "-servername", matrixHost, "-verify_hostname", matrixHost, "-verify_return_error", "-CAfile", filepath.Join(m.directory, "cert.pem")}
	if test.MutualTLS {
		args = append(args, "-cert", filepath.Join(m.directory, "cert.pem"), "-key", filepath.Join(m.directory, "key.pem"))
	}
	if test.Fragment != 0 {
		args = append(args, "-max_send_frag", strconv.Itoa(test.Fragment))
	}
	if strings.HasPrefix(test.Mode, "connect") {
		args = append(args, "-proxy", address, "-connect", "backend:8443")
	} else {
		args = append(args, "-connect", address)
	}
	if test.Mode == "connect-auth" {
		args = append(args, "-proxy_user", "matrix", "-proxy_pass", "pass:matrix")
	}
	cmd := exec.CommandContext(ctx, "openssl", args...)
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	log, err := os.Create(filepath.Join(m.directory, fmt.Sprintf("%s-%d-client.log", test.Name, index)))
	if err != nil {
		return nil, err
	}
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		_ = log.Close()
		return nil, err
	}
	client := &opensslClient{cmd: cmd, input: input, reader: bufio.NewReader(output), log: log}
	if err = m.waitAttached(ctx, cmd.Process.Pid); err != nil {
		client.close()
		return nil, err
	}
	return client, nil
}

func (c *opensslClient) close() {
	_ = c.input.Close()
	_ = c.cmd.Process.Kill()
	_ = c.cmd.Wait()
	_ = c.log.Close()
}

func requestPath(test scenario, index int) string {
	if test.Name == "nginx-cache" {
		index = 0
	}
	return test.Prefix + test.Name + "/" + strconv.Itoa(index)
}

func (c *opensslClient) request(test scenario, index int) (observation, error) {
	path := requestPath(test, index)
	target := path
	if test.Mode == "absolute" {
		target = "https://backend:8443" + path
	}
	headers := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nX-Matrix-ID: %s-%d\r\n", target, matrixHost, test.Name, index)
	if test.Existing {
		headers += "traceparent: " + existingContext + "\r\n"
	}
	if test.Body > 0 {
		headers += fmt.Sprintf("Content-Length: %d\r\n", test.Body)
	}
	payload := headers + "\r\n" + strings.Repeat("x", test.Body)
	if test.Split {
		if _, err := io.WriteString(c.input, headers); err != nil {
			return observation{}, err
		}
		time.Sleep(200 * time.Millisecond)
		payload = "\r\n" + strings.Repeat("x", test.Body)
	}
	if _, err := io.WriteString(c.input, payload); err != nil {
		return observation{}, err
	}
	response, err := http.ReadResponse(c.reader, nil)
	if err != nil {
		return observation{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return observation{}, fmt.Errorf("HTTP %s: %s", response.Status, body)
	}
	var received observation
	if err = json.NewDecoder(response.Body).Decode(&received); err != nil {
		return received, err
	}
	_, _ = io.Copy(io.Discard, response.Body)
	received.ClientPID = c.cmd.Process.Pid
	received.RequestID = fmt.Sprintf("%s-%d", test.Name, index)
	received.Cache = response.Header.Get("X-Matrix-Cache")
	if received.Cache != "HIT" && received.EchoID != received.RequestID {
		return received, fmt.Errorf("response request ID %q, expected %q", received.EchoID, received.RequestID)
	}
	received.HTTPVersion = response.Proto
	return received, nil
}

func (m *matrix) curl(ctx context.Context, test scenario, index int) (observation, error) {
	var address string
	if test.Mode == "h3" {
		data, err := m.docker("port", "--protocol", "udp", test.Service, strconv.Itoa(test.Port))
		if err != nil {
			return observation{}, err
		}
		address = strings.TrimSpace(string(data))
	} else {
		var err error
		address, err = m.port(test.Service, test.Port)
		if err != nil {
			return observation{}, err
		}
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return observation{}, err
	}
	args := []string{"--silent", "--show-error", "--max-time", "20", "--cacert", filepath.Join(m.directory, "cert.pem"), "--resolve", matrixHost + ":" + port + ":127.0.0.1", "--header", fmt.Sprintf("X-Matrix-ID: %s-%d", test.Name, index)}
	if test.Existing {
		args = append(args, "--header", "traceparent: "+existingContext)
	}
	switch test.Mode {
	case "h3":
		args = append(args, "--noproxy", "*", "--http3-only", "https://"+matrixHost+":"+port+requestPath(test, index))
	case "forward-http":
		args = append(args, "--noproxy", "", "--proxy", "http://"+matrixHost+":"+port, "http://backend:8080"+requestPath(test, index))
	case "https-proxy":
		args = append(args, "--noproxy", "", "--http1.1", "--proxy-cacert", filepath.Join(m.directory, "cert.pem"), "--proxy", "https://"+matrixHost+":"+port, "https://backend:8443"+requestPath(test, index))
	default:
		args = append(args, "--noproxy", "*", "--http2", "https://"+matrixHost+":"+port+requestPath(test, index))
	}
	binary := "curl"
	if test.Mode == "h3" {
		binary = m.http3
	}
	// curl blocks on its config input before opening sockets, allowing discovery
	// to attach without introducing another proxy into the network path.
	cmd := exec.CommandContext(ctx, binary, "--config", "-", "--user-agent", matrixHost)
	if test.Mode == "h3" {
		library, err := filepath.Abs(filepath.Join(filepath.Dir(binary), "../lib"))
		if err != nil {
			return observation{}, err
		}
		cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+library)
	}
	input, err := cmd.StdinPipe()
	if err != nil {
		return observation{}, err
	}
	var output, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &output, &stderr
	if err = cmd.Start(); err != nil {
		return observation{}, err
	}
	if err = m.waitAttached(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return observation{}, err
	}
	for i := 0; i < len(args); i++ {
		name := strings.TrimPrefix(args[i], "--")
		switch name {
		case "silent", "show-error", "http1.1", "http2", "http3-only":
			_, err = fmt.Fprintln(input, name)
		default:
			value := args[i]
			if strings.HasPrefix(args[i], "--") {
				i++
				value = args[i]
			} else {
				name = "url"
			}
			encoded, _ := json.Marshal(value)
			_, err = fmt.Fprintf(input, "%s = %s\n", name, encoded)
		}
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return observation{}, err
		}
	}
	_ = input.Close()
	if err = cmd.Wait(); err != nil {
		return observation{}, fmt.Errorf("curl: %w: %s", err, stderr.String())
	}
	var received observation
	if err = json.Unmarshal([]byte(output.String()), &received); err != nil {
		return received, fmt.Errorf("decode curl response: %w: %s", err, output.String())
	}
	received.ClientPID = cmd.Process.Pid
	received.RequestID = fmt.Sprintf("%s-%d", test.Name, index)
	if received.EchoID != received.RequestID {
		return received, fmt.Errorf("response request ID %q, expected %q", received.EchoID, received.RequestID)
	}
	return received, nil
}
