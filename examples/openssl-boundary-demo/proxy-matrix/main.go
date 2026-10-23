// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Command proxy-matrix measures the current Frida backend through real proxies.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const matrixHost = "obi-proxy-matrix"

type matrix struct {
	ctx       context.Context
	compose   string
	project   string
	directory string
	env       []string
	roles     map[int]string
	http3     string
}

func (m *matrix) docker(args ...string) ([]byte, error) {
	args = append([]string{"compose", "-p", m.project, "-f", m.compose}, args...)
	cmd := exec.CommandContext(m.ctx, "docker", args...)
	cmd.Env = m.env
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker %s: %w\n%s", strings.Join(args, " "), err, output)
	}
	return output, nil
}

func (m *matrix) port(service string, port int) (string, error) {
	data, err := m.docker("port", service, strconv.Itoa(port))
	return strings.TrimSpace(string(data)), err
}

func (m *matrix) refreshProcesses() error {
	for _, role := range []string{"backend", "backend2", "nginx", "apache", "unobserved"} {
		data, err := m.docker("top", role)
		if err != nil {
			return err
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || (fields[0] != role && fields[0] != "SERVICE") {
				continue
			}
			pid, parseErr := strconv.Atoi(fields[3])
			if parseErr == nil {
				m.roles[pid] = role
			}
		}
	}
	return nil
}

func (m *matrix) waitAttached(ctx context.Context, pid int) error {
	return poll(ctx, func() (bool, error) {
		data, err := m.docker("logs", "--no-color", "obi")
		if err != nil {
			return false, err
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			if strings.Contains(line, "Frida OpenSSL agent attached") && strings.Contains(line, fmt.Sprintf("pid=%d ", pid)) {
				return true, nil
			}
		}
		return false, nil
	})
}

func poll(ctx context.Context, predicate func() (bool, error)) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready, err := predicate()
		if err != nil || ready {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func certificate(directory string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: matrixHost},
		DNSNames:  []string{matrixHost, "backend", "backend2", "apache", "nginx"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(directory, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0o600)
}

func writeConfig(directory, propagation string) error {
	config := `file_format: "1.0"
log_level: info
tracer_provider:
  processors:
    - batch:
        exporter:
          otlp_http:
            endpoint: http://collector:4318/v1/traces
        schedule_delay: 100
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: exclude
        min_process_age: 1ms
        poll_interval: 100ms
      rules:
        - action: include
          match:
            process:
              exe_path_regex: '(^|/)(nginx|httpd)$'
              cmd_args_regex: '/example/obi-proxy-matrix-'
        - action: include
          match:
            process:
              exe_path_regex: '(^|/)(openssl|curl)$'
              cmd_args_regex: 'obi-proxy-matrix'
      runtimes:
        frida:
          enabled: true
          library: /opt/frida/libfrida-core.so
      engine:
        batching:
          batch_length: 1
          batch_timeout: 100ms
        propagation:
          context_propagation: PROPAGATION
    enrich:
      enrichers:
        kubernetes:
          mode: disabled
`
	return os.WriteFile(filepath.Join(directory, "obi.yaml"), []byte(strings.ReplaceAll(config, "PROPAGATION", propagation)), 0o644)
}

func (m *matrix) saveLogs() error {
	var result error
	for _, role := range []string{"backend", "backend2", "nginx", "apache", "unobserved", "obi", "collector"} {
		data, err := m.docker("logs", "--no-color", "--no-log-prefix", role)
		if err == nil {
			err = os.WriteFile(filepath.Join(m.directory, role+".log"), data, 0o600)
		}
		result = errors.Join(result, err)
	}
	return result
}

func (m *matrix) proxyLogs() ([]proxyEvent, error) {
	var result []proxyEvent
	for _, role := range []string{"backend", "backend2", "nginx", "apache", "unobserved"} {
		data, err := m.docker("logs", "--no-color", "--no-log-prefix", role)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			var event proxyEvent
			if json.Unmarshal(scanner.Bytes(), &event) == nil && event.Role != "" {
				if role == "backend2" || role == "unobserved" {
					event.Role = "backend2"
				}
				result = append(result, event)
			}
		}
	}
	return result, nil
}

func run() error {
	compose := flag.String("compose", "examples/openssl-boundary-demo/proxy-matrix/compose.yaml", "Compose file")
	output := flag.String("output", "", "new directory for logs and results")
	project := flag.String("project", "obi-frida-proxy-matrix", "isolated Compose project")
	propagation := flag.String("propagation", "disabled", "existing socket header propagation: disabled or headers")
	only := flag.String("cases", "", "comma-separated case names; empty runs the full matrix")
	http3 := flag.String("http3-client", "bin/frida-http3/bin/curl", "curl with OpenSSL/ngtcp2 HTTP/3 support")
	keep := flag.Bool("keep", false, "leave Compose running for inspection")
	flag.Parse()
	if *propagation != "disabled" && *propagation != "headers" {
		return errors.New("--propagation must be disabled or headers")
	}
	selected := make(map[string]bool)
	if *only != "" {
		for name := range strings.SplitSeq(*only, ",") {
			selected[name] = true
		}
		for _, test := range cases() {
			delete(selected, test.Name)
		}
		if len(selected) != 0 {
			return fmt.Errorf("unknown cases: %v", selected)
		}
		for name := range strings.SplitSeq(*only, ",") {
			selected[name] = true
		}
	}
	if *output == "" {
		*output = filepath.Join("testoutput", "frida-proxies-"+time.Now().UTC().Format("20060102T150405"))
	}
	directory, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(directory), 0o750); err != nil {
		return err
	}
	if err = os.Mkdir(directory, 0o750); err != nil {
		return fmt.Errorf("create a new output directory (parent must exist): %w", err)
	}
	if err = certificate(directory); err != nil {
		return err
	}
	if err = writeConfig(directory, *propagation); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 15*time.Minute)
	defer timeout()
	m := &matrix{ctx: ctx, compose: *compose, project: *project, directory: directory, roles: make(map[int]string), http3: *http3}
	m.env = append(os.Environ(), "MATRIX_ARTIFACTS="+directory, "MATRIX_UID="+strconv.Itoa(os.Getuid()), "MATRIX_GID="+strconv.Itoa(os.Getgid()))
	defer func() {
		cleanup, finish := context.WithTimeout(context.Background(), 30*time.Second)
		defer finish()
		m.ctx = cleanup
		if err := m.saveLogs(); err != nil {
			fmt.Fprintln(os.Stderr, "saving logs:", err)
		}
		if !*keep {
			if _, err := m.docker("down", "--volumes"); err != nil {
				fmt.Fprintln(os.Stderr, "cleanup:", err)
			}
		}
	}()
	if _, err = m.docker("up", "-d"); err != nil {
		return err
	}
	startup, stop := context.WithTimeout(ctx, 60*time.Second)
	defer stop()
	if err = poll(startup, func() (bool, error) {
		address, lookupErr := m.port("nginx", 8443)
		if lookupErr != nil {
			return false, lookupErr
		}
		conn, dialErr := net.DialTimeout("tcp4", address, 200*time.Millisecond)
		if dialErr != nil {
			return false, nil
		}
		_ = conn.Close()
		return true, nil
	}); err != nil {
		return fmt.Errorf("proxy startup: %w", err)
	}
	if err = m.refreshProcesses(); err != nil {
		return err
	}
	for pid, role := range m.roles {
		if role == "unobserved" {
			continue
		}
		if err = m.waitAttached(startup, pid); err != nil {
			return fmt.Errorf("waiting for %s PID %d attachment: %w", role, pid, err)
		}
	}
	var results []caseResult
	writeResults := func() error {
		data, marshalErr := json.MarshalIndent(struct {
			Propagation string       `json:"socket_propagation"`
			Cases       []caseResult `json:"cases"`
		}{*propagation, results}, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		return os.WriteFile(filepath.Join(directory, "results.json"), append(data, '\n'), 0o644)
	}
	for _, test := range cases() {
		if *only != "" && !selected[test.Name] {
			continue
		}
		fmt.Println("RUN", test.Name)
		result := m.runCase(test)
		results = append(results, result)
		fmt.Printf("%s: %s (wire context=%t, ancestry=%t)\n", test.Name, result.Support, result.ContextContinues, result.FullAncestry)
		if err = writeResults(); err != nil {
			return err
		}
		if result.Error != "" {
			return fmt.Errorf("%s: %s", test.Name, result.Error)
		}
	}
	if !*keep {
		// Close upstream pools before the final export snapshot, leaving OBI and
		// the Collector running. Keep the pre-drain count to expose late exports.
		if _, err = m.docker("stop", "--timeout", "5", "nginx", "unobserved", "apache", "backend", "backend2"); err != nil {
			return err
		}
		time.Sleep(3 * time.Second)
		spans, spanErr := m.spans()
		if spanErr != nil {
			return spanErr
		}
		events, eventErr := m.proxyLogs()
		if eventErr != nil {
			return eventErr
		}
		for i, result := range results {
			for _, test := range cases() {
				if test.Name == result.Name {
					results[i] = evaluate(test, result.Observations, events, spans)
					results[i].SpansBeforeDrain = len(result.Spans)
				}
			}
		}
		if err = writeResults(); err != nil {
			return err
		}
	}
	fmt.Println("Results:", filepath.Join(directory, "results.json"))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "matrix failed:", err)
		os.Exit(1)
	}
}
