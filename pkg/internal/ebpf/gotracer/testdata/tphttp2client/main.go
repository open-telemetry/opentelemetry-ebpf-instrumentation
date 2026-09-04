// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"unsafe"

	"golang.org/x/net/http2"
)

var useTLS = flag.Bool("tls", false, "use TLS for the loopback connection")

type target struct {
	plainAddress string
	tlsAddress   string
	tlsConfig    *tls.Config
}

func main() {
	flag.Parse()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Traceparent")
		fmt.Fprintf(w, "%d:%s", len(values), strings.Join(values, ","))
	})

	plainListener, err := net.Listen("tcp", "127.0.0.1:0")
	check(err)
	go servePlaintext(plainListener, handler)

	tlsServer := httptest.NewUnstartedServer(handler)
	tlsServer.EnableHTTP2 = true
	tlsServer.StartTLS()
	defer tlsServer.Close()

	fixture := target{
		plainAddress: plainListener.Addr().String(),
		tlsAddress:   tlsServer.Listener.Addr().String(),
		tlsConfig:    &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}},
	}

	fmt.Println("READY")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		switch scanner.Text() {
		case "PLAINTEXT_BUFFERED":
			report(fixture.request(false, false))
		case "PLAINTEXT_IMMEDIATE":
			report(fixture.request(false, true))
		case "TLS_BUFFERED":
			report(fixture.request(true, false))
		case "TLS_IMMEDIATE":
			report(fixture.request(true, true))
		case "REQUEST":
			report(fixture.request(*useTLS, false))
		case "EXIT":
			return
		}
	}
}

func servePlaintext(listener net.Listener, handler http.Handler) {
	server := &http2.Server{}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go server.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
	}
}

func (t target) request(useTLS, immediate bool) (string, error) {
	conn, err := net.Dial("tcp", t.plainAddress)
	scheme := "http"
	authority := t.plainAddress
	if useTLS {
		conn, err = tls.Dial("tcp", t.tlsAddress, t.tlsConfig.Clone())
		scheme = "https"
		authority = t.tlsAddress
	}
	if err != nil {
		return "", err
	}
	defer conn.Close()

	transport := &http2.Transport{}
	client, err := transport.NewClientConn(conn)
	if err != nil {
		return "", err
	}
	defer client.Close()

	if immediate {
		// Frames are larger than this buffer, so bufio.Writer bypasses it and
		// calls conn.Write before Framer.WriteHeaders returns.
		if err := setFramerWriter(client, bufio.NewWriterSize(conn, 1)); err != nil {
			return "", err
		}
	}

	req, err := http.NewRequest(http.MethodGet, scheme+"://"+authority+"/", http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := client.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func setFramerWriter(client *http2.ClientConn, writer io.Writer) error {
	clientValue := reflect.ValueOf(client).Elem()
	framerField := clientValue.FieldByName("fr")
	if !framerField.IsValid() {
		return fmt.Errorf("http2.ClientConn.fr field not found")
	}
	framer := reflect.NewAt(framerField.Type(), unsafe.Pointer(framerField.UnsafeAddr())).Elem()
	framerValue := framer.Interface().(*http2.Framer)

	writerField := reflect.ValueOf(framerValue).Elem().FieldByName("w")
	if !writerField.IsValid() {
		return fmt.Errorf("http2.Framer.w field not found")
	}
	writable := reflect.NewAt(writerField.Type(), unsafe.Pointer(writerField.UnsafeAddr())).Elem()
	writable.Set(reflect.ValueOf(writer))
	return nil
}

func report(result string, err error) {
	if err != nil {
		fmt.Printf("ERROR %v\n", err)
		return
	}
	fmt.Printf("TP_RESULT=%s\n", result)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
