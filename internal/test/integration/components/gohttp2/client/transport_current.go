// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !legacy_stdlib

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"reflect"
	"strings"
	"unsafe"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var errAbandonedBeforeFramer = errors.New("forced abandonment before Framer.WriteHeaders")

const hpackDefaultDynamicTableSize = 4096

type directH2Transport struct {
	conn *http2.ClientConn
}

func (t *directH2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.conn.RoundTrip(req)
}

func (t *directH2Transport) CloseIdleConnections() {
	_ = t.conn.Close()
}

func (t *directH2Transport) abandonOwned(req *http.Request) error {
	encoder := clientConnEncoder(t.conn)
	encoder.SetMaxDynamicTableSize(0)
	defer encoder.SetMaxDynamicTableSize(hpackDefaultDynamicTableSize)

	observed := false
	trace := &httptrace.ClientTrace{
		WroteHeaderField: func(key string, _ []string) {
			if strings.EqualFold(key, "traceparent") {
				observed = true
				setClientConnWriteError(t.conn, errAbandonedBeforeFramer)
			}
		},
		WroteHeaders: func() {
			setClientConnWriteError(t.conn, nil)
			clearCurrentStreamSentHeaders(t.conn)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := t.conn.RoundTrip(req)
	setClientConnWriteError(t.conn, nil)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !observed {
		return errors.New("traceparent field was not observed before abandonment")
	}
	if !errors.Is(err, errAbandonedBeforeFramer) {
		return fmt.Errorf("unexpected abandonment result: %w", err)
	}
	return err
}

func clientConnEncoder(conn *http2.ClientConn) *hpack.Encoder {
	field := reflect.ValueOf(conn).Elem().FieldByName("henc")
	if !field.IsValid() || !field.CanAddr() {
		panic("http2.ClientConn.henc is unavailable")
	}
	writable := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	return writable.Interface().(*hpack.Encoder)
}

func setClientConnWriteError(conn *http2.ClientConn, err error) {
	field := reflect.ValueOf(conn).Elem().FieldByName("werr")
	if !field.IsValid() || !field.CanAddr() {
		panic("http2.ClientConn.werr is unavailable")
	}
	writable := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	if err == nil {
		writable.Set(reflect.Zero(field.Type()))
		return
	}
	writable.Set(reflect.ValueOf(err))
}

func clearCurrentStreamSentHeaders(conn *http2.ClientConn) {
	streams := reflect.ValueOf(conn).Elem().FieldByName("streams")
	if !streams.IsValid() || streams.Kind() != reflect.Map {
		panic("http2.ClientConn.streams is unavailable")
	}
	var current reflect.Value
	var currentID uint64
	iterator := streams.MapRange()
	for iterator.Next() {
		id := iterator.Key().Uint()
		if !current.IsValid() || id > currentID {
			current = iterator.Value()
			currentID = id
		}
	}
	if !current.IsValid() || current.Kind() != reflect.Pointer || current.IsNil() {
		panic("current http2 client stream is unavailable")
	}
	field := current.Elem().FieldByName("sentHeaders")
	if !field.IsValid() {
		return
	}
	if !field.CanAddr() {
		panic("http2.clientStream.sentHeaders is not addressable")
	}
	writable := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	writable.SetBool(false)
}

func newTransport() (interface {
	http.RoundTripper
	CloseIdleConnections()
}, string, error) {
	if os.Getenv("TEST_HTTP2_PROTOCOLS") == "1" {
		protocols := &http.Protocols{}
		protocols.SetHTTP2(true)
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Protocols = protocols
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		return transport, "net/http", nil
	}
	target, err := url.Parse(os.Getenv("TARGET_URL"))
	if err != nil {
		return nil, "", err
	}
	conn, err := tls.Dial("tcp", target.Host, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	})
	if err != nil {
		return nil, "", err
	}
	clientConn, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		_ = conn.Close()
		return nil, "", err
	}
	return &directH2Transport{conn: clientConn}, "golang.org/x/net/http2", nil
}
