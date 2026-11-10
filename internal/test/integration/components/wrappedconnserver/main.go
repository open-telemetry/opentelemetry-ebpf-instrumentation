// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

type wrappedConn struct{ net.Conn }

type prefixedConn struct {
	_ [32]byte
	net.Conn
}

type wrappedListener struct {
	net.Listener
	prefixed bool
}

func (l wrappedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.prefixed {
		return &prefixedConn{Conn: c}, nil
	}
	return &wrappedConn{Conn: c}, nil
}

func main() {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A read on another socket must not supply the HTTP server's connection.
		c, err := net.DialTimeout("tcp", backend.Addr().String(), time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, _ = c.Write([]byte("ping"))
		var reply [4]byte
		if _, err := io.ReadFull(c, reply[:]); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"local":  r.Context().Value(http.LocalAddrContextKey).(net.Addr).String(),
			"remote": r.RemoteAddr,
		})
	})

	for _, mode := range []struct {
		addr     string
		wrapped  bool
		prefixed bool
		h2c      bool
		tls      bool
	}{
		{addr: ":8080"},
		{addr: ":8081", wrapped: true},
		{addr: ":8082", wrapped: true, prefixed: true},
		{addr: ":8083", h2c: true},
		{addr: ":8084", wrapped: true, h2c: true},
		{addr: ":8085", wrapped: true, prefixed: true, h2c: true},
		{addr: ":8383", tls: true},
		{addr: ":8384", wrapped: true, tls: true},
		{addr: ":8385", wrapped: true, prefixed: true, tls: true},
	} {
		listener, err := net.Listen("tcp", mode.addr)
		if err != nil {
			log.Fatal(err)
		}
		if mode.wrapped {
			listener = wrappedListener{Listener: listener, prefixed: mode.prefixed}
		}
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		if mode.h2c {
			server.Protocols = new(http.Protocols)
			server.Protocols.SetHTTP1(true)
			server.Protocols.SetUnencryptedHTTP2(true)
		}
		go func() {
			if mode.tls {
				log.Fatal(server.ServeTLS(listener, "cert.pem", "key.pem"))
			}
			log.Fatal(server.Serve(listener))
		}()
	}
	select {}
}
