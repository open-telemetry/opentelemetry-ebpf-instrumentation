// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Workload for the failed-connect suite. It produces the two kinds of socket
// that have to be told apart: a pooled connection that completed its handshake,
// carried nothing and was closed by this process, and a connect to a port
// nobody listens on.
//
// ROLE=peer runs the other end: it accepts connections and leaves them alone,
// so the pooled sockets stay established and idle until this process closes
// them.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

type pooledConn struct {
	conn   net.Conn
	opened time.Time
}

type pool struct {
	mu    sync.Mutex
	conns []pooledConn
}

// Closes every connection that has been idle for at least minIdle. The caller
// is serving an inbound request, which is what puts a span misattributed to the
// close into that request's trace.
func (p *pool) closeIdle(minIdle time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	kept := p.conns[:0]

	for _, pc := range p.conns {
		if time.Since(pc.opened) < minIdle {
			kept = append(kept, pc)
			continue
		}
		if err := pc.conn.Close(); err != nil {
			log.Printf("closing idle connection: %v", err)
		}
	}

	p.conns = kept
}

func (p *pool) add(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.conns = append(p.conns, pooledConn{conn: conn, opened: time.Now()})

	return nil
}

// Every attempt is refused, so each one is a connect that genuinely failed and
// has to keep being reported.
func dialUnreachable(addr string, every time.Duration) {
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			log.Printf("unexpected connection to %s", addr)
			conn.Close()
		}
		time.Sleep(every)
	}
}

func runPeer(port string) {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("listening on %s: %v", port, err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("accepting: %v", err)
		}
		// Held open and never read from, so the connection stays established
		// and carries no bytes until the client closes it.
		go func() {
			var buf [1]byte
			//nolint:errcheck // the read returns when the client closes
			conn.Read(buf[:])
			conn.Close()
		}()
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}

	return fallback
}

func envSeconds(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}

	seconds, err := strconv.Atoi(value)
	if err != nil {
		log.Fatalf("%s=%q is not a number of seconds: %v", name, value, err)
	}

	return time.Duration(seconds) * time.Second
}

func main() {
	if os.Getenv("ROLE") == "peer" {
		runPeer(envOr("PEER_PORT", "7000"))
		return
	}

	idlePeer := envOr("IDLE_PEER", "idlepeer:7000")
	unreachablePeer := envOr("UNREACHABLE_PEER", "idlepeer:7001")
	idleFor := envSeconds("IDLE_FOR_SECONDS", 3*time.Second)

	go dialUnreachable(unreachablePeer, 2*time.Second)

	p := &pool{}

	http.HandleFunc("/work", func(w http.ResponseWriter, _ *http.Request) {
		p.closeIdle(idleFor)

		if err := p.add(idlePeer); err != nil {
			log.Printf("connecting to %s: %v", idlePeer, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(w, "ok")
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
