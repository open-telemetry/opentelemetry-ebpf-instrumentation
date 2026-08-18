// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Workload for the response-observation suite. Every inbound request makes three
// outbound calls. They differ in what instrumentation gets to see of the response.
//
// ROLE=peer is the origin. It answers 200 and is the authority on what happened.
//
// ROLE=relay is a transparent TCP relay in front of the peer. It forwards both
// directions byte for byte and changes only how the response is segmented on the
// wire: the first byte goes out in its own TCP segment and the rest follows
// RESEGMENT_DELAY_MS later. OBI's tcp_cleanup_rbuf probe returns early on any read
// of one byte or fewer, and the remainder does not begin with a status line, so no
// probe parses the 200. The bytes the caller receives are the same either way.
//
// ROLE=resetter accepts a connection, reads the request, and resets it without
// answering. Nothing comes back, which is the case the byte counter tells apart from
// a response that arrived and went unparsed.
//
// The default role calls the relay (received), the peer directly (parsed), and the
// resetter (silent) on every request, so one run carries all three. Keep-alives are
// off, so each call's socket closes right after it completes. That close is what makes
// the kernel finish the incomplete record.
package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

// resegmentAt is the size of the first segment, in bytes. One byte is what puts the
// read under OBI's copied_len <= 1 early return in return_recvmsg.
const resegmentAt = 1

// noKeepAlive closes a call's socket as soon as the response has been read.
func noKeepAlive() *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
}

// call performs a GET and drains the response, so the exchange completes from the
// application's point of view whether or not it was observed.
func call(client *http.Client, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", url, resp.StatusCode)
	}

	log.Printf("call to %s completed: status=%d bytes=%d", url, resp.StatusCode, len(body))

	return nil
}

// runResetter answers nothing. It reads what the caller sent so the request is
// genuinely delivered, then sets SO_LINGER to zero and closes, which makes the kernel
// send an RST.
func runResetter(port string) {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("listening on %s: %v", port, err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("accepting: %v", err)
		}

		go func() {
			tcp, ok := conn.(*net.TCPConn)
			if !ok {
				conn.Close()
				return
			}

			// Read first, so this is an exchange that got no answer. A reset before
			// the connection carried anything is a different case.
			buf := make([]byte, 4096)
			//nolint:errcheck // a caller that vanished first is still a reset case
			tcp.SetReadDeadline(time.Now().Add(2 * time.Second))
			//nolint:errcheck // the request's content is irrelevant, only its arrival
			tcp.Read(buf)

			// Zero linger turns the close into an RST.
			//nolint:errcheck // if this fails the close below is merely a FIN
			tcp.SetLinger(0)
			tcp.Close()
		}()
	}
}

func runPeer(port string) {
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		// Long enough that the first byte is not the whole response.
		fmt.Fprintln(w, "answered by the peer, which is the authority on this call")
	})
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// relayResponse copies peer to caller, splitting the first segment of every
// chunk it forwards.
func relayResponse(dst, src net.Conn, delay time.Duration) {
	buf := make([]byte, 32*1024)

	for {
		n, err := src.Read(buf)
		if n > resegmentAt {
			if _, werr := dst.Write(buf[:resegmentAt]); werr != nil {
				return
			}
			time.Sleep(delay)
			if _, werr := dst.Write(buf[resegmentAt:n]); werr != nil {
				return
			}
		} else if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func runRelay(port, peer string, delay time.Duration) {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("listening on %s: %v", port, err)
	}

	for {
		down, err := listener.Accept()
		if err != nil {
			log.Fatalf("accepting: %v", err)
		}

		go func() {
			defer down.Close()

			up, err := net.Dial("tcp", peer)
			if err != nil {
				log.Printf("connecting to %s: %v", peer, err)
				return
			}
			defer up.Close()

			// Caller to peer, untouched.
			//nolint:errcheck // the copy ends when either side closes
			go io.Copy(up, down)

			relayResponse(down, up, delay)
		}()
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}

	return fallback
}

func envMillis(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}

	millis, err := strconv.Atoi(value)
	if err != nil {
		log.Fatalf("%s=%q is not a number of milliseconds: %v", name, value, err)
	}

	return time.Duration(millis) * time.Millisecond
}

func main() {
	switch os.Getenv("ROLE") {
	case "peer":
		runPeer(envOr("PEER_PORT", "9000"))
		return
	case "resetter":
		runResetter(envOr("RESETTER_PORT", "9200"))
		return
	case "relay":
		runRelay(envOr("RELAY_PORT", "9100"), envOr("PEER", "peer:9000"),
			envMillis("RESEGMENT_DELAY_MS", 5*time.Millisecond))
		return
	}

	unobservedURL := "http://" + envOr("RELAY", "relay:9100") + "/unobserved"
	observedURL := "http://" + envOr("PEER", "peer:9000") + "/observed"
	resetURL := "http://" + envOr("RESETTER", "resetter:9200") + "/reset"
	client := noKeepAlive()

	http.HandleFunc("/work", func(w http.ResponseWriter, _ *http.Request) {
		// Through the relay: the call succeeds and instrumentation never sees a
		// status line.
		if err := call(client, unobservedURL); err != nil {
			log.Printf("unobserved call: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Straight to the peer: the control, observed in full.
		if err := call(client, observedURL); err != nil {
			log.Printf("observed call: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// To the resetter: no response arrives. The error is expected, so it is
		// logged and the handler still succeeds.
		if err := call(client, resetURL); err != nil {
			log.Printf("reset call failed as expected: %v", err)
		} else {
			log.Printf("reset call unexpectedly succeeded")
		}

		fmt.Fprintln(w, "ok")
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
