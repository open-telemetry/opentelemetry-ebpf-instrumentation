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
// The default role calls the relay (unread), the peer directly (parsed), the resetter
// (silent), and a second peer it abandons (received) on every request, so one run
// carries all four. Keep-alives are off, so each call's socket closes right after it
// completes. That close is what makes the kernel finish the incomplete record.
//
// The abandoned call is the one whose response arrives but is never read: the request
// goes out on a raw socket, the answer lands in the receive queue, and the socket closes
// without a read ever being issued. No probe sees those bytes, so the record is finished
// by the close rather than by the response, and only the socket's byte counter says an
// answer came at all. That is the case whose duration overstates the request, so it is
// the one whose duration is withheld from the metrics.
//
// It also drives REUSE_CALLS calls per request through a second relay over a pool
// holding a single connection, with keep-alives on. Nothing closes that socket, so the
// close no longer finishes anything: each record is finished by the next request taking
// the connection. That is the reuse case, where a record used to be discarded outright
// and the call went unreported. /stats reports what the application itself measured, so
// the assertions compare against the workload rather than a hardcoded count.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"sync"
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

// keepAlive holds one connection per host and keeps it, so consecutive calls travel the
// same socket and no close ever finishes a record.
func keepAlive() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxConnsPerHost:     1,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     time.Minute,
		},
	}
}

// reuseStats is what the application knows about its own keep-alive traffic. The test
// compares OBI's spans against it: the defect reported one span per connection, so the
// connection count is what separates a fix from a coincidence.
type reuseStats struct {
	Calls         int   `json:"calls"`
	Done          bool  `json:"done"`
	Connections   int   `json:"connections"`
	Aborts        int   `json:"aborts"`
	MaxCallMicros int64 `json:"maxCallMicros"`
	mutex         sync.Mutex
}

func (s *reuseStats) recordCall(elapsed time.Duration, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Calls++
	if err != nil {
		s.Aborts++
	}
	if micros := elapsed.Microseconds(); micros > s.MaxCallMicros {
		s.MaxCallMicros = micros
	}
}

func (s *reuseStats) recordConnection() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Connections++
}

func (s *reuseStats) finish() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Done = true
}

func (s *reuseStats) snapshot() reuseStats {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return reuseStats{
		Done:          s.Done,
		Calls:         s.Calls,
		Connections:   s.Connections,
		Aborts:        s.Aborts,
		MaxCallMicros: s.MaxCallMicros,
	}
}

// callReusing times one call and counts the connections it had to open, so a run that
// silently stopped reusing the socket cannot pass as a fix.
func callReusing(client *http.Client, url string, stats *reuseStats) {
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { stats.recordConnection() },
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatalf("building a request for %s: %v", url, err)
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	started := time.Now()
	err = performRequest(client, req)
	stats.recordCall(time.Since(started), err)

	if err != nil {
		log.Printf("reused-connection call: %v", err)
	}
}

// performRequest drains the body so the connection returns to the pool for the next
// call. A body left unread makes the transport open a new connection instead.
func performRequest(client *http.Client, req *http.Request) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if _, err := io.ReadAll(resp.Body); err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", req.URL, resp.StatusCode)
	}

	return nil
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

// abandonCall sends a request on a raw socket and closes without ever reading the
// answer. The bytes still arrive, so the socket's counter advances, but no read is
// issued and no probe sees them: the record is finished by the close, holding a
// duration that runs to the close rather than to the response.
func abandonCall(addr, path string, settle time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	request := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		return err
	}

	// Long enough for the answer to reach the receive queue, so this is a response
	// that arrived unseen rather than one that never came.
	time.Sleep(settle)

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

func envCount(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}

	count, err := strconv.Atoi(value)
	if err != nil {
		log.Fatalf("%s=%q is not a number: %v", name, value, err)
	}

	return count
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
	abandonAddr := envOr("ABANDON_PEER", "abandonpeer:9500")
	abandonSettle := envMillis("ABANDON_SETTLE_MS", 100*time.Millisecond)
	reusedURL := "http://" + envOr("REUSE_RELAY", "reuserelay:9300") + "/reused"
	client := noKeepAlive()

	// Two pooled connections carrying the same number of calls. They differ only in
	// whether the responses can be parsed, which is what separates a loss caused by the
	// unparsed response from one caused by reuse itself.
	reusedControlURL := "http://" + envOr("REUSE_PEER", "reusepeer:9400") + "/reused-control"
	parentedURL := "http://" + envOr("PARENT_RELAY", "parentrelay:9600") + "/parented"

	// Kept alive so consecutive calls travel one socket, and called from inside a
	// request so each has its own inbound parent. A record whose response went unparsed
	// is still on that socket when the next call takes it, which is the state a client
	// request must not mistake for a call it can inherit a parent from.
	parentedClient := keepAlive()

	// The same shape with responses that parse normally: a kept-alive socket, one call
	// per inbound request. It separates a parent lost to connection reuse from one lost
	// to the response going unparsed.
	parentedControlURL := "http://" + envOr("PARENT_PEER", "reusepeer:9400") + "/parented-control"
	parentedControlClient := keepAlive()
	reuseClient := keepAlive()
	reuseControlClient := keepAlive()
	reuseCalls := envCount("REUSE_CALLS", 60)
	// Long enough that the handler that started the run has returned and instrumentation
	// is attached before the first call.
	reuseStartDelay := envMillis("REUSE_START_DELAY_MS", time.Second)
	stats := &reuseStats{}
	controlStats := &reuseStats{}

	http.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		snapshot := map[string]reuseStats{
			"unparsed": stats.snapshot(),
			"parsed":   controlStats.snapshot(),
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(snapshot); err != nil {
			log.Printf("encoding stats: %v", err)
		}
	})

	// The pooled calls run in their own goroutine, after the handler that started them
	// has returned. A client call made while an inbound request is being served is held
	// downstream until that request's end timestamp is known, which is a separate
	// mechanism from the reuse this suite covers.
	var startOnce sync.Once
	http.HandleFunc("/start-reuse", func(w http.ResponseWriter, _ *http.Request) {
		startOnce.Do(func() {
			go func() {
				time.Sleep(reuseStartDelay)
				for range reuseCalls {
					callReusing(reuseClient, reusedURL, stats)
				}
				// The last call on a pooled connection is finished by whatever comes
				// next. Closing the socket is what a client eventually does, and it
				// keeps the run's tail from waiting on a sweep.
				reuseClient.CloseIdleConnections()
				stats.finish()

				for range reuseCalls {
					callReusing(reuseControlClient, reusedControlURL, controlStats)
				}
				reuseControlClient.CloseIdleConnections()
				controlStats.finish()
			}()
		})
		fmt.Fprintln(w, "started")
	})

	http.HandleFunc("/parented-control", func(w http.ResponseWriter, _ *http.Request) {
		if err := call(parentedControlClient, parentedControlURL); err != nil {
			log.Printf("parented control call: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(w, "ok")
	})

	http.HandleFunc("/parented", func(w http.ResponseWriter, _ *http.Request) {
		// One call per request. The socket is shared across requests, the parent is not.
		if err := call(parentedClient, parentedURL); err != nil {
			log.Printf("parented call: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(w, "ok")
	})

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

		// To the abandoned peer: the response arrives and is never read.
		if err := abandonCall(abandonAddr, "/abandoned", abandonSettle); err != nil {
			log.Printf("abandoned call: %v", err)
		}

		fmt.Fprintln(w, "ok")
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
