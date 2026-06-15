// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
)

const (
	programPortmapper = 100000
	rpcVersion        = 2
	msgCall           = 0
	msgReply          = 1
	replyAccepted     = 0
	authNull          = 0
	rmLastFrag        = 0x80000000
)

var mu sync.Mutex

func main() {
	rpcPort := os.Getenv("SUNRPC_PORT")
	if rpcPort == "" {
		rpcPort = "11111"
	}

	go func() {
		if err := listenSunRPC(rpcPort); err != nil {
			log.Fatalf("sunrpc server failed: %v", err)
		}
	}()

	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "8080"
	}

	http.HandleFunc("/sunrpc", handleSunRPC)
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	log.Printf("listening for HTTP on :%s, SunRPC on :%s", httpPort, rpcPort)
	log.Fatal(http.ListenAndServe(":"+httpPort, nil))
}

func handleSunRPC(w http.ResponseWriter, _ *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	rpcPort := os.Getenv("SUNRPC_PORT")
	if rpcPort == "" {
		rpcPort = "11111"
	}

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", rpcPort))
	if err != nil {
		http.Error(w, "sunrpc dial failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	call := buildCallRecord(42, programPortmapper, rpcVersion, 0, authNull, nil)
	if _, err := conn.Write(wrapTCPRecord(call)); err != nil {
		http.Error(w, "sunrpc write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	reply, err := readRecord(conn)
	if err != nil {
		http.Error(w, "sunrpc read failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if len(reply) < 8 {
		http.Error(w, "sunrpc short reply", http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"xid":     binary.BigEndian.Uint32(reply[0:4]),
		"msgType": binary.BigEndian.Uint32(reply[4:8]),
	})
}

func listenSunRPC(port string) error {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleSunRPCConn(conn)
	}
}

func handleSunRPCConn(conn net.Conn) {
	defer conn.Close()

	for {
		record, err := readRecord(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("sunrpc read error: %v", err)
			}
			return
		}
		if len(record) < 8 {
			continue
		}

		xid := binary.BigEndian.Uint32(record[0:4])
		msgType := binary.BigEndian.Uint32(record[4:8])
		if msgType != msgCall {
			continue
		}

		reply := buildAcceptedReplyRecord(xid, 0)
		if _, err := conn.Write(wrapTCPRecord(reply)); err != nil {
			log.Printf("sunrpc write error: %v", err)
			return
		}
	}
}

func readRecord(r io.Reader) ([]byte, error) {
	var parts [][]byte
	total := 0

	for {
		var hdr [4]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if len(parts) == 0 {
				return nil, err
			}
			return nil, err
		}

		last := hdr[0]&0x80 != 0
		length := int(binary.BigEndian.Uint32(hdr[:]) & 0x7fffffff)
		if length < 0 || length > 1<<20 {
			return nil, fmt.Errorf("invalid record length %d", length)
		}

		fragment := make([]byte, length)
		if _, err := io.ReadFull(r, fragment); err != nil {
			return nil, err
		}
		parts = append(parts, fragment)
		total += length
		if last {
			break
		}
	}

	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out, nil
}

func buildCallRecord(xid, prog, vers, proc, authFlavor uint32, authBody []byte) []byte {
	body := appendU32(nil, rpcVersion)
	body = appendU32(body, prog)
	body = appendU32(body, vers)
	body = appendU32(body, proc)
	body = appendOpaque(body, authFlavor, authBody)
	body = appendOpaque(body, authNull, nil)

	msg := appendU32(nil, xid)
	msg = appendU32(msg, msgCall)
	msg = append(msg, body...)
	return msg
}

func buildAcceptedReplyRecord(xid uint32, acceptStat uint32) []byte {
	body := appendU32(nil, replyAccepted)
	body = appendOpaque(body, authNull, nil)
	body = appendU32(body, acceptStat)

	msg := appendU32(nil, xid)
	msg = appendU32(msg, msgReply)
	msg = append(msg, body...)
	return msg
}

func wrapTCPRecord(record []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, rmLastFrag|uint32(len(record)))
	return append(hdr, record...)
}

func appendU32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func appendOpaque(b []byte, flavor uint32, data []byte) []byte {
	b = appendU32(b, flavor)
	b = appendU32(b, uint32(len(data)))
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}
