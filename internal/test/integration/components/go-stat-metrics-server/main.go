// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
)

func main() {
	go serve(":8081", handleConnection)
	go serve(":8082", resetConnection)
	go serve(":8083", handleShutdownConnection)
	serve(":8080", handleConnection)
}

func serve(addr string, handle func(net.Conn)) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("Failed to start server on %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("Server listening on %s.\n", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Accept error: %v\n", err)
			continue
		}

		go handle(conn)
	}
}

// handleShutdownConnection closes only after both sides shut the connection down,
// so the socket is already in TCP_CLOSE when the application closes it.
func handleShutdownConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	message, _ := reader.ReadString('\n')
	fmt.Printf("Received: %s", message)

	conn.Write([]byte("ACK\n"))
	conn.(*net.TCPConn).CloseWrite()

	// returns on the client's FIN
	io.Copy(io.Discard, reader)
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	message, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Printf("Received: %s", message)

	conn.Write([]byte("ACK\n"))
}

// resetConnection aborts the connection with SO_LINGER{0}, so close() sends a
// RST instead of a FIN.
func resetConnection(conn net.Conn) {
	message, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Printf("Received (will reset): %s", message)

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
	}
	conn.Close()
}
