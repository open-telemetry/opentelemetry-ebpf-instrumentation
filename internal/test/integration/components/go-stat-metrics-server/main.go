// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

func main() {
	go serve(":8081")
	serve(":8080")
}

func serve(addr string) {
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

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	message, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Printf("Received: %s", message)

	conn.Write([]byte("ACK\n"))
}
