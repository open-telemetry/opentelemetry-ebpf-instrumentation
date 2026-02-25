// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	counter := 1
	address := os.Getenv("TARGET_ADDRESS")

	if address == "" {
		address = "localhost:8080"
		fmt.Printf("Env var TARGET_ADDRESS not set, defaulting to %s\n", address)
	}

	for {
		fmt.Printf("[%d] Connecting to %s...\n", counter, address)

		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			fmt.Printf("Connection failed: %v\n", err)
			time.Sleep(3 * time.Second)
			continue
		}

		// Send incremental "Hello World"
		message := fmt.Sprintf("Hello World %d\n", counter)
		fmt.Fprintf(conn, "%s", message)

		response, _ := bufio.NewReader(conn).ReadString('\n')
		fmt.Printf("Server says: %s", response)

		conn.Close()
		fmt.Println("Connection closed. Sleeping 3s...")

		counter++
		time.Sleep(3 * time.Second)
	}
}
