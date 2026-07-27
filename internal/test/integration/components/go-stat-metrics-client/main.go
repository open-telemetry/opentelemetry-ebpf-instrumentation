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

	// Generate TCP retransmits by sending data over a lossy connection (pumba-loss injects loss on this container)
	retransmitAddress := os.Getenv("RETRANSMIT_TARGET_ADDRESS")
	if retransmitAddress != "" {
		go func() {
			for {
				conn, err := net.DialTimeout("tcp", retransmitAddress, 2*time.Second)
				if err != nil {
					time.Sleep(1 * time.Second)
					continue
				}
				fmt.Fprintf(conn, "retransmit probe\n")
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				bufio.NewReader(conn).ReadString('\n')
				conn.Close()
				time.Sleep(1 * time.Second)
			}
		}()
	}

	// Generate failed TCP connections by dialing a port where nothing listens
	failAddress := os.Getenv("FAIL_TARGET_ADDRESS")
	if failAddress != "" {
		go func() {
			for {
				conn, err := net.DialTimeout("tcp", failAddress, 2*time.Second)
				if err != nil {
					fmt.Printf("Expected failed connection to %s: %v\n", failAddress, err)
				} else {
					conn.Close()
				}
				time.Sleep(1 * time.Second)
			}
		}()
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
