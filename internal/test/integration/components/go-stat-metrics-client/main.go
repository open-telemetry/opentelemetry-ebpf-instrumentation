// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	// lets OBI instrument the client before its first connect
	if delay, err := time.ParseDuration(os.Getenv("START_DELAY")); err == nil {
		time.Sleep(delay)
	}

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

	// Generate TCP resets: the server aborts every connection on this address
	resetAddress := os.Getenv("RESET_TARGET_ADDRESS")
	if resetAddress != "" {
		go func() {
			for {
				conn, err := net.DialTimeout("tcp", resetAddress, 2*time.Second)
				if err != nil {
					time.Sleep(1 * time.Second)
					continue
				}
				fmt.Fprintf(conn, "reset probe\n")
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, err = bufio.NewReader(conn).ReadString('\n')
				fmt.Printf("Expected reset from %s: %v\n", resetAddress, err)
				conn.Close()
				time.Sleep(1 * time.Second)
			}
		}()
	}

	// Generate resets the kernel raises itself: the server shuts down reading and
	// writing, then this client sends data after the server's FIN
	readShutdownAddress := os.Getenv("READ_SHUTDOWN_TARGET_ADDRESS")
	if readShutdownAddress != "" {
		go func() {
			for {
				conn, err := net.DialTimeout("tcp", readShutdownAddress, 2*time.Second)
				if err != nil {
					time.Sleep(1 * time.Second)
					continue
				}
				fmt.Fprintf(conn, "read shutdown probe\n")
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, _ = io.ReadAll(conn) // returns at the server's FIN
				_, err = fmt.Fprintf(conn, "data after the server shut down\n")
				fmt.Printf("Sent data after shutdown to %s: %v\n", readShutdownAddress, err)
				time.Sleep(500 * time.Millisecond) // let the server's reset arrive
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

	// Shut connections down from both sides before closing them, so the sockets reach TCP_CLOSE
	// while the application still holds them
	shutdownAddress := os.Getenv("SHUTDOWN_TARGET_ADDRESS")
	if shutdownAddress != "" {
		go func() {
			for {
				conn, err := net.DialTimeout("tcp", shutdownAddress, 2*time.Second)
				if err != nil {
					time.Sleep(1 * time.Second)
					continue
				}
				fmt.Fprintf(conn, "shutdown probe\n")
				// the reply, then the server's FIN
				io.Copy(io.Discard, conn)
				conn.(*net.TCPConn).CloseWrite()
				// lets the server's ACK of our FIN arrive before close()
				time.Sleep(1 * time.Second)
				conn.Close()
				time.Sleep(1 * time.Second)
			}
		}()
	}

	// Keep one connection open, so a test can find the client's socket in the context propagation sockmap
	holdAddress := os.Getenv("HOLD_TARGET_ADDRESS")
	if holdAddress != "" {
		go func() {
			conn, err := net.DialTimeout("tcp", holdAddress, 2*time.Second)
			for err != nil {
				time.Sleep(1 * time.Second)
				conn, err = net.DialTimeout("tcp", holdAddress, 2*time.Second)
			}
			// keeps conn reachable, so the GC finalizer never closes it
			defer conn.Close()
			fmt.Fprintf(conn, "hold probe\n")
			select {}
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
