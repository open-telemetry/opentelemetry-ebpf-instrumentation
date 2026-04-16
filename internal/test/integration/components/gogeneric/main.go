// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"github.com/twmb/franz-go/pkg/kgo"
)

var (
	addr    = flag.String("addr", ":8080", "The address to bind to")
	brokers = flag.String("brokers", os.Getenv("KAFKA_PEERS"), "The Kafka brokers to connect to, as a comma separated list")
)

const kafkaRetryDelay = 3 * time.Second

func main() {
	flag.Parse()

	if *brokers == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	brokerList := strings.Split(*brokers, ",")
	log.Printf("Kafka brokers: %s", strings.Join(brokerList, ", "))

	// Create a new Fiber app
	app := fiber.New(fiber.Config{
		AppName: "Fiber Example Server",
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())

	client := newKafkaClient(*brokers)

	app.Get("/produce", producerHandlerWithTopic(client, "my-topic"))
	app.Get("/produce/orders", producerHandlerWithTopic(client, "orders"))
	app.Get("/consume", consumerHandler(client))

	// Routes
	app.Get("/", handleHome)
	app.Get("/api/hello", handleHello)
	app.Get("/api/time", handleTime)
	app.Post("/api/echo", handleEcho)

	// Start server
	log.Println("Starting server on " + *addr)
	if err := app.Listen(*addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func newKafkaClient(brokers string) *kgo.Client {
	for {
		b := strings.Split(brokers, ",")
		client, err := kgo.NewClient(
			kgo.SeedBrokers(b...),
			kgo.ConsumeTopics("my-topic"), // only needed for the consumer
			kgo.DefaultProduceTopic("my-topic"),
		)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), kafkaRetryDelay)
			err = ensureTopics(ctx, client, "my-topic")
			cancel()
			if err == nil {
				return client
			}
			client.Close()
		}

		log.Printf("Kafka is not ready yet, retrying in %s: %v", kafkaRetryDelay, err)
		time.Sleep(kafkaRetryDelay)
	}
}

// handleHome returns a welcome message
func handleHome(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"message": "Welcome to Fiber Example Server",
		"endpoints": []string{
			"GET  /",
			"GET  /api/hello",
			"GET  /api/time",
			"POST /api/echo",
		},
	})
}

// handleHello returns a greeting with optional name parameter
func handleHello(c *fiber.Ctx) error {
	name := c.Query("name", "World")
	return c.JSON(fiber.Map{
		"message": "Hello, " + name + "!",
	})
}

// handleTime returns the current server time
func handleTime(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"time": time.Now().Format(time.RFC3339),
	})
}

// handleEcho echoes back the request body
func handleEcho(c *fiber.Ctx) error {
	type EchoRequest struct {
		Message string `json:"message"`
	}

	var req EchoRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	return c.JSON(fiber.Map{
		"echo": req.Message,
	})
}
