// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
)

func newKafkaTLSClient(brokers string) *kgo.Client {
	for {
		b := strings.Split(brokers, ",")
		client, err := kgo.NewClient(
			kgo.SeedBrokers(b...),
			kgo.ConsumeTopics("my-topic"),
			kgo.DefaultProduceTopic("my-topic"),
			kgo.DialTLSConfig(&tls.Config{InsecureSkipVerify: true}), //nolint:gosec
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

		log.Printf("Kafka TLS is not ready yet, retrying in %s: %v", kafkaRetryDelay, err)
		time.Sleep(kafkaRetryDelay)
	}
}

func ensureTopics(ctx context.Context, client *kgo.Client, topics ...string) error {
	adm := kadm.NewClient(client)
	resp, err := adm.CreateTopics(ctx, 1, 1, nil, topics...)
	if err != nil {
		return fmt.Errorf("create topics: %w", err)
	}
	for _, t := range resp.Sorted() {
		if t.Err != nil && !errors.Is(t.Err, kerr.TopicAlreadyExists) {
			return fmt.Errorf("topic %s: %w", t.Topic, t.Err)
		}
	}

	return nil
}

func producerHandler(client *kgo.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		record := &kgo.Record{
			Key:   []byte(fmt.Sprintf("address-%s", c.IP())),
			Value: c.Body(),
		}
		results := client.ProduceSync(c.Context(), record)
		if err := results.FirstErr(); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"status": "produced"})
	}
}

func producerHandlerWithTopic(client *kgo.Client, topic string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		record := &kgo.Record{
			Key:   []byte(fmt.Sprintf("address-%s", c.IP())),
			Value: c.Body(),
			Topic: topic,
		}
		results := client.ProduceSync(c.Context(), record)
		if err := results.FirstErr(); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"status": "produced", "topic": topic})
	}
}

func stdProducerHandlerWithTopic(client *kgo.Client, topic string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		record := &kgo.Record{
			Key:   []byte(fmt.Sprintf("address-%s", r.RemoteAddr)),
			Value: body,
			Topic: topic,
		}
		results := client.ProduceSync(r.Context(), record)
		if err := results.FirstErr(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"produced","topic":%q}`, topic)
	}
}

// consumerHandler polls for available records and returns them.
// The client must be created with kgo.ConsumeTopics(...) or kgo.ConsumePartitions(...).
func consumerHandler(client *kgo.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		fetches := client.PollFetches(c.Context())
		if errs := fetches.Errors(); len(errs) > 0 {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": errs[0].Err.Error()})
		}

		type message struct {
			Key       string `json:"key"`
			Value     string `json:"value"`
			Topic     string `json:"topic"`
			Partition int32  `json:"partition"`
			Offset    int64  `json:"offset"`
		}

		var messages []message
		fetches.EachRecord(func(r *kgo.Record) {
			messages = append(messages, message{
				Key:       string(r.Key),
				Value:     string(r.Value),
				Topic:     r.Topic,
				Partition: r.Partition,
				Offset:    r.Offset,
			})
		})

		return c.JSON(fiber.Map{"messages": messages})
	}
}
