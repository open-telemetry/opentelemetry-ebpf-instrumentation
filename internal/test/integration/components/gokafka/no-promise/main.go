// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/IBM/sarama"
)

var logger *slog.Logger

type server struct {
	kafkaBrokerSvcAddr  string
	KafkaProducerClient sarama.AsyncProducer
}

func main() {
	logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	port := os.Getenv("CHECKOUT_PORT")
	if port == "" {
		port = "8080"
	}

	svc := new(server)
	svc.kafkaBrokerSvcAddr = os.Getenv("KAFKA_ADDR")
	if svc.kafkaBrokerSvcAddr == "" {
		svc.kafkaBrokerSvcAddr = "localhost:9092"
	}

	var err error
	deadline := time.Now().Add(5 * time.Minute)
	for {
		svc.KafkaProducerClient, err = CreateKafkaProducer([]string{svc.kafkaBrokerSvcAddr}, logger)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			logger.Error(fmt.Sprintf("failed to create Kafka producer after retries: %s", err))
			os.Exit(1)
		}
		logger.Warn(fmt.Sprintf("failed to create Kafka producer, retrying in 1s: %s", err))
		time.Sleep(time.Second)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/message", svc.handleMessage)

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: mux,
	}

	go func() {
		logger.Info(fmt.Sprintf("starting HTTP server on :%s", port))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error(err.Error())
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error(err.Error())
	}
	logger.Info("HTTP server stopped")
}

func (s *server) handleMessage(w http.ResponseWriter, r *http.Request) {
	s.sendToKafka(r.Context(), []byte("order placed"))

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("message sent\n"))
}

func (s *server) sendToKafka(ctx context.Context, message []byte) {
	msg := sarama.ProducerMessage{
		Topic: Topic,
		Value: sarama.ByteEncoder(message),
	}

	// Send message and handle response
	startTime := time.Now()
	select {
	case s.KafkaProducerClient.Input() <- &msg:
		select {
		case successMsg := <-s.KafkaProducerClient.Successes():
			logger.Info(fmt.Sprintf("Successful to write message. offset: %v, duration: %v", successMsg.Offset, time.Since(startTime)))
		case errMsg := <-s.KafkaProducerClient.Errors():
			logger.Error(fmt.Sprintf("Failed to write message: %v", errMsg.Err))
		case <-ctx.Done():
			logger.Warn(fmt.Sprintf("Context canceled before success message received: %v", ctx.Err()))
		}
	case <-ctx.Done():
		logger.Error(fmt.Sprintf("Failed to send message to Kafka within context deadline: %v", ctx.Err()))
		return
	}
}
