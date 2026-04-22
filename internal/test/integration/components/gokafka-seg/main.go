// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	kafka "github.com/segmentio/kafka-go"
)

func producerHandler(kafkaWriter *kafka.Writer) func(http.ResponseWriter, *http.Request) {
	return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			log.Fatalln(err)
		}
		msg := kafka.Message{
			Key:   []byte(fmt.Sprintf("address-%s", req.RemoteAddr)),
			Value: body,
		}
		err = kafkaWriter.WriteMessages(req.Context(), msg)
		if err != nil {
			fmt.Printf("error %v\n", err)
		}
	})
}

func producerHandlerWithTopic(kafkaWriter *kafka.Writer, topic string) func(http.ResponseWriter, *http.Request) {
	return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			log.Fatalln(err)
		}
		msg := kafka.Message{
			Key:   []byte(fmt.Sprintf("address-%s", req.RemoteAddr)),
			Value: body,
			Topic: topic,
		}
		err = kafkaWriter.WriteMessages(req.Context(), msg)
		if err != nil {
			fmt.Printf("error %v\n", err)
		}
	})
}

func getKafkaWriter(kafkaURL, topic string) *kafka.Writer {
	return &kafka.Writer{
		Addr:     kafka.TCP(kafkaURL),
		Topic:    topic,
		Balancer: &kafka.LeastBytes{},
	}
}

func getKafkaWriterNoTopic(kafkaURL string) *kafka.Writer {
	return &kafka.Writer{
		Addr:         kafka.TCP(kafkaURL),
		Balancer:     &kafka.LeastBytes{},
		BatchSize:    1,
		BatchTimeout: 1,
		Async:        true,
	}
}

func getKafkaReader(kafkaURL, topic, groupID string) *kafka.Reader {
	brokers := strings.Split(kafkaURL, ",")
	return kafka.NewReader(kafka.ReaderConfig{
		Brokers:  brokers,
		GroupID:  groupID,
		Topic:    topic,
		MinBytes: 1,
		MaxBytes: 10e6, // 10MB
	})
}

func ensureTopic(kafkaURL, topic string) error {
	conn, err := kafka.Dial("tcp", kafkaURL)
	if err != nil {
		return err
	}
	defer conn.Close()

	controller, err := conn.Controller()
	if err != nil {
		return err
	}

	controllerAddr := fmt.Sprintf("%s:%d", controller.Host, controller.Port)
	controllerConn, err := kafka.Dial("tcp", controllerAddr)
	if err != nil {
		return err
	}
	defer controllerConn.Close()

	return controllerConn.CreateTopics(kafka.TopicConfig{
		Topic:             topic,
		NumPartitions:     1,
		ReplicationFactor: 1,
	})
}

func main() {
	// get kafka writer using environment variables.
	kafkaURL := os.Getenv("kafkaURL")
	topic := os.Getenv("topic")

	for {
		client := kafka.Client{
			Addr: kafka.TCP(kafkaURL),
		}
		_, err := client.Metadata(context.Background(), &kafka.MetadataRequest{})
		if err == nil && ensureTopic(kafkaURL, topic) == nil {
			break
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			fmt.Printf("Waiting on kafka to start ...\n")
		}
		time.Sleep(2 * time.Second)
	}

	kafkaWriter := getKafkaWriter(kafkaURL, topic)
	defer kafkaWriter.Close()

	kafkaWriter2 := getKafkaWriterNoTopic(kafkaURL)
	defer kafkaWriter2.Close()

	groupID := os.Getenv("groupID")

	reader := getKafkaReader(kafkaURL, topic, groupID)
	defer reader.Close()

	go func() {
		fmt.Println("start consuming ... !!")
		for {
			m, err := reader.ReadMessage(context.Background())
			if err != nil {
				log.Fatalln(err)
			}
			fmt.Printf("message at topic:%v partition:%v offset:%v	%s = %s\n", m.Topic, m.Partition, m.Offset, string(m.Key), string(m.Value))
		}
	}()

	// Add handle func for producer.
	http.HandleFunc("/ping", producerHandler(kafkaWriter))
	http.HandleFunc("/withTopic", producerHandlerWithTopic(kafkaWriter2, topic))

	// Run the web server.
	fmt.Println("started test server on port 8080 ...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
