"use strict";

// Minimal librdkafka (confluent-kafka-javascript) client that speaks
// Fetch/Produce v13+ (topic-by-UUID). It creates a single topic with many
// partitions so the broker's Metadata response is large enough to arrive across
// multiple recv() chunks, exercising OBI's multi-chunk Kafka response capture.

const Kafka = require("@confluentinc/kafka-javascript");
const http = require("http");

const brokers = process.env.KAFKA_BOOTSTRAP_SERVERS || "localhost:9092";
const target = process.env.KAFKA_TOPIC || "obi-node-rdkafka-topic";
// Many partitions inflate the Metadata response so its body is large enough to
// (a) arrive separately from the 8-byte header and (b) be emitted as several
// large-buffer append chunks. The capture budget is OTEL_EBPF_BPF_BUFFER_SIZE_KAFKA
// (64K max); ~200 partitions is roughly 5KB, well within it.
const numPartitions = 200;

function createTopics() {
  return new Promise((resolve) => {
    const admin = Kafka.AdminClient.create({ "bootstrap.servers": brokers });
    admin.createTopic(
      { topic: target, num_partitions: numPartitions, replication_factor: 1 },
      () => {
        // ignore "already exists"
        admin.disconnect();
        resolve();
      }
    );
  });
}

function startProducer() {
  const producer = new Kafka.Producer({ "bootstrap.servers": brokers });
  producer.setPollInterval(1000);
  producer.on("event.error", (e) => console.error("producer error", e));
  producer.connect();
  producer.on("ready", () => {
    console.log("producer ready");
    setInterval(() => {
      try {
        producer.produce(target, null, Buffer.from("hello"), "key", Date.now());
      } catch (e) {
        console.error("produce err", e);
      }
    }, 3000);
  });
}

function startConsumer() {
  const consumer = new Kafka.KafkaConsumer(
    {
      "group.id": "obi-noderdkafka-group",
      "bootstrap.servers": brokers,
      // force periodic metadata refresh so OBI reliably observes a metadata
      // request/response after it attaches.
      "topic.metadata.refresh.interval.ms": 10000,
    },
    { "auto.offset.reset": "earliest" }
  );
  consumer.on("event.error", (e) => console.error("consumer error", e));
  consumer.connect();
  consumer.on("ready", () => {
    console.log("consumer ready, subscribing to", target);
    consumer.subscribe([target]);
    consumer.consume();
  });
  consumer.on("data", (m) =>
    console.log("consumed", m.topic, "partition", m.partition, "offset", m.offset)
  );
}

async function main() {
  await createTopics();
  // brief settle for topic propagation before produce/consume start
  setTimeout(() => {
    startProducer();
    startConsumer();
  }, 3000);

  // health endpoint so the integration harness has a service to poll
  http
    .createServer((_req, res) => {
      res.writeHead(200);
      res.end("OK");
    })
    .listen(8080);
  console.log("noderdkafka up: brokers=%s target=%s partitions=%d", brokers, target, numPartitions);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
