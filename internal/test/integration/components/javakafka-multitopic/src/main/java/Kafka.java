import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

public class Kafka {

    // Several topics so the consumer's Metadata response is MULTI-topic. The
    // parser must resolve every topic, not just the first one in the response;
    // subscribing to all of them means at least one topic is not first, so a
    // parser that only handles the first topic leaves the rest as "*".
    static final List<String> TOPICS = Arrays.asList(
            "obi-java-multitopic-1",
            "obi-java-multitopic-2",
            "obi-java-multitopic-3");

    public static void main(String[] args) {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
            server.createContext("/message", new HttpHandler() {
                @Override
                public void handle(HttpExchange exchange) throws IOException {
                    String response = "OK";
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            });

            String bootstrapServers = System.getenv("KAFKA_BOOTSTRAP_SERVERS");

            if (bootstrapServers == null || bootstrapServers.isEmpty()) {
                bootstrapServers = "localhost:9092";
            }
            // Producer
            Properties producerProps = new Properties();
            producerProps.put("bootstrap.servers", bootstrapServers);
            producerProps.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
            producerProps.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
            producerProps.put("partitioner.class", "org.apache.kafka.clients.producer.RoundRobinPartitioner");
            Thread producerThread = new Thread(() -> {
                KafkaProducer<String, String> producer = new KafkaProducer<>(producerProps);
                for (;;) {
                    for (String topic : TOPICS) {
                        producer.send(new ProducerRecord<>(topic, "key", "value"));
                    }
                    System.out.println("Produced messages");
                    try {
                        Thread.sleep(5000);
                    } catch (Exception ignore) {}
                }
            });

            // Consumer
            Properties consumerProps = new Properties();
            consumerProps.put("bootstrap.servers", bootstrapServers);
            consumerProps.put("group.id", "1");
            consumerProps.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
            consumerProps.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
            consumerProps.put("auto.offset.reset", "earliest");
            // force to refresh metadata info because it can happen that OBI cannot catch it earlier
            // otherwise we can just sleep at the beginning
            consumerProps.put("metadata.max.age.ms", "10000");

            Thread consumerThread = new Thread(() -> {
                KafkaConsumer<String, String> consumer = new KafkaConsumer<>(consumerProps);
                consumer.subscribe(TOPICS);

                while (true) {
                    System.out.println("Polling for new messages...");
                    ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(5000));
                    for (ConsumerRecord<String, String> record : records) {
                        System.out.printf("Consumed message: topic = %s, offset = %d, key = %s, value = %s%n",
                                record.topic(), record.offset(), record.key(), record.value());
                    }
                }
            });

            producerThread.start();
            consumerThread.start();
            server.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
