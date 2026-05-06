// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

import org.apache.qpid.jms.JmsConnectionFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import javax.jms.Connection;
import javax.jms.DeliveryMode;
import javax.jms.Destination;
import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.Session;
import javax.jms.TextMessage;

public class AMQP {
    private static final String BROKER_URL = System.getenv().getOrDefault(
        "AMQP_URL",
        "amqp://127.0.0.1:5672?jms.connectTimeout=5000&jms.requestTimeout=5000&jms.sendTimeout=5000&jms.prefetchPolicy.all=0"
    );
    private static final String BROKER_USERNAME = System.getenv().getOrDefault("AMQP_USERNAME", "artemis");
    private static final String BROKER_PASSWORD = System.getenv().getOrDefault("AMQP_PASSWORD", "artemis");
    private static final String QUEUE_NAME = System.getenv().getOrDefault("AMQP_QUEUE", "oats-java-amqp");
    private static final AtomicInteger counter = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        try (ServerSocket server = new ServerSocket()) {
            server.bind(new InetSocketAddress("0.0.0.0", 8080));
            while (true) {
                Socket socket = server.accept();
                Thread handler = new Thread(() -> handleClient(socket));
                handler.setDaemon(true);
                handler.start();
            }
        }
    }

    private static void handleClient(Socket socket) {
        try (
            Socket s = socket;
            BufferedReader reader = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
            OutputStream output = s.getOutputStream()
        ) {
            s.setSoTimeout(5_000);
            String requestLine = reader.readLine();
            if (requestLine == null) {
                return;
            }

            while (true) {
                String headerLine = reader.readLine();
                if (headerLine == null || headerLine.isEmpty()) {
                    break;
                }
            }

            String[] requestParts = requestLine.split(" ");
            if (requestParts.length < 2 || !"GET".equals(requestParts[0])) {
                writeResponse(output, 405, "");
                return;
            }

            if (!"/message".equals(requestParts[1])) {
                writeResponse(output, 404, "");
                return;
            }

            try {
                String payload = amqpRoundtrip();
                writeResponse(output, 200, payload);
            } catch (Exception e) {
                writeResponse(output, 500, e.toString());
            }
        } catch (IOException ignored) {
            // Connection closed by peer; ignore for test helper service.
        }
    }

    private static synchronized String amqpRoundtrip() throws Exception {
        long deadlineMs = System.currentTimeMillis() + 30_000;
        Exception lastErr = null;

        while (System.currentTimeMillis() < deadlineMs) {
            String payload = "java-amqp-" + counter.incrementAndGet();
            try {
                sendAndReceive(payload);
                return payload;
            } catch (Exception e) {
                lastErr = e;
                Thread.sleep(1_000);
            }
        }

        throw new RuntimeException("AMQP roundtrip failed: " + lastErr, lastErr);
    }

    private static void sendAndReceive(String payload) throws Exception {
        publishMessage(payload);
        consumeMessage(payload);
    }

    private static void publishMessage(String payload) throws Exception {
        JmsConnectionFactory factory = new JmsConnectionFactory(BROKER_URL);
        try (Connection connection = factory.createConnection(BROKER_USERNAME, BROKER_PASSWORD)) {
            connection.start();
            try (Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE)) {
                Destination destination = session.createQueue(QUEUE_NAME);
                MessageProducer producer = session.createProducer(destination);
                producer.setDeliveryMode(DeliveryMode.NON_PERSISTENT);
                producer.setDisableMessageID(true);
                producer.setDisableMessageTimestamp(true);

                TextMessage outbound = session.createTextMessage(payload);
                producer.send(outbound);
            }
        }
    }

    private static void consumeMessage(String payload) throws Exception {
        JmsConnectionFactory factory = new JmsConnectionFactory(BROKER_URL);
        try (Connection connection = factory.createConnection(BROKER_USERNAME, BROKER_PASSWORD)) {
            connection.start();
            try (Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE)) {
                Destination destination = session.createQueue(QUEUE_NAME);
                MessageConsumer consumer = session.createConsumer(destination);
                Message inbound = consumer.receive(5_000);
                if (inbound == null) {
                    throw new RuntimeException("timed out waiting for AMQP message");
                }
                if (!(inbound instanceof TextMessage textMessage)) {
                    throw new RuntimeException("unexpected AMQP message type");
                }
                if (!payload.equals(textMessage.getText())) {
                    throw new RuntimeException("unexpected AMQP payload");
                }
            }
        }
    }

    private static void writeResponse(OutputStream output, int status, String bodyText) throws IOException {
        byte[] body = bodyText.getBytes(StandardCharsets.UTF_8);
        String statusText = switch (status) {
            case 200 -> "OK";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            default -> "Internal Server Error";
        };

        String headers = "HTTP/1.1 " + status + " " + statusText + "\r\n"
            + "Content-Type: text/plain; charset=utf-8\r\n"
            + "Content-Length: " + body.length + "\r\n"
            + "Connection: close\r\n"
            + "\r\n";

        output.write(headers.getBytes(StandardCharsets.US_ASCII));
        output.write(body);
        output.flush();
    }
}
