// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

import com.aerospike.client.AerospikeClient;
import com.aerospike.client.Bin;
import com.aerospike.client.Host;
import com.aerospike.client.Key;
import com.aerospike.client.Record;
import com.aerospike.client.policy.ClientPolicy;
import com.aerospike.client.policy.WritePolicy;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Tracks the products a shopper has looked at, backed by Aerospike.
 *
 * The frontend calls this on each product page view. It exists so the store
 * demo exercises OBI's Aerospike instrumentation the same way cartservice
 * exercises the Redis path.
 *
 *   POST /viewed/{productId}   record a view          -> Aerospike PUT
 *   GET  /viewed/{productId}   read one entry         -> Aerospike GET
 *   GET  /viewed               list everything seen   -> Aerospike SCAN
 *   GET  /_healthz             readiness probe        -> no Aerospike call
 */
public class RecentlyViewed {
    private static final String NAMESPACE = "test";
    private static final String SET = "viewed";
    private static final int PORT = 8080;
    private static final int CONNECT_ATTEMPTS = 30;

    private static AerospikeClient client;
    private static WritePolicy writePolicy;

    public static void main(String[] args) throws Exception {
        String host = envOrDefault("AEROSPIKE_ADDR", "aerospike:3000");
        client = connect(host);
        if (client == null) {
            System.err.println("could not reach aerospike at " + host);
            System.exit(1);
        }

        // sendKey puts the primary key on the wire, so OBI can report it as
        // db.query.text rather than only the key digest.
        writePolicy = new WritePolicy();
        writePolicy.sendKey = true;

        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/_healthz", exchange -> respond(exchange, 200, "ok"));
        server.createContext("/viewed", RecentlyViewed::handleViewed);
        server.setExecutor(null);
        System.out.println("recentlyviewed listening on :" + PORT + ", aerospike at " + host);
        server.start();
    }

    private static void handleViewed(HttpExchange exchange) throws IOException {
        String productId = productIdFrom(exchange.getRequestURI().getPath());
        String method = exchange.getRequestMethod();

        try {
            if ("POST".equals(method) && !productId.isEmpty()) {
                recordView(productId);
                respond(exchange, 200, "{\"recorded\":\"" + productId + "\"}");
                return;
            }
            if ("GET".equals(method) && !productId.isEmpty()) {
                String body = readView(productId);
                respond(exchange, body == null ? 404 : 200, body == null ? "{}" : body);
                return;
            }
            if ("GET".equals(method)) {
                respond(exchange, 200, listViews());
                return;
            }
            respond(exchange, 405, "{\"error\":\"method not allowed\"}");
        } catch (Exception e) {
            System.out.println("aerospike op failed: " + e.getMessage());
            respond(exchange, 500, "{\"error\":\"upstream failure\"}");
        }
    }

    private static void recordView(String productId) {
        Key key = new Key(NAMESPACE, SET, productId);
        client.put(writePolicy, key,
                new Bin("product_id", productId),
                new Bin("viewed_at", System.currentTimeMillis()));
    }

    private static String readView(String productId) {
        Record record = client.get(null, new Key(NAMESPACE, SET, productId));
        if (record == null) {
            return null;
        }
        return "{\"product_id\":\"" + productId + "\",\"viewed_at\":"
                + record.getLong("viewed_at") + "}";
    }

    private static String listViews() {
        List<String> ids = new ArrayList<>();
        client.scanAll(null, NAMESPACE, SET, (key, record) -> {
            Object id = record.getValue("product_id");
            if (id != null) {
                synchronized (ids) {
                    ids.add("\"" + id + "\"");
                }
            }
        });
        return "{\"viewed\":[" + String.join(",", ids) + "]}";
    }

    /** Everything after the last '/', empty when the path is just "/viewed". */
    private static String productIdFrom(String path) {
        String trimmed = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        int slash = trimmed.lastIndexOf('/');
        String tail = slash < 0 ? "" : trimmed.substring(slash + 1);
        return "viewed".equals(tail) ? "" : tail;
    }

    private static AerospikeClient connect(String hostPort) throws InterruptedException {
        String[] parts = hostPort.split(":", 2);
        String host = parts[0];
        int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 3000;

        ClientPolicy policy = new ClientPolicy();
        policy.timeout = 10_000;

        // The server is often still starting when this pod comes up.
        for (int i = 0; i < CONNECT_ATTEMPTS; i++) {
            try {
                return new AerospikeClient(policy, new Host(host, port));
            } catch (Exception e) {
                System.out.println("waiting for aerospike: " + e.getMessage());
                Thread.sleep(1000);
            }
        }
        return null;
    }

    private static String envOrDefault(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, payload.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(payload);
        }
    }
}
