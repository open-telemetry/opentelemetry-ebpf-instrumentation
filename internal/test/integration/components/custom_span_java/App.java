// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class App {

    private static final long PROVIDER;
    private static final long ORDER_START;
    private static final long ORDER_END;
    private static final long CACHE_HIT;

    static {
        PROVIDER = Stapsdt.providerInit("custom_span_java");
        ORDER_START = Stapsdt.addProbeU64U64(PROVIDER, "order_start");
        ORDER_END = Stapsdt.addProbeU64I32(PROVIDER, "order_end");
        CACHE_HIT = Stapsdt.addProbeU64(PROVIDER, "cache_hit");
        int rc = Stapsdt.providerLoad(PROVIDER);
        if (rc != 0) {
            throw new RuntimeException("providerLoad failed rc=" + rc);
        }
    }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8395"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/smoke", App::handleSmoke);
        server.createContext("/order", App::handleOrder);
        server.createContext("/cache", App::handleCache);
        server.setExecutor(null);
        System.out.println("custom_span_java listening on " + port);
        server.start();
    }

    private static void handleSmoke(HttpExchange ex) throws IOException {
        reply(ex, 200, "ok");
    }

    private static void handleOrder(HttpExchange ex) throws IOException {
        String query = ex.getRequestURI().getRawQuery();
        long orderId = parseLong(queryParam(query, "id"), 1L);
        String customer = queryParam(query, "customer");
        if (customer == null || customer.isEmpty()) {
            customer = "anonymous";
        }
        byte[] customerBytes = customer.getBytes(StandardCharsets.UTF_8);
        Stapsdt.fireU64Str(ORDER_START, orderId, customerBytes);
        try {
            Thread.sleep(5);
        } catch (InterruptedException ignored) {
        }
        Stapsdt.fireU64I32(ORDER_END, orderId, 0);
        reply(ex, 200, "ok");
    }

    private static void handleCache(HttpExchange ex) throws IOException {
        String key = queryParam(ex.getRequestURI().getRawQuery(), "key");
        if (key == null) {
            key = "";
        }
        Stapsdt.fireStr(CACHE_HIT, key.getBytes(StandardCharsets.UTF_8));
        reply(ex, 200, "ok");
    }

    private static String queryParam(String query, String key) {
        if (query == null) return null;
        for (String part : query.split("&")) {
            int eq = part.indexOf('=');
            if (eq < 0) continue;
            if (part.substring(0, eq).equals(key)) {
                return part.substring(eq + 1);
            }
        }
        return null;
    }

    private static long parseLong(String s, long fallback) {
        if (s == null) return fallback;
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static void reply(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }
}
