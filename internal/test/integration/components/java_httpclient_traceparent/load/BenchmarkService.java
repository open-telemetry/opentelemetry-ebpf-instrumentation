/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.lang.management.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.Executors;

public class BenchmarkService {
  private static final HttpClient client =
      HttpClient.newBuilder()
          .version(HttpClient.Version.HTTP_1_1)
          .connectTimeout(Duration.ofSeconds(10))
          .build();
  private static final Map<Integer, String> padding = new HashMap<>();

  static {
    for (int size : new int[] {128, 1024, 8192}) {
      char[] value = new char[size];
      Arrays.fill(value, 'x');
      padding.put(size, new String(value));
    }
  }

  public static void main(String[] args) throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress(8080), 256);
    server.setExecutor(Executors.newFixedThreadPool(64));
    server.createContext(
        "/health",
        exchange ->
            reply(
                exchange,
                200,
                "{\"version\":\""
                    + System.getProperty("otel.obi.java.agent.version", "")
                    + "\",\"propagation\":\""
                    + System.getProperty("otel.obi.java.agent.httpclient.propagation", "false")
                    + "\",\"java\":\""
                    + System.getProperty("java.version")
                    + "\"}"));
    server.createContext(
        "/stats",
        exchange -> {
          com.sun.management.ThreadMXBean threads =
              (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
          long allocated = 0;
          for (long value : threads.getThreadAllocatedBytes(threads.getAllThreadIds()))
            if (value > 0) allocated += value;
          long gcCount = 0, gcMs = 0, directBytes = 0, directCount = 0;
          for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            gcCount += gc.getCollectionCount();
            gcMs += gc.getCollectionTime();
          }
          for (BufferPoolMXBean pool :
              ManagementFactory.getPlatformMXBeans(BufferPoolMXBean.class)) {
            if ("direct".equals(pool.getName())) {
              directBytes = pool.getMemoryUsed();
              directCount = pool.getCount();
            }
          }
          reply(
              exchange,
              200,
              "{\"allocated_live_threads\":"
                  + allocated
                  + ",\"gc_count\":"
                  + gcCount
                  + ",\"gc_ms\":"
                  + gcMs
                  + ",\"heap_used\":"
                  + ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed()
                  + ",\"direct_bytes\":"
                  + directBytes
                  + ",\"direct_count\":"
                  + directCount
                  + ",\"threads\":"
                  + threads.getThreadCount()
                  + "}");
        });
    server.createContext(
        "/state",
        exchange -> {
          try {
            Class<?> helper =
                Class.forName(
                    "io.opentelemetry.obi.java.instrumentations.data.JdkHttpClientPropagation",
                    true,
                    null);
            java.lang.reflect.Field requests = helper.getDeclaredField("requestScopes");
            requests.setAccessible(true);
            java.lang.reflect.Field retained = helper.getDeclaredField("retainedReservations");
            retained.setAccessible(true);
            reply(
                exchange,
                200,
                ((Map<?, ?>) requests.get(null)).size() + ":" + retained.getInt(null));
          } catch (Exception error) {
            reply(exchange, 500, error.toString());
          }
        });
    server.createContext(
        "/call",
        exchange -> {
          try {
            String sizeHeader = exchange.getRequestHeaders().getFirst("X-Header-Bytes");
            int size = sizeHeader == null ? 128 : Integer.parseInt(sizeHeader);
            HttpRequest.Builder request =
                HttpRequest.newBuilder(
                        URI.create(
                            "https://proxy:8443/backend/"
                                + exchange
                                    .getRequestHeaders()
                                    .getFirst("Traceparent")
                                    .substring(3, 35)))
                    .timeout(Duration.ofSeconds(10))
                    .version(HttpClient.Version.HTTP_1_1)
                    .header("X-Padding", padding.get(size))
                    .header("tracestate", "fixture=preserved")
                    .GET();
            String owned = exchange.getRequestHeaders().getFirst("X-Application-Traceparent");
            if (owned != null) request.header("traceparent", owned);
            HttpRequest original = request.build();
            HttpResponse<String> response =
                "async".equals(System.getenv("HTTPCLIENT_API"))
                    ? client.sendAsync(original, HttpResponse.BodyHandlers.ofString()).join()
                    : client.send(original, HttpResponse.BodyHandlers.ofString());
            exchange
                .getResponseHeaders()
                .set(
                    "X-Traceparent-Count",
                    response.headers().firstValue("X-Traceparent-Count").orElse("missing"));
            response
                .headers()
                .firstValue("X-Received-Traceparent")
                .ifPresent(
                    value -> exchange.getResponseHeaders().set("X-Received-Traceparent", value));
            reply(exchange, response.statusCode(), response.body());
          } catch (Exception error) {
            reply(exchange, 500, error.toString());
          }
        });
    server.start();
  }

  private static void reply(HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, bytes.length);
    try (java.io.OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
    exchange.close();
  }
}
