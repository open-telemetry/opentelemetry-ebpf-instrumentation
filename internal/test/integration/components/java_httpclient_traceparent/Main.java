/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.net.CookieHandler;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class Main {
  private static final CyclicBarrier concurrentCalls = new CyclicBarrier(4);
  private static final HttpClient client =
      HttpClient.newBuilder()
          .version(HttpClient.Version.HTTP_1_1)
          .connectTimeout(Duration.ofSeconds(10))
          .build();

  public static void main(String[] args) throws Exception {
    String mode = args[0];
    int port = "service".equals(mode) ? 8080 : 8086;
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.setExecutor(Executors.newFixedThreadPool(8));
    server.createContext(
        "/health",
        exchange -> {
          exchange
              .getResponseHeaders()
              .set("X-Java-Feature", Integer.toString(Runtime.version().feature()));
          reply(exchange, 200, System.getProperty("otel.obi.java.agent.version", ""));
        });
    server.createContext(
        "/propagation-state",
        exchange -> {
          try {
            Class<?> helper =
                Class.forName(
                    "io.opentelemetry.obi.java.instrumentations.data.JdkHttpClientPropagation",
                    true,
                    null);
            java.lang.reflect.Field requestScopes = helper.getDeclaredField("requestScopes");
            java.lang.reflect.Field retained = helper.getDeclaredField("retainedReservations");
            requestScopes.setAccessible(true);
            retained.setAccessible(true);
            reply(
                exchange,
                200,
                ((Map<?, ?>) requestScopes.get(null)).size() + ":" + retained.getInt(null));
          } catch (Exception error) {
            reply(exchange, 500, error.toString());
          }
        });
    if ("service".equals(mode)) {
      server.createContext("/call/", Main::call);
      if (Runtime.version().feature() >= 21) {
        HttpServer virtual = HttpServer.create(new InetSocketAddress(8081), 0);
        virtual.setExecutor(
            (java.util.concurrent.ExecutorService)
                Executors.class.getMethod("newVirtualThreadPerTaskExecutor").invoke(null));
        virtual.createContext("/call/", Main::call);
        virtual.start();
      }
    } else {
      server.createContext("/", exchange -> reply(exchange, 200, "downstream"));
    }
    server.start();
  }

  private static void call(HttpExchange exchange) {
    try {
      String path = exchange.getRequestURI().getPath().substring("/call".length());
      String testMode = exchange.getRequestHeaders().getFirst("X-Test-Mode");
      boolean http2 = "http2".equals(testMode);
      boolean fallback = "http2-fallback".equals(testMode);
      HttpClient selected = client;
      AtomicReference<CompletableFuture<HttpResponse<String>>> nested = new AtomicReference<>();
      if ("reentrant-async".equals(testMode)) {
        final String nestedPath = path + "-nested";
        selected =
            HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .cookieHandler(
                    new CookieHandler() {
                      public Map<String, List<String>> get(
                          URI uri, Map<String, List<String>> headers) {
                        if (nested.get() == null) {
                          nested.set(
                              client.sendAsync(
                                  HttpRequest.newBuilder(
                                          URI.create("https://proxy:8443" + nestedPath))
                                      .GET()
                                      .build(),
                                  HttpResponse.BodyHandlers.ofString()));
                        }
                        return Collections.emptyMap();
                      }

                      public void put(URI uri, Map<String, List<String>> headers) {}
                    })
                .build();
      } else if ("redirect".equals(testMode)) {
        selected =
            HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .build();
      } else if ("auth".equals(testMode)) {
        selected =
            HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .authenticator(
                    new java.net.Authenticator() {
                      protected java.net.PasswordAuthentication getPasswordAuthentication() {
                        return new java.net.PasswordAuthentication(
                            "fixture", "fixture".toCharArray());
                      }
                    })
                .build();
      }
      if ("tls-failure".equals(testMode)) {
        javax.net.ssl.SSLContext tls = javax.net.ssl.SSLContext.getInstance("TLS");
        tls.init(
            null,
            new javax.net.ssl.TrustManager[] {
              new javax.net.ssl.X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                  return new java.security.cert.X509Certificate[0];
                }

                public void checkClientTrusted(
                    java.security.cert.X509Certificate[] chain, String auth)
                    throws java.security.cert.CertificateException {
                  throw new java.security.cert.CertificateException("test rejection");
                }

                public void checkServerTrusted(
                    java.security.cert.X509Certificate[] chain, String auth)
                    throws java.security.cert.CertificateException {
                  throw new java.security.cert.CertificateException("test rejection");
                }
              }
            },
            null);
        selected =
            HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).sslContext(tls).build();
      }
      HttpRequest.Builder request =
          HttpRequest.newBuilder(
                  URI.create(
                      ("connect-failure".equals(testMode)
                              ? "https://proxy:1"
                              : fallback ? "https://proxy:8445" : "https://proxy:8443")
                          + path))
              .version(http2 || fallback ? HttpClient.Version.HTTP_2 : HttpClient.Version.HTTP_1_1)
              .timeout(Duration.ofSeconds(15))
              .GET();
      String owned = exchange.getRequestHeaders().getFirst("X-Application-Traceparent");
      if (owned != null) {
        request.header("TrAcEpArEnT", owned);
      }
      if ("oversized".equals(testMode)) {
        request.header("X-Large", "x".repeat(17 * 1024));
      }
      if ("timeout".equals(testMode)) {
        request.timeout(Duration.ofMillis(200));
      }
      if ("duplicate-owned".equals(testMode)) {
        request.header("traceparent", owned);
      }
      if ("post".equals(testMode)
          || "expect-continue".equals(testMode)
          || "expect-reject".equals(testMode)) {
        request.POST(HttpRequest.BodyPublishers.ofString("body-preserved-by-injection"));
      }
      if ("expect-continue".equals(testMode) || "expect-reject".equals(testMode)) {
        request.expectContinue(true);
      }
      HttpRequest original = request.build();
      if (path.contains("-concurrent-")) {
        concurrentCalls.await(10, TimeUnit.SECONDS);
      }
      HttpResponse<String> response;
      try {
        if ("interrupt".equals(testMode)) {
          Thread.currentThread().interrupt();
        }
        if ("virtual-thread".equals(testMode)) {
          if (!"java.lang.VirtualThread".equals(Thread.currentThread().getClass().getName())) {
            throw new IllegalStateException("request handler is not a virtual thread");
          }
        }
        response =
            "async".equals(testMode)
                ? selected.sendAsync(original, HttpResponse.BodyHandlers.ofString()).join()
                : selected.send(original, HttpResponse.BodyHandlers.ofString());
        if ("reuse".equals(testMode)) {
          response = selected.send(original, HttpResponse.BodyHandlers.ofString());
        }
      } catch (java.io.IOException | InterruptedException expected) {
        if (!"timeout".equals(testMode)
            && !"interrupt".equals(testMode)
            && !"tls-failure".equals(testMode)
            && !"connect-failure".equals(testMode)) {
          throw expected;
        }
        reply(exchange, 200, "expected failure");
        return;
      } finally {
        Thread.interrupted();
      }
      if (nested.get() != null && nested.get().join().statusCode() != 200) {
        throw new IllegalStateException("nested async request failed");
      }
      if (response.version() != (http2 ? HttpClient.Version.HTTP_2 : HttpClient.Version.HTTP_1_1)
          || !original
              .headers()
              .allValues("traceparent")
              .equals(
                  owned == null
                      ? Collections.emptyList()
                      : "duplicate-owned".equals(testMode)
                          ? java.util.Arrays.asList(owned, owned)
                          : Collections.singletonList(owned))) {
        throw new IllegalStateException("HTTP version or application request was changed");
      }
      reply(exchange, response.statusCode(), response.body());
    } catch (Exception error) {
      error.printStackTrace();
      try {
        reply(exchange, 500, error.toString());
      } catch (Exception ignored) {
      }
    }
  }

  private static void reply(HttpExchange exchange, int status, String body)
      throws java.io.IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
    try (java.io.OutputStream output = exchange.getResponseBody()) {
      output.write(bytes);
    }
    exchange.close();
  }
}
