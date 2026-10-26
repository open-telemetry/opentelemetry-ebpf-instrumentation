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
  private static final java.util.concurrent.ExecutorService httpExecutor =
      Executors.newFixedThreadPool(2);
  private static final HttpClient client =
      HttpClient.newBuilder()
          .version(HttpClient.Version.HTTP_1_1)
          .executor(httpExecutor)
          .connectTimeout(Duration.ofSeconds(10))
          .build();
  private static final HttpRequest sharedRequest =
      HttpRequest.newBuilder(URI.create("https://proxy:8443/shared-immutable"))
          .header("X-Application", "preserved")
          .header("tracestate", "fixture=preserved")
          .timeout(Duration.ofSeconds(15))
          .GET()
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
      boolean async = "true".equals(exchange.getRequestHeaders().getFirst("X-Async"));
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
      java.io.IOException bodyFailure = new java.io.IOException("fixture body failure");
      request.header("X-Application", "preserved").header("tracestate", "fixture=preserved");
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
      if ("cancel-transport".equals(testMode)) {
        request.timeout(Duration.ofSeconds(2));
      }
      if ("write-failure".equals(testMode)) {
        request.POST(
            HttpRequest.BodyPublishers.fromPublisher(
                subscriber ->
                    subscriber.onSubscribe(
                        new java.util.concurrent.Flow.Subscription() {
                          private boolean finished;

                          public synchronized void request(long count) {
                            if (!finished) {
                              finished = true;
                              subscriber.onError(bodyFailure);
                            }
                          }

                          public synchronized void cancel() {
                            finished = true;
                          }
                        })));
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
      HttpRequest original = "shared-immutable".equals(testMode) ? sharedRequest : request.build();
      if (path.contains("-concurrent-")) {
        concurrentCalls.await(10, TimeUnit.SECONDS);
      }
      HttpResponse<String> response;
      CompletableFuture<Object> capacity =
          "tracking-capacity".equals(testMode) ? fillTrackingCapacity() : null;
      try {
        if (async && "cancel-transport".equals(testMode)) {
          CompletableFuture<HttpResponse<String>> future =
              selected.sendAsync(original, HttpResponse.BodyHandlers.ofString());
          waitForProxyRequest(path);
          boolean cancelled = future.cancel(true);
          // Aborting the exchange can complete the dependent stage before cancel marks it
          // cancelled.
          try {
            future.join();
            throw new IllegalStateException("transport completed normally after cancellation");
          } catch (java.util.concurrent.CancellationException expected) {
            exchange.getResponseHeaders().set("X-Cancel-Exception", expected.getClass().getName());
          } catch (java.util.concurrent.CompletionException expected) {
            boolean cancellation = false;
            for (Throwable error = expected; error != null; error = error.getCause()) {
              cancellation |= error instanceof java.util.concurrent.CancellationException;
            }
            if (!cancellation) {
              throw expected;
            }
            exchange.getResponseHeaders().set("X-Cancel-Exception", expected.getClass().getName());
          }
          exchange.getResponseHeaders().set("X-Cancel-Result", Boolean.toString(cancelled));
          checkPropagationScope();
          reply(exchange, 200, "expected failure");
          return;
        }
        if (async && "synchronous-throw".equals(testMode)) {
          try {
            selected.sendAsync(original, null);
            throw new IllegalStateException("null handler was accepted");
          } catch (NullPointerException expected) {
            checkPropagationScope();
            reply(exchange, 200, "expected failure");
            return;
          }
        }
        if (async && "detached".equals(testMode)) {
          selected
              .sendAsync(original, HttpResponse.BodyHandlers.ofString())
              .thenRun(Main::checkPropagationScope);
          checkPropagationScope();
          reply(exchange, 200, "detached");
          return;
        }
        if (async && "cancel".equals(testMode)) {
          java.util.concurrent.CountDownLatch gate = new java.util.concurrent.CountDownLatch(1);
          HttpClient gated =
              HttpClient.newBuilder()
                  .version(HttpClient.Version.HTTP_1_1)
                  .executor(
                      task ->
                          httpExecutor.execute(
                              () -> {
                                try {
                                  gate.await();
                                  task.run();
                                } catch (InterruptedException interrupted) {
                                  Thread.currentThread().interrupt();
                                }
                              }))
                  .build();
          CompletableFuture<HttpResponse<String>> future =
              gated.sendAsync(original, HttpResponse.BodyHandlers.ofString());
          try {
            if (!future.cancel(false) || !future.isCancelled()) {
              throw new IllegalStateException("future cancellation changed");
            }
            checkPropagationScope();
          } finally {
            gate.countDown();
          }
          reply(exchange, 200, "cancelled");
          return;
        }
        if ("interrupt".equals(testMode)) {
          Thread.currentThread().interrupt();
        }
        if ("virtual-thread".equals(testMode)) {
          if (!"java.lang.VirtualThread".equals(Thread.currentThread().getClass().getName())) {
            throw new IllegalStateException("request handler is not a virtual thread");
          }
        }
        response =
            async || "async".equals(testMode)
                ? ("push-overload".equals(testMode)
                        ? selected.sendAsync(
                            original,
                            HttpResponse.BodyHandlers.ofString(),
                            (initiating, push, acceptor) -> {
                              throw new IllegalStateException("unexpected HTTP/1.1 push");
                            })
                        : selected.sendAsync(original, HttpResponse.BodyHandlers.ofString()))
                    .thenApply(
                        value -> {
                          if (async) {
                            checkPropagationScope();
                          }
                          return value;
                        })
                    .join()
                : selected.send(original, HttpResponse.BodyHandlers.ofString());
        if ("reuse".equals(testMode)) {
          response =
              async
                  ? selected.sendAsync(original, HttpResponse.BodyHandlers.ofString()).join()
                  : selected.send(original, HttpResponse.BodyHandlers.ofString());
        }
        if (async) {
          checkPropagationScope();
          CompletableFuture.runAsync(Main::checkPropagationScope, httpExecutor).join();
        }
      } catch (java.io.IOException
          | InterruptedException
          | java.util.concurrent.CompletionException expected) {
        if (!"timeout".equals(testMode)
            && !"interrupt".equals(testMode)
            && !"tls-failure".equals(testMode)
            && !"connect-failure".equals(testMode)
            && !"write-failure".equals(testMode)) {
          throw expected;
        }
        if ("timeout".equals(testMode)
                && !hasCause(expected, java.net.http.HttpTimeoutException.class)
            || "tls-failure".equals(testMode)
                && !hasCause(expected, javax.net.ssl.SSLHandshakeException.class)
            || "connect-failure".equals(testMode)
                && !hasCause(expected, java.net.ConnectException.class)
            || "interrupt".equals(testMode) && !hasCause(expected, InterruptedException.class)) {
          throw new IllegalStateException("unexpected application exception", expected);
        }
        if ("write-failure".equals(testMode)) {
          boolean originalFailure = false;
          for (Throwable error = expected; error != null; error = error.getCause()) {
            originalFailure |= error == bodyFailure;
          }
          if (!originalFailure) {
            throw new IllegalStateException("body publisher exception changed", expected);
          }
        }
        reply(exchange, 200, "expected failure");
        return;
      } finally {
        if (capacity != null) {
          capacity.complete(null);
        }
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

  private static void checkPropagationScope() {
    try {
      Class<?> helper =
          Class.forName(
              "io.opentelemetry.obi.java.instrumentations.data.JdkHttpClientPropagation",
              true,
              null);
      java.lang.reflect.Field field = helper.getDeclaredField("currentSend");
      field.setAccessible(true);
      if (((ThreadLocal<?>) field.get(null)).get() != null) {
        throw new IllegalStateException(
            "HttpClient propagation scope leaked into application code");
      }
    } catch (ReflectiveOperationException error) {
      throw new IllegalStateException(error);
    }
  }

  private static boolean hasCause(Throwable failure, Class<? extends Throwable> type) {
    for (Throwable error = failure; error != null; error = error.getCause()) {
      if (type.isInstance(error)) {
        return true;
      }
    }
    return false;
  }

  private static CompletableFuture<Object> fillTrackingCapacity() throws Exception {
    Class<?> helper =
        Class.forName(
            "io.opentelemetry.obi.java.instrumentations.data.JdkHttpClientPropagation", true, null);
    Object scope = helper.getMethod("enterAsync").invoke(null);
    Object request = new Object();
    CompletableFuture<Object> transport = new CompletableFuture<>();
    try {
      java.lang.reflect.Method register =
          helper.getMethod("register", Object.class, Object[].class, boolean.class);
      register.invoke(null, request, new Object[0], true);
      for (int i = 1; i < 10_000; i++) {
        register.invoke(null, new Object(), new Object[0], true);
      }
      helper
          .getMethod("trackTransport", Object.class, CompletableFuture.class)
          .invoke(null, request, transport);
      java.lang.reflect.Field requests = helper.getDeclaredField("requestScopes");
      requests.setAccessible(true);
      if (((Map<?, ?>) requests.get(null)).size() != 10_000) {
        throw new IllegalStateException("tracking limit was not reached");
      }
      return transport;
    } catch (Exception error) {
      transport.complete(null);
      throw error;
    } finally {
      helper.getMethod("exit", helper).invoke(null, scope);
    }
  }

  private static void waitForProxyRequest(String path) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (System.nanoTime() < deadline) {
      java.net.HttpURLConnection connection =
          (java.net.HttpURLConnection)
              URI.create("http://proxy:8082/records" + path).toURL().openConnection();
      connection.setConnectTimeout(1000);
      connection.setReadTimeout(1000);
      try {
        if (connection.getResponseCode() == 200) {
          connection.getInputStream().close();
          return;
        }
      } finally {
        connection.disconnect();
      }
      Thread.sleep(10);
    }
    throw new IllegalStateException("transport did not reach the TLS proxy");
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
