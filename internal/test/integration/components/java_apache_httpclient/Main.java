/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.util.EntityUtils;

public class Main {
  private static final CyclicBarrier concurrentCalls = new CyclicBarrier(4);
  private static final java.util.concurrent.ScheduledExecutorService cancellations =
      Executors.newSingleThreadScheduledExecutor();
  private static final CloseableHttpClient client = newClient();
  private static final CloseableHttpClient fragmented =
      HttpClients.custom()
          .setDefaultConnectionConfig(
              org.apache.http.config.ConnectionConfig.custom()
                  .setBufferSize(64)
                  .setFragmentSizeHint(64)
                  .build())
          .build();

  private static CloseableHttpClient newClient() {
    BasicCredentialsProvider credentials = new BasicCredentialsProvider();
    credentials.setCredentials(
        AuthScope.ANY, new UsernamePasswordCredentials("fixture", "fixture"));
    return HttpClients.custom()
        .addInterceptorFirst(
            (org.apache.http.HttpRequestInterceptor)
                (request, context) -> {
                  org.apache.http.Header reentrant = request.getFirstHeader("X-Reentrant");
                  if (reentrant != null) {
                    try (CloseableHttpResponse response =
                        client.execute(new HttpGet("https://proxy:8443" + reentrant.getValue()))) {
                      EntityUtils.consume(response.getEntity());
                    }
                  }
                })
        .setDefaultCredentialsProvider(credentials)
        .setMaxConnTotal(256)
        .setMaxConnPerRoute(256)
        .setDefaultRequestConfig(
            RequestConfig.custom()
                .setConnectTimeout(10000)
                .setSocketTimeout(10000)
                .setConnectionRequestTimeout(10000)
                .build())
        .build();
  }

  public static void main(String[] args) throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress(24180), 0);
    server.setExecutor(Executors.newFixedThreadPool(128));
    server.createContext(
        "/health",
        exchange -> reply(exchange, 200, System.getProperty("otel.obi.java.agent.version", "")));
    server.createContext(
        "/propagation-state",
        exchange -> {
          try {
            Class<?> helper =
                Class.forName(
                    "io.opentelemetry.obi.java.instrumentations.data.JdkHttpClientPropagation",
                    false,
                    null);
            Field requests = helper.getDeclaredField("requestScopes");
            Field reservations = helper.getDeclaredField("retainedReservations");
            requests.setAccessible(true);
            reservations.setAccessible(true);
            reply(
                exchange,
                200,
                ((Map<?, ?>) requests.get(null)).size() + ":" + reservations.getInt(null));
          } catch (Exception error) {
            reply(exchange, 500, error.toString());
          }
        });
    server.createContext(
        "/active-executions",
        exchange -> {
          try {
            Class<?> helper =
                Class.forName(
                    "io.opentelemetry.obi.java.instrumentations.data.ApacheHttpClientPropagation",
                    false,
                    null);
            reply(exchange, 200, helper.getMethod("activeExecutions").invoke(null).toString());
          } catch (Exception error) {
            reply(exchange, 500, error.toString());
          }
        });
    server.createContext(
        "/capability",
        exchange ->
            reply(
                exchange,
                200,
                System.getProperty("otel.obi.java.agent.apache4.propagation", "missing")));
    server.createContext("/call/", Main::call);
    server.start();
  }

  private static Result result(HttpResponse response) throws IOException {
    return new Result(
        response.getStatusLine().getStatusCode(), EntityUtils.toString(response.getEntity()));
  }

  private static Result execute(HttpRequestBase request, int overload) throws IOException {
    CloseableHttpClient selected = overload == -1 ? fragmented : client;
    HttpHost host = new HttpHost("proxy", 8443, "https");
    BasicHttpContext context = new BasicHttpContext();
    ResponseHandler<Result> handler = Main::result;
    if (overload == -1) {
      overload = 0;
    }
    switch (overload) {
      case 0:
        try (CloseableHttpResponse response = selected.execute(request)) {
          return result(response);
        }
      case 1:
        try (CloseableHttpResponse response = selected.execute(request, context)) {
          return result(response);
        }
      case 2:
        try (CloseableHttpResponse response = selected.execute(host, request)) {
          return result(response);
        }
      case 3:
        try (CloseableHttpResponse response = selected.execute(host, request, context)) {
          return result(response);
        }
      case 4:
        return selected.execute(request, handler);
      case 5:
        return selected.execute(request, handler, context);
      case 6:
        return selected.execute(host, request, handler);
      default:
        return selected.execute(host, request, handler, context);
    }
  }

  private static void call(HttpExchange exchange) {
    String mode = exchange.getRequestHeaders().getFirst("X-Test-Mode");
    if (mode == null) {
      mode = "";
    }
    boolean failure =
        mode.equals("timeout")
            || mode.equals("abort")
            || mode.equals("connect-failure")
            || mode.equals("tls-failure")
            || mode.equals("write-failure");
    Field capacity = null;
    int previousCapacity = 0;
    java.util.concurrent.atomic.AtomicBoolean writeFailed =
        new java.util.concurrent.atomic.AtomicBoolean();
    try {
      if (mode.equals("capacity")) {
        Class<?> helper =
            Class.forName(
                "io.opentelemetry.obi.java.instrumentations.data.JdkHttpClientPropagation",
                false,
                null);
        capacity = helper.getDeclaredField("retainedReservations");
        capacity.setAccessible(true);
        previousCapacity = capacity.getInt(null);
        if (previousCapacity != 0) {
          throw new IllegalStateException("capacity test requires a drained source");
        }
        Field limit = helper.getDeclaredField("MAX_TRACKED_REQUESTS");
        limit.setAccessible(true);
        capacity.setInt(null, limit.getInt(null));
      }
      String path = exchange.getRequestURI().getPath().substring("/call".length());
      String address = "https://proxy:8443" + path;
      if (mode.equals("connect-failure")) {
        address = "https://proxy:1" + path;
      }
      if (mode.equals("tls-failure")) {
        address = "https://proxy:8082" + path;
      }
      boolean get = mode.equals("retry") || mode.equals("redirect") || mode.equals("auth");
      HttpRequestBase request;
      if (get) {
        request = new HttpGet(address);
      } else {
        HttpPost post = new HttpPost(address);
        boolean bodyLike = mode.equals("body-like");
        if (mode.equals("write-failure") || bodyLike) {
          post.setEntity(
              new ByteArrayEntity(
                  bodyLike ? readAll(exchange.getRequestBody()) : new byte[1024 * 1024]) {
                @Override
                public void writeTo(java.io.OutputStream output) throws IOException {
                  try {
                    output.flush();
                    try {
                      Thread.sleep(200);
                    } catch (InterruptedException error) {
                      Thread.currentThread().interrupt();
                    }
                    super.writeTo(output);
                  } catch (IOException error) {
                    writeFailed.set(true);
                    throw error;
                  }
                }
              });
        } else {
          post.setEntity(new ByteArrayEntity(readAll(exchange.getRequestBody())));
        }
        request = post;
      }
      request.setHeader("X-Unrelated", "preserved");
      request.setHeader("tracestate", "vendor=value");
      String owned = exchange.getRequestHeaders().getFirst("X-Application-Traceparent");
      if (mode.equals("ancestor-owned")) {
        owned = exchange.getRequestHeaders().getFirst("traceparent");
      }
      if (owned != null) {
        request.setHeader("TrAcEpArEnT", owned);
      }
      if (mode.equals("duplicate-owned")) {
        request.addHeader("TRACEPARENT", owned);
      }
      if (mode.equals("oversized")) {
        char[] padding = new char[20 * 1024];
        java.util.Arrays.fill(padding, 'x');
        request.setHeader("X-Padding", new String(padding));
      }
      if (mode.startsWith("expect-")) {
        request.setHeader("Expect", "100-continue");
      }
      if (mode.equals("timeout") || mode.equals("tls-failure")) {
        request.setConfig(RequestConfig.custom().setSocketTimeout(200).build());
      }
      if (mode.equals("abort")) {
        cancellations.schedule(request::abort, 200, TimeUnit.MILLISECONDS);
      }
      if (path.contains("-concurrent-")) {
        concurrentCalls.await(10, TimeUnit.SECONDS);
      }
      if (mode.equals("reentrant")) {
        request.setHeader("X-Reentrant", path + "-nested");
      }
      int overload = mode.startsWith("overload-") ? Integer.parseInt(mode.substring(9)) : 0;
      if (mode.equals("split")) {
        overload = -1;
      }
      Result response;
      if (mode.equals("handler-reentrant")) {
        response = null;
      } else {
        response = execute(request, overload);
      }
      if (mode.equals("reuse")) {
        response = execute(request, overload);
      }
      if (mode.equals("handler-reentrant")) {
        response =
            client.execute(
                request,
                outer -> {
                  EntityUtils.consume(outer.getEntity());
                  return client.execute(
                      new HttpGet("https://proxy:8443" + path + "-nested"), Main::result);
                });
      }
      if (capacity != null) {
        capacity.setInt(null, previousCapacity);
        capacity = null;
      }
      if (failure) {
        reply(exchange, 500, "expected failure did not occur");
      } else {
        reply(exchange, response.status, response.body);
      }
    } catch (Exception error) {
      try {
        boolean expected = failure && (!mode.equals("write-failure") || writeFailed.get());
        reply(exchange, expected ? 200 : 500, expected ? "expected failure" : error.toString());
      } catch (Exception ignored) {
        exchange.close();
      }
    } finally {
      if (capacity != null) {
        try {
          capacity.setInt(null, previousCapacity);
        } catch (Exception error) {
          throw new IllegalStateException(error);
        }
      }
    }
  }

  private static byte[] readAll(InputStream input) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    byte[] buffer = new byte[4096];
    int length;
    while ((length = input.read(buffer)) != -1) {
      output.write(buffer, 0, length);
    }
    return output.toByteArray();
  }

  private static void reply(HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, bytes.length);
    exchange.getResponseBody().write(bytes);
    exchange.close();
  }

  private static class Result {
    final int status;
    final String body;

    Result(int status, String body) {
      this.status = status;
      this.body = body;
    }
  }
}
