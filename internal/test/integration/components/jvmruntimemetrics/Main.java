// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class Main {
  private static volatile byte[][] allocations;

  public static void main(String[] args) throws IOException {
    HttpServer server = HttpServer.create(new InetSocketAddress(8085), 0);
    server.createContext("/smoke", Main::respond);
    server.createContext(
        "/gc",
        exchange -> {
          allocations = new byte[64][];
          for (int i = 0; i < allocations.length; i++) {
            allocations[i] = new byte[1024 * 1024];
          }
          System.gc();
          respond(exchange);
        });
    server.start();
  }

  private static void respond(HttpExchange exchange) throws IOException {
    byte[] response = "OK".getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(200, response.length);
    try {
      exchange.getResponseBody().write(response);
    } finally {
      exchange.close();
    }
  }
}
