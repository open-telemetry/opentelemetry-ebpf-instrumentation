// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// C++ HTTP server emitting folly-style USDT probes:
//   custom_span_cpp:order_start / order_end  — paired, semaphored
//   custom_span_cpp:cache_hit                — single-shot, semaphored
//
// Each FOLLY_SDT_WITH_SEMAPHORE probe is gated by a u16 semaphore the
// kernel atomically bumps when a uprobe attaches (RefCtrOffset). This
// sample is the only one in the integration suite that exercises the
// semaphore path; the other samples emit always-fires probes
// (sema_off = 0 in OBI attach logs).

#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include <folly/tracing/StaticTracepoint.h>

FOLLY_SDT_DEFINE_SEMAPHORE(custom_span_cpp, order_start)
FOLLY_SDT_DEFINE_SEMAPHORE(custom_span_cpp, order_end)
FOLLY_SDT_DEFINE_SEMAPHORE(custom_span_cpp, cache_hit)

static void process_order(uint64_t order_id, const char *customer) {
  FOLLY_SDT_WITH_SEMAPHORE(custom_span_cpp, order_start, order_id, customer);
  std::this_thread::sleep_for(std::chrono::milliseconds(5));
  int32_t status = 0;
  FOLLY_SDT_WITH_SEMAPHORE(custom_span_cpp, order_end, order_id, status);
}

static void cache_lookup(const char *key) {
  FOLLY_SDT_WITH_SEMAPHORE(custom_span_cpp, cache_hit, key);
}

static const char ok_response[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

static void qparam(const char *q, const char *k, char *out, size_t out_sz) {
  out[0] = '\0';
  if (!q) {
    return;
  }
  size_t klen = std::strlen(k);
  while (*q) {
    const char *eq = std::strchr(q, '=');
    if (!eq) {
      break;
    }
    const char *amp = std::strchr(eq, '&');
    size_t name_len = static_cast<size_t>(eq - q);
    if (name_len == klen && std::strncmp(q, k, klen) == 0) {
      size_t val_len =
          amp ? static_cast<size_t>(amp - eq - 1) : std::strlen(eq + 1);
      if (val_len >= out_sz) {
        val_len = out_sz - 1;
      }
      std::memcpy(out, eq + 1, val_len);
      out[val_len] = '\0';
      return;
    }
    if (!amp) {
      break;
    }
    q = amp + 1;
  }
}

static void handle_client(int fd) {
  char buf[4096];
  ssize_t total = 0;
  while (total < static_cast<ssize_t>(sizeof(buf)) - 1) {
    ssize_t r = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
    if (r <= 0) {
      close(fd);
      return;
    }
    total += r;
    buf[total] = '\0';
    if (std::strstr(buf, "\r\n\r\n")) {
      break;
    }
  }

  char method[8] = {0};
  char path[256] = {0};
  std::sscanf(buf, "%7s %255s", method, path);

  char *query = std::strchr(path, '?');
  if (query) {
    *query = '\0';
    ++query;
  }

  if (std::strcmp(path, "/smoke") == 0) {
    send(fd, ok_response, sizeof(ok_response) - 1, 0);
    close(fd);
    return;
  }
  if (std::strcmp(path, "/order") == 0) {
    char id_str[32] = {0};
    char customer[128] = "anonymous";
    qparam(query, "id", id_str, sizeof(id_str));
    qparam(query, "customer", customer, sizeof(customer));
    uint64_t order_id = std::strtoull(id_str, nullptr, 10);
    if (order_id == 0) {
      order_id = 1;
    }
    process_order(order_id, customer);
    send(fd, ok_response, sizeof(ok_response) - 1, 0);
    close(fd);
    return;
  }
  if (std::strcmp(path, "/cache") == 0) {
    char key[128] = {0};
    qparam(query, "key", key, sizeof(key));
    cache_lookup(key);
    send(fd, ok_response, sizeof(ok_response) - 1, 0);
    close(fd);
    return;
  }
  const char not_found[] =
      "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
  send(fd, not_found, sizeof(not_found) - 1, 0);
  close(fd);
}

int main() {
  int port = std::atoi(std::getenv("PORT") ? std::getenv("PORT") : "8397");
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    std::perror("socket");
    return 1;
  }
  int yes = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  if (bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    std::perror("bind");
    return 1;
  }
  listen(s, 32);
  std::printf("custom_span_cpp listening on %d\n", port);
  std::fflush(stdout);
  for (;;) {
    int fd = accept(s, nullptr, nullptr);
    if (fd < 0) {
      std::perror("accept");
      continue;
    }
    handle_client(fd);
  }
}
