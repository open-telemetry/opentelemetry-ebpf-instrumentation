// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Tiny HTTP server that emits SystemTap USDT probes around a fake "order
// processing" code path. OBI consumes these via the custom_span feature
// and emits spans.
//
// Probes:
//   custom_span_c:order_start(order_id u64, customer char *)
//   custom_span_c:order_end  (order_id u64, status   i32)
//   custom_span_c:cache_hit  (key      char *)
//
// HTTP routes:
//   GET /order?id=<int>&customer=<str>   triggers a paired span
//   GET /cache?key=<str>                  triggers a single-shot span
//   GET /smoke                            readiness probe

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sdt.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define LISTEN_PORT_DEFAULT 8390
#define BUF_SIZE 8192

static const char http_200_ok[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
static const char http_404[] =
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

static void sleep_ms(unsigned ms) {
  struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
  nanosleep(&ts, NULL);
}

static void url_decode(const char *src, size_t srclen, char *dst,
                       size_t dstmax) {
  size_t di = 0;
  for (size_t i = 0; i < srclen && di + 1 < dstmax; i++) {
    if (src[i] == '%' && i + 2 < srclen) {
      char hex[3] = {src[i + 1], src[i + 2], 0};
      dst[di++] = (char)strtol(hex, NULL, 16);
      i += 2;
    } else if (src[i] == '+') {
      dst[di++] = ' ';
    } else {
      dst[di++] = src[i];
    }
  }
  dst[di] = '\0';
}

static int qparam(const char *query, const char *key, char *out,
                  size_t outlen) {
  size_t klen = strlen(key);
  const char *p = query;
  while (p && *p) {
    const char *eq = strchr(p, '=');
    if (!eq)
      break;
    size_t nlen = (size_t)(eq - p);
    const char *next = strchr(eq, '&');
    size_t vlen = next ? (size_t)(next - eq - 1) : strlen(eq + 1);
    if (nlen == klen && strncmp(p, key, klen) == 0) {
      url_decode(eq + 1, vlen, out, outlen);
      return 1;
    }
    if (!next)
      break;
    p = next + 1;
  }
  return 0;
}

// External linkage + noinline so symbol survives -O2 for function-mode
// custom_span uprobe attach.
__attribute__((noinline)) void process_order(uint64_t order_id,
                                             const char *customer) {
  DTRACE_PROBE2(custom_span_c, order_start, order_id, customer);
  sleep_ms(20);
  int32_t status = 0;
  DTRACE_PROBE2(custom_span_c, order_end, order_id, status);
}

// Volatile sink keeps a prologue instruction before the DTRACE_PROBE site so
// the function-entry IP and the USDT probePC differ. On pre-5.15 kernels
// without bpf_get_attach_cookie() OBI falls back to an IP-keyed spec map; if
// two custom_spans share an IP the second one's spec masks the first. Keeping
// them at distinct IPs lets `cache.hit` (usdt_noret) and `cache.func.c`
// (function_span at cache_lookup) coexist on every supported kernel.
static volatile int cache_lookup_calls;
__attribute__((noinline)) void cache_lookup(const char *key) {
  cache_lookup_calls++;
  DTRACE_PROBE1(custom_span_c, cache_hit, key);
}

static void handle_client(int fd) {
  char buf[BUF_SIZE];
  ssize_t total = 0;
  while (total < (ssize_t)sizeof(buf) - 1) {
    ssize_t r = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
    if (r <= 0) {
      close(fd);
      return;
    }
    total += r;
    buf[total] = '\0';
    if (strstr(buf, "\r\n\r\n"))
      break;
  }

  char method[8] = {0};
  char path[256] = {0};
  sscanf(buf, "%7s %255s", method, path);

  char *query = strchr(path, '?');
  if (query) {
    *query = '\0';
    query++;
  }

  if (strcmp(path, "/smoke") == 0) {
    send(fd, http_200_ok, sizeof(http_200_ok) - 1, 0);
    close(fd);
    return;
  }
  if (strcmp(path, "/order") == 0) {
    char id_str[32] = {0};
    char customer[128] = "anonymous";
    qparam(query, "id", id_str, sizeof(id_str));
    qparam(query, "customer", customer, sizeof(customer));
    uint64_t order_id = strtoull(id_str, NULL, 10);
    if (order_id == 0)
      order_id = 1;
    process_order(order_id, customer);
    send(fd, http_200_ok, sizeof(http_200_ok) - 1, 0);
    close(fd);
    return;
  }
  if (strcmp(path, "/cache") == 0) {
    char key[128] = "default";
    qparam(query, "key", key, sizeof(key));
    cache_lookup(key);
    send(fd, http_200_ok, sizeof(http_200_ok) - 1, 0);
    close(fd);
    return;
  }

  send(fd, http_404, sizeof(http_404) - 1, 0);
  close(fd);
}

int main(void) {
  int port = LISTEN_PORT_DEFAULT;
  const char *port_env = getenv("PORT");
  if (port_env)
    port = atoi(port_env);

  int srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv < 0) {
    perror("socket");
    return 1;
  }
  int one = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(port),
      .sin_addr.s_addr = htonl(INADDR_ANY),
  };
  if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return 1;
  }
  if (listen(srv, 64) < 0) {
    perror("listen");
    return 1;
  }
  fprintf(stderr, "custom_span_c listening on :%d\n", port);
  fflush(stderr);

  for (;;) {
    int c = accept(srv, NULL, NULL);
    if (c < 0) {
      if (errno == EINTR)
        continue;
      perror("accept");
      continue;
    }
    handle_client(c);
  }
}
