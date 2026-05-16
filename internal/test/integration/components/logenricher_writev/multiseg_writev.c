// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Tiny HTTP server that exercises the logenricher multi-segment iovec path.
// On GET /json_logger it parses the W3C `traceparent` header and emits a JSON
// log line via writev(2) with 3 separate iovec segments. The kernel presents
// this as a single ITER_IOVEC iov_iter to pipe_write, so the BPF logenricher
// must concatenate all segments to reconstruct the line.
//
// On GET /smoke it returns 200 — used by the test harness for readiness.
//
// Build: gcc -O2 -static -o multiseg_writev multiseg_writev.c
// Run:   PORT=8388 ./multiseg_writev

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define LISTEN_PORT_DEFAULT 8388
#define BUF_SIZE 8192

static const char http_200_ok[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
static const char http_404[] =
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

static int extract_trace_id(const char *tp, char out[33]) {
  if (!tp)
    return 0;
  const char *dash = strchr(tp, '-');
  if (!dash)
    return 0;
  const char *trace_start = dash + 1;
  const char *trace_end = strchr(trace_start, '-');
  if (!trace_end)
    return 0;
  size_t n = (size_t)(trace_end - trace_start);
  if (n != 32)
    return 0;
  memcpy(out, trace_start, 32);
  out[32] = '\0';
  return 1;
}

static void parse_request_line(const char *buf, char path[64]) {
  path[0] = '\0';
  while (*buf && *buf != ' ')
    buf++;
  while (*buf == ' ')
    buf++;
  size_t pi = 0;
  while (*buf && *buf != ' ' && *buf != '\r' && *buf != '?' && pi < 63) {
    path[pi++] = *buf++;
  }
  path[pi] = '\0';
}

static const char *find_header(const char *buf, const char *name,
                               size_t *out_len) {
  size_t nlen = strlen(name);
  const char *p = buf;
  while ((p = strstr(p, "\r\n")) != NULL) {
    p += 2;
    if (*p == '\r' || *p == '\0')
      break;
    int matched = 1;
    for (size_t i = 0; i < nlen; i++) {
      if (tolower((unsigned char)p[i]) != tolower((unsigned char)name[i])) {
        matched = 0;
        break;
      }
    }
    if (matched && p[nlen] == ':') {
      const char *v = p + nlen + 1;
      while (*v == ' ' || *v == '\t')
        v++;
      const char *end = strstr(v, "\r\n");
      if (!end)
        return NULL;
      *out_len = (size_t)(end - v);
      return v;
    }
  }
  return NULL;
}

// Split JSON across 3 iovec segments so the kernel iov_iter has nr_segs==3.
// The BPF logenricher must concatenate all segments to capture the full line.
static void emit_multiseg_log(const char *trace_id_or_empty) {
  static const char seg1[] =
      "{\"level\":\"INFO\",\"message\":\"this is a json log via multi-seg "
      "writev\",\"traceparent_seen\":\"";
  static const char seg3[] = "\"}\n";

  struct iovec iov[3];
  iov[0].iov_base = (void *)seg1;
  iov[0].iov_len = sizeof(seg1) - 1;
  iov[1].iov_base = (void *)trace_id_or_empty;
  iov[1].iov_len = strlen(trace_id_or_empty);
  iov[2].iov_base = (void *)seg3;
  iov[2].iov_len = sizeof(seg3) - 1;

  if (writev(STDOUT_FILENO, iov, 3) < 0) {
    perror("writev");
  }
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

  char path[64];
  parse_request_line(buf, path);

  if (strcmp(path, "/smoke") == 0 || strcmp(path, "/json_logger") == 0) {
    if (strcmp(path, "/json_logger") == 0) {
      char trace_id[33] = "";
      size_t tp_len = 0;
      const char *tp = find_header(buf, "traceparent", &tp_len);
      if (tp && tp_len < 200) {
        char tp_buf[256];
        memcpy(tp_buf, tp, tp_len);
        tp_buf[tp_len] = '\0';
        extract_trace_id(tp_buf, trace_id);
      }
      emit_multiseg_log(trace_id);
    }
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
  fprintf(stderr, "multiseg_writev listening on :%d\n", port);
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
