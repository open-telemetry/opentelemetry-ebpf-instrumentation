// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

enum {
  max_request = 1024 * 1024,
  partial_body = 2048,
  retry_body = 256 * 1024
};
static const char response[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n";
static const char existing[] =
    "00-11111111111111111111111111111111-2222222222222222-01";
static const char *const cases[] = {"classic",  "extended", "extended2",
                                    "readonly", "existing", "fragmented",
                                    "opaque",   "partial",  "retry"};
typedef int (*write_ex2_fn)(SSL *, const void *, size_t, uint64_t, size_t *);

static void check(bool ok, const char *what) {
  if (!ok) {
    fprintf(stderr, "fixture: %s (errno=%d)\n", what, errno);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}

static void command(const char *expected) {
  char line[32];
  check(fgets(line, sizeof(line), stdin) && strcmp(line, expected) == 0,
        "controller command");
}

static int listener(uint16_t *port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  check(fd >= 0, "socket");
  struct sockaddr_in address = {.sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  check(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0, "bind");
  check(listen(fd, 1) == 0, "listen");
  socklen_t length = sizeof(address);
  check(getsockname(fd, (struct sockaddr *)&address, &length) == 0,
        "getsockname");
  *port = ntohs(address.sin_port);
  return fd;
}

static void timeout(int fd) {
  const struct timeval limit = {.tv_sec = 15};
  check(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)) == 0,
        "receive timeout");
  check(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit)) == 0,
        "send timeout");
}

static void peer(const char *certificate, const char *key) {
  SSL_CTX *context = SSL_CTX_new(TLS_server_method());
  check(context != NULL, "server context");
  check(SSL_CTX_use_certificate_file(context, certificate, SSL_FILETYPE_PEM) ==
            1,
        "certificate");
  check(SSL_CTX_use_PrivateKey_file(context, key, SSL_FILETYPE_PEM) == 1,
        "key");
  uint16_t port;
  const int incoming = listener(&port);
  printf("{\"port\":%u}\n", port);
  command("start\n");
  const int fd = accept(incoming, NULL, NULL);
  check(fd >= 0, "accept");
  timeout(fd);
  SSL *ssl = SSL_new(context);
  check(ssl != NULL && SSL_set_fd(ssl, fd) == 1 && SSL_accept(ssl) == 1,
        "server handshake");
  unsigned char *buffer = malloc(max_request + 1);
  check(buffer != NULL, "peer buffer");
  const bool has_ex2 = dlsym(RTLD_DEFAULT, "SSL_write_ex2") != NULL;
  const size_t case_count = sizeof(cases) / sizeof(cases[0]);
  for (size_t index = 0; index < case_count; index++) {
    if (!has_ex2 && strcmp(cases[index], "extended2") == 0) {
      continue;
    }
    if (strcmp(cases[index], "retry") == 0) {
      const struct timespec delay = {.tv_nsec = 750000000};
      nanosleep(&delay, NULL);
    }
    size_t used = 0;
    size_t total = 0;
    while (total == 0 || used < total) {
      check(used < max_request, "request bound");
      const int count = SSL_read(ssl, buffer + used, (int)(max_request - used));
      check(count > 0, "peer SSL_read");
      used += (size_t)count;
      buffer[used] = 0;
      unsigned char *end = memmem(buffer, used, "\r\n\r\n", 4);
      if (end != NULL && total == 0) {
        const unsigned char *length =
            memmem(buffer, (size_t)(end - buffer), "Content-Length: ", 16);
        total = (size_t)(end - buffer) + 4;
        if (length != NULL) {
          total += strtoul((const char *)length + 16, NULL, 10);
        }
        check(total <= max_request, "body bound");
      }
    }
    check(used == total, "unexpected pipelining");
    printf("{\"case\":\"%s\",\"request\":\"", cases[index]);
    for (size_t i = 0; i < used; i++) {
      printf("%02x", buffer[i]);
    }
    printf("\"}\n");
    check(SSL_write(ssl, response, sizeof(response) - 1) ==
              sizeof(response) - 1,
          "peer response");
  }
  command("stop\n");
  free(buffer);
  SSL_free(ssl);
  SSL_CTX_free(context);
  close(fd);
  close(incoming);
}

static void client(uint16_t port, const char *certificate) {
  SSL_CTX *context = SSL_CTX_new(TLS_client_method());
  check(context != NULL, "client context");
  check(SSL_CTX_load_verify_locations(context, certificate, NULL) == 1,
        "client CA");
  SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  check(fd >= 0, "client socket");
  timeout(fd);
  const struct sockaddr_in address = {.sin_family = AF_INET,
                                      .sin_port = htons(port),
                                      .sin_addr.s_addr =
                                          htonl(INADDR_LOOPBACK)};
  check(connect(fd, (const struct sockaddr *)&address, sizeof(address)) == 0,
        "connect");
  uint16_t incoming_port;
  const int incoming = listener(&incoming_port);
  SSL *ssl = SSL_new(context);
  check(ssl != NULL && SSL_set_fd(ssl, fd) == 1 &&
            SSL_set1_host(ssl, "localhost") == 1,
        "client SSL setup");
  printf("{\"pid\":%d,\"incoming_port\":%u}\n", getpid(), incoming_port);
  command("start\n");
  const int upstream = accept(incoming, NULL, NULL);
  check(upstream >= 0, "upstream accept");
  timeout(upstream);
  char input[4096] = {0};
  size_t upstream_used = 0;
  while (strstr(input, "\r\n\r\n") == NULL) {
    const ssize_t count = read(upstream, input + upstream_used,
                               sizeof(input) - upstream_used - 1);
    check(count > 0, "upstream read");
    upstream_used += (size_t)count;
  }
  check(strncmp(input, "GET /upstream HTTP/1.1\r\n", 24) == 0,
        "upstream request");
  check(SSL_connect(ssl) == 1, "client handshake");
  const int original_flags = fcntl(fd, F_GETFL);
  check(original_flags >= 0 &&
            fcntl(fd, F_SETFL, original_flags | O_NONBLOCK) == 0,
        "nonblocking read setup");
  size_t read_count = 12345;
  int result = SSL_read_ex(ssl, input, sizeof(input), &read_count);
  check(result == 0 && SSL_get_error(ssl, result) == SSL_ERROR_WANT_READ,
        "initial WANT_READ");
  check(fcntl(fd, F_SETFL, original_flags) == 0, "restore blocking");
  write_ex2_fn write_ex2 = (write_ex2_fn)dlsym(RTLD_DEFAULT, "SSL_write_ex2");
  const size_t case_count = sizeof(cases) / sizeof(cases[0]);
  unsigned int retries = 0;
  for (size_t index = 0; index < case_count; index++) {
    const char *name = cases[index];
    if (write_ex2 == NULL && strcmp(name, "extended2") == 0) {
      continue;
    }
    const bool partial = strcmp(name, "partial") == 0;
    const bool retry = strcmp(name, "retry") == 0;
    size_t body = 0;
    if (partial) {
      body = partial_body;
    } else if (retry) {
      body = retry_body;
    }
    const size_t capacity = max_request;
    unsigned char *memory = mmap(NULL, capacity, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(memory != MAP_FAILED, "client mapping");
    int header = snprintf(
        (char *)memory, capacity,
        "GET /probe HTTP/1.1\r\nHost: localhost\r\nX-Case: %s\r\n", name);
    check(header > 0, "request headers");
    if (strcmp(name, "existing") == 0) {
      header += snprintf((char *)memory + header, capacity - (size_t)header,
                         "traceparent: %s\r\n", existing);
    }
    if (body != 0) {
      header += snprintf((char *)memory + header, capacity - (size_t)header,
                         "Content-Length: %zu\r\n", body);
    }
    memcpy(memory + header, "\r\n", 2);
    header += 2;
    memset(memory + header, retry ? 'r' : 'p', body);
    size_t length = (size_t)header + body;
    if (strcmp(name, "opaque") == 0) {
      static const unsigned char opaque[] = "\0OBI\1\r\nX-Case: opaque\r\n\r\n";
      length = sizeof(opaque) - 1;
      memcpy(memory, opaque, length);
    }
    unsigned char *expected = malloc(length);
    check(expected != NULL, "expected bytes");
    memcpy(expected, memory, length);
    if (partial) {
      check((SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE) &
             SSL_MODE_ENABLE_PARTIAL_WRITE) != 0,
            "partial mode");
      check(SSL_set_max_send_fragment(ssl, 512) == 1, "fragment size");
    }
    if (retry) {
      SSL_clear_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
      check((SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER) &
             SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER) != 0,
            "moving mode");
      const int send_buffer = 4096;
      check(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer,
                       sizeof(send_buffer)) == 0,
            "send buffer");
      check(fcntl(fd, F_SETFL, original_flags | O_NONBLOCK) == 0,
            "nonblocking write setup");
    }
    if (strcmp(name, "readonly") == 0) {
      check(mprotect(memory, capacity, PROT_READ) == 0, "readonly mapping");
    }
    size_t sent = 0;
    unsigned char *moving = NULL;
    while (sent < length) {
      size_t requested = length - sent;
      if (strcmp(name, "fragmented") == 0 && sent == 0) {
        requested = 5;
      }
      const void *buffer = moving != NULL ? moving : memory + sent;
      size_t transferred = 0;
      if (strcmp(name, "classic") == 0) {
        result = SSL_write(ssl, buffer, (int)requested);
        if (result > 0) {
          transferred = (size_t)result;
        }
      } else if (strcmp(name, "extended2") == 0) {
        result = write_ex2(ssl, buffer, requested, 0, &transferred);
      } else {
        result = SSL_write_ex(ssl, buffer, requested, &transferred);
      }
      if (result <= 0) {
        const int error = SSL_get_error(ssl, result);
        check(retry && (error == SSL_ERROR_WANT_READ ||
                        error == SSL_ERROR_WANT_WRITE),
              "write error");
        if (retries++ == 0) {
          puts("{\"event\":\"retry pending\"}");
        }
        unsigned char *next = malloc(requested);
        check(next != NULL, "moving retry buffer");
        memcpy(next, memory + sent, requested);
        free(moving);
        moving = next;
        struct pollfd waiting = {
            .fd = fd,
            .events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT};
        check(poll(&waiting, 1, 50) >= 0, "retry poll");
        continue;
      }
      free(moving);
      moving = NULL;
      check(transferred > 0 && transferred <= requested, "caller byte count");
      sent += transferred;
      if (partial && sent == transferred) {
        check(sent >= (size_t)header && sent < length, "partial header count");
        memset(memory + sent, 'q', length - sent);
        memset(expected + sent, 'q', length - sent);
        printf("{\"partial_prefix\":%zu}\n", sent - (size_t)header);
      }
    }
    check(memcmp(memory, expected, length) == 0, "original input changed");
    check(mprotect(memory, capacity, PROT_READ | PROT_WRITE) == 0,
          "mapping restore");
    free(expected);
    check(munmap(memory, capacity) == 0, "mapping release");
    check(fcntl(fd, F_SETFL, original_flags) == 0, "blocking response setup");
    size_t used = 0;
    while (used < sizeof(response) - 1) {
      const size_t requested = strcmp(name, "classic") == 0 ? 7 : 11;
      if (strcmp(name, "classic") == 0) {
        result = SSL_read(ssl, input + used, (int)requested);
        check(result > 0, "classic response");
        read_count = (size_t)result;
      } else {
        check(SSL_read_ex(ssl, input + used, requested, &read_count) == 1,
              "extended response");
      }
      used += read_count;
    }
    check(used == sizeof(response) - 1 && memcmp(input, response, used) == 0,
          "response bytes");
  }
  check(retries > 0, "retry path not exercised");
  check(write(upstream, response, sizeof(response) - 1) == sizeof(response) - 1,
        "upstream response");
  printf("{\"event\":\"passed\",\"cases\":%zu,\"retries\":%u}\n",
         case_count - (write_ex2 == NULL ? 1 : 0), retries);
  command("stop\n");
  SSL_free(ssl);
  SSL_CTX_free(context);
  close(upstream);
  close(incoming);
  close(fd);
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  alarm(180);
  check(argc == 4,
        "usage: native-fixture --peer CERT KEY | --client PORT CERT");
  if (strcmp(argv[1], "--peer") == 0) {
    peer(argv[2], argv[3]);
  } else {
    check(strcmp(argv[1], "--client") == 0, "unknown fixture mode");
    const unsigned long port = strtoul(argv[2], NULL, 10);
    check(port > 0 && port <= UINT16_MAX, "port");
    client((uint16_t)port, argv[3]);
  }
  return EXIT_SUCCESS;
}
