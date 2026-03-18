// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Simple HTTP proxy that uses splice(2) to forward responses zero-copy,
// mirroring how docker-proxy uses do_splice in the kernel trace.
//
// Listens on :8080, accepts HTTP clients, and for every request issues
// GET /smoke HTTP/1.1 to localhost:3030, then splices the response back
// through a kernel pipe to the client without copying data to userspace.
//
// Build:  gcc -pthread -o splice_proxy_t splice_proxy_t.c
// Run:    DOWNSTREAM_HOST=localhost DOWNSTREAM_PORT=3030 ./splice_proxy_t

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LISTEN_PORT 8080
#define DOWNSTREAM_PATH "/smoke"
#define SPLICE_CHUNK (64 * 1024)

// Global downstream configuration (set from environment in main).
static const char *downstream_host = "127.0.0.1";
static int downstream_port = 3030;

// Connect to the downstream service.
static int connect_downstream(void) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    return -1;
  }

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(downstream_port),
      .sin_addr.s_addr = inet_addr(downstream_host),
  };
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("connect downstream");
    close(fd);
    return -1;
  }
  return fd;
}

// Drain HTTP request headers from the client socket (we always proxy to
// /smoke).
static int drain_request(int client_fd) {
  char buf[8192];
  int total = 0;

  while (total < (int)sizeof(buf) - 1) {
    ssize_t n = recv(client_fd, buf + total, sizeof(buf) - 1 - total, 0);
    if (n <= 0)
      return -1;
    total += (int)n;
    buf[total] = '\0';
    if (strstr(buf, "\r\n\r\n"))
      return 0; // all headers received
  }
  return -1; // headers too large
}

// Core of the proxy: send a fixed GET to downstream, then splice its response
// back to the client through a kernel pipe (no userspace copy of the body).
//
//   downstream_fd splice --> pipe[1]
//                 pipe[0] splice --> client_fd
//
static void proxy_request(int client_fd) {
  int downstream_fd = connect_downstream();
  if (downstream_fd < 0) {
    const char *err = "HTTP/1.1 502 Bad Gateway\r\n"
                      "Content-Length: 0\r\n"
                      "Connection: close\r\n\r\n";
    write(client_fd, err, strlen(err));
    return;
  }

  // Issue the downstream request with a regular write - only the response
  // path uses splice, matching what docker-proxy does (splice_to_socket).
  char req[512];
  int req_len = snprintf(req, sizeof(req),
                         "GET %s HTTP/1.1\r\n"
                         "Host: %s:%d\r\n"
                         "Connection: close\r\n"
                         "\r\n",
                         DOWNSTREAM_PATH, downstream_host, downstream_port);
  if (write(downstream_fd, req, req_len) < 0) {
    perror("write downstream");
    goto out;
  }

  // Create the pipe that sits between downstream and client.
  int pfd[2];
  if (pipe(pfd) < 0) {
    perror("pipe");
    goto out;
  }

  // Splice loop: move data from downstream socket into the pipe, then move
  // it out of the pipe into the client socket.  Neither hop touches
  // userspace memory for the payload bytes.
  for (;;) {
    // Phase 1: downstream socket → pipe write-end
    ssize_t spliced = splice(downstream_fd, NULL, pfd[1], NULL, SPLICE_CHUNK,
                             SPLICE_F_MOVE | SPLICE_F_MORE);
    if (spliced == 0)
      break; // downstream closed / EOF
    if (spliced < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        break;
      perror("splice downstream→pipe");
      break;
    }

    // Phase 2: pipe read-end → client socket (loop until all bytes sent)
    ssize_t remaining = spliced;
    while (remaining > 0) {
      ssize_t sent = splice(pfd[0], NULL, client_fd, NULL, (size_t)remaining,
                            SPLICE_F_MOVE);
      if (sent <= 0) {
        if (sent < 0)
          perror("splice pipe→client");
        goto close_pipe;
      }
      remaining -= sent;
    }
  }

close_pipe:
  close(pfd[0]);
  close(pfd[1]);
out:
  close(downstream_fd);
}

static void handle_client(int client_fd) {
  if (drain_request(client_fd) < 0)
    return;
  proxy_request(client_fd);
}

// Thread argument structure.
struct thread_arg {
  int client_fd;
  struct sockaddr_in peer;
};

// Thread entry point for handling a client connection.
static void *client_thread(void *arg) {
  struct thread_arg *targ = (struct thread_arg *)arg;
  int client_fd = targ->client_fd;

  printf("connection from %s:%d\n", inet_ntoa(targ->peer.sin_addr),
         ntohs(targ->peer.sin_port));

  free(targ);

  handle_client(client_fd);
  close(client_fd);
  return NULL;
}

int main(void) {
  // Read downstream configuration from environment.
  const char *env_host = getenv("DOWNSTREAM_HOST");
  if (env_host)
    downstream_host = env_host;

  const char *env_port = getenv("DOWNSTREAM_PORT");
  if (env_port)
    downstream_port = atoi(env_port);

  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    perror("socket");
    return 1;
  }

  int opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(LISTEN_PORT),
      .sin_addr.s_addr = INADDR_ANY,
  };
  if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return 1;
  }
  if (listen(server_fd, 128) < 0) {
    perror("listen");
    return 1;
  }

  printf("splice_proxy listening on :%d  ->  %s:%d%s\n", LISTEN_PORT,
         downstream_host, downstream_port, DOWNSTREAM_PATH);

  for (;;) {
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    int client_fd = accept(server_fd, (struct sockaddr *)&peer, &peer_len);
    if (client_fd < 0) {
      perror("accept");
      continue;
    }

    // Allocate thread argument (freed by the thread).
    struct thread_arg *targ = malloc(sizeof(*targ));
    if (!targ) {
      perror("malloc");
      close(client_fd);
      continue;
    }
    targ->client_fd = client_fd;
    targ->peer = peer;

    pthread_t tid;
    if (pthread_create(&tid, NULL, client_thread, targ) != 0) {
      perror("pthread_create");
      free(targ);
      close(client_fd);
      continue;
    }
    // Detach thread so resources are freed automatically when it exits.
    pthread_detach(tid);
  }
}
