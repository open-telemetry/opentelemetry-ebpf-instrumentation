FROM gcc:14.3.0-trixie@sha256:15923fde7cc441594a4daad0e4b33027c8a53174ffd1b6e38d36789db5ef50d4 AS builder

COPY splice_proxy_t.c .

RUN gcc -pthread -o splice_proxy_t splice_proxy_t.c

FROM node:25.8.1-trixie@sha256:394048fb359d02efc485852ab638cac322a35af228c2cef83d23fc7dd01f4a36

COPY --from=builder /splice_proxy_t proxy
EXPOSE 8080

# Copy the source code into the image for building
COPY app.js .
COPY package-lock.json .
COPY package.json .

COPY run.sh .

# Install dependencies from committed lockfile
RUN npm ci

ENTRYPOINT [ "bash", "/run.sh" ]