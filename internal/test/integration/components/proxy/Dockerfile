FROM gcc:16.1.0-trixie@sha256:af4cbf4b5789035f6fad5221e1c3e2dc5c2a419b32c83640c6ef27b4af4a5854 AS builder

COPY splice_proxy_t.c .

RUN gcc -pthread -o splice_proxy_t splice_proxy_t.c

FROM node:25.9.0-trixie@sha256:74ff139f927c4a233bf0757edefe1ee057d185d6548c65d2741bdda68660fb6a

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