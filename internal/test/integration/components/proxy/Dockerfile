FROM gcc:14.4.0-trixie@sha256:df8990c2f53aa9ef57808e755aa8f580dd86b9b34c6233715de23e89f7e06b65 AS builder

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