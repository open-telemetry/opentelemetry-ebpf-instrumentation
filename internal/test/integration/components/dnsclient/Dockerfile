# Dockerfile that will build a container resolving names in a loop over musl's
# unconnected UDP resolver socket. Alpine is required for musl.
# Docker command must be invoked from the project root directory
FROM python:3.15-alpine@sha256:1afb480ba8d3b3b7a8439a84f2365ce5c75ac45a79cf07daa091b49235cbe27b

WORKDIR /

COPY internal/test/integration/components/dnsclient/dnsclient.py .

USER 0:0

CMD [ "python3", "/dnsclient.py" ]
