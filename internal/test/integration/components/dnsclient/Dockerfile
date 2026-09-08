# Dockerfile that will build a container resolving names in a loop over musl's
# unconnected UDP resolver socket. Alpine is required for musl.
# Docker command must be invoked from the project root directory
FROM python:3.14-alpine@sha256:a1321512d6a287428c50dcdf2ab3857761127e03a23b1f648e9c1c0de59288f8

WORKDIR /

COPY internal/test/integration/components/dnsclient/dnsclient.py .

USER 0:0

CMD [ "python3", "/dnsclient.py" ]
