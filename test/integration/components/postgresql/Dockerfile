FROM postgres:latest@sha256:0f4f20021a065d114083d1b95d9fb89ad847cbc4c3cc9238417815c7df42350f
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data