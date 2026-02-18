FROM postgres:latest@sha256:b6b4d0b75c699a2c94dfc5a94fe09f38630f3b67ab0e1653ede1b7ac8e13c197
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data