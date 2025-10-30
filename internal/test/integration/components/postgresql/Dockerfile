FROM postgres:latest@sha256:78f1aed6e8c0185d3c6963c8343dd018c63e8ba5ebd78c159c7c772a05e75b30
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data