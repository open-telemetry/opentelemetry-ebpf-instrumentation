FROM postgres:latest@sha256:feff5b24fedd610975a1f5e743c51a4b360437f4dc3a11acf740dcd708f413f6
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data