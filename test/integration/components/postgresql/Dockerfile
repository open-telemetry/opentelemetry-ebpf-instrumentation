FROM postgres:latest@sha256:ad98a3ba6a3b5e53e9bd95afed6930d3103efc890240643a168b590bcf2e6e81
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data