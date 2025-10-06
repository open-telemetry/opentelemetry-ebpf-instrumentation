FROM postgres:latest@sha256:073e7c8b84e2197f94c8083634640ab37105effe1bc853ca4d5fbece3219b0e8
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data