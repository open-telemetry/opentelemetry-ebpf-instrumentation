FROM postgres:latest@sha256:e1dc516c05e74a525757c079668f5de53855f5611b3971a6491586f2ffe05db7
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data