FROM postgres:latest@sha256:23624e87b1f831cdadd264e9c15fb1fdbf0c5549ff5a1e37ec9ec524389fb4ff
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data