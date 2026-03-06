FROM postgres:latest@sha256:69e8582b781cb44fa4557b98ed586fe68361e320d9b12f9707494335634f4f3d
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data