FROM postgres:latest@sha256:1d288494853e244e7a78d87b3526e650e5221c622f9768ecac9313d0874a9c39
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data