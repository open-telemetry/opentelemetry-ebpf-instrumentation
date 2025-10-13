# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:8b60ef1d4853e1ecb76884e5f978a7c2c0e8de21daee36dd2038dff4d7447a7d
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]