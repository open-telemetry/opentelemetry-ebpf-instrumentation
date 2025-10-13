# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:2de78cfbe28d99ee29c7a6b6d313617619d7fce68ed22337609f31a50cffc407
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]