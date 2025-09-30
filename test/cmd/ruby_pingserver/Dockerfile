# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:2b2a9024cd72c6ed415f25330a08d921af02ece06dbc310eef220b626ad97d89
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]