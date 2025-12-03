# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:cff944ca9f1398116ca31573b65a9f4e2e71336701f9229cb24a2e023e477a00
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]