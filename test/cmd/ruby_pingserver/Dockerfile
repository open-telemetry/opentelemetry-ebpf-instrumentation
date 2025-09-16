# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:73e085e58f9496502b0463a787b497b961d946bc1db43c6782c0c3c95281e432
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]