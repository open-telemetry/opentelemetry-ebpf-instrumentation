# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:5d96773450828d4add543e3b48d70202a9f5c7ac28025f09ba5becb77076a9fc
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]