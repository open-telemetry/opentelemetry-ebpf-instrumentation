# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:dc2c036bad26999117e3b3872f30fa327d7f6830bc120f15ad639d61499f5ef8
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]