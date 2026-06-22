FROM ruby:4.0.5@sha256:d07ce5b3f4dc2246980d6d5bcd1e9e54ea62445b2b531ea1819112c69bf29d36 AS builder

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY . .

RUN apt-get update && apt-get install -y default-libmysqlclient-dev

# Install Rails 
RUN gem install rails
RUN gem install bundler rails
RUN bundle install

EXPOSE 3040

FROM ruby:4.0.5-slim@sha256:3d2d07ec3c267107a2a253327c108c1e5b74ea84cfa5ab125f127beb86dccd86

RUN apt-get update && apt-get install -y default-libmysqlclient-dev

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
