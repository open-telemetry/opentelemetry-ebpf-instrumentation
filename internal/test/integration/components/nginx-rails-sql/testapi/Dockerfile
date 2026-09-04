FROM ruby:4.0.1@sha256:63630ac659ef391f38632b3eff2527575056c732531bc53f450a2a9d1b1a8b19 AS builder

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

FROM ruby:4.0.1-slim@sha256:939bb2710ba0a49ffdba9470b4e562c9dfc5ee6718ba5a5214d1d421d0414d29

RUN apt-get update && apt-get install -y default-libmysqlclient-dev

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
