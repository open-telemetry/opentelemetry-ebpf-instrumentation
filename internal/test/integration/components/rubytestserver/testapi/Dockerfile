FROM ruby:3.4.8@sha256:998b24b17d0e8ac2a9974c11052cba9bb46f8ba519169969492181f262d27a58 AS builder

# Set the working directory to /build
WORKDIR /build

ENV BUNDLE_PATH=/usr/local/bundle

# Copy the source code into the image for building
COPY internal/test/integration/components/rubytestserver/testapi .

RUN gem update --system
RUN gem install bundler -v 4.0.7
RUN bundle install
RUN bundle binstubs railties
RUN bundle exec rake db:migrate

FROM ruby:3.4.8-slim@sha256:ff7780d9fc05a54690c722ee0621bae2aa818331be88ebbeb0f5e7bd7cdb7f37

RUN gem update --system

WORKDIR /build

ENV BUNDLE_PATH=/usr/local/bundle

COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

EXPOSE 3040

# Run the node app
CMD [ "bundle", "exec", "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
