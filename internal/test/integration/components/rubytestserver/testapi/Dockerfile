FROM ruby:3.4.7@sha256:cff944ca9f1398116ca31573b65a9f4e2e71336701f9229cb24a2e023e477a00 AS builder

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/rubytestserver/testapi .

# Install Rails 
RUN gem install rails
RUN gem install bundler
RUN bundle install
RUN bundle exec rake app:update:bin
RUN bin/rails db:migrate

EXPOSE 3040

FROM ruby:3.4.7-slim@sha256:c1bc8f6bc1075857b9138a600b59127f5570a494e84e80725ea276812465e24e

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the node app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
