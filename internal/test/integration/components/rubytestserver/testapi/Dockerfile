FROM ruby:3.4.7@sha256:5d96773450828d4add543e3b48d70202a9f5c7ac28025f09ba5becb77076a9fc AS builder

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

FROM ruby:3.4.7-slim@sha256:d3cc2ade22dd18f9ad2260170b8d1566160345dc9351cca9e7984a2f3774f790

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the node app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
