FROM ruby:3.4.8@sha256:a02a5f7b2412b75ac6ad4f14b253a33d59626b110b3e3d151cf6b1ddf86bb2cc AS builder

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

FROM ruby:3.4.8-slim@sha256:dcc535e858eeeac1f70eaf8c39ef7ee257b183a9e495cc5a9ef3e340eadf2d3d

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the node app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
