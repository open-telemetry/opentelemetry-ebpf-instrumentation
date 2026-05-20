FROM ruby:4.0.4@sha256:8b9d39df3e5a2e6b8a488fd07e58d9589ab8fbce79afdabf8b141eb359eafeea AS builder

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

FROM ruby:4.0.4-slim@sha256:2f6614b6d259073d02a4c5ae3b42244fe791efec6536678777c8167cfc26bb79

RUN apt-get update && apt-get install -y default-libmysqlclient-dev

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
