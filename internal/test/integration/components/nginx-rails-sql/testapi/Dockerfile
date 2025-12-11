FROM ruby:3.0.2@sha256:15dd21ae353c5f4faebed038d9d131c47b9fd84c14be8c3cfbc750204b63f009 AS builder

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

FROM ruby:3.0.2-slim@sha256:9c4076bcc90de736bca3419299cf7b5e5ce0c83d659bad4c1f88a1ad8ca6dbf4

RUN apt-get update && apt-get install -y default-libmysqlclient-dev

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
