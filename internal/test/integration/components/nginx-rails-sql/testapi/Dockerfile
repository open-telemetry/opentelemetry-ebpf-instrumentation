FROM ruby:3.4.8@sha256:998b24b17d0e8ac2a9974c11052cba9bb46f8ba519169969492181f262d27a58 AS builder

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

FROM ruby:3.4.8-slim@sha256:ff7780d9fc05a54690c722ee0621bae2aa818331be88ebbeb0f5e7bd7cdb7f37

RUN apt-get update && apt-get install -y default-libmysqlclient-dev

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
