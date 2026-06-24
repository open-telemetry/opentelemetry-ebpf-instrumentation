FROM ruby:4.0.5@sha256:07ac0966b795b2e1515ba5dc31eb70eb9841620c747a36ba8d048cd6b38163c6 AS builder

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

FROM ruby:4.0.5-slim@sha256:2726c400123eedf50d49696f27bcb01e90758ebd2a8e3bc73b9f18f75f3b87f5

RUN apt-get update && apt-get install -y default-libmysqlclient-dev

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
