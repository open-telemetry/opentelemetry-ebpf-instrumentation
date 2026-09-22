FROM ruby:4.0.6-slim@sha256:58479f164d5947f852da27a4436c89bb986a811f959c40552bc7f6ccaabcc9c9

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends build-essential libpq-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV BUNDLE_PATH=/usr/local/bundle

COPY internal/test/integration/components/rubytestserver/tapasapi/Gemfile \
     internal/test/integration/components/rubytestserver/tapasapi/Gemfile.lock ./
RUN gem install bundler -v 4.0.16 && bundle _4.0.16_ install

COPY internal/test/integration/components/rubytestserver/tapasapi .

EXPOSE 3040

CMD ["bundle", "exec", "puma", "-b", "tcp://0.0.0.0:3040", "config.ru"]
