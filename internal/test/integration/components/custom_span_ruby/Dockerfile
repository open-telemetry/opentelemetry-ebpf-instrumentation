# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        ruby ruby-dev gcc make libelf-dev git \
    && rm -rf /var/lib/apt/lists/*

# Clone ruby-stapsdt and overlay our arm64-capable libstapsdt fork in place of
# the bundled (x86_64-only) submodule. The gem's extconf.rb compiles whatever
# lives in ext/libstapsdt/ at install time.
RUN git clone --depth 1 https://github.com/rock-core/ruby-stapsdt.git /ruby-stapsdt

COPY internal/test/integration/components/libstapsdt-arm64/ /libstapsdt-fork/

WORKDIR /ruby-stapsdt
# Drop the submodule entry from the index, drop .gitmodules (so the cleared
# path isn't re-resolved as a submodule), then overlay our fork's source.
RUN git config user.email "build@obi.local" && git config user.name "build" \
    && git rm -rf --cached --ignore-unmatch ext/libstapsdt .gitmodules \
    && rm -rf ext/libstapsdt .gitmodules \
    && cp -r /libstapsdt-fork ext/libstapsdt \
    && git add -A ext/libstapsdt \
    && git commit -qm "vendor libstapsdt-arm64 fork" \
    && gem build stapsdt.gemspec \
    && gem install ./stapsdt-*.gem

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

RUN apt-get update && apt-get install -y --no-install-recommends \
        ruby libelf1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /var/lib/gems /var/lib/gems
COPY --from=builder /usr/lib/ruby /usr/lib/ruby

COPY internal/test/integration/components/custom_span_ruby/app.rb /app.rb
EXPOSE 8393
ENTRYPOINT ["ruby", "/app.rb"]
