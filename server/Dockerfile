FROM rust:1-bookworm AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install --yes --no-install-recommends make perl \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src

ENV CARGO_PROFILE_RELEASE_STRIP=symbols
RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home autharo

COPY --from=builder /build/target/release/authserver /usr/local/bin/authserver

USER autharo
EXPOSE 10000

ENTRYPOINT ["/usr/local/bin/authserver"]
