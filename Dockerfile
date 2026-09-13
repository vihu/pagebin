FROM rust:1-slim-bookworm AS build

WORKDIR /build
ENV SQLX_OFFLINE=true

COPY Cargo.toml Cargo.lock README.md ./
COPY src/ src/
COPY migrations/ migrations/
COPY templates/*.html templates/
COPY static/app.css static/admin.js static/
RUN cargo build --release --locked \
    && install -d -m 0750 -o 65532 -g 65532 /data

FROM debian:bookworm-slim

COPY --from=build /build/target/release/pagebin /pagebin
COPY --from=build --chown=65532:65532 /data /data
COPY LICENSE /usr/share/licenses/pagebin/LICENSE

LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
USER 65532:65532
WORKDIR /
EXPOSE 5050
VOLUME ["/data"]
ENTRYPOINT ["/pagebin"]
