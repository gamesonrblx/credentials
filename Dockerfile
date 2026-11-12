FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p credentials-gateway -p credentials-injector

FROM debian:bookworm-slim
# The upstream HTTPS client verifies against the system trust store.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# The data directory exists before VOLUME so a new named volume starts out
# owned by the runtime user instead of root.
RUN useradd --create-home --uid 10001 credentials \
    && install -d -o 10001 -g 10001 -m 0700 /var/credentials /var/injector
COPY --from=build /src/target/release/credentials-gateway /usr/local/bin/credentials-gateway
COPY --from=build /src/target/release/credentials-injector /usr/local/bin/credentials-injector
USER credentials
VOLUME ["/var/credentials"]
EXPOSE 8443
ENTRYPOINT ["credentials-gateway"]
