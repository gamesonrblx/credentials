FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p credentials-gateway -p credentials-injector

FROM debian:bookworm-slim
RUN useradd --create-home --uid 10001 credentials
COPY --from=build /src/target/release/credentials-gateway /usr/local/bin/credentials-gateway
COPY --from=build /src/target/release/credentials-injector /usr/local/bin/credentials-injector
USER credentials
EXPOSE 8080
ENTRYPOINT ["credentials-gateway"]
