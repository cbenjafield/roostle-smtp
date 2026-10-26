FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/roostle-smtp /usr/local/bin/roostle-smtp
# Ports 25 and 587 are privileged; bind them via the container runtime or run as root.
EXPOSE 25 587 2525
ENTRYPOINT ["roostle-smtp"]
