# SigmaDesk server image (accounts, node list, user pages, admin console, share links).
# The desktop app is not built here (--no-default-features leaves out the window libraries).
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --no-default-features --bin sigmadesk-server

FROM debian:bookworm-slim
COPY --from=build /src/target/release/sigmadesk-server /usr/local/bin/sigmadesk-server
COPY docker/start-server.sh /usr/local/bin/start-server.sh
RUN chmod +x /usr/local/bin/start-server.sh && mkdir -p /data
VOLUME ["/data"]
EXPOSE 21180
CMD ["/usr/local/bin/start-server.sh"]
