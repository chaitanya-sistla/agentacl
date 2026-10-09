# The AgentACL fleet server. Build from the repository root:
#   docker build -f deploy/fleet/Dockerfile -t agentacl-server .
FROM rust:1.85-slim-bookworm AS build
WORKDIR /src
# The image's own toolchain, not the repository's pinned one (which would be
# downloaded with its macOS targets on every build).
ENV RUSTUP_TOOLCHAIN=1.85
COPY . .
RUN cargo build --release --locked -p agentacl-server

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin agentacl \
 && mkdir -p /data && chown agentacl /data
COPY --from=build /src/target/release/agentacl-server /usr/local/bin/agentacl-server
USER agentacl
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/agentacl-server"]
CMD ["serve", "--db", "/data/agentacl-server.db", "--listen", "0.0.0.0:8080"]
