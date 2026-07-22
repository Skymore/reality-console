FROM rust:1.88-bookworm AS builder

WORKDIR /source
ENV CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR=/source/target/cargo
COPY . .
RUN cargo build --release --locked --manifest-path node-host/Cargo.toml --bin node-host

FROM debian:bookworm-slim AS xray

ARG TARGETARCH
ARG XRAY_VERSION=26.3.27
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
RUN case "$TARGETARCH" in \
      amd64) archive=Xray-linux-64.zip; archive_sha=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae; binary_sha=8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed ;; \
      arm64) archive=Xray-linux-arm64-v8a.zip; archive_sha=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c; binary_sha=c2d20a7045250497083afea0d79db0672f6c89a25aaaf37c92de034d6b764b04 ;; \
      *) echo "unsupported Docker target architecture: $TARGETARCH" >&2; exit 64 ;; \
    esac \
    && curl --fail --location --retry 3 --output /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/${archive}" \
    && echo "${archive_sha}  /tmp/xray.zip" | sha256sum --check --strict \
    && unzip -p /tmp/xray.zip xray > /xray \
    && echo "${binary_sha}  /xray" | sha256sum --check --strict \
    && chmod 0755 /xray \
    && printf '%s\n' "$binary_sha" > /xray.sha256

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 private-network \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin private-network \
    && install -d -m 0700 -o 10001 -g 10001 /var/lib/private-network-node
COPY --from=builder /source/target/cargo/release/node-host /opt/private-network/node-host
COPY --from=xray /xray /opt/private-network/xray
COPY --from=xray /xray.sha256 /opt/private-network/xray.sha256
COPY deploy/docker/node-host/entrypoint.sh /usr/local/bin/private-network-node
RUN chmod 0755 /opt/private-network/node-host /opt/private-network/xray /usr/local/bin/private-network-node

USER 10001:10001
VOLUME ["/var/lib/private-network-node"]
EXPOSE 443/tcp
ENTRYPOINT ["/usr/local/bin/private-network-node"]
CMD ["run"]
