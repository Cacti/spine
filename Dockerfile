# syntax=docker/dockerfile:1
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        cmake \
        ninja-build \
        pkg-config \
        libmariadb-dev \
        libsnmp-dev \
        libssl-dev \
        libseccomp-dev \
        libuv1-dev \
        libc-ares-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -G Ninja -S . -B build \
        -DSPINE_BUILD_MAIN=ON \
        -DBUILD_TESTING=OFF \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build build \
    && cmake --install build

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libmariadb3 \
        libsnmp40 \
        libssl3 \
        libuv1 \
        libseccomp2 \
        libcares2 \
        zlib1g \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r spine && useradd -r -g spine -s /sbin/nologin spine \
    && mkdir -p /etc/spine && chown -R spine:spine /etc/spine

COPY --from=builder /usr/local/bin/spine /usr/local/bin/spine
COPY etc/spine.conf.dist /etc/spine/spine.conf

USER spine
ENTRYPOINT ["/usr/local/bin/spine"]
CMD ["--help"]

LABEL org.opencontainers.image.title="spine" \
      org.opencontainers.image.description="High-speed poller for Cacti" \
      org.opencontainers.image.source="https://github.com/Cacti/spine" \
      org.opencontainers.image.licenses="GPL-2.0-or-later"
