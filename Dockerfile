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
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/spine /usr/local/bin/spine

RUN mkdir -p /etc/spine

ENTRYPOINT ["/usr/local/bin/spine"]
