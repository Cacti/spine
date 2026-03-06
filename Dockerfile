# syntax=docker/dockerfile:1
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        make \
        autoconf \
        automake \
        libtool \
        pkg-config \
        libmariadb-dev \
        libsnmp-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN autoreconf -fi \
    && ./configure --prefix=/usr/local \
    && make -j"$(nproc)" spine

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libmariadb3 \
        libsnmp40 \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/spine /usr/local/bin/spine

RUN mkdir -p /etc/spine

ENTRYPOINT ["/usr/local/bin/spine"]
