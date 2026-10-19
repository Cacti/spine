FROM mirror.gcr.io/library/debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS builder

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

FROM mirror.gcr.io/library/debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update && apt-get install -y --no-install-recommends \
        libmariadb3 \
        libsnmp40 \
        libssl3 \
        php-cli \
        procps \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/spine /usr/local/bin/spine

RUN mkdir -p /etc/spine

ENTRYPOINT ["/usr/local/bin/spine"]
