FROM mirror.gcr.io/library/debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS builder

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

FROM mirror.gcr.io/library/debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

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
