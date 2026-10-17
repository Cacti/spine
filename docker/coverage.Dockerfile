# Single stage: the .gcda files land beside the objects, so /src must survive
# into the running container.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make autoconf automake libtool pkg-config \
        libmariadb-dev libsnmp-dev libssl-dev gcovr \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN autoreconf -fi \
    && ./configure CFLAGS="-fprofile-arcs -ftest-coverage -O0 -g" LDFLAGS="-fprofile-arcs" \
    && make -j"$(nproc)" spine
ENTRYPOINT ["/src/spine"]
