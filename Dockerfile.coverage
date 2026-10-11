# Single stage: the .gcda files land beside the objects, so /src must survive
# into the running container.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
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
