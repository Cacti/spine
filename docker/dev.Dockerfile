# +-------------------------------------------------------------------------+
# | Copyright (C) 2004-2024 The Cacti Group                                 |
# +-------------------------------------------------------------------------+
# | Development/verification image — NOT for production use.               |
# | Builds with ASan + full static analysis tooling.                       |
# +-------------------------------------------------------------------------+

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    automake \
    libtool \
    dos2unix \
    help2man \
    libmariadb-dev \
    libsnmp-dev \
    libssl-dev \
    zlib1g-dev \
    cppcheck \
    clang-tools \
    valgrind \
    gdb \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .

# ASan build: catches heap/stack overflows and use-after-free at runtime.
# -fno-omit-frame-pointer gives usable stack traces under valgrind/gdb.
RUN ./bootstrap \
  && CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -Wall -Wextra" \
     ./configure --enable-warnings \
  && make -j"$(nproc)"

COPY scripts/verify.sh /usr/local/bin/verify.sh
RUN chmod +x /usr/local/bin/verify.sh

CMD ["/usr/local/bin/verify.sh"]
