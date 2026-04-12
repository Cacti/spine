# Spine: a poller for Cacti

Spine is a high speed poller replacement for `cmd.php`. It is almost 100%
compatible with the legacy cmd.php processor and provides much more flexibility,
speed and concurrency than `cmd.php`.

Make sure that you have the proper development environment to compile Spine.
This includes a C compiler, CMake, Ninja, and the required dependency headers.
If you have questions please consult the forums and/or online documentation.

-----------------------------------------------------------------------------

## Platform Support

Spine is tested across Linux, macOS, and Windows, but the support level is not
identical on every platform.

| Platform | Build Status | Runtime Status | Notes |
| --- | --- | --- | --- |
| Linux | Full | Full | Primary production target. Native CMake builds and tests are exercised in CI. |
| macOS | Full | Full | CMake main-build coverage is exercised in CI. Linux still has broader ecosystem and integration coverage. |
| FreeBSD | Full | Full | CMake build and CTest smoke coverage are exercised via CI VM runs. |
| Windows | Partial | Partial | MSYS2/MinGW-native smoke coverage is exercised in CI. Full binary/runtime support still depends on a complete Windows Net-SNMP toolchain path. |

## Unix Installation

These instructions assume the default install location for spine of
`/usr/local/spine`. If you choose to use another prefix, make sure you update
the commands as required for that new path.

To compile and install Spine with the default options:

```shell
cmake -G Ninja -S . -B build -DSPINE_BUILD_MAIN=ON
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build
chown root:root /usr/local/spine/bin/spine
chmod u+s /usr/local/spine/bin/spine
```

To install under a non-default prefix, pass
`-DCMAKE_INSTALL_PREFIX=/your/prefix` to the configure step above.

## FreeBSD Development

1. Install dependencies:

   ```shell
   pkg install -y cmake ninja pkgconf mysql80-client net-snmp openssl
   ```

2. Configure/build/test:

   ```shell
   cmake -G Ninja -S . -B build -DSPINE_BUILD_MAIN=ON
   cmake --build build
   ctest --test-dir build --output-on-failure
   ```

## Windows Development

Windows development targets a native MSYS2/MinGW toolchain. Cygwin is no longer
part of the supported build story for this repository.

### Preferred Toolchain: MSYS2/MinGW

1. Install [MSYS2](https://www.msys2.org/).

2. Open the `MSYS2 MinGW 64-bit` shell.

3. Install the native build dependencies:

   ```shell
   pacman -S --needed \
     mingw-w64-x86_64-gcc \
     mingw-w64-x86_64-cmake \
     mingw-w64-x86_64-ninja \
     mingw-w64-x86_64-libmariadbclient \
     mingw-w64-x86_64-openssl \
     pkgconf
   ```

4. If your MSYS2 mirror publishes Net-SNMP for MinGW, install it too:

   ```shell
   pacman -S --needed mingw-w64-x86_64-net-snmp
   ```

5. Configure and build Spine with CMake:

   ```shell
   cmake -G Ninja -S . -B build -DSPINE_BUILD_MAIN=ON
   cmake --build build
   ctest --test-dir build --output-on-failure
   ```

6. If Net-SNMP is not yet available in your Windows package set, you can still
   validate the native platform layer and unit coverage with:

   ```shell
   cmake -G Ninja -S . -B build -DSPINE_BUILD_MAIN=OFF
   cmake --build build
   ctest --test-dir build --output-on-failure
   ```

## Known Issues

1. On native Windows, Microsoft does not support a TCP Socket send timeout. Therefore,
   if you are using TCP ping on Windows, spine will not perform a second or
   subsequent retries to connect and the host will be assumed down on the first
   failure.

   If this is a problem it is suggested to use another Availability/Reachability
   method, or moving to Linux/UNIX.

2. Spine takes quite a few MySQL connections. The number of connections is
   calculated as follows: (1 for main poller + 1 per each thread + 1 per each
   script server)

   Therefore, if you have 4 processes, with 10 threads each, and 5 script
   servers each your spine will take approximately:

   `total connections = 4 * ( 1 + 10 + 5 ) = 64`

3. Raw ICMP privilege model is platform-specific:

   - Linux/FreeBSD/macOS usually require elevated/raw-socket privileges.
   - Windows uses native ICMP APIs and does not require setuid/capabilities for
     the same code path.

-----------------------------------------------------------------------------
Copyright (c) 2004-2026 - The Cacti Group, Inc.
