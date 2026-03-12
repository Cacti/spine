# Cacti Spine Packaging

This directory contains the files and instructions necessary to build native packages for various operating systems.

## Supported Platforms

- **Debian/Ubuntu**: See [debian/README](debian/README) for build instructions using `dpkg-buildpackage`.
- **RHEL/CentOS/Rocky Linux**: See [rpm/README](rpm/README) for build instructions using `rpmbuild`.
- **FreeBSD**: Contains a standard FreeBSD port `Makefile`.

## Alternative: Docker

For containerized environments or consistent builds regardless of the host OS, refer to the `Dockerfile` and `Dockerfile.dev` in the project root.
