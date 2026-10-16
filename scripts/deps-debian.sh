#!/bin/sh
# Debian/Ubuntu packages for igmpshark. Adapted from the dbshark deps-debian.sh
# in the attached sqlshark zip. PostgreSQL is not required.
set -eu
MODE=${1:-all}
export DEBIAN_FRONTEND=noninteractive
BUILD="gcc g++ make cmake ninja-build pkg-config flex bison python3
    libglib2.0-dev libgcrypt20-dev libpcap-dev libpcre2-dev libc-ares-dev
    zlib1g-dev libgnutls28-dev libxml2-dev liblz4-dev libzstd-dev
    libnghttp2-dev libbrotli-dev libkrb5-dev libssh-dev libspeexdsp-dev
    libmaxminddb-dev libcurl4-openssl-dev curl xz-utils tar"
TEST="python3 libcap2-bin procps iproute2"
apt-get update
case "$MODE" in
    build) apt-get install -y --no-install-recommends $BUILD ;;
    test) apt-get install -y --no-install-recommends $TEST ;;
    all) apt-get install -y --no-install-recommends $BUILD $TEST ;;
    *) echo "usage: $0 [all|build|test]" >&2; exit 1 ;;
esac
echo "deps-debian: installed $MODE"
