#!/bin/sh
# Build libwireshark, libwiretap, and libwsutil from the Wireshark 4.6.9
# source tarball shipped in this repository. Adapted from the dbshark
# reference (sqlshark-cursor-jsonb-promotion-races-94e7
# tests/dbshark/build/build-wireshark-4.2.6.sh). The source is not downloaded.
# Installs no system Wireshark packages.
#
# Usage:
#   ./scripts/build-wireshark-4.6.9.sh [install-dir]
# Default install-dir: $HOME/wireshark-4.6.9
#
# NATIVE defaults to 0 so the libraries can move between nodes. Set NATIVE=1
# to pass -march=native.
# CXX defaults to g++. On some images /usr/bin/c++ is clang++ and cannot find
# libstdc++.
#
# Environment:
#   NATIVE=0                default. Set NATIVE=1 to pass -march=native.
#   WS_CMAKE_EXTRA="..."    extra cmake options
#   JOBS=N                  parallel compile jobs
#
# Dependencies: scripts/deps-rhel.sh or scripts/deps-debian.sh.
# flex and c-ares are required. On UBI 9, scripts/install-flex-c-ares.sh
# installs them.

set -e

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
INSTALL=${1:-$HOME/wireshark-4.6.9}
JOBS=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}
TARBALL=$ROOT/third_party/wireshark-4.6.9.tar.xz
TARBALL_SHA256=d062d416a1ab3a49975aafe3a671c882dde0562ccd71b078808ceb59d465fc0f

if command -v cmake >/dev/null 2>&1; then
    CMAKE=cmake
elif command -v cmake3 >/dev/null 2>&1; then
    CMAKE=cmake3
else
    echo "error: cmake or cmake3 required (RHEL 9: dnf install cmake)" >&2
    exit 1
fi

if command -v ninja >/dev/null 2>&1; then
    NINJA=ninja
elif command -v ninja-build >/dev/null 2>&1; then
    NINJA=ninja-build
else
    echo "error: ninja or ninja-build required (RHEL 9: dnf install ninja-build)" >&2
    exit 1
fi

if [ ! -f "$INSTALL/CMakeLists.txt" ]; then
    if [ ! -f "$TARBALL" ]; then
        echo "error: $TARBALL is missing. This tree ships the Wireshark 4.6.9 source so the build does not download it." >&2
        exit 1
    fi
    echo "$TARBALL_SHA256  $TARBALL" | sha256sum -c -
    mkdir -p "$INSTALL"
    tar -xJf "$TARBALL" --strip-components=1 -C "$INSTALL"
fi

if ! grep -q 'set(PROJECT_MAJOR_VERSION 4)' "$INSTALL/CMakeLists.txt" \
    || ! grep -q 'set(PROJECT_MINOR_VERSION 6)' "$INSTALL/CMakeLists.txt" \
    || ! grep -q 'set(PROJECT_PATCH_VERSION 9)' "$INSTALL/CMakeLists.txt"; then
    echo "error: $INSTALL is not Wireshark 4.6.9 source" >&2
    exit 1
fi

cd "$INSTALL"

OPT="-O3"
if [ "${NATIVE:-0}" = "1" ]; then
    OPT="$OPT -march=native"
fi
export CC="${CC:-gcc}"
export CXX="${CXX:-g++}"

# shellcheck disable=SC2086
$CMAKE -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="$OPT" \
    -DCMAKE_CXX_FLAGS="$OPT" \
    -DBUILD_wireshark=OFF -DBUILD_tshark=OFF \
    -DBUILD_dumpcap=OFF -DBUILD_editcap=OFF -DBUILD_mergecap=OFF \
    -DBUILD_capinfos=OFF -DBUILD_text2pcap=OFF -DBUILD_reordercap=OFF \
    -DBUILD_rawshark=OFF -DBUILD_captype=OFF -DBUILD_randpkt=OFF \
    -DBUILD_dftest=OFF -DBUILD_dcerpcidl2wrs=OFF -DBUILD_androiddump=OFF \
    -DBUILD_sshdump=OFF -DBUILD_ciscodump=OFF -DBUILD_dpauxmon=OFF \
    -DBUILD_randpktdump=OFF -DBUILD_wifidump=OFF -DBUILD_udpdump=OFF \
    -DBUILD_sharkd=OFF -DBUILD_mmdbresolve=OFF \
    ${WS_CMAKE_EXTRA:-}

$NINJA -C build -j "$JOBS" libwireshark.so libwiretap.so libwsutil.so

echo "built libraries in $INSTALL/build/run"
echo "build igmpshark with: WS=$INSTALL ./scripts/build.sh"
