#!/bin/sh
# Build libwireshark, libwiretap, and libwsutil from unchanged Wireshark v4.2.6
# source. Adapted from the dbshark reference
# (sqlshark-cursor-jsonb-promotion-races-94e7 tests/dbshark/build/build-wireshark-4.2.6.sh).
# Tested on Debian/Ubuntu here. The same flags are the RHEL 8/9 path.
# Installs no system Wireshark packages.
#
# Usage:
#   ./scripts/build-wireshark-4.2.6.sh [install-dir]
# Default install-dir: $HOME/wireshark-4.2.6
#
# NATIVE defaults to 0 so the libraries can move between nodes. Set NATIVE=1
# to match the dbshark script's original default.
# CXX defaults to g++. On some images /usr/bin/c++ is clang++ and cannot find
# libstdc++.
#
# Environment:
#   WS_SOURCE=tarball|git   tarball (default): wireshark.org release tarball,
#                           sha256 verified. git: gitlab.com tag v4.2.6.
#   NATIVE=0                default. Set NATIVE=1 to pass -march=native.
#   WS_CMAKE_EXTRA="..."    extra cmake options (e.g. -DENABLE_PLUGINS=OFF)
#   JOBS=N                  parallel compile jobs
#
# Dependencies: scripts/deps-rhel.sh or scripts/deps-debian.sh.

set -e

INSTALL=${1:-$HOME/wireshark-4.2.6}
JOBS=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}
WS_SOURCE=${WS_SOURCE:-tarball}
TARBALL_URL=https://www.wireshark.org/download/src/all-versions/wireshark-4.2.6.tar.xz
TARBALL_SHA256=5ec6028df29068d889c98489bf194a884b00831106fea1e921fea3c65f2003f5

if command -v cmake >/dev/null 2>&1; then
    CMAKE=cmake
elif command -v cmake3 >/dev/null 2>&1; then
    CMAKE=cmake3
else
    echo "error: cmake or cmake3 required (RHEL 8/9: dnf install cmake)" >&2
    exit 1
fi

if command -v ninja >/dev/null 2>&1; then
    NINJA=ninja
elif command -v ninja-build >/dev/null 2>&1; then
    NINJA=ninja-build
else
    echo "error: ninja or ninja-build required (RHEL 8/9: dnf install ninja-build)" >&2
    exit 1
fi

if [ ! -f "$INSTALL/CMakeLists.txt" ]; then
    case "$WS_SOURCE" in
        git)
            git clone --branch v4.2.6 --depth 1 https://gitlab.com/wireshark/wireshark.git "$INSTALL"
            ;;
        tarball)
            tmp=$(mktemp -d)
            echo "fetching $TARBALL_URL"
            curl -fsSL "$TARBALL_URL" -o "$tmp/ws.tar.xz"
            echo "$TARBALL_SHA256  $tmp/ws.tar.xz" | sha256sum -c -
            mkdir -p "$INSTALL"
            tar -xJf "$tmp/ws.tar.xz" --strip-components=1 -C "$INSTALL"
            rm -rf "$tmp"
            ;;
        *)
            echo "error: WS_SOURCE must be tarball or git" >&2
            exit 1
            ;;
    esac
fi

if ! grep -q 'set(PROJECT_MAJOR_VERSION 4)' "$INSTALL/CMakeLists.txt" \
    || ! grep -q 'set(PROJECT_MINOR_VERSION 2)' "$INSTALL/CMakeLists.txt" \
    || ! grep -q 'set(PROJECT_PATCH_VERSION 6)' "$INSTALL/CMakeLists.txt"; then
    echo "error: $INSTALL is not Wireshark 4.2.6 source" >&2
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
