#!/bin/sh
# Configure and build igmpshark. Wireshark 4.2.6 must already be built.
#   WS=$HOME/wireshark-4.2.6 ./scripts/build.sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
WS=${WS:-$HOME/wireshark-4.2.6}
cmake -S "$ROOT" -B "$ROOT/build" -DWIRESHARK_ROOT="$WS"
cmake --build "$ROOT/build" -j "${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"
echo "binary: $ROOT/build/run/igmpshark"
