#!/bin/sh
# Unit tests do not need libwireshark, root, or a cluster.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mkdir -p "$ROOT/build"
cc=${CC:-gcc}
"$cc" -std=c11 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -I "$ROOT/src" \
    -o "$ROOT/build/test_igmp" \
    "$ROOT/src/igmp_parse.c" "$ROOT/src/engine.c" "$ROOT/src/reconcile.c" \
    "$ROOT/tests/test_igmp.c"
"$cc" -std=c11 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -I "$ROOT/src" \
    -o "$ROOT/build/test_runtime" \
    "$ROOT/src/igmp_parse.c" "$ROOT/src/engine.c" "$ROOT/src/reconcile.c" \
    "$ROOT/src/backend.c" "$ROOT/src/pods.c" "$ROOT/src/coord.c" \
    "$ROOT/src/runtime.c" "$ROOT/src/query.c" "$ROOT/src/kube_parse.c" \
    "$ROOT/tests/test_runtime.c"
"$ROOT/build/test_igmp"
"$ROOT/build/test_runtime"
echo unit-ok
