#!/bin/sh
# Run cilium-dbg inside the Cilium agent's mount namespace.
# `bpf multicast` opens pinned maps under /sys/fs/bpf. The agent often has a
# private bpffs there, so the same binary on the host path updates a different
# filesystem and the agent's `group list` stays empty.
set -eu
pid=
for d in /proc/[0-9]*; do
    comm=$(cat "$d/comm" 2>/dev/null || true)
    if [ "$comm" = "cilium-agent" ]; then
        pid=${d#/proc/}
        break
    fi
done
if [ -z "$pid" ]; then
    echo "cilium-agent process not found; hostPID is required" >&2
    exit 1
fi
dbg=${CILIUM_DBG_IN_AGENT:-/usr/bin/cilium-dbg}
exec nsenter -t "$pid" -m -- "$dbg" "$@"
