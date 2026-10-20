#!/bin/sh
# Run cilium-dbg inside the Cilium agent's mount, network, and PID namespaces.
# `bpf multicast` opens pinned maps under the agent's /sys/fs/bpf, and
# `subscriber add` looks up cilium_vxlan with netlink. The host /sys/fs/bpf
# is often a different filesystem, so the same binary on the host path
# updates maps the agent's `group list` does not show.
# cilium-dbg finds that bpffs by reading /proc/self/mountinfo. The agent's
# /proc is the container PID namespace, so this process has to enter that
# namespace too. Mount namespace alone leaves /proc/self missing and cilium-dbg
# exits with "could not get mount info for map root lookup".
# These are local bpf() calls. A Kubernetes service account cannot do them.
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
if [ ! -r "/proc/$pid/ns/mnt" ] || [ ! -r "/proc/$pid/ns/pid" ]; then
    echo "cannot read /proc/$pid/ns; the pod must be able to setns" >&2
    exit 1
fi
dbg=${CILIUM_DBG_IN_AGENT:-/usr/bin/cilium-dbg}
exec nsenter -t "$pid" -m -n -p --preserve-credentials -- "$dbg" "$@"
