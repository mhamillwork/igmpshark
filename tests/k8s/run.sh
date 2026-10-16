#!/bin/sh
# Real Kubernetes + Cilium checks. This script does not start a cluster and
# does not treat a missing cluster as success.
#
# Exit 0 only when the listed checks were actually performed.
# Exit 2 when the environment cannot run them.
set -eu

if ! command -v kubectl >/dev/null 2>&1; then
    echo "SKIP: kubectl is not installed; real Cilium checks were not run" >&2
    exit 2
fi
if ! kubectl get nodes >/dev/null 2>&1; then
    echo "SKIP: kubectl cannot reach a cluster; real Cilium checks were not run" >&2
    exit 2
fi
if ! kubectl -n kube-system get ds cilium >/dev/null 2>&1; then
    echo "SKIP: no kube-system DaemonSet named cilium; forwarding was not measured" >&2
    exit 2
fi

echo "Cilium is present. This repository does not ship a passing fake of the"
echo "datapath test. Inspect membership with:"
echo "  kubectl -n kube-system exec ds/cilium -- cilium-dbg bpf multicast subscriber list all"
echo "  kubectl -n kube-system exec ds/cilium -- cilium-dbg bpf multicast group list"
echo "Packet delivery still has to be measured with sequence-numbered multicast"
echo "sockets on the subscriber pods. That measurement was not automated here"
echo "because this environment has no Cilium installation."
exit 2
