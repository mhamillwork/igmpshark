# Cilium multicast

Multicast forwarding was only made to work on **RHEL 9** with **Cilium 1.19.2 or 1.19.3** (`quay.io/cilium/cilium:v1.19.2` or `v1.19.3`). Use the `cilium-dbg` binary from that same image. The Helm chart copies it out of `cilium.image`; a dbg binary from another release is not safe.

Cilium documents multicast as beta, VXLAN mode, and kernels at least 5.10 on AMD64 (6.0 on AArch64). RHEL 9's 5.14 kernel is the one that meets that bar in practice. RHEL 8's 4.18 kernel is not a multicast target, even where a newer Cilium build otherwise starts. This checkout still has no Cilium agent, so the commands below were checked against the Cilium 1.19 multicast guide and a list-format fixture, not against a live 1.19.2 or 1.19.3 agent.

## Three states

1. Pod membership. igmpshark tracks group, subscriber IP, pod UID, node, interface index and generation, IGMP version, filter mode, and source list.
2. Local endpoint forwarding. Cilium's BPF IGMP handler inserts a subscriber-map value whose key is the packet source address and whose remote flag is clear. The group map has to exist first or the handler does not record the subscriber. There is no endpoint-ID delete API.
3. Remote-node forwarding. `cilium-dbg bpf multicast subscriber add <group> <address>` inserts a key with the remote flag set. The address is the other node's CiliumInternalIP (`kubectl get ciliumnodes` column `CILIUMINTERNALIP`, and the node annotation `network.cilium.io/ipv4-cilium-host`). It is not the pod IP, not `status.hostIP`, and not the cilium-health address. The first IPv4 on `cilium_host` is not reliable either: a stale router address can still be configured there, and Linux returns the newest address first. igmpshark reads that annotation from the Kubernetes node. `cilium-dbg node list -o json` is the fallback when the annotation is absent: the secondary IPv4 inside `primary-address.ipv4.alloc-range` that is not the primary, health, or ingress address. The fallback can still pick the health address when several in-CIDR secondaries are listed and the annotation is missing, because the JSON has no address type. Passing any other address creates a remote entry that VXLAN will not deliver. A node that has no member of the group does not get a remote row on the node where the application runs. The other node gets one remote row for this node's CiliumInternalIP. After the peers leave, a node that never ran the application deletes those remote rows and then the group. `key already exists` on add, and a missing key on delete, are success, so that cleanup is not stuck replaying the add.

`subscriber delete <group> <address>` deletes whatever key is passed. That is the supported way to drop a stale local entry after a pod crashes without a leave: delete the pod source IP. It is also how a remote node IP is removed. Deleting a remote node IP does not remove a local pod entry, and the reverse is also true.

`group delete` removes the inner map, including healthy local subscribers. igmpshark emits it only when the group has no joined local subscribers, no remote subscribers, and no unmanaged rows. A subscriber list that fills the read buffer is a failed load, not an empty map. The read is 4MiB. A plan larger than one pass is applied from the front and computed again, so an engine with 0 memberships still removes the Local Endpoint and Remote Node rows the list returned, and still adds the peer's current CiliumInternalIP.

## Commands the CLI backend runs

```text
cilium-dbg bpf multicast group add <group>
cilium-dbg bpf multicast group delete <group>
cilium-dbg bpf multicast subscriber add <group> <node-ip>
cilium-dbg bpf multicast subscriber delete <group> <address>
cilium-dbg bpf multicast subscriber list all
cilium-dbg bpf multicast group list
```

Arguments are a fixed argv. The list parser accepts `Group Subscriber Type` rows. Cilium 1.19 labels a node entry `Remote Node` and a pod entry `Local`. A group address on its own is a group marker. Managed versus unmanaged is decided by the on-disk ledger plus the engine, not by a flag Cilium does not have.

`cilium multicast add` programs every node from one CLI. igmpshark does not use it. Each DaemonSet pod programs only the agent on its own node. `cilium-dbg bpf multicast` opens the pinned maps in the Cilium agent's namespaces (`scripts/cilium-dbg-in-agent.c`). The host `/sys/fs/bpf` is often a different filesystem from the one the agent lists. cilium-dbg reads `/proc/self/mountinfo` to find the right one, so the helper remounts proc in a private mount namespace after joining the agent. The helper matches `cilium-agent` by process name, argv0, or the executable path. When none match, the log includes pid 1's name and how many processes `/proc` shows. `pid 1 is igmpshark` means the pod is not in the host PID namespace. `pid 1 is systemd` with a large process count means this node has no `cilium-agent` process to join. Other nodes' subscribers still come from the coord snapshots.

## What Cilium already does

Cilium snoops IGMP in the datapath and can install local subscribers on its own, but only after the group map exists, and only from IGMPv3 CHANGE_TO_EXCLUDE (record type 4) or an IGMPv2 report. MODE_IS_EXCLUDE, which is the record a host sends in reply to a query, is not recorded. igmpshark creates the group first, then injects a CHANGE_TO_EXCLUDE report from inside the pod network namespace with the pod IP as the source. It does not subscriber-add the pod IP. Cilium restart recreates empty maps; the next reconcile adds desired groups and remote nodes again, then injects for local members whose pod address is missing. igmpshark does not restart Cilium or flush unrelated endpoints. A large delete or add walks eight `cilium-dbg` calls per reconcile, so clearing many remote rows takes several passes.

Filter mode and source lists follow RFC 3376 inside the engine. Cilium forwarding is group-wide. An INCLUDE source list does not restrict which sources Cilium forwards.

## Cleanup this does not claim

After the pod list for this node has completed, a Local Endpoint whose address is not a current pod on this node is deleted. That is the previous pod IP left behind when a restart never sent a leave. The address that still belongs to a running pod is kept, so the group is not removed out from under it. A local row is not adopted as an igmpshark membership just because Cilium still lists it.

A remote-node delete is not a fix for a local entry leaked by a crashed pod. The local delete is the pod-IP key. The 1.19 guide shows `subscriber delete` taking the same group and address pair used for remote nodes. Whether 1.19.2 and 1.19.3 still delete a non-remote pod key with that command was not re-checked on a live agent. If they refuse it, local crash cleanup needs an upstream delete-by-endpoint API, which these docs do not provide.
