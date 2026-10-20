# Cilium multicast

Multicast forwarding was only made to work on **RHEL 9** with **Cilium 1.19.2 or 1.19.3** (`quay.io/cilium/cilium:v1.19.2` or `v1.19.3`). Use the `cilium-dbg` binary from that same image. The Helm chart copies it out of `cilium.image`; a dbg binary from another release is not safe.

Cilium documents multicast as beta, VXLAN mode, and kernels at least 5.10 on AMD64 (6.0 on AArch64). RHEL 9's 5.14 kernel is the one that meets that bar in practice. RHEL 8's 4.18 kernel is not a multicast target, even where a newer Cilium build otherwise starts. This checkout still has no Cilium agent, so the commands below were checked against the Cilium 1.19 multicast guide and a list-format fixture, not against a live 1.19.2 or 1.19.3 agent.

## Three states

1. Pod membership. igmpshark tracks group, subscriber IP, pod UID, node, interface index and generation, IGMP version, filter mode, and source list.
2. Local endpoint forwarding. Cilium's BPF IGMP handler inserts a subscriber-map value whose key is the packet source address and whose remote flag is clear. The group map has to exist first or the handler does not record the subscriber. There is no endpoint-ID delete API.
3. Remote-node forwarding. `cilium-dbg bpf multicast subscriber add <group> <address>` inserts a key with the remote flag set. The address is the other node's CiliumNode internal IP. Passing a pod IP creates a remote entry for that address and does not fix local forwarding.

`subscriber delete <group> <address>` deletes whatever key is passed. That is the supported way to drop a stale local entry after a pod crashes without a leave: delete the pod source IP. It is also how a remote node IP is removed. Deleting a remote node IP does not remove a local pod entry, and the reverse is also true.

`group delete` removes the inner map, including healthy local subscribers. igmpshark emits it only when the group has no joined local subscribers, no remote subscribers, and no unmanaged rows.

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

`cilium multicast add` programs every node from one CLI. igmpshark does not use it. Each DaemonSet pod programs only the agent on its own node. `cilium-dbg bpf multicast` opens the pinned maps in the Cilium agent's namespaces (`scripts/cilium-dbg-in-agent.c`). The host `/sys/fs/bpf` is often a different filesystem from the one the agent lists. cilium-dbg reads `/proc/self/mountinfo` to find the right one, so the helper remounts proc in a private mount namespace after joining the agent. Other nodes' subscribers still come from the coord snapshots.

## What Cilium already does

Cilium snoops IGMP in the datapath and can install local subscribers on its own. igmpshark still creates the group first, solicits a fresh report when it is the querier, and deletes entries the datapath will not delete after a crash. Cilium restart recreates empty maps; the next reconcile adds desired groups and remote nodes again. igmpshark does not restart Cilium or flush unrelated endpoints.

Filter mode and source lists follow RFC 3376 inside the engine. Cilium forwarding is group-wide. An INCLUDE source list does not restrict which sources Cilium forwards.

## Cleanup this does not claim

A remote-node delete is not a fix for a local entry leaked by a crashed pod. The local delete is the pod-IP key. The 1.19 guide shows `subscriber delete` taking the same group and address pair used for remote nodes. Whether 1.19.2 and 1.19.3 still delete a non-remote pod key with that command was not re-checked on a live agent. If they refuse it, local crash cleanup needs an upstream delete-by-endpoint API, which these docs do not provide.
