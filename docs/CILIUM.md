# Cilium multicast

Target assumption: Cilium 1.16 or 1.17 with multicast enabled (beta, normally VXLAN). This checkout did not have a Cilium agent, so none of the commands below were executed here. The CLI text parser was checked against a fixture of the documented table shape, not against a live agent.

Cilium 1.18 had a nil-map panic on multicast upgrade in some builds. Prefer a 1.16/1.17 release, or a later release where that panic is fixed, and use the `cilium-dbg` binary from that same image. The Helm chart copies it out of `cilium.image` in an init container. A mismatched dbg binary is not safe.

## Three states

1. Pod membership. igmpshark tracks group, subscriber IP, pod UID, node, interface index and generation, IGMP version, filter mode, and source list.
2. Local endpoint forwarding. Cilium's BPF IGMP handler inserts a subscriber-map value whose key is the packet source address and whose remote flag is clear. The handler returns without inserting anything when the group map does not exist yet (`if (!sub_map) return DROP_IGMP_HANDLED` in the 1.16 datapath). There is no endpoint-ID delete API.
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

Arguments are a fixed argv. The list parser accepts `Group Subscriber Type` rows with `Local` or `Remote`, and a group address alone as a group marker. Managed versus unmanaged is decided by the on-disk ledger plus the engine, not by a flag Cilium does not have.

Cluster-wide `cilium multicast add` from 1.17 is not used. Each DaemonSet node programs the agent on that node through its socket (`/var/run/cilium/cilium.sock`).

## What Cilium already does

Cilium snoops IGMP in the datapath and can install local subscribers on its own. igmpshark still creates the group first, solicits a fresh report when it is the querier, and deletes entries the datapath will not delete after a crash. Cilium restart recreates empty maps; the next reconcile adds desired groups and remote nodes again. igmpshark does not restart Cilium or flush unrelated endpoints.

Filter mode and source lists follow RFC 3376 inside the engine. Cilium forwarding is group-wide. An INCLUDE source list does not restrict which sources Cilium forwards.

## Cleanup this does not claim

A remote-node delete is not a fix for a local entry leaked by a crashed pod. The local delete is the pod-IP key. If a future Cilium build stops honoring `subscriber delete` for non-remote keys, local crash cleanup would need an upstream API that deletes by endpoint identity. That API was not found in the 1.16 subscriber map (`SubscriberV4InnerMap.Delete` deletes the address it is given).
