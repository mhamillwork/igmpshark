# Operations

## Timers

Defaults match the IGMPv2/v3 robustness variables.

| Setting | Default | Meaning |
| --- | --- | --- |
| `--query-interval-ms` | 125000 | General query period when this node is querier |
| `--query-response-ms` | 10000 | Query response interval |
| `--robustness` | 2 | Retransmissions, including last-member queries |
| `--lmqi-ms` | 1000 | Last-member query interval |
| `--startup-grace-ms` | 15000 | Additions only, until a pod list has also succeeded when `--kube` is on |
| `--reconcile-ms` | 5000 | How often desired state is applied |
| `--max-members` | 1024 | Engine capacity |

Membership interval is `robustness * query-interval + query-response` (260 s at the defaults). Other-querier-present is `robustness * query-interval + query-response/2` (255 s).

## Expected cleanup

These are bounds, not measurements from a Cilium cluster. The simulation measured the same state machine at a faster timer profile: leave cleared at 200 ms (`2 * 100 ms`) and a quiet subscriber cleared at 2500 ms against a 2100 ms membership interval.

| Event | Bound after the trigger is known |
| --- | --- |
| IGMPv2 leave, other subscribers on the same interface | `robustness * lmqi` plus one reconcile interval (7 s at the defaults). Immediate leave, if enabled, applies only when that interface and generation has exactly one joined subscriber, then waits one reconcile interval. |
| IGMPv1, or a host that stops reporting while the pod remains | One membership interval after the last query that went unanswered, plus one reconcile interval (about 265 s). Nothing expires while `igmpshark_querier_degraded` is 1. |
| Pod delete, force delete, or OOM that removes the pod object | One reconcile interval after the watch delivers the delete. A NotReady node or an API error is not a delete. |
| Container restart, same pod UID | No cleanup. The restart counter is ignored. |
| Replacement pod, new UID, same IP | The new UID is bound immediately. A late delete for the old UID does not remove it. |
| igmpshark restart | Grace period first (15 s), then the normal bounds. State is restored from the local snapshot before deletes. |
| Cilium restart | Next reconcile re-adds groups and remote nodes. Local pod entries reappear when the injected IGMPv3 CHANGE_TO_EXCLUDE report hits the datapath. |
| API or coord outage | No mass delete. Remote rows for nodes whose snapshots are stale are held. |

## Dry-run

`--dry-run` or Helm `config.dryRun=true` loads the backend, plans operations, and writes nothing. `igmpshark_mutations_total` stays at the value from before the flag was set. The simulation asserts it stays 0 and that an unmanaged row is unchanged.

## Inspect

```sh
curl -s localhost:9080/healthz
curl -s localhost:9080/readyz
curl -s localhost:9080/metrics
kubectl -n kube-system exec ds/cilium -c cilium-agent -- \
  cilium-dbg bpf multicast subscriber list all
kubectl -n kube-system exec ds/cilium -c cilium-agent -- \
  cilium-dbg bpf multicast group list
```

Metrics to look at: `igmpshark_memberships`, `igmpshark_joins_total`, `igmpshark_leaves_total`, `igmpshark_expires_total`, `igmpshark_cleanups_total`, `igmpshark_malformed_total`, `igmpshark_capture_drops_total`, `igmpshark_queue_drops_total`, `igmpshark_queue_depth`, `igmpshark_reconcile_failures_total`, `igmpshark_reconcile_retries_total`, `igmpshark_k8s_watch_healthy`, `igmpshark_querier_degraded`, `igmpshark_queries_seen_total`, `igmpshark_queries_sent_total`, `igmpshark_coord_ok`.

Logs are single-line JSON on stderr.

## Missing IGMP

`hostNetwork` does not mean the pod's reports are visible. Capture the interface you configured (`any` is cooked capture) and confirm proto 2:

```sh
tcpdump -i any -n igmp
```

If tcpdump shows reports and igmpshark does not, check the BPF filter compiled, the interface name, and whether libwireshark rejected the link type (`igmpshark_malformed_total` versus a silent skip). If the reports use a source that is not a pod IP on this node after the first pod list, they are counted in `igmpshark_ignored_unbound_total` on purpose.

If the group exists in Cilium but the pod address is not a `Local` subscriber, the join was snooped before the group map existed. Cilium does not create that row from a query response. The next reconciles inject an IGMPv3 CHANGE_TO_EXCLUDE report from the pod namespace (`local-join` in the log) until that `Local` row appears. A node that only has the other node's remote subscriber does not inject; the node where the pod runs does.

An IGMP v3 report (`to_ex` or `to_in`) sourced from the application pod IP is that pod's membership. The Local endpoint row is that pod IP. An IGMP v3 query sourced from `node-ip` is igmpshark soliciting a report; that source is this node's CiliumInternalIP, and it is the address other nodes install as the Remote Node subscriber. The remote row is the VXLAN tunnel destination. It stays the node identity when the report source and the query source differ.

A `to_in` or IGMPv2 leave drops that subscriber out of the snapshot immediately, including when the leave is captured on a different interface from the join. igmpshark does not inject another report while the leave is waiting, so Cilium's removal of the local row is not written back. Other nodes drop the remote subscriber on their next reconcile. A process stopped inside a pod that never sent a leave, or whose leave was already undone by an older image, stays published until that pod is deleted.

`pod-ip` is an application pod address on this node, logged when the watch first learns that address or it changes after a restart. `pod-local` is the same kind of address learned from the packet itself: the source has a `/32 host LOCAL` route in a pod network namespace on this node, so the report is recorded even when the watch has not published that IP yet. `ignored-unbound` is only a source that is neither in the pod table nor a local pod namespace. The script that joins groups 15–20 seconds after a restart is recorded by that path. `node-ip` does not list application pod addresses.

`node-ip` in the log is the CiliumInternalIP. `source` is `annotation` when it came from `network.cilium.io/ipv4-cilium-host`, and `cilium-internal` when the node list was the only source. `node-list-ip` is present when that list disagreed. `host-ip` is the Kubernetes node InternalIP (`status.hostIP`). `cilium-host-ip` is whatever address was configured first on `cilium_host`; traffic from the cilium-health endpoint and from a stale address on that interface shows up in tcpdump and is not a pod. Remote subscribers have to be the CiliumInternalIP or VXLAN does not land on the other node. `cilium-identity-disagree` names the annotation and the node-list address when they differ; the annotation is the one installed. `cilium-identity-failed` means neither the node list nor the annotation could be read, and no Kubernetes node IP was installed in its place.

A pod restart that changes the pod IP leaves the old address as a second Local Endpoint when that join was never in igmpshark. Cilium then has two local subscribers for one group. After this node's pod list has completed, the address that is no longer a pod is deleted. The running pod's address stays, including when the new address is only known from a pod network namespace and the list snapshot does not contain it yet. `is_ex` is a join. It is not a leave, and a second copy of that report inside the dedup window does not remove the group. Until that image is deployed, remove the old row on the node that lists it: `cilium-dbg bpf multicast subscriber delete <group> <old-pod-ip>`.

A delete is one JSON line, `msg` `member-deleted`, with `reason` and the subscriber `ip` when the address is known. `count` is how many groups that decision covered. `pod-ip-changed` is the previous address after a restart. `pod-deleted` is a watch delete. `pod-list-absent` is a pod missing from a completed list whose network namespace is also gone. `departed-local` is a Cilium Local Endpoint for an address that is not a running pod. `timer`, `iface-down`, and `ifindex-reuse` are the other reasons. `member-kept` with reason `pod-local` means a cleanup looked at that address and left the groups in place because the pod namespace is still on this node.

`backend-apply-failed` with `key already exists` used to pin the retry plan on every node that was not itself leaving the group, so unsubscribe cleared only the nodes that ran the application. That result is now success. A node with no local member deletes the remote subscriber and then the group once the peer snapshots are gone. A pod restart used to forget those rows because the ledger is an emptyDir; remote rows are still owned after that.

`igmpshark_memberships` is the engine. It is not the size of the Cilium map. A node can report 0 while `cilium-dbg bpf multicast subscriber list all` still shows old Local Endpoint and Remote Node rows. That happens when the subscriber list is too large for the read or the reconcile plan from before the pod list finished is replayed forever. The list is read in full, and once the pod list has completed those rows are deleted. The other node's current groups are installed as one Remote Node row at that node's CiliumInternalIP. A peer snapshot that has been silent for more than two membership intervals no longer pins the previous remote rows. `backend-load-failed` with `cilium list failed` or `cilium list truncated` means this pass changed nothing.

## Capabilities and mounts

The DaemonSet runs as root and privileged so it can open raw sockets, enter the Cilium agent's namespaces, and call `bpf()` on the multicast maps. A service account cannot update those maps. The service account can get, list, and watch pods and nodes, and can create and update ConfigMaps used as snapshots. It cannot delete pods or ConfigMaps. The pod mounts the Cilium agent socket directory and bpffs read-only. It does not mount the host root or a kubeconfig.

## RHEL

Multicast runs on RHEL 9 nodes with Cilium 1.19.2 or 1.19.3. Build the agent there with `sudo ./scripts/deps-rhel.sh`, then the Wireshark and igmpshark commands in the README. Wireshark 4.6.9 source is already in `third_party/wireshark-4.6.9.tar.xz`. `scripts/build-wireshark-4.6.9.sh` checks that file's sha256 and extracts it. It does not download Wireshark. Load a built image with `podman load` or `docker load`.

Do not link the RHEL wireshark RPM; it is 3.4.10 on RHEL 9. RHEL 8 can still compile this C program, and `scripts/deps-rhel.sh` accepts it for that, but RHEL 8 is not a multicast node. Cilium's own multicast guide requires a 5.10 kernel on AMD64, and the combination that actually forwarded was RHEL 9 plus Cilium 1.19.2 or 1.19.3. The unit tests need Python only for the fixture generator and the simulation; the C tests themselves are C11.

## Image

The image is UBI 9. It installs `flex`, `c-ares`, and `c-ares-devel` with dnf, then compiles libwireshark 4.6.9 from `third_party/wireshark-4.6.9.tar.xz`.

```sh
docker build -f dockerfile/Dockerfile.igmp-shark -t igmpshark:local .
docker save igmpshark:local | gzip > igmpshark.tar.gz
docker load < igmpshark.tar.gz
```

The image contains no credentials. The chart's service account token is mounted by Kubernetes at runtime.

## Real cluster test

`tests/k8s/run.sh` exits 2 unless `kubectl` can see a `cilium` DaemonSet. It does not fake a pass. Same-node and cross-node delivery, force-delete timing, and crash loops have to be measured there with sequence-numbered multicast and `cilium-dbg bpf multicast subscriber list all` before and after. The file-backend simulation does not prove any of that.
