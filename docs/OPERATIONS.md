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
| Cilium restart | Next reconcile re-adds groups and remote nodes. Local pod entries reappear when the solicited report hits the datapath. |
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

If the group is created in Cilium but the pod still receives nothing, the datapath may have handled the report before the group existed. With `--active-querier` the node solicits another report. Without it, the external querier has to ask again, or the application has to retransmit.

## Capabilities and mounts

The DaemonSet runs as root so it can open raw sockets. It drops all capabilities and adds `NET_RAW` and `NET_ADMIN`. It mounts the Cilium agent socket directory and bpffs read-only. It does not mount the host root or a kubeconfig. The service account can get, list, and watch pods and nodes, and can create and update ConfigMaps used as snapshots. It cannot delete pods or ConfigMaps.

## RHEL

RHEL 9 is the intended build host: `sudo ./scripts/deps-rhel.sh` then the Wireshark and igmpshark build commands in the README. The Wireshark tarball URL and sha256 are in `scripts/build-wireshark-4.2.6.sh`. For a disconnected build, put `wireshark-4.2.6.tar.xz` where the script can see an already extracted tree, or pass that tree as the install directory, and load the image with `docker load` or `podman load` rather than pulling it.

RHEL 8 can compile Wireshark 4.2.6 with the same package script (gcc 8, CRB/PowerTools). Do not link the RHEL wireshark RPM; it is not 4.2.6. RHEL 8's 4.18 kernel is older than the kernels Cilium multicast is developed against, so a successful RHEL 8 build is not a statement that the datapath will forward. Use a RHEL 9 node, or another 5.10+ kernel, for the agent. The unit tests need Python only for the fixture generator and the simulation; the C tests themselves are C11.

## Image

```sh
docker build -t igmpshark:local .
# disconnected: copy the tarball to third_party/wireshark-4.2.6.tar.xz first
docker save igmpshark:local | gzip > igmpshark.tar.gz
docker load < igmpshark.tar.gz
```

The image contains no credentials. The chart's service account token is mounted by Kubernetes at runtime.

## Real cluster test

`tests/k8s/run.sh` exits 2 unless `kubectl` can see a `cilium` DaemonSet. It does not fake a pass. Same-node and cross-node delivery, force-delete timing, and crash loops have to be measured there with sequence-numbered multicast and `cilium-dbg bpf multicast subscriber list all` before and after. The file-backend simulation does not prove any of that.
