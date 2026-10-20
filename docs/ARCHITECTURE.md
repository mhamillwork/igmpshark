# Architecture

igmpshark is one process per node. Protocol state, the Kubernetes pod table, and the Cilium backend are separate. Unit tests call the first two with a fake clock and a file or in-memory backend. They do not open packet sockets.

## Pipeline

1. libpcap captures on the configured interfaces with BPF filter `igmp`, or reads a pcap/pcapng file and exits.
2. libwireshark 4.6.9 dissects the frame. A frame the IGMP dissector does not accept is ignored. Linux cooked capture (`any`, DLT_LINUX_SLL / SLL2) is mapped to the same parser as Ethernet.
3. The parser checks the IPv4 and IGMP checksums and rejects truncated or non-routable groups (`224.0.0.0/24` is ignored).
4. The engine updates membership. A 50 ms dedup window suppresses the same frame observed on two interfaces. An identical report outside that window is a refresh.
5. When `--kube` has completed one pod list, a report is accepted only if its source address is a current pod on this node. The packet source alone is not a membership identity.
6. Snapshots in `--coord-dir` publish this node's joined groups. Other nodes' fresh snapshots become remote subscribers keyed by the publishing node's CiliumInternalIP, the IPv4 address of `cilium_host`. The application pod IP is not copied to other nodes.
7. Reconciliation diffs desired state against the backend and applies idempotent operations. Startup grace and a missing pod list suppress deletes.

## Ownership

Each node writes only `<coord-dir>/<node-name>.snap`, by renaming a temporary file. Readers never write another node's file. The `NODE` timestamp is wall-clock milliseconds. A snapshot older than two membership intervals, or more than 30 seconds ahead of this node's wall clock, is not installed as a remote subscriber. Those node IPs are held, so a stale peer is not deleted either. If the directory cannot be read, remote deletes are skipped entirely. Local timer expiry and explicit pod deletion still proceed.

With `--kube-coord`, the same text is published as a ConfigMap named `igmpshark-<node>` labeled `app.kubernetes.io/name=igmpshark`, base64-encoded under `data.snapshot`. Peers are fetched into the local coord directory before this node rewrites its own file, so a fetch cannot roll the local snapshot backwards. ConfigMap mode was not executed against an API server here. The file directory is what the simulation tests.

The CLI backend keeps an ownership ledger (`--ledger`). A Cilium row is managed only when the ledger or the live engine contains it. Rows Cilium or an administrator created some other way are left in place. `group delete` is not emitted while any unmanaged or held subscriber remains, because that command destroys the group's inner map.

Reference counts are per group and remote node IP. Removing one pod does not remove the node entry while another joined subscriber on that node remains.

## Restarts

On startup the process reloads its own snapshot into the engine with fresh membership deadlines and does not count those as new joins. Deletes wait for `--startup-grace-ms` (default 15 s) and, when `--kube` is set, for one successful pod list. Adds are allowed immediately, so a Cilium restart that emptied the maps is repaired without waiting.

A container restart that keeps the pod UID is recorded and ignored. A new UID on a reused IP is bound onto existing and new reports. A delayed delete for the old UID does not remove the new one.

Interface disappearance or a name change at the same ifindex retires the old interface generation. Later reports on the new generation create new memberships.

## Querier

Passive mode (the default) never expires a member only because unsolicited reports stopped. Expiry starts after a query is observed. Until then `igmpshark_querier_degraded` is 1 and `/readyz` returns `degraded` with HTTP 200.

`--active-querier` elects the lowest `self-ip`. A query or a fresh snapshot from a DaemonSet with a lower address yields. A higher address does not displace a lower querier that is still inside the other-querier-present interval. Only the elected process queues general queries, last-member queries, and the group-specific solicit sent when a group is created. Solicitation matters because Cilium's datapath will not record a local subscriber until the group exists; the solicit asks the pod to report again so Cilium inserts the local entry. igmpshark does not insert local entries itself.

## Queues and limits

The capture queue defaults to 64 frames. Overflow increments `igmpshark_queue_drops_total` and `igmpshark_capture_drops_total`. pcap's own drop counter is copied into the capture-drop metric when the kernel reports it. Memberships are capped by `--max-members` (default 1024, hard cap 4096). Source lists are capped at 16 addresses per member. The Kubernetes event queue holds 256 events; overflow is counted and the watch does another full list rather than deleting from a partial view.

`cilium-dbg` is executed with `execvp` and a 3 second deadline. Packet bytes are never interpolated into a shell. A failed list is an error, not an empty map, so a missing binary cannot wipe memberships.

## Clocks

Protocol timers use the monotonic clock. Snapshot timestamps use the realtime clock so a peer file written on another node can be aged here. A timestamp up to 30 seconds ahead of this node is still fresh. The control socket's `NOW` command, used by tests, rebases the grace clock onto that logical time on the first use. Production does not set `NOW`.
