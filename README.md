# igmpshark

`igmpshark` is a C daemon that captures IPv4 IGMP, tracks membership, and reconciles Cilium multicast forwarding. It is meant to run as a Kubernetes DaemonSet, one process per node, and to behave like an IGMP-snooping switch: queries, membership timers, and last-member processing.

IPv6 MLD is not implemented. Cilium multicast is group-level; source lists are tracked in the protocol engine and are not enforced by the datapath.

## What was validated here

| Check | Result |
| --- | --- |
| Unit tests `test_igmp` and `test_runtime` | passed |
| AddressSanitizer and UndefinedBehaviorSanitizer on those tests | passed |
| libwireshark 4.2.6 dissection of `tests/fixtures/igmp.pcap` and `igmp.pcapng` | passed (`test_ws`, 3 IGMP frames each, truncated and TCP rejected) |
| Multi-process file-backend simulation `tests/sim/run_local.py` | passed |
| Offline `--pcap` replay | run as part of the commands below |
| Docker Compose image | not built in this environment |
| Live Cilium forwarding and cleanup | not run; no Cilium agent was available |

Logical cleanup measured by the simulation, with query interval 1000 ms, query response 100 ms, robustness 2, and last-member interval 100 ms:

- IGMPv2 leave of one subscriber on a shared attachment: gone at 200 ms, the other subscriber kept.
- Quiet subscriber after a query, pod still present: gone at 2500 ms (membership deadline 2100 ms).
- Pod deletion, IP reuse, API outage, and dry-run were checked in the same run. Dry-run performed zero mutations.

Default timers are the IGMPv2/v3 values (query interval 125 s). See `docs/OPERATIONS.md` for the resulting bounds. Those default bounds were not measured on a live cluster.

## Build

Wireshark must be exactly 4.2.6. The daemon links `libwireshark`, `libwiretap`, and `libwsutil` and refuses any other version.

```sh
sudo ./scripts/deps-debian.sh build          # or scripts/deps-rhel.sh on RHEL 9
NATIVE=0 ./scripts/build-wireshark-4.2.6.sh "$HOME/wireshark-4.2.6"
WS=$HOME/wireshark-4.2.6 ./scripts/build.sh
# binary: build/run/igmpshark
```

`NATIVE` defaults to 0. `CXX` defaults to `g++` because `/usr/bin/c++` is clang++ on some images and cannot find libstdc++.

Unit tests do not need Wireshark:

```sh
./scripts/test.sh
cmake -S . -B build -DIGMPSHARK_WITH_WIRESHARK=OFF && cmake --build build && ctest --test-dir build --output-on-failure
```

With Wireshark configured, `ctest` also runs `test_ws` against the fixtures.

Address-sanitized unit tests:

```sh
gcc -std=c11 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -fsanitize=address,undefined -I src \
  -o /tmp/test_igmp_asan src/igmp_parse.c src/engine.c src/reconcile.c tests/test_igmp.c
gcc -std=c11 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -fsanitize=address,undefined -I src \
  -o /tmp/test_runtime_asan src/igmp_parse.c src/engine.c src/reconcile.c src/backend.c \
  src/pods.c src/coord.c src/runtime.c src/query.c tests/test_runtime.c
/tmp/test_igmp_asan && /tmp/test_runtime_asan
```

## Fixtures and replay

```sh
python3 tests/fixtures/gen_pcap.py tests/fixtures
WS=$HOME/wireshark-4.2.6 ./scripts/build.sh
./build/run/test_ws tests/fixtures/igmp.pcap tests/fixtures/igmp.pcapng
./build/run/igmpshark --pcap tests/fixtures/igmp.pcap --backend file \
  --state /tmp/igmp-pcap.tsv --node-name replay --node-ip 10.0.0.1 --startup-grace-ms 0
./build/run/igmpshark --pcap tests/fixtures/igmp.pcapng --backend file \
  --state /tmp/igmp-pcapng.tsv --node-name replay --node-ip 10.0.0.1 --startup-grace-ms 0
```

## Simulation

The simulation uses the real binary, a file backend, and a shared snapshot directory. It is not Cilium.

```sh
python3 tests/sim/run_local.py ./build/run/igmpshark
```

Compose runs that same script inside the image. The image is UBI 9. Its build installs `flex`, `c-ares`, and `c-ares-devel` with dnf, then compiles Wireshark 4.2.6, and is slow:

```sh
docker build -t igmpshark:local .
docker compose -f tests/sim/compose.yaml run --rm sim
```

## Install

```sh
helm install igmpshark chart/igmpshark \
  --set image.repository=igmpshark \
  --set image.tag=local \
  --set cilium.image=quay.io/cilium/cilium:v1.19.3 \
  --set config.dryRun=true
```

Set `config.dryRun=false` only after `/metrics` shows the groups you expect. Dry-run still captures and plans; it does not call `cilium-dbg`.

Useful runtime flags: `--iface`, `--dry-run`, `--active-querier`, `--immediate-leave`, `--kube`, `--kube-coord`, `--coord-dir`, `--listen`. `igmpshark --help` lists the timers.

HTTP: `/healthz`, `/readyz` (body `degraded` while no querier is known; HTTP 200 so a missing querier does not restart the pod), `/metrics`.

## Cilium, in one paragraph

Multicast nodes are RHEL 9 running Cilium 1.19.2 or 1.19.3. Set `cilium.image` to that cluster's image (`v1.19.2` or `v1.19.3`); the chart only copies `cilium-dbg` out of it.

Three different things are easy to mix up. A pod's membership is protocol state inside igmpshark. Local forwarding is a Cilium subscriber-map entry keyed by the pod's source address and inserted by Cilium's own IGMP handler, which does not record the subscriber until the group map exists. Remote forwarding is a subscriber-map entry keyed by the other node's CiliumNode internal IP, not by a pod IP. `cilium-dbg bpf multicast subscriber add` marks the entry remote, so igmpshark never uses it for a pod address. Stale local entries are removed with `subscriber delete <group> <pod-source-ip>`. `group delete` wipes every subscriber of that group and is used only when nothing managed or unmanaged remains. Details are in `docs/CILIUM.md`.

## Layout

- `src/` protocol engine, capture, Cilium file/CLI backends, Kubernetes watch
- `chart/igmpshark` DaemonSet, ServiceAccount, RBAC
- `docs/` architecture, Cilium notes, operations
- `scripts/` Wireshark 4.2.6 build and dependency lists
- `tests/` unit tests, fixtures, multi-process simulation, cluster script

The attached `sqlshark-cursor-jsonb-promotion-races-94e7.zip` is the dbshark reference and is not part of the build. License notices for the adapted files are in `LICENSE`.
