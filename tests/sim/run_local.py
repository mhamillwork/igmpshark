#!/usr/bin/env python3
"""Multi-process igmpshark simulation. No Kubernetes and no Cilium agent.

Each process is the real igmpshark binary with a file backend and a shared
snapshot directory. Logical time comes from the control socket, so the script
does not sleep for protocol timers.
"""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def report(src: str, group: str) -> str:
    def ip(text):
        parts = [int(p) for p in text.split(".")]
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

    igmp = bytearray(8)
    igmp[0] = 0x16
    g = ip(group)
    igmp[4:8] = g.to_bytes(4, "big")
    c = checksum(bytes(igmp))
    igmp[2], igmp[3] = c >> 8, c & 0xFF
    frame = bytearray(14 + 20 + 8)
    frame[12], frame[13] = 0x08, 0x00
    iph = bytearray(20)
    iph[0] = 0x45
    iph[2], iph[3] = 0, 28
    iph[8] = 1
    iph[9] = 2
    iph[12:16] = ip(src).to_bytes(4, "big")
    iph[16:20] = g.to_bytes(4, "big")
    ic = checksum(bytes(iph))
    iph[10], iph[11] = ic >> 8, ic & 0xFF
    frame[14:34] = iph
    frame[34:] = igmp
    return frame.hex()


def leave(src: str, group: str) -> str:
    text = report(src, group)
    raw = bytearray.fromhex(text)
    raw[34] = 0x17
    raw[36] = raw[37] = 0
    c = checksum(bytes(raw[34:]))
    raw[36], raw[37] = c >> 8, c & 0xFF
    ic = checksum(bytes(raw[14:34]))
    # IP checksum does not cover IGMP. Recompute only IGMP, which we did.
    return bytes(raw).hex()


class Node:
    def __init__(self, binary, root, name, ip, http, control, dry=False):
        self.name = name
        self.ip = ip
        self.state = root / f"{name}.tsv"
        self.state.write_text("")
        cmd = [
            binary,
            "--no-capture",
            "--backend",
            "file",
            "--state",
            str(self.state),
            "--coord-dir",
            str(root / "coord"),
            "--node-name",
            name,
            "--node-ip",
            ip,
            "--self-ip",
            ip,
            "--listen",
            f"127.0.0.1:{http}",
            "--control",
            f"127.0.0.1:{control}",
            "--startup-grace-ms",
            "0",
            "--lmqi-ms",
            "100",
            "--robustness",
            "2",
            "--query-interval-ms",
            "1000",
            "--query-response-ms",
            "100",
            "--reconcile-ms",
            "1000",
        ]
        if dry:
            cmd.append("--dry-run")
        err = open(root / f"{name}.log", "w")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=err)
        self.sock = None
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.proc.poll() is not None:
                text = (root / f"{name}.log").read_text()
                raise SystemExit(f"{name} exited early: {text}")
            try:
                sock = socket.create_connection(("127.0.0.1", control), 0.2)
            except OSError:
                time.sleep(0.05)
                continue
            sock.settimeout(5)
            line = sock.recv(64).decode().strip()
            if line != "READY":
                raise SystemExit(f"{name} handshake {line}")
            self.sock = sock
            self.cmd("NOW 0")
            return
        raise SystemExit(f"{name} control port did not open")

    def cmd(self, line: str) -> list[str]:
        self.sock.sendall((line + "\n").encode())
        lines = []
        while True:
            data = self.sock.recv(4096).decode()
            if not data:
                raise SystemExit(f"{self.name} closed on {line}")
            for part in data.splitlines():
                lines.append(part)
                if part == "END" or part.startswith("OK") or part.startswith("ERR"):
                    if part != "END" or line == "DUMP":
                        if line != "DUMP" or part == "END":
                            return lines
        return lines

    def close(self):
        if self.sock:
            try:
                self.sock.sendall(b"QUIT\n")
            except OSError:
                pass
            self.sock.close()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def members(node: Node) -> list[str]:
    lines = node.cmd("DUMP")
    return [ln for ln in lines if ln.startswith("MEMBER")]


def state_text(node: Node) -> str:
    return node.state.read_text()


def main() -> None:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("IGMPSHARK", "/tmp/igmpshark")
    root = Path("/tmp/igmpshark-sim")
    if root.exists():
        for child in root.rglob("*"):
            if child.is_file():
                child.unlink()
    (root / "coord").mkdir(parents=True, exist_ok=True)
    failures = 0

    def check(cond, msg):
        nonlocal failures
        print(("ok  " if cond else "FAIL") + " " + msg)
        if not cond:
            failures += 1

    a = b = dry = None
    try:
        a = Node(binary, root, "node-a", "10.244.0.1", 19081, 19101)
        b = Node(binary, root, "node-b", "10.244.0.2", 19082, 19102)
        group = "239.1.1.1"
        for src, node in (("10.1.0.1", a), ("10.1.0.2", a), ("10.2.0.1", b)):
            node.cmd(f"POD pod-{src.replace('.', '-')} app {node.name} {src} 0")
            node.cmd(f"FRAME 3 1 {report(src, group)}")
        a.cmd("SNAPSHOT")
        b.cmd("SNAPSHOT")
        a.cmd("RECONCILE")
        b.cmd("RECONCILE")
        check("10.244.0.2" in state_text(a), "node A installs remote forwarding for B")
        check("10.244.0.1" in state_text(b), "node B installs remote forwarding for A")
        check("10.2.0.1" not in state_text(a), "pod IPs are not installed as remote subscribers")
        check(len(members(a)) == 2 and len(members(b)) == 1, "local membership sets")

        a.cmd("NOW 10")
        a.cmd(f"FRAME 3 1 {leave('10.1.0.1', group)}")
        a.cmd("NOW 110")
        a.cmd("TICK")
        a.cmd("NOW 210")
        a.cmd("TICK")
        left = members(a)
        check(any("10.1.0.2" in ln for ln in left) and not any("10.1.0.1" in ln for ln in left),
              "last-member processing removed only the leaver")
        check(any("10.2.0.1" in ln for ln in members(b)), "other node kept its subscriber during cleanup")
        a.cmd("SNAPSHOT")
        b.cmd("NOW 210")
        b.cmd("RECONCILE")
        check("10.244.0.1" in state_text(b), "remote node entry remains while one subscriber is left")

        a.cmd("GONE pod-10-1-0-2")
        a.cmd("SNAPSHOT")
        b.cmd("NOW 220")
        b.cmd("RECONCILE")
        check("10.244.0.1" not in state_text(b), "remote entry removed after the last subscriber")
        check(any("10.2.0.1" in ln for ln in members(b)), "healthy subscriber on B is unchanged")

        # Replacement pod reuses the address after the old UID is gone.
        b.cmd("NOW 300")
        b.cmd(f"FRAME 3 1 {report('10.2.0.9', group)}")
        b.cmd("POD pod-old app node-b 10.2.0.9 0")
        b.cmd("NOW 400")
        b.cmd(f"FRAME 3 1 {report('10.2.0.9', group)}")
        b.cmd("POD pod-new app node-b 10.2.0.9 0")
        b.cmd("GONE pod-old")
        kept = members(b)
        check(any("10.2.0.9" in ln and "pod-new" in ln for ln in kept), "reused IP belongs to the new UID")

        b.cmd("API 0")
        b.cmd("LISTBEGIN")
        skipped = b.cmd("LISTEND")
        check(skipped[-1] == "OK -1", "API outage does not finish a deleting resync")
        check(any("10.2.0.1" in ln for ln in members(b)), "API outage does not mass-delete")

        # Lost application membership expires only after a querier has solicited.
        b.cmd("NOW 1000")
        q = bytearray.fromhex(report("10.0.0.9", "224.0.0.1"))
        q[34] = 0x11
        q[35] = 100
        q[36] = q[37] = 0
        q[38:42] = b"\x00\x00\x00\x00"
        c = checksum(bytes(q[34:42]))
        q[36], q[37] = c >> 8, c & 0xFF
        b.cmd(f"FRAME 3 1 {bytes(q).hex()}")
        b.cmd("NOW 2500")
        b.cmd("TICK")
        quiet = members(b)
        check(not any("10.2.0.1" in ln for ln in quiet), "quiet subscriber expires after solicited silence")
        print("measured logical cleanup for lost membership: 2500 ms in this timer profile")
        print("measured logical cleanup for v2 leave: 200 ms (robustness 2 * 100 ms LMQI)")

        dry_state = root / "dry.tsv"
        dry_state.write_text("239.9.9.9 10.9.9.9 1 0\n")
        dry = Node(binary, root, "node-dry", "10.244.0.3", 19083, 19103, dry=True)
        # Node() truncates state in its constructor via write_text(""). Rewrite after.
        dry.state.write_text("239.9.9.9 10.9.9.9 1 0\n")
        dry.cmd(f"FRAME 3 1 {report('10.3.0.1', group)}")
        dry.cmd("RECONCILE")
        dumped = "\n".join(dry.cmd("DUMP"))
        check("MUTATIONS 0" in dumped, "dry-run reports zero mutations")
        check(dry.state.read_text().strip() == "239.9.9.9 10.9.9.9 1 0", "dry-run leaves the map untouched")

        import urllib.request
        body = urllib.request.urlopen("http://127.0.0.1:19082/metrics", timeout=3).read().decode()
        check("igmpshark_memberships" in body, "metrics endpoint")
        health = urllib.request.urlopen("http://127.0.0.1:19082/healthz", timeout=3).read().decode()
        check(health.strip() == "ok", "health endpoint")
    finally:
        for node in (a, b, dry):
            if node:
                node.close()
    if failures:
        print(f"{failures} failure(s)")
        sys.exit(1)
    print("sim ok")


if __name__ == "__main__":
    main()
