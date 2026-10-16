#!/usr/bin/env python3
"""Write reproducible Ethernet IGMP fixtures as classic pcap and pcapng.

The frames are built in this file. No external capture tools are required.
"""

import struct
import sys
from pathlib import Path


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(src: str, dst: str, payload: bytes) -> bytes:
    def ip(text):
        return bytes(int(p) for p in text.split("."))

    header = bytearray(20)
    header[0] = 0x45
    struct.pack_into("!H", header, 2, 20 + len(payload))
    header[8] = 1
    header[9] = 2
    header[12:16] = ip(src)
    header[16:20] = ip(dst)
    struct.pack_into("!H", header, 10, checksum(bytes(header)))
    return bytes(header) + payload


def igmp_finish(body: bytearray) -> bytes:
    struct.pack_into("!H", body, 2, checksum(bytes(body)))
    return bytes(body)


def v2_report(src: str, group: str) -> bytes:
    body = bytearray(8)
    body[0] = 0x16
    g = bytes(int(p) for p in group.split("."))
    body[4:8] = g
    payload = igmp_finish(body)
    return eth(src, group) + ipv4(src, group, payload)


def v2_query(src: str) -> bytes:
    body = bytearray(8)
    body[0] = 0x11
    body[1] = 100
    payload = igmp_finish(body)
    return eth(src, "224.0.0.1") + ipv4(src, "224.0.0.1", payload)


def v3_report(src: str) -> bytes:
    body = bytearray(8 + 8 + 12)
    body[0] = 0x22
    struct.pack_into("!H", body, 6, 2)
    body[8] = 4  # TO_EXCLUDE
    struct.pack_into("!I", body, 12, (239 << 24) | (1 << 16) | (1 << 8) | 1)
    body[16] = 3  # TO_INCLUDE
    struct.pack_into("!H", body, 18, 1)
    struct.pack_into("!I", body, 20, (239 << 24) | (1 << 16) | (1 << 8) | 2)
    struct.pack_into("!I", body, 24, (192 << 24) | (0 << 16) | (2 << 8) | 10)
    payload = igmp_finish(body)
    return eth(src, "224.0.0.22") + ipv4(src, "224.0.0.22", payload)


def eth(src: str, group: str) -> bytes:
    parts = [int(p) for p in group.split(".")]
    dst = bytes([0x01, 0x00, 0x5E, parts[1] & 0x7F, parts[2], parts[3]])
    return dst + bytes.fromhex("020000000001") + b"\x08\x00"


def tcp_frame() -> bytes:
    eth_hdr = bytes.fromhex("0200000000020200000000010800")
    payload = b"GET / HTTP/1.0\r\n\r\n"
    header = bytearray(20)
    header[0] = 0x45
    struct.pack_into("!H", header, 2, 40 + len(payload))
    header[8] = 64
    header[9] = 6
    header[12:16] = bytes([10, 1, 0, 9])
    header[16:20] = bytes([10, 1, 0, 10])
    struct.pack_into("!H", header, 10, checksum(bytes(header)))
    tcp = bytearray(20)
    struct.pack_into("!HH", tcp, 0, 12345, 80)
    tcp[12] = 5 << 4
    tcp[13] = 0x18
    return eth_hdr + bytes(header) + bytes(tcp) + payload


def truncated() -> bytes:
    return v2_report("10.1.0.5", "239.1.1.1")[:30]


def frames():
    return [
        v2_report("10.1.0.5", "239.1.1.1"),
        v3_report("10.1.0.6"),
        v2_query("10.0.0.9"),
        truncated(),
        tcp_frame(),
    ]


def write_pcap(path: Path, pkts) -> None:
    out = bytearray()
    out += struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, pkt in enumerate(pkts):
        out += struct.pack("<IIII", 1_700_000_000, i, len(pkt), len(pkt))
        out += pkt
    path.write_bytes(out)


def pad4(data: bytes) -> bytes:
    return data + b"\x00" * ((4 - (len(data) % 4)) % 4)


def write_pcapng(path: Path, pkts) -> None:
    def block(btype: int, body: bytes) -> bytes:
        total = 12 + len(body)
        if total % 4:
            body += b"\x00" * (4 - (total % 4))
            total = 12 + len(body)
        return struct.pack("<II", btype, total) + body + struct.pack("<I", total)

    shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + struct.pack("<HH", 0, 0)
    idb = struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HH", 0, 0)
    out = bytearray(block(0x0A0D0D0A, shb) + block(1, idb))
    for i, pkt in enumerate(pkts):
        body = struct.pack("<IIIII", 0, 0, i, len(pkt), len(pkt)) + pad4(pkt)
        out += block(6, body)
    path.write_bytes(out)


def main() -> None:
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    dest.mkdir(parents=True, exist_ok=True)
    pkts = frames()
    write_pcap(dest / "igmp.pcap", pkts)
    write_pcapng(dest / "igmp.pcapng", pkts)
    print(f"wrote {len(pkts)} frames to {dest}")


if __name__ == "__main__":
    main()
