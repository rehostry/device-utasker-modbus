#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Host-side Ethernet peer for the uTasker MODBUS-slave rehost.

Speaks raw Ethernet to the rehosted firmware through the frame spool that
``bp_handlers/eth_bridge.py`` services:

    <spool>/to_fw/NNN.frame   we write frames here; the bridge feeds them to the
                              firmware via its own fnSimulateEthernetIn
    <spool>/from_fw.pcap      the bridge appends every transmitted frame here
                              (2-byte big-endian length prefix + raw frame)

Implements just enough of ARP / IPv4 / TCP to complete a **real MODBUS/TCP
round-trip against the firmware's own stack**: ARP resolve -> TCP 3-way
handshake to :502 -> MBAP+PDU request -> parse the firmware's response.

Nothing about the Modbus reply is synthesised here: the request is placed on the
wire and the response bytes are whatever the firmware's `fnMODBUS` /
`fnHandleMODBUS_input` / `fnSendMODBUS_response` path produced.

Usage:
    modbus_peer.py arp                     # resolve the firmware, prove RX->TX
    modbus_peer.py fc03 [--addr N --count N]
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import time

SPOOL = os.environ.get("HAL_UT_ETH_SPOOL", "/tmp/rehostry_utasker_eth")
INBOX = os.path.join(SPOOL, "to_fw")
TXLOG = os.path.join(SPOOL, "from_fw.pcap")

# The firmware's identity, recovered from its own config/registers:
#   IP  192.168.0.3   (uTasker network parameters at flash 0x08012ea4)
#   MAC 00:00:00:00:00:00  (what it programmed into ETH_MACA0HR/LR)
FW_IP = "192.168.0.3"
FW_MAC = bytes(6)
HOST_IP = "192.168.0.99"
HOST_MAC = bytes.fromhex("deadbeef0001")
MODBUS_PORT = 502

ETH_ARP = 0x0806
ETH_IP4 = 0x0800
IPPROTO_TCP = 6


def ip2b(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def b2ip(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _seq() -> int:
    _seq.n = getattr(_seq, "n", 0) + 1
    return _seq.n


def send(frame: bytes) -> None:
    os.makedirs(INBOX, exist_ok=True)
    name = "%06d.frame" % _seq()
    tmp = os.path.join(INBOX, name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(frame)
    os.replace(tmp, os.path.join(INBOX, name))


class TxReader:
    """Incremental reader over the bridge's append-only TX stream."""

    def __init__(self) -> None:
        self.pos = os.path.getsize(TXLOG) if os.path.exists(TXLOG) else 0

    def read(self, timeout: float = 6.0):
        """Yield frames appended since the last call, waiting up to `timeout`."""
        deadline = time.time() + timeout
        out = []
        while time.time() < deadline:
            if os.path.exists(TXLOG) and os.path.getsize(TXLOG) > self.pos:
                with open(TXLOG, "rb") as fh:
                    fh.seek(self.pos)
                    blob = fh.read()
                off = 0
                while off + 2 <= len(blob):
                    (ln,) = struct.unpack_from(">H", blob, off)
                    if off + 2 + ln > len(blob):
                        break
                    out.append(blob[off + 2: off + 2 + ln])
                    off += 2 + ln
                self.pos += off
                if out:
                    return out
            time.sleep(0.15)
        return out


# ---- frame builders ----------------------------------------------------
def eth(dst: bytes, src: bytes, etype: int, payload: bytes) -> bytes:
    f = dst + src + struct.pack(">H", etype) + payload
    return f + b"\x00" * max(0, 60 - len(f))          # pad to the 60-byte minimum


def arp_request(target_ip: str) -> bytes:
    p = struct.pack(">HHBBH", 1, ETH_IP4, 6, 4, 1)
    p += HOST_MAC + ip2b(HOST_IP) + bytes(6) + ip2b(target_ip)
    return eth(b"\xff" * 6, HOST_MAC, ETH_ARP, p)


def _cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4(dst_ip: str, proto: int, payload: bytes, ident: int = 0x1234) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, 64,
                      proto, 0, ip2b(HOST_IP), ip2b(dst_ip))
    hdr = hdr[:10] + struct.pack(">H", _cksum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(dst_mac: bytes, dport: int, sport: int, seq: int, ack: int,
        flags: int, payload: bytes = b"") -> bytes:
    off_flags = (5 << 12) | flags
    t = struct.pack(">HHIIHHHH", sport, dport, seq, ack, off_flags, 8192, 0, 0)
    pseudo = ip2b(HOST_IP) + ip2b(FW_IP) + struct.pack(">BBH", 0, IPPROTO_TCP,
                                                      len(t) + len(payload))
    t = t[:16] + struct.pack(">H", _cksum(pseudo + t + payload)) + t[18:]
    return eth(dst_mac, HOST_MAC, ETH_IP4, ipv4(FW_IP, IPPROTO_TCP, t + payload))


def parse_tcp(frame: bytes):
    """-> (sport, dport, seq, ack, flags, payload) or None."""
    if len(frame) < 34 or struct.unpack(">H", frame[12:14])[0] != ETH_IP4:
        return None
    ihl = (frame[14] & 0xF) * 4
    if frame[14 + 9] != IPPROTO_TCP:
        return None
    total_len = struct.unpack(">H", frame[16:18])[0]
    t = frame[14 + ihl: 14 + total_len]
    if len(t) < 20:
        return None
    sport, dport, seq, ack, off_flags, _win, _ck, _u = struct.unpack(">HHIIHHHH", t[:20])
    doff = (off_flags >> 12) * 4
    return sport, dport, seq, ack, off_flags & 0x1FF, t[doff:]


class Session:
    """A single TCP session to the firmware's MODBUS/TCP listener.

    The firmware completes one session per boot reliably, so a sweep or an
    attack must reuse one connection rather than reconnecting per request.
    """

    def __init__(self, sport: int = 50000) -> None:
        self.rx = TxReader()
        self.sport = sport
        self.seq = 0x1000
        self.ack = 0
        self.mac = FW_MAC
        self.txn = 0

    def resolve(self, timeout: float = 8.0) -> bool:
        send(arp_request(FW_IP))
        for f in self.rx.read(timeout):
            if struct.unpack(">H", f[12:14])[0] == ETH_ARP and \
                    struct.unpack(">H", f[20:22])[0] == 2:
                self.mac = f[22:28]
                return True
        return False

    def connect(self, timeout: float = 8.0) -> bool:
        send(tcp(self.mac, MODBUS_PORT, self.sport, self.seq, 0, 0x02))
        for f in self.rx.read(timeout):
            p = parse_tcp(f)
            if p and p[0] == MODBUS_PORT and (p[4] & 0x12) == 0x12:
                self.ack = (p[2] + 1) & 0xFFFFFFFF
                self.seq += 1
                send(tcp(self.mac, MODBUS_PORT, self.sport, self.seq, self.ack, 0x10))
                return True
        return False

    def request(self, pdu: bytes, timeout: float = 8.0):
        """Send one MODBUS PDU and return the response PDU (or None)."""
        self.txn = (self.txn + 1) & 0xFFFF
        mbap = struct.pack(">HHHB", self.txn, 0, len(pdu) + 1, 1)
        send(tcp(self.mac, MODBUS_PORT, self.sport, self.seq, self.ack, 0x18,
                 mbap + pdu))
        self.seq = (self.seq + len(mbap) + len(pdu)) & 0xFFFFFFFF
        for f in self.rx.read(timeout):
            p = parse_tcp(f)
            if p and p[0] == MODBUS_PORT and p[5]:
                # ack the firmware's data so the session stays open
                self.ack = (p[2] + len(p[5])) & 0xFFFFFFFF
                send(tcp(self.mac, MODBUS_PORT, self.sport, self.seq, self.ack, 0x10))
                return p[5][7:] if len(p[5]) > 7 else b""
        return None

    def read_holding(self, addr: int, count: int = 1):
        return self.request(struct.pack(">BHH", 3, addr, count))

    def write_single(self, addr: int, value: int):
        return self.request(struct.pack(">BHH", 6, addr, value))


def decode(resp) -> str:
    if resp is None:
        return "no reply"
    if not resp:
        return "empty"
    fc = resp[0]
    if fc & 0x80:
        return "EXCEPTION 0x%02x" % (resp[1] if len(resp) > 1 else 0)
    if fc == 3 and len(resp) >= 2:
        n = resp[1]
        regs = struct.unpack(">%dH" % (n // 2), resp[2:2 + n])
        return "FC03 ok: %s" % list(regs)
    if fc == 6 and len(resp) >= 5:
        a, v = struct.unpack(">HH", resp[1:5])
        return "FC06 ok: reg %d = %d" % (a, v)
    return "fc=0x%02x %s" % (fc, resp.hex())


def do_sweep(addrs) -> int:
    """Probe several holding-register addresses over ONE session."""
    s = Session(sport=50100)
    if not s.resolve():
        print("[peer] no ARP reply", file=sys.stderr)
        return 1
    if not s.connect():
        print("[peer] no SYN-ACK", file=sys.stderr)
        return 1
    print(f"[peer] session up to {FW_IP}:{MODBUS_PORT} (mac {s.mac.hex(':')})")
    ok = 0
    for a in addrs:
        r = s.read_holding(a, 2)
        txt = decode(r)
        print(f"  addr {a:6d}: {txt}")
        if r and not (r[0] & 0x80):
            ok += 1
    print(f"[peer] {ok}/{len(addrs)} addresses returned register data")
    return 0 if ok else 1


# ---- scenarios ---------------------------------------------------------
def do_arp() -> int:
    rx = TxReader()
    print(f"[peer] ARP who-has {FW_IP}  (tell {HOST_IP})")
    send(arp_request(FW_IP))
    for f in rx.read(8.0):
        if struct.unpack(">H", f[12:14])[0] == ETH_ARP:
            op = struct.unpack(">H", f[20:22])[0]
            sha, spa = f[22:28], f[28:32]
            if op == 2 and b2ip(spa) == FW_IP:
                print(f"[peer] ARP reply: {FW_IP} is at {sha.hex(':')}  <-- firmware "
                      f"stack answered")
                return 0
            print(f"[peer] ARP op={op} from {b2ip(spa)} ({sha.hex(':')})")
    print("[peer] no ARP reply", file=sys.stderr)
    return 1


def do_fc03(addr: int, count: int, sport: int = 50000) -> int:
    rx = TxReader()
    seq = 0x1000
    dst = FW_MAC

    print(f"[peer] ARP who-has {FW_IP}")
    send(arp_request(FW_IP))
    for f in rx.read(8.0):
        if struct.unpack(">H", f[12:14])[0] == ETH_ARP and \
                struct.unpack(">H", f[20:22])[0] == 2:
            dst = f[22:28]
            print(f"[peer] firmware MAC = {dst.hex(':')}")

    print(f"[peer] TCP SYN -> {FW_IP}:{MODBUS_PORT}")
    send(tcp(dst, MODBUS_PORT, sport, seq, 0, 0x02))
    peer_seq = None
    for f in rx.read(8.0):
        p = parse_tcp(f)
        if p and p[0] == MODBUS_PORT and (p[4] & 0x12) == 0x12:
            peer_seq = p[2]
            print(f"[peer] SYN-ACK (seq=0x{peer_seq:08x})")
            break
    if peer_seq is None:
        print("[peer] no SYN-ACK — TCP did not come up", file=sys.stderr)
        return 1
    seq += 1
    send(tcp(dst, MODBUS_PORT, sport, seq, (peer_seq + 1) & 0xFFFFFFFF, 0x10))

    # MBAP: txn=1 proto=0 len=6 unit=1 ; PDU: FC03 addr count
    pdu = struct.pack(">BHH", 3, addr, count)
    req = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu
    print(f"[peer] MODBUS FC03 addr={addr} count={count}  ({req.hex()})")
    send(tcp(dst, MODBUS_PORT, sport, seq, (peer_seq + 1) & 0xFFFFFFFF, 0x18, req))

    for f in rx.read(10.0):
        p = parse_tcp(f)
        if not p or p[0] != MODBUS_PORT or not p[5]:
            continue
        resp = p[5]
        print(f"[peer] MODBUS response: {resp.hex()}")
        if len(resp) >= 9 and resp[7] == 3:
            n = resp[8]
            regs = struct.unpack(">%dH" % (n // 2), resp[9:9 + n])
            print(f"[peer] *** FC03 OK — {n} bytes, registers: {list(regs)} ***")
            return 0
        if len(resp) >= 9 and resp[7] & 0x80:
            print(f"[peer] MODBUS exception 0x{resp[8]:02x} (a valid protocol reply)")
            return 0
    print("[peer] no MODBUS response", file=sys.stderr)
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("arp", help="ARP-resolve the firmware (proves RX -> stack -> TX)")
    sw = sub.add_parser("sweep", help="probe holding-register addresses over one session")
    sw.add_argument("--addrs", default="0,1,2,4,8,16,100,1000,4096,40001")
    f = sub.add_parser("fc03", help="full MODBUS/TCP FC03 round-trip")
    f.add_argument("--addr", type=int, default=0)
    f.add_argument("--count", type=int, default=4)
    f.add_argument("--sport", type=int, default=50000,
                   help="host TCP source port (vary it to open a fresh session)")
    a = ap.parse_args()
    if a.cmd == "arp":
        return do_arp()
    if a.cmd == "sweep":
        return do_sweep([int(x) for x in a.addrs.split(",") if x.strip()])
    return do_fc03(a.addr, a.count, a.sport)


if __name__ == "__main__":
    raise SystemExit(main())
