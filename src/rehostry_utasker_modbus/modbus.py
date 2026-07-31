# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Raw-Ethernet MODBUS/TCP client for the uTasker rehost.

The rehosted firmware has no host TCP/IP stack behind it: frames are exchanged
with it through the spool that ``bp_handlers/eth_bridge.py`` services (RX via the
firmware's own ``fnSimulateEthernetIn``, TX observed at ``fnStartEthTx``). So a
client has to speak Ethernet/ARP/IPv4/TCP itself -- that is what this module is.

Just enough of each layer to hold a real MODBUS/TCP session against the firmware's
own stack: ARP resolve, TCP 3-way handshake to :502, then MBAP+PDU requests with
sequence/ack tracking so several requests share one connection (the firmware
completes one session per boot reliably, so reconnecting per request does not
work).

Nothing about a MODBUS reply is synthesised here -- responses are the bytes the
firmware's ``fnHandleMODBUS_input`` / ``fnSendMODBUS_response`` path produced.

The slave's holding-register map was probed with ``Session.read_holding``:
**registers 2..6 exist** (0,1 and >=7 answer exception 0x02 ILLEGAL DATA ADDRESS),
and their low bits are live -- they track device state rather than being static.
"""
from __future__ import annotations

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




def reg_value(resp):
    """First holding-register value out of an FC03 response (None on exception)."""
    if not resp or (resp[0] & 0x80) or len(resp) < 4:
        return None
    n = resp[1]
    if n < 2:
        return None
    return struct.unpack(">H", resp[2:4])[0]


def drain_inbox() -> int:
    """Discard frames queued for the firmware (used between connect attempts)."""
    n = 0
    try:
        for name in os.listdir(INBOX):
            if name.endswith(".frame"):
                try:
                    os.remove(os.path.join(INBOX, name))
                    n += 1
                except OSError:
                    pass
    except OSError:
        pass
    return n
