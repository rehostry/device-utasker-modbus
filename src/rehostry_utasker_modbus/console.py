# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Host-side client for uTasker's OWN serial command console.

The rendezvous is the same spool directory ``bp_handlers/eth_bridge.py`` and
``bp_handlers/serial_bridge.py`` service -- there is no socket on this device:

    <spool>/tty_in/<seq>_<base>.bytes   bytes for the firmware to receive
    <spool>/tty_out_<base>.bin          bytes the firmware transmitted

``base`` is the USART register-block base.  Which block carries the console is
**not** assumed: `probe_channels` asks the firmware, by sending the same bytes to
each opened block and seeing which one answers.

⚠ QUIESCENCE, NOT A BUDGET.  `read_until_quiet` waits for the reply to STOP
GROWING and reports whether it hit its ceiling.  A probe that stops a fixed
number of seconds after the last byte it happened to see has already produced
five false failures on this fleet (DEVICE-PLAYBOOK: "never let a run budget
classify"), so the ceiling is recorded in the result and a result that hit it is
flagged rather than scored.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

#: a uTasker menu line: a short command token, at least two spaces, a
#: description.  Anything indented is a heading, and `===...` is the rule under
#: the title, so neither can be mistaken for a command.
_MENU_LINE = re.compile(r"^(\S{1,12})[ ]{2,}(\S.*)$")

#: the three USART register blocks uTasker's own ``fnConfigSCI`` opens on this
#: image (see peripheral_models/stm32_usart.py).
USART1 = 0x40011000
USART2 = 0x40004400
USART3 = 0x40004800
BLOCKS = (USART1, USART2, USART3)

SPOOL = os.environ.get("HAL_UT_ETH_SPOOL", "/tmp/rehostry_utasker_eth")
_seq = [0]


def set_spool(path: str) -> str:
    global SPOOL
    SPOOL = path
    os.makedirs(os.path.join(SPOOL, "tty_in"), exist_ok=True)
    return SPOOL


def _inbox() -> str:
    return os.path.join(SPOOL, "tty_in")


def out_path(base: int) -> str:
    return os.path.join(SPOOL, "tty_out_%08x.bin" % base)


def send(base: int, data: bytes) -> None:
    """Queue bytes for the firmware to receive on ``base``."""
    os.makedirs(_inbox(), exist_ok=True)
    _seq[0] += 1
    tmp = os.path.join(_inbox(), ".tmp%d" % _seq[0])
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.rename(tmp, os.path.join(_inbox(), "%04d_%08x.bytes" % (_seq[0], base)))


def read_all(base: int) -> bytes:
    try:
        with open(out_path(base), "rb") as fh:
            return fh.read()
    except OSError:
        return b""


def mark(base: int) -> int:
    """Current length of the firmware's transmit stream on ``base``."""
    return len(read_all(base))


def read_until_quiet(base: int, since: int, quiet: float = 4.0,
                     ceiling: float = 40.0,
                     poll: float = 0.25) -> Tuple[bytes, str]:
    """Everything transmitted after ``since`` once it stops growing.

    Returns ``(bytes, status)`` where status is one of:

    * ``"quiet"``    -- bytes arrived and then stopped for ``quiet`` seconds.
                        This is the only status whose bytes are a COMPLETE reply.
    * ``"silent"``   -- nothing arrived at all within ``ceiling``.  A real
                        outcome (the firmware chose not to answer), NOT a
                        measurement failure -- but it is its own status, never
                        folded into "the answer was empty".
    * ``"growing"``  -- still arriving when ``ceiling`` expired.  The reply is
                        INCOMPLETE and must be treated as unmeasured.  A caller
                        that scores this as the answer has let a run budget do
                        the classifying, which has produced five false failures
                        on this fleet.
    """
    t0 = time.monotonic()
    last_len = mark(base)
    last_change = time.monotonic()
    while True:
        time.sleep(poll)
        n = mark(base)
        now = time.monotonic()
        grew = n != last_len
        if grew:
            last_len = n
            last_change = now
        if n > since and now - last_change >= quiet:
            return read_all(base)[since:], "quiet"
        if now - t0 >= ceiling:
            if n == since:
                return b"", "silent"
            return read_all(base)[since:], "growing" if grew else "quiet"


def ask(base: int, line: bytes, quiet: float = 4.0,
        ceiling: float = 40.0) -> Tuple[bytes, str]:
    """Send ``line`` and return what the firmware transmitted in reply."""
    since = mark(base)
    send(base, line)
    return read_until_quiet(base, since, quiet=quiet, ceiling=ceiling)


def probe_channels(probe: bytes = b"\r",
                   quiet: float = 4.0,
                   ceiling: float = 30.0) -> Dict[int, bytes]:
    """Ask every opened USART block the same question; return what each said.

    This is how the console's register block is IDENTIFIED rather than assumed:
    the blocks are byte-identical from the host's side, and only the firmware
    decides which of them has an application behind it.

    ⚠ ONE WINDOW FOR ALL THREE, on purpose. An earlier version waited on each
    block in turn, so a silent block was observed in a DIFFERENT window from the
    answering one and its silence could always have been "we stopped watching too
    early" -- a run budget doing the classifying. Here all three are sent the
    same bytes, watched in the same window, and the window closes only once at
    least one block has answered and gone quiet. The block that answers is the
    positive control for the two that do not.
    """
    marks = {b: mark(b) for b in BLOCKS}
    for b in BLOCKS:
        send(b, probe)
    t0 = time.monotonic()
    last = dict(marks)
    last_change = time.monotonic()
    while True:
        time.sleep(0.25)
        now = mark_all()
        changed = any(now[b] != last[b] for b in BLOCKS)
        if changed:
            last = now
            last_change = time.monotonic()
        answered = any(now[b] > marks[b] for b in BLOCKS)
        if answered and time.monotonic() - last_change >= quiet:
            break
        if time.monotonic() - t0 >= ceiling:
            break
    return {b: read_all(b)[marks[b]:] for b in BLOCKS}


def mark_all() -> Dict[int, int]:
    return {b: mark(b) for b in BLOCKS}


# ---- the console's OWN published menu, parsed from the guest's bytes --------

def parse_menu(blob: bytes) -> Dict[str, str]:
    """Parse uTasker's own menu listing into {token: description}.

    The console prints one command per line as ``<token><spaces><description>``.
    Nothing here is hard-coded from the image: the tokens come out of the bytes
    the guest transmitted on this run.
    """
    out: Dict[str, str] = {}
    text = blob.decode("latin-1")
    for raw in text.replace("\r", "\n").split("\n"):
        m = _MENU_LINE.match(raw.rstrip())
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def menu_tokens(blob: bytes) -> List[str]:
    return sorted(parse_menu(blob))


# ---- the VALUES the console computes, and the firmware's own invariants -----
#
# Every inventory entry needs its own witness CARRYING A VALUE (two entries on
# another row were "declared answered but not driven", sharing one `Done!`
# string).  These two parsers read numbers the guest computed, and each comes
# with an invariant the FIRMWARE maintains between its own counters -- which a
# replayed transcript cannot satisfy against a per-run frame count.

_COUNTER = re.compile(r"^([A-Za-z][A-Za-z .]*?)\s*=\s*(\d+)\s*$")


def parse_ipstat(blob: bytes) -> Dict[str, int]:
    """``ipstat``'s Ethernet-statistics block as {label: count}."""
    out: Dict[str, int] = {}
    for raw in blob.decode("latin-1").replace("\r", "\n").split("\n"):
        m = _COUNTER.match(raw.strip())
        if m:
            out[m.group(1).strip()] = int(m.group(2))
    return out


#: ``Total Rx frames`` must equal the sum of these, and ``Total Tx frames`` the
#: sum of the Tx ones.  The labels are the firmware's own, read off the reply.
IPSTAT_RX_PARTS = ("Rx ARP", "Rx ICMP", "Rx UDP", "Rx TCP",
                   "Rx other protocols", "Foreign Rx ARP", "Foreign Rx ICMP",
                   "Foreign Rx UDP", "Foreign Rx TCP")
IPSTAT_TX_PARTS = ("ARP sent", "ICMP sent", "UDP sent", "TCP sent")


def ipstat_invariants(st: Dict[str, int]) -> Dict[str, Any]:
    """Whether the guest's own counters add up, and by how much."""
    have_rx = all(k in st for k in IPSTAT_RX_PARTS) and "Total Rx frames" in st
    have_tx = all(k in st for k in IPSTAT_TX_PARTS) and "Total Tx frames" in st
    rx_sum = sum(st.get(k, 0) for k in IPSTAT_RX_PARTS)
    tx_sum = sum(st.get(k, 0) for k in IPSTAT_TX_PARTS)
    return {
        "parsed_labels": len(st),
        "total_rx": st.get("Total Rx frames"),
        "rx_parts_sum": rx_sum if have_rx else None,
        "rx_adds_up": bool(have_rx and st["Total Rx frames"] == rx_sum),
        "total_tx": st.get("Total Tx frames"),
        "tx_parts_sum": tx_sum if have_tx else None,
        "tx_adds_up": bool(have_tx and st["Total Tx frames"] == tx_sum),
        "rx_nonzero": bool(st.get("Total Rx frames", 0) > 0),
        "tx_nonzero": bool(st.get("Total Tx frames", 0) > 0),
    }


_HEAP = re.compile(r"Free heap\s*=\s*(0x[0-9a-fA-F]+)\s*from\s*(0x[0-9a-fA-F]+)")


def parse_memory(blob: bytes) -> Dict[str, Any]:
    """``memory``'s heap report, and whether the firmware's own figures cohere."""
    m = _HEAP.search(blob.decode("latin-1"))
    if not m:
        return {"free": None, "total": None, "coherent": False}
    free = int(m.group(1), 16)
    total = int(m.group(2), 16)
    return {"free": free, "total": total, "free_hex": m.group(1),
            "total_hex": m.group(2), "coherent": 0 < free < total}


_UPTIME = re.compile(r"operating for\s+(\d+)\s+Days?\s+(\d+):(\d\d):(\d\d)")


def parse_uptime(blob: bytes) -> Optional[int]:
    """``up_time``'s figure, in seconds, or None."""
    m = _UPTIME.search(blob.decode("latin-1"))
    if not m:
        return None
    d, h, mi, s = (int(x) for x in m.groups())
    return ((d * 24 + h) * 60 + mi) * 60 + s
