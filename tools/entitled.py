# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""CHECK 3 — the rung this run is ENTITLED to, computed over its OBSERVATIONS.

⚠ Why `tools/enumerate_ladder.py` cannot do this job.  The fleet's standard
enumerator runs ``itertools.product((False, True), repeat=len(TERMS))`` and feeds
those free booleans to the ladder.  It quantifies over the ladder's **terms** and
never inspects how a term is **constructed**.  A ladder can therefore be a
perfectly correct function of its terms while a term is itself built circularly,
and the enumerator reports CLEAN either way — it did on three of four rows in one
lane, and on `nanovna-h4` and `zephyr-mqtt` the same day.

So this module does the other half: it re-derives the rung from RULES §0's own
wording applied to the run's **observations**, independently of `_ladder` /
`_extend_milestone`, and reports `credited-but-not-entitled` when the run printed
a rung its observations do not support.

For every term that gates a rung, what it is CONSTRUCTED from:

  M1  `booted`                    the child process reached its MODBUS listener;
                                  constructed from the emulator's own log and the
                                  spool, not from any rung.
  M3  a TCP session on :502       the host's own socket-level view of the
                                  firmware's SYN-ACK, via the frame spool.
  M4  `modbus_round_trip`         the FC06 read-back's HIGH BYTE equals the high
                                  byte written -> a value the firmware served;
                                  AND `provenance.ok`, which proves the guest was
                                  the child THIS process spawned on ITS private
                                  spool. Constructed from guest bytes only.
  M6  `m6.passed == m6.rounds`    per round: the attacker's value differs between
                                  two reads, register 4 ADVANCED (no phase writes
                                  it) and reg5 == -reg4 mod 2^16 at both reads.
                                  Guest state, guest arithmetic.
  M7  `m7.passed == m7.classes`   per class: the exception code is the
                                  spec-predicted one, register 6 is unchanged and
                                  a bare FC03 answers afterwards. Guest bytes.
  M8  parity                      per ENTRY, its own witness:
                                  :502 -> the M4 term above;
                                  console -> `console.passed == console.rounds`,
                                  whose per-round terms are the guest's own menu
                                  token sets, the guest's own counter-addition
                                  invariant, the guest's own heap figures, and a
                                  per-round RANDOM token refused by the guest's
                                  own parser.
                                  Parity is STRICT: len(passed) == inventory_size.

⚠ NOTE on checks 1 and 2.  On this row `landed` is constructed from
`modbus_round_trip AND provenance.ok`, and `milestone` is then derived FROM
`landed` -- so "landed without M4" and "landed disagrees with the rung" are 0 BY
CONSTRUCTION and prove nothing here. They are reported as 0 with that caveat
attached, never as a pass. This module's `credited-but-not-entitled` count is the
check that can actually fail.

Usage:
    python3 tools/entitled.py run.json [run.json ...]
    # or, from a live run:
    python3 -c "import json;from rehostry_utasker_modbus import attack;\
                print(json.dumps(attack.run_attack()))" > run.json
"""
from __future__ import annotations

import ast
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

#: RULES §0, in the order the ladder climbs.
RUNGS = ["M0", "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"]


def _phase_strict(phase: Optional[Dict[str, Any]], total_key: str) -> bool:
    """`passed == <total>` and the total is positive -- Rule 2, never `>= 1`."""
    if not isinstance(phase, dict):
        return False
    total = phase.get(total_key)
    if not isinstance(total, int) or total < 1:
        return False
    return phase.get("passed") == total


def entitled(run: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """The highest rung this run's OBSERVATIONS support, and why.

    Deliberately does NOT read `run["milestone"]`, `run["landed"]`,
    `run["interface_parity_full"]` or `run["m5_m8_status"]` -- every one of those
    is the ladder's own output, and a check that reads them is checking the
    ladder against itself.
    """
    obs: Dict[str, Any] = {}
    if run.get("harness_fault"):
        return "unmeasured", {"harness_fault": run["harness_fault"]}

    obs["booted"] = bool(run.get("booted"))
    prov = run.get("provenance") or {}
    obs["provenance_ok"] = bool(prov.get("ok"))
    obs["spawned"] = bool(prov.get("spawned"))
    obs["bridge_bound"] = bool(prov.get("bridge_bound"))

    atk = run.get("attack") or {}
    # M4 from the bytes: the read-back's high byte, recomputed here rather than
    # trusting the run's own `landed` flag for it.
    after = atk.get("after")
    wrote = atk.get("value")
    high_ok = False
    if isinstance(after, int) and isinstance(wrote, int):
        high_ok = ((after >> 8) & 0xFF) == ((wrote >> 8) & 0xFF)
    obs["m4_readback_high_byte_matches"] = high_ok
    obs["m4_write_acknowledged"] = bool(atk.get("write_acknowledged"))
    obs["m4_before"] = atk.get("before")
    obs["m4_after_hex"] = atk.get("after_hex")
    obs["m4_value_hex"] = atk.get("value_hex")
    # RECOMPUTED from the bytes, not read off `atk["landed"]`.
    m4 = bool(obs["booted"] and obs["provenance_ok"]
              and obs["m4_write_acknowledged"] and high_ok)
    obs["m4"] = m4

    m6 = _phase_strict(run.get("m6"), "rounds")
    m7 = _phase_strict(run.get("m7"), "classes")
    obs["m6_strict"] = m6
    obs["m7_strict"] = m7

    con = run.get("console")
    con_ok = _phase_strict(con, "rounds")
    if isinstance(con, dict):
        if con.get("voided") or con.get("unmeasured"):
            con_ok = False
        obs["console_voided"] = bool(con.get("voided"))
        obs["console_unmeasured"] = con.get("unmeasured")
        obs["console_block"] = con.get("console_block")
        obs["console_answering_blocks"] = con.get("answering_blocks")
        # per-round terms, re-checked here from the recorded observations
        rounds = con.get("results") or []
        obs["console_rounds_all_terms_true"] = bool(rounds) and all(
            all((r.get("terms") or {}).values()) for r in rounds
            if not r.get("unmeasured"))
        con_ok = con_ok and obs["console_rounds_all_terms_true"]
    obs["console_strict"] = con_ok

    entries = [m4, con_ok]
    obs["entries_at_m4"] = [i for i, v in enumerate(entries) if v]
    obs["inventory_size"] = len(entries)
    parity_full = m4 and con_ok and len(obs["entries_at_m4"]) == len(entries)
    obs["parity_full"] = parity_full

    if not obs["booted"]:
        return "M0", obs
    if not m4:
        return "M3", obs
    if parity_full:
        return "M8", obs
    if m7:
        return "M7", obs
    if m6:
        return "M6", obs
    return "M4", obs


def audit(run: Dict[str, Any]) -> Dict[str, Any]:
    """The three checks, with numbers."""
    ent, obs = entitled(run)
    credited = run.get("milestone")
    idx = {r: i for i, r in enumerate(RUNGS)}
    over = (credited in idx and ent in idx and idx[credited] > idx[ent])
    return {
        "credited": credited,
        "entitled": ent,
        "credited_but_not_entitled": 1 if over else 0,
        # check 1: landed without M4
        "defect_landed_without_m4": 1 if (run.get("landed")
                                          and not obs.get("m4")) else 0,
        # check 2: landed vs rung
        "landed_vs_rung_disagreement": 1 if (
            bool(run.get("landed")) != (credited in ("M4", "M6", "M7", "M8"))) else 0,
        "checks_1_and_2_are_zero_by_construction": True,
        "observations": obs,
    }


def landed_site_count(path: str) -> int:
    """How many places ASSIGN `landed`.  Asserted > 0: a run whose `landed` is
    never assigned from an observation has it derived from the rung instead, and
    then checks 1 and 2 cannot fail even in principle."""
    tree = ast.parse(open(path, "r", encoding="utf-8").read())
    n = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if (isinstance(t, ast.Subscript)
                        and isinstance(t.slice, ast.Constant)
                        and t.slice.value == "landed"):
                    n += 1
    return n


def main(argv: List[str]) -> int:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    attack_py = os.path.join(here, "src", "rehostry_utasker_modbus", "attack.py")
    sites = landed_site_count(attack_py) if os.path.exists(attack_py) else -1
    print("landed assignment sites in attack.py: %d" % sites)
    assert sites > 0, "no `result['landed'] = ...` site: landed is not observed"
    bad = 0
    for p in argv:
        with open(p, "r", encoding="utf-8") as fh:
            run = json.load(fh)
        rep = audit(run)
        bad += rep["credited_but_not_entitled"]
        print("\n== %s" % p)
        print(json.dumps(rep, indent=2, sort_keys=True))
    print("\ncredited-but-not-entitled total: %d" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
