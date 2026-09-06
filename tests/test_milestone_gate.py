# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The milestone must be DERIVED from the run, never seeded above M0.

Regression pin for a false rung measured live on 2026-09-05. `run_attack()`
seeded its result dict with `"milestone": "M1"` and returns that dict verbatim
on its failure paths, so a run with `uTaskerMODBUS.bin` moved off disk printed

    {"booted": false, "landed": false, "milestone": "M1", ...}

The fleet guard (`scratch-census-guard-a48/census_score.py`) scores that
`WALL-M1`, and the census counts an M1 device -- indistinguishable from one that
genuinely booted without faulting. That is ADVERSARIAL attack 1 ("can the
verdict pass with no firmware?") succeeding as a false RUNG rather than as a
false `landed`.

These read the source rather than booting, so they run in any interpreter and
cannot themselves be fooled by an emulator that fails to start.
"""
import ast
import inspect

from rehostry_utasker_modbus import attack


def _seed_dict():
    """The result dict `run_attack` seeds and returns on its failure paths."""
    tree = ast.parse(inspect.getsource(attack.run_attack).lstrip())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        keys = {k.value: v for k, v in zip(node.keys, node.values)
                if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        if {"booted", "landed", "milestone"} <= set(keys):
            return keys
    raise AssertionError("run_attack() no longer seeds a result dict")


def test_the_seeded_rung_is_M0_so_a_dead_arm_cannot_claim_a_rung():
    v = _seed_dict()["milestone"]
    assert isinstance(v, ast.Constant), "the seed must be a plain constant"
    assert v.value == "M0", (
        "the failure-path seed is the rung a run with NO firmware prints; "
        "anything above M0 is a rung claimed without evidence, got %r"
        % (v.value,))


def test_the_seed_is_the_honest_all_negative_state():
    keys = _seed_dict()
    for name in ("booted", "landed"):
        v = keys[name]
        assert isinstance(v, ast.Constant) and v.value is False, (
            "%s must be seeded False alongside the M0 rung" % name)


def test_the_higher_rungs_are_still_set_from_evidence():
    """The fix lowers the DEAD arm only; it does not re-grade the device.

    Every promotion below is gated on evidence the run actually produced, so a
    live run reports exactly the rung it reported before this fix.
    """
    src = inspect.getsource(attack.run_attack)
    assert 'result["milestone"] = "M3"' in src
    assert 'result["milestone"] = "M4"' in src


# ---------------------------------------------------------------- M6 / M7 --
# Structural checks on the two rungs added 2026-09-05. They do NOT assert the
# device reaches them -- only a live run does -- they assert the gate is
# CAPABLE of printing them, cannot print them without M4, and that neither knob
# is a no-op. A knob nobody flipped looks exactly like proof.

def test_the_gate_can_print_m6_and_m7_and_only_above_a_real_m4():
    live = {"milestone": "M4", "landed": True}
    assert attack._extend_milestone(
        dict(live, m6_stateful=True, m7_adversarial_tolerated=True)
    )["milestone"] == "M7"
    assert attack._extend_milestone(
        dict(live, m6_stateful=True, m7_adversarial_tolerated=False)
    )["milestone"] == "M6"
    # M7 does NOT chain off M6 -- RULES §1a, 2026-09-02.
    assert attack._extend_milestone(
        dict(live, m6_stateful=False, m7_adversarial_tolerated=True)
    )["milestone"] == "M7"
    # Neither rung may lift a run that did not reach M4. This is the same
    # defect class as the seeded "M1" above, one rung higher up.
    for extra in ({"m6_stateful": True}, {"m7_adversarial_tolerated": True},
                  {"m6_stateful": True, "m7_adversarial_tolerated": True}):
        dead = attack._extend_milestone(
            dict({"milestone": "M0", "landed": False}, **extra))
        assert dead["milestone"] == "M0" and dead["landed"] is False


def test_a_harness_fault_prints_no_rung_at_all():
    """"Could not measure" must never share a value with "measured and it was
    bad" (playbook w29.2/w37.3): a bare WALL credits nothing, an "M4" would
    have written a rung nobody measured into the census."""
    res = attack._extend_milestone({"milestone": "M4", "landed": True,
                                    "m6_stateful": True,
                                    "m7_adversarial_tolerated": True,
                                    "harness_fault": "TypeError: boom"})
    assert res["milestone"] is None and res["landed"] is False


def test_m7_classes_are_distinct_have_twins_and_name_their_source():
    """Every class needs a twin that DIFFERS (or the control arm sends the same
    bytes and cannot fail) and an honest provenance for its predicted code.
    Exactly one class here is firmware-recovered rather than spec-predicted,
    and it must say so -- a probe-derived constant presented as a spec
    prediction is Rule 1's circularity wearing a citation."""
    import random
    cls = attack.m7_classes(random.Random(7))
    assert len(cls) == 8
    assert len({c["name"] for c in cls}) == len(cls)
    assert len({c["code"] for c in cls}) >= 4, "too few distinct exception codes"
    spec = [c for c in cls if c["source"] == "modbus-spec"]
    recovered = [c for c in cls if c["source"] == "firmware-recovered"]
    assert len(spec) == 7 and len(recovered) == 1
    assert recovered[0]["name"] == "mbap_protocol_id_nonzero"
    assert "recovered by probing" in recovered[0]["spec"]
    for c in cls:
        assert c["pdu"] != c["twin"], "%s: the twin is the same frame" % c["name"]
        assert c["source"] in ("modbus-spec", "firmware-recovered")


def test_the_m6_knob_uses_the_firmwares_own_mbap_check_and_is_surgical():
    """--m6-freeze must corrupt only the STATE-CHANGING request, by a field the
    firmware itself validates -- not the read-backs, and not the predicate."""
    src = inspect.getsource(attack.run_m6)
    assert "proto=1 if freeze else 0" in src
    # The two bare read-backs must not be routed through the freeze path.
    assert src.count("_regs(sess, STABLE_REGISTER, 1)") == 2
    assert src.count("_regs(sess, RAMPING_REGISTERS[0], 5)") == 2
    assert "freeze" not in src.split("stable_a = ")[1].split("want =")[0]


def test_the_m6_invariant_is_the_pair_no_phase_writes():
    """Registers 4 and 5 are the pair, deliberately. Asserting `reg3 == -reg2`
    as well failed 3/3 rounds on 2026-09-05 -- correctly, because the M4 phase
    writes register 2 earlier in the same run and desyncs that pair. The
    invariant was real; the statement of it was wrong."""
    src = inspect.getsource(attack.run_m6)
    assert "block[3] == ((0x10000 - block[2]) & 0xFFFF)" in src
    assert "block[1] == ((0x10000 - block[0])" not in src
    # ...and the ramp witness must be read off a register no phase writes.
    assert "block_a[2] != block_b[2]" in src
    assert attack.TARGET_REGISTER == 2, (
        "if the M4 phase's target moves, re-check which pair stays synced")
