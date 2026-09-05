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
