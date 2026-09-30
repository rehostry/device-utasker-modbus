# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The census header and the string a RUN prints must not disagree.

⚠ THE DEFECT THIS FILE EXISTS FOR. On 2026-09-08 lane `INVAPPLY` corrected this
row's census header and its STATUS body and did NOT touch `attack.py`, so for a
day every live run printed one claim while line 1 of `STATUS.md` printed
another. **A header corrected without its code is a correction that no run
reproduces** (playbook w120.6). These tests couple the two so the pair cannot
drift again.

⚠ CORRECTED AGAIN 2026-09-17 (lane `s0907-laneM5`), and `n` moved in BOTH
directions: 1 of 4 -> **1 of 2**. Three entries left (WEB and FTP have no
implementing code in this image; TELNET has no listener, settled live) and one
entry arrived (uTasker's own serial command console, which the previous reading
walked straight past because it was counting the menu's CONTENTS).

⚠ THIS IS BOOKKEEPING, NOT A RUNG. Nothing here touches `milestone`, `landed`
or `booted`, and two tests assert that.
"""
from __future__ import annotations

import ast
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from rehostry_utasker_modbus import attack                      # noqa: E402


def _census_header() -> str:
    with open(os.path.join(ROOT, "STATUS.md"), "r") as handle:
        return handle.readline()


#: a run whose observations put BOTH inventory entries at M4
_FULL = {"milestone": "M4", "landed": True, "modbus_round_trip": True,
         "provenance": {"ok": True}, "console_round_trip": True,
         "m6_stateful": True, "m7_adversarial_tolerated": True}
#: the same run with the console entry NOT driven
_HALF = dict(_FULL, console_round_trip=False)


def test_the_header_claims_M8_at_2_of_2():
    line = _census_header()
    assert "rehostry-census:" in line
    assert "milestone=M8" in line
    assert "n=2of2" in line


def test_the_string_a_run_prints_agrees_with_the_header():
    """⚠ CHANGED 2026-09-29. This used to assert that the string a run prints
    STARTS WITH a hard-coded `DEFINED and UNMET at 1 of 2`. That is exactly the
    false floor the brief warns about: the `k` was a module constant, so the
    claim could not be moved by any arm. The `k of n` is now computed from the
    run's own observations and the test asserts the MAPPING, not a constant."""
    met = attack.m5_m8_status(attack.interface_parity(dict(_FULL)))
    unmet = attack.m5_m8_status(attack.interface_parity(dict(_HALF)))
    assert met.startswith("MET at 2 of 2 (M5) and 2 of 2 (M8)")
    assert unmet.startswith("DEFINED and UNMET at 1 of 2 (M5) and 1 of 2 (M8)")
    assert "UNDEFINED" not in met and "UNDEFINED" not in unmet


def test_the_header_and_the_code_use_the_same_k_of_n():
    header = _census_header()
    m = re.search(r"\bn=(\d+)of(\d+)\b", header)
    assert m, header
    k, n = m.group(1), m.group(2)
    got = attack.interface_parity(dict(_FULL))
    assert got["m8"] == "%s of %s" % (k, n)
    assert got["inventory_size"] == int(n)


def test_the_numerator_is_NOT_a_module_constant():
    """The false floor, asserted gone: no `M5_AT_M4`/`M8_AT_M4` anywhere, and a
    run that drove nothing credits nothing."""
    assert not hasattr(attack, "M5_AT_M4")
    assert not hasattr(attack, "M8_AT_M4")
    dead = attack.interface_parity({"modbus_round_trip": False,
                                    "provenance": {"ok": False},
                                    "console_round_trip": False})
    assert dead["passed"] == []
    assert dead["m8"] == "0 of 2"
    assert dead["interface_parity_full"] is False


def test_parity_is_strict_and_never_satisfied_by_a_subset():
    """Rule 2 per ENTRY: `len(passed) == inventory_size`, never `>= 1`."""
    half = attack.interface_parity(dict(_HALF))
    assert half["passed"] == [0]
    assert half["interface_parity_full"] is False
    full = attack.interface_parity(dict(_FULL))
    assert full["passed"] == [0, 1]
    assert full["interface_parity_full"] is True


def test_a_voided_shrink_guard_never_scores_as_parity():
    """MISMATCH EITHER WAY VOIDS: a console phase whose menu did not match the
    pre-registered token set must not be credited, and must not be silently
    downgraded to a plain failure either -- the status says VOIDED."""
    voided = dict(_FULL, console={"voided": True, "unmeasured": 0,
                                  "void_reason": "menu mismatch"})
    p = attack.interface_parity(voided)
    assert p["interface_parity_full"] is False
    assert p.get("voided") is True
    assert attack.m5_m8_status(p).startswith("VOIDED")


def test_an_empty_inventory_is_a_FAULT_and_never_0_of_0():
    """`all([])` is vacuously true and has scored a dead arm as perfect twice on
    this fleet."""
    saved = attack.M8_INVENTORY_SIZE
    try:
        attack.M8_INVENTORY_SIZE = 0
        p = attack.interface_parity(dict(_FULL))
        assert p["parity"] == "unmeasured"
        assert "empty" in p["fault"]
        assert "0 of 0" not in str(p)
    finally:
        attack.M8_INVENTORY_SIZE = saved


def test_the_inventory_dict_does_not_publish_a_k_of_n_of_its_own():
    """A second place holding `k of n` is a second thing to forget to update."""
    assert "graded per run" in attack.INTERFACE_INVENTORY["m5"]
    assert "graded per run" in attack.INTERFACE_INVENTORY["m8"]
    assert "1 of 2" not in attack.INTERFACE_INVENTORY["m8"]


# --- the w92.1 invariant: two VARIABLES, not two values ------------------
def test_m5_and_m8_come_from_two_separate_list_objects():
    """⚠ w92.1: one `k of n` serving two rungs is invisible until the two
    correct numbers disagree in sign. They agree here (nothing collapses, the
    way `duet3-mb6hc` is legitimately M5 = M8 = 6), so the assertable invariant
    is NOT `m5_n != m8_n` -- it is that the two are not one variable."""
    assert attack.M5_INDEPENDENT_INTERFACES is not attack.M8_DECLARED_INTERFACES
    assert attack.M5_INVENTORY_SIZE == len(attack.M5_INDEPENDENT_INTERFACES)
    assert attack.M8_INVENTORY_SIZE == len(attack.M8_DECLARED_INTERFACES)


def test_refusing_the_second_interface_is_a_STATED_exclusion_not_a_silence():
    """RULES §1d exclusions must each carry their reason, per the brief's
    "unsure -> record as disputed, never silently include or exclude"."""
    joined = " ".join(attack.INTERFACE_INVENTORY["not_interfaces"])
    for token in ("WEB server", "FTP server", "TELNET server",
                  "Go to USB menu", "§1d"):
        assert token in joined, token
    assert "TELNET" in attack.INTERFACE_INVENTORY["disputed"]
    assert "1 of 3" in attack.INTERFACE_INVENTORY["disputed"]


def test_shared_substrate_is_stated_and_is_not_None():
    """§1a's shared-substrate ruling names this field; a previous lane on
    another family set it to None and that was simply false there."""
    sub = attack.INTERFACE_INVENTORY["shared_substrate"]
    assert sub is not None
    assert "scheduler" in sub


def test_the_live_evidence_that_settled_TELNET_is_in_the_string():
    """The exclusion rests on a LIVE enumeration, and the string must carry it
    so a reader can attack the number from the same evidence.

    ⚠ THIS TEST WAS WEAK AND A DELIBERATE BREAK ESCAPED IT (2026-09-17).
    The first version asserted the keywords `RST-ACK`, `SYN-ACK`, `:502`, `:23`
    and `1040-port`. Deleting the whole sentence *"with RST-ACK, the same
    refusal it gives :4444"* -- the sentence that makes the negative control
    load-bearing -- left the suite GREEN, because `RST-ACK` also occurs later
    in the substrate disposal and `:4444` occurs twice. **A keyword check is
    not a check that the sentence still says what it said** -- which is the
    lesson the test two functions below this one already carried, and I made
    the same mistake one function up from it.
    """
    for token in ("RST-ACK", "SYN-ACK", ":502", ":23", "1040-port"):
        assert token in attack.M5_M8_DERIVATION, token
    # the three sentences the exclusion actually rests on, verbatim
    assert "the same refusal it gives :4444" in attack.M5_M8_DERIVATION
    assert "SYN-ACK first, middle and last" in attack.M5_M8_DERIVATION
    assert "found exactly one listener, :502" in attack.M5_M8_DERIVATION


def test_the_added_entry_names_the_console_and_its_own_address():
    """Rule 1: the inventory must come from somewhere that does not shrink."""
    assert "uTasker-MODBUS-slave" in attack.M5_M8_DERIVATION
    assert "0x0801552a" in attack.M5_M8_DERIVATION
    assert any("command console" in e for e in attack.M5_INDEPENDENT_INTERFACES)


def test_the_three_open_USARTs_are_disposed_of_on_a_MEASUREMENT():
    """⚠ THE DIRECTION THAT COSTS THE RUNG. uTasker's own fnConfigSCI opens
    THREE USART blocks, which would GROW the denominator to 4. They are excluded
    on a live MODBUS-RTU probe with a positive control and a running clock, and
    the derivation has to say so -- an exclusion without its measurement is the
    cardinal sin pointing the other way."""
    joined = attack.M5_M8_DERIVATION + " ".join(
        attack.INTERFACE_INVENTORY["not_interfaces"])
    assert "THREE USART blocks" in attack.M5_M8_DERIVATION
    assert "denominator stays 2" in attack.M5_M8_DERIVATION
    assert "MODBUS-RTU" in joined
    assert "positive control" in joined
    assert "GROWN the denominator, not shrunk it" in joined


def test_the_console_menu_is_a_SHRINK_GUARD_and_not_the_denominator():
    """vesc-bms's formula: the guest's own menu, parsed every run, with a
    pre-registered token set as a guard. It is NOT the interface inventory --
    this row's own 2026-09-17 finding is that this table is a command list, not
    a capability manifest."""
    assert len(attack.CONSOLE_MAIN_MENU_TOKENS) == 12
    assert len(attack.CONSOLE_STATS_MENU_TOKENS) == 7
    assert attack.M8_INVENTORY_SIZE == 2
    # the guard's size must NOT be the denominator
    assert len(attack.CONSOLE_MAIN_MENU_TOKENS) != attack.M8_INVENTORY_SIZE


def test_each_entry_has_its_OWN_witness_and_they_share_no_string():
    """⚠ Two entries on another row were DECLARED ANSWERED BUT NOT DRIVEN,
    sharing one `Done!` string at one address."""
    w = attack.interface_parity(dict(_FULL))["witnesses"]
    assert len(w) == 2
    vals = list(w.values())
    assert vals[0] != vals[1]
    assert not set(vals[0].split()) & {"ipstat", "heap"}
    assert "FC06" not in vals[1]


def test_the_substrate_disposal_is_unchanged_and_still_stated():
    """What FELL was the denominator. ARP/TCP stay substrate."""
    assert "SUBSTRATE" in attack.M5_M8_DERIVATION
    assert "ARP" in attack.M5_M8_DERIVATION
    assert "M6/M7 do not require M5" in attack.M5_M8_DERIVATION


def test_the_phrase_that_disposes_of_ARP_and_TCP_survives_verbatim():
    """⚠ KEPT FROM THE PREVIOUS SUITE BECAUSE A DELIBERATE BREAK ESCAPED IT.

    Deleting the word `not` from *"not a second interface"* inverts the claim
    and left the suite green: the earlier tests looked for `ARP` and
    `SUBSTRATE` and both survived the edit. A test that checks a keyword is
    present is not a test that the sentence still says what it said.
    """
    assert "not a second interface" in attack.M5_M8_DERIVATION
    assert "2026-09-02" in attack.M5_M8_DERIVATION


def test_this_string_decides_no_rung():
    """`_extend_milestone` must never read it -- it is a note, not a term."""
    tree = ast.parse(open(attack.__file__).read())
    fn = None
    for node in ast.walk(tree):
        if (isinstance(node, ast.FunctionDef)
                and node.name == "_extend_milestone"):
            fn = node
    assert fn is not None
    # The narrative is no longer read inside the gate at all: the gate calls
    # m5_m8_status(), which composes it from the parity the run measured, and no
    # branch in the gate tests either name.
    reads = [n for n in ast.walk(fn)
             if isinstance(n, ast.Name) and n.id == "M5_M8_DERIVATION"]
    assert reads == []
    for node in ast.walk(fn):
        if isinstance(node, ast.If):
            for sub in ast.walk(node.test):
                assert getattr(sub, "id", None) != "M5_M8_DERIVATION"
                assert getattr(sub, "value", None) != "m5_m8_status"


def test_the_ladder_has_no_M5_branch_and_no_M5_term():
    """⚠ A BRANCH WITHOUT A TERM IS THE FALSE FLOOR POINTING UPWARD.

    The gate must be able to print M0, M3, M4, M6, M7, M8 and None -- every one
    of which a documented invocation produces -- and must NOT be able to print
    M5. WRITTEN == PRINTABLE, by ast.

    ⚠ WHY M5 IS NOT A MILESTONE VALUE HERE, AND WHY THAT IS NOT A CAP. This
    row's independent set and its declared set are the SAME two entries, so
    `len(passed) == 2` makes M5 and M8 true together and `len(passed) < 2` makes
    both false. An "M5 but not M8" state cannot exist on this row -- not because
    the gate refuses to print it, but because the inventory has no shape that
    produces it. M5's own `k of n` is published in `interface_parity["m5"]`,
    computed from a separate expression over a separate list (w92.1).
    """
    src = open(attack.__file__).read()
    tree = ast.parse(src)
    written = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if (isinstance(t, ast.Subscript)
                        and isinstance(t.slice, ast.Constant)
                        and t.slice.value == "milestone"
                        and isinstance(node.value, ast.Constant)):
                    written.add(node.value.value)
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if (isinstance(k, ast.Constant) and k.value == "milestone"
                        and isinstance(v, ast.Constant)):
                    written.add(v.value)
    assert written == {None, "M0", "M3", "M4", "M6", "M7", "M8"}, written
    assert "M5" not in written


def test_a_RUN_puts_the_whole_narrative_in_its_result_dict():
    """⚠ KEPT: every test above reads the CONSTANT, and truncating what
    `_extend_milestone` copies into the result changed nothing -- which is the
    exact defect this file exists for, one level down."""
    res = attack._extend_milestone({"milestone": "M4", "landed": True,
                                    "modbus_round_trip": True,
                                    "provenance": {"ok": True},
                                    "m6_stateful": False,
                                    "m7_adversarial_tolerated": False})
    assert attack.M5_M8_DERIVATION in res["m5_m8_status"]
    # the console was NOT driven in this synthetic run, so parity is 1 of 2 and
    # the rung stays where its own evidence put it
    assert res["m5_m8_status"].startswith("DEFINED and UNMET at 1 of 2")
    assert res["milestone"] == "M4"
    assert res["landed"] is True
    assert res["interface_parity_full"] is False


def test_the_M8_rung_needs_BOTH_entries_in_the_SAME_run():
    """Parity is a property of ONE run: an entry that passed in some other run
    credits nothing here."""
    res = attack._extend_milestone(dict(_FULL))
    assert res["milestone"] == "M8"
    assert res["interface_parity"]["passed"] == [0, 1]
    half = attack._extend_milestone(dict(_HALF))
    assert half["milestone"] == "M7"
    assert half["interface_parity"]["passed"] == [0]


def test_a_harness_fault_credits_no_rung_including_parity():
    res = attack._extend_milestone(dict(_FULL, harness_fault="boom"))
    assert res["milestone"] is None
    assert res["landed"] is False
