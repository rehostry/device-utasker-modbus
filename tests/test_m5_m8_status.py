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


def test_the_header_still_claims_defined_and_unmet_at_1_of_2():
    line = _census_header()
    assert "rehostry-census:" in line
    assert "M5-and-M8-EACH-DEFINED-and-UNMET-at-1-of-2" in line


def test_the_string_a_run_prints_agrees_with_the_header():
    assert attack.M5_M8_STATUS.startswith("DEFINED and UNMET at 1 of 2")
    assert "UNDEFINED" not in attack.M5_M8_STATUS


def test_the_header_and_the_code_use_the_same_k_of_n():
    header = _census_header()
    m = re.search(r"UNMET-at-(\d+)-of-(\d+)", header)
    assert m, header
    k, n = m.group(1), m.group(2)
    assert ("UNMET at %s of %s" % (k, n)) in attack.M5_M8_STATUS


def test_the_inventory_dict_agrees_with_the_printed_string():
    assert attack.INTERFACE_INVENTORY["m5"] in attack.M5_M8_STATUS
    assert attack.INTERFACE_INVENTORY["m8"].endswith("1 of 2")


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
        assert token in attack.M5_M8_STATUS, token
    # the three sentences the exclusion actually rests on, verbatim
    assert "the same refusal it gives :4444" in attack.M5_M8_STATUS
    assert "SYN-ACK first, middle and last" in attack.M5_M8_STATUS
    assert "found exactly one listener, :502" in attack.M5_M8_STATUS


def test_the_added_entry_names_the_console_and_its_own_address():
    """Rule 1: the inventory must come from somewhere that does not shrink."""
    assert "uTasker-MODBUS-slave" in attack.M5_M8_STATUS
    assert "0x0801552a" in attack.M5_M8_STATUS
    assert any("command console" in e for e in attack.M5_INDEPENDENT_INTERFACES)


def test_the_substrate_disposal_is_unchanged_and_still_stated():
    """What FELL was the denominator. ARP/TCP stay substrate."""
    assert "SUBSTRATE" in attack.M5_M8_STATUS
    assert "ARP" in attack.M5_M8_STATUS
    assert "M6/M7 do not require M5" in attack.M5_M8_STATUS


def test_the_phrase_that_disposes_of_ARP_and_TCP_survives_verbatim():
    """⚠ KEPT FROM THE PREVIOUS SUITE BECAUSE A DELIBERATE BREAK ESCAPED IT.

    Deleting the word `not` from *"not a second interface"* inverts the claim
    and left the suite green: the earlier tests looked for `ARP` and
    `SUBSTRATE` and both survived the edit. A test that checks a keyword is
    present is not a test that the sentence still says what it said.
    """
    assert "not a second interface" in attack.M5_M8_STATUS
    assert "2026-09-02" in attack.M5_M8_STATUS


def test_this_string_decides_no_rung():
    """`_extend_milestone` must never read it -- it is a note, not a term."""
    tree = ast.parse(open(attack.__file__).read())
    fn = None
    for node in ast.walk(tree):
        if (isinstance(node, ast.FunctionDef)
                and node.name == "_extend_milestone"):
            fn = node
    assert fn is not None
    reads = [n for n in ast.walk(fn)
             if isinstance(n, ast.Name) and n.id == "M5_M8_STATUS"]
    assert len(reads) == 1
    for node in ast.walk(fn):
        if isinstance(node, ast.If):
            for sub in ast.walk(node.test):
                assert getattr(sub, "id", None) != "M5_M8_STATUS"
                assert getattr(sub, "value", None) != "m5_m8_status"


def test_the_ladder_has_no_M5_branch_and_no_M5_term():
    """⚠ A BRANCH WITHOUT A TERM IS THE FALSE FLOOR POINTING UPWARD.

    M5 is DEFINED and UNMET here, so the gate must be able to print M0, M3, M4,
    M6, M7 and None -- and must NOT be able to print M5, because no phase of
    this run measures a second interface. WRITTEN == PRINTABLE, by ast.
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
    assert written == {None, "M0", "M3", "M4", "M6", "M7"}, written
    assert "M5" not in written
    assert '"M5"' not in src and "'M5'" not in src


def test_a_RUN_puts_the_whole_string_in_its_result_dict():
    """⚠ KEPT: every test above reads the CONSTANT, and truncating what
    `_extend_milestone` copies into the result changed nothing -- which is the
    exact defect this file exists for, one level down."""
    res = attack._extend_milestone({"milestone": "M4", "landed": True,
                                    "m6_stateful": False,
                                    "m7_adversarial_tolerated": False})
    assert res["m5_m8_status"] == attack.M5_M8_STATUS
    # and this is BOOKKEEPING: the rung is untouched by it
    assert res["milestone"] == "M4"
    assert res["landed"] is True
