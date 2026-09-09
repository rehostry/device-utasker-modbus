# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The census header and the string a RUN prints must not disagree.

⚠ THE DEFECT THIS FILE EXISTS FOR. On 2026-09-08 lane `INVAPPLY` corrected this
row's census header and its STATUS body -- M5 and M8 are each **DEFINED and
UNMET at 1 of 4**, against the firmware's own serial configuration menu, which
is verbatim in `uTaskerMODBUS.bin` at 0x109cc. It did not touch `attack.py`, so
for a day every live run printed `"m5_m8_status": "UNDEFINED: one link, one
application service..."` while line 1 of `STATUS.md` said
`DEFINED-and-UNMET-at-1-of-4`.

**A header corrected without its code is a correction that no run reproduces**
(playbook w120.6). These tests couple the two so the pair cannot drift again.

⚠ THIS IS BOOKKEEPING, NOT A RUNG. Nothing here touches `milestone`, `landed`
or `booted`, and the last test asserts that.
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


def test_the_header_still_claims_defined_and_unmet_at_1_of_4():
    line = _census_header()
    assert "rehostry-census:" in line
    assert "M5-and-M8-EACH-DEFINED-and-UNMET-at-1-of-4" in line


def test_the_string_a_run_prints_agrees_with_the_header():
    assert attack.M5_M8_STATUS.startswith("DEFINED and UNMET at 1 of 4")
    assert "UNDEFINED" not in attack.M5_M8_STATUS


def test_the_string_names_all_four_declared_services():
    for service in ("MODBUS/TCP", "FTP", "WEB", "TELNET"):
        assert service in attack.M5_M8_STATUS, service


def test_the_string_names_the_inventory_source_and_its_address():
    """Rule 1: the inventory must come from somewhere that does not shrink."""
    assert "serial configuration menu" in attack.M5_M8_STATUS
    assert "0x109cc" in attack.M5_M8_STATUS


def test_the_substrate_disposal_is_unchanged_and_still_stated():
    """What FELL was 'one application service'. ARP/TCP stay substrate."""
    assert "SUBSTRATE" in attack.M5_M8_STATUS
    assert "ARP" in attack.M5_M8_STATUS
    assert "M6/M7 do not require M5" in attack.M5_M8_STATUS


def test_the_two_denominators_are_stated_as_computed_separately():
    assert "different" in attack.M5_M8_STATUS
    assert "separately" in attack.M5_M8_STATUS


def test_the_header_and_the_code_use_the_same_k_of_n():
    header = _census_header()
    m = re.search(r"UNMET-at-(\d+)-of-(\d+)", header)
    assert m, header
    k, n = m.group(1), m.group(2)
    assert ("UNMET at %s of %s" % (k, n)) in attack.M5_M8_STATUS


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
    # it is WRITTEN into the result once, and read by no predicate
    assert len(reads) == 1
    for node in ast.walk(fn):
        if isinstance(node, ast.If):
            for sub in ast.walk(node.test):
                assert getattr(sub, "id", None) != "M5_M8_STATUS"
                assert getattr(sub, "value", None) != "m5_m8_status"


def test_the_phrase_that_disposes_of_ARP_and_TCP_survives_verbatim():
    """⚠ ADDED BECAUSE A DELIBERATE BREAK WAS NOT CAUGHT.

    Deleting the word `not` from *"not a second interface"* inverts the claim
    and left the suite green: the earlier tests looked for `ARP` and
    `SUBSTRATE` and both survived the edit. A test that checks a keyword is
    present is not a test that the sentence still says what it said.
    """
    assert "not a second interface" in attack.M5_M8_STATUS
    assert "2026-09-02" in attack.M5_M8_STATUS


def test_a_RUN_puts_the_whole_string_in_its_result_dict():
    """⚠ ADDED BECAUSE A DELIBERATE BREAK WAS NOT CAUGHT.

    Every test above reads the CONSTANT. Truncating what `_extend_milestone`
    copies into the result changed nothing, and the result is the only thing a
    run prints -- which is the exact defect this whole file exists for, one
    level down.
    """
    res = attack._extend_milestone({"milestone": "M4", "landed": True,
                                    "m6_stateful": False,
                                    "m7_adversarial_tolerated": False})
    assert res["m5_m8_status"] == attack.M5_M8_STATUS
    # and this is BOOKKEEPING: the rung is untouched by it
    assert res["milestone"] == "M4"
    assert res["landed"] is True
