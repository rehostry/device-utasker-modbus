# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Structural checks that do not need the (non-redistributed) firmware image."""
from __future__ import annotations

import pathlib
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONFIGS = ROOT / "src" / "rehostry_utasker_modbus" / "configs"
sys.path.insert(0, str(ROOT / "src"))


def test_firmware_is_not_committed():
    """The uTasker image is the vendor's; it must never be in the tree."""
    assert not list(ROOT.rglob("*.bin.committed"))
    gi = (ROOT / ".gitignore").read_text()
    for pat in ("*.bin", "*.out", "*.elf"):
        assert pat in gi, f"{pat} must be git-ignored"


def test_config_parses_and_pins_the_recovered_entry():
    cfg = yaml.safe_load((CONFIGS / "utasker_config.yaml").read_text())
    m = cfg["machine"]
    assert m["arch"] == "cortex-m3"          # unicorn's M-profile decoder
    assert m["entry_addr"] == 0x08015ECD     # vector[1], Thumb bit set
    assert m["init_sp"] == 0x2002FFFC        # vector[0]
    assert m["vector_base"] == 0x0800C080


def test_memory_and_peripheral_regions_are_4k_aligned_and_disjoint():
    cfg = yaml.safe_load((CONFIGS / "utasker_config.yaml").read_text())
    spans = []
    for group in ("memories", "peripherals"):
        for name, r in (cfg.get(group) or {}).items():
            base, size = r["base_addr"], r["size"]
            assert base % 0x1000 == 0, f"{name} base not 4k-aligned"
            assert size % 0x1000 == 0, f"{name} size not a 4k multiple"
            spans.append((base, base + size, name))
    spans.sort()
    for (a0, a1, an), (b0, _b1, bn) in zip(spans, spans[1:]):
        assert a1 <= b0, f"{an} overlaps {bn}"


def test_models_import_and_declare_the_reversed_constants():
    # The models subclass AutoPeripheral, which lives on the rehostry/core-patches
    # HALucinator core (see README "Core dependency"). Without it on PYTHONPATH
    # there is nothing to assert against, so skip rather than fail.
    pytest.importorskip("halucinator.peripheral_models.auto_model",
                        reason="needs the rehostry/core-patches HALucinator core")
    from rehostry_utasker_modbus.peripheral_models import (  # noqa: PLC0415
        cortex_m_scs, stm32_eth, stm32_rcc,
    )
    # RCC: the enable->ready pairs the firmware polls (HSERDY 17, PLLRDY 25)
    assert stm32_rcc.CR_READY_FOR[16] == 17
    assert stm32_rcc.CR_READY_FOR[24] == 25
    # ETH: the exact PHY the driver insists on (LAN8742A, 0x0007c130)
    assert (stm32_eth.PHY_REGS[0x02] << 16 | stm32_eth.PHY_REGS[0x03]) == 0x0007C130
    # SCS: NVIC set/clear register windows
    assert cortex_m_scs.ISER0 == 0x100 and cortex_m_scs.ICPR0 == 0x280


def test_overlays_reference_real_handlers():
    pytest.importorskip("halucinator.bp_handlers.bp_handler",
                        reason="needs the rehostry/core-patches HALucinator core")
    for name in ("probe_overlay.yaml", "eth_bridge_overlay.yaml"):
        ov = yaml.safe_load((CONFIGS / name).read_text())
        for inter in ov["intercepts"]:
            mod, cls = inter["class"].rsplit(".", 1)
            imported = __import__(mod, fromlist=[cls])
            assert hasattr(imported, cls), f"{name}: missing {cls}"
