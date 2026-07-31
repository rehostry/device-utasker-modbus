# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Packaged-path helpers for the uTasker MODBUS-slave rehost."""
from __future__ import annotations

from pathlib import Path

PACKAGE = "rehostry_utasker_modbus"
BASE_CONFIG = "utasker_config.yaml"
ADDRS_CONFIG = "utasker_addrs.yaml"
ETH_BRIDGE_OVERLAY = "eth_bridge_overlay.yaml"
PROBE_OVERLAY = "probe_overlay.yaml"
FIRMWARE_BIN = "uTaskerMODBUS.bin"

# Recovered from the corpus ELF (see configs/utasker_config.yaml).
ENTRY = 0x08015ECD          # reset vector | Thumb bit
INIT_SP = 0x2002FFFC
VECTOR_BASE = 0x0800C080
CONFIG_FILES = [BASE_CONFIG, ADDRS_CONFIG]


def configs_dir() -> Path:
    return Path(__file__).resolve().parent / "configs"


def firmware_bin() -> Path:
    return configs_dir() / FIRMWARE_BIN


def firmware_present() -> bool:
    return firmware_bin().is_file()
