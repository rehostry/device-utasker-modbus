# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Spawn recipe for the uTasker MODBUS-slave rehost.

Runs against the INSTALLED halucinator@dev core -- no source-tree injection. The
firmware executes the ARMv7E-M DSP multiply `smulbb` at 0x0800e63a, which the
default Cortex-M3 decoder rejects, so we pin an M4 core via HAL_CORTEXM_CPU_MODEL
(a runtime knob the dev core's unicorn backend reads). AutoPeripheral is part of
the installed core.
"""
from __future__ import annotations

import os
import sys
from typing import List, Optional

from . import paths

RUN_NAME = "utasker-modbus"
CORTEXM_CPU_MODEL = "UC_CPU_ARM_CORTEX_M4"


def spawn_argv(python: Optional[str] = None, emulator: str = "unicorn",
               overlays: Optional[List[str]] = None) -> list:
    argv = [python or sys.executable, "-m", "halucinator.main",
            "--emulator", emulator]
    for f in list(paths.CONFIG_FILES) + list(overlays or []):
        argv += ["-c", f]
    argv += ["-n", RUN_NAME]
    return argv


def spawn_cwd() -> str:
    """Run from the packaged configs dir so config basenames and the relative
    `file: uTaskerMODBUS.bin` resolve."""
    return str(paths.configs_dir())


def spawn_env(extra: Optional[dict] = None) -> dict:
    env = dict(os.environ)
    # Defensively drop the OLD source-injection knobs. A leaked HALUCINATOR_SRC
    # or PYTHONPATH pointing at an out-of-tree core would silently shadow the
    # installed dev core (halucinator@dev) and reintroduce stale-core bugs. The
    # device + core are installed editable; config/firmware paths resolve from
    # the package (see paths.py), so nothing needs to be on PYTHONPATH.
    env.pop("HALUCINATOR_SRC", None)
    env.pop("PYTHONPATH", None)
    env["PYTHONUNBUFFERED"] = "1"
    # MUST: ARMv7E-M DSP instructions (smulbb) are not in the default M3 decoder.
    # HAL_CORTEXM_CPU_MODEL is a runtime knob read by the installed dev core's
    # unicorn backend -- NOT a source-tree injection.
    env.setdefault("HAL_CORTEXM_CPU_MODEL", CORTEXM_CPU_MODEL)
    if extra:
        env.update(extra)
    return env
