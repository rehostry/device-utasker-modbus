# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Device model of the Cortex-M System Control Space page at 0xE000E000.

WHY THIS IS LOAD-BEARING.  uTasker's software frame-reception path dispatches the
Ethernet ISR *itself*, gated on the NVIC's enable state (0x0800c7ee..0x0800c810):

    ldr.w r0,[pc,...]      ; r0 = 0xe000e204   NVIC_ISPR1  (set-pending, IRQ32-63)
    ldr   r2,[r0]
    orr   r2,r2,#0x20000000;   bit 29 -> IRQ 32+29 = 61 = ETH on STM32F4
    str   r2,[r0]          ;   mark the Ethernet interrupt pending
    ldr   r0,[r0]
    str   r0,[r1]          ; r1 = 0xe000e284   NVIC_ICPR1  (clear-pending)
    ldr   r2,[pc,...]      ; r2 = 0xe000e104   NVIC_ISER1  (set-enable)
    ldr   r3,[r2]
    lsls  r0,r3,#2         ;   test bit 29 -- is the ETH interrupt ENABLED?
    itt   mi
    ldrmi.w r1,[r4,#0x134] ;     yes -> fetch the handler pointer
    blxmi r1               ;     ... and call it directly

So a received frame only reaches the stack if ``NVIC_ISER1`` **reads back** the
enable bit the driver previously wrote.  A catch-all MMIO model that returns 0
silently swallows every frame: the descriptor is filled, ``ETH_DMASR.RS`` is
raised, and then nothing ever processes it.

THE MODEL.  A register file with the NVIC's real set/clear-register semantics:

  * ``ISER[n]`` (0x100+) — write-1-to-set; a read returns the enabled mask.
  * ``ICER[n]`` (0x180+) — write-1-to-clear the enable; a read returns the same
    enabled mask (the architecture aliases them).
  * ``ISPR[n]`` (0x200+) — write-1-to-set pending; a read returns pending.
  * ``ICPR[n]`` (0x280+) — write-1-to-clear pending; a read returns pending.

Everything else in the page (SysTick, SCB/VTOR, IPR) is delegated to the
inherited ``AutoPeripheral``: its busy-wait escalation is what advances the RTOS
tick, and replacing that with a plain register file starves the scheduler (the
task loop stops dispatching entirely).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from halucinator.peripheral_models.auto_model import AutoPeripheral

log = logging.getLogger(__name__)

# Offsets within the 0xE000E000 page.
ISER0, ISER_END = 0x100, 0x140
ICER0, ICER_END = 0x180, 0x1C0
ISPR0, ISPR_END = 0x200, 0x240
ICPR0, ICPR_END = 0x280, 0x2C0


class CortexMScs(AutoPeripheral):
    """Cortex-M SCS with faithful NVIC set/clear-register aliasing."""

    def __init__(self, name: str, address: int, size: int,
                 db_path: Optional[str] = None, **kwargs: Any) -> None:
        super().__init__(name, address, size, db_path=db_path, **kwargs)
        self.regs: Dict[int, int] = {}
        self.enabled: Dict[int, int] = {}     # index -> enable mask
        self.pending: Dict[int, int] = {}     # index -> pending mask
        log.info("CortexMScs: modeling Cortex-M SCS @0x%08x", address)

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        reg = offset & ~0x3
        if ISER0 <= reg < ISER_END:
            val = self.enabled.get((reg - ISER0) // 4, 0)
        elif ICER0 <= reg < ICER_END:
            val = self.enabled.get((reg - ICER0) // 4, 0)
        elif ISPR0 <= reg < ISPR_END:
            val = self.pending.get((reg - ISPR0) // 4, 0)
        elif ICPR0 <= reg < ICPR_END:
            val = self.pending.get((reg - ICPR0) // 4, 0)
        else:
            # Everything else in the page (SysTick, SCB/VTOR, IPR) keeps the
            # inherited AutoPeripheral behaviour -- notably its busy-wait
            # escalation, which is what advances the RTOS tick. Overriding this
            # with a plain register file starves the scheduler.
            return super().hw_read(offset, size, pc=pc, **kwargs)
        shift = (offset & 0x3) * 8
        return (val >> shift) & self._mask(size)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> None:
        reg = offset & ~0x3
        shift = (offset & 0x3) * 8
        val = (value & self._mask(size)) << shift
        if ISER0 <= reg < ISER_END:
            i = (reg - ISER0) // 4
            self.enabled[i] = self.enabled.get(i, 0) | val
        elif ICER0 <= reg < ICER_END:
            i = (reg - ICER0) // 4
            self.enabled[i] = self.enabled.get(i, 0) & ~val
        elif ISPR0 <= reg < ISPR_END:
            i = (reg - ISPR0) // 4
            self.pending[i] = self.pending.get(i, 0) | val
        elif ICPR0 <= reg < ICPR_END:
            i = (reg - ICPR0) // 4
            self.pending[i] = self.pending.get(i, 0) & ~val
        else:
            super().hw_write(offset, size, value, pc=pc, **kwargs)
