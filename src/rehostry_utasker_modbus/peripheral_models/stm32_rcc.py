# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Device model of the STM32F2/F4 RCC (reset & clock control) at 0x40023800.

Mapped at the 4 kB page base 0x40023000 (HALucinator requires 4 kB-aligned
regions); ``PAGE_OFFSET`` accounts for RCC sitting 0x800 into that page.

REVERSED (from the firmware's own clock bring-up in ``main``, 0x0800c088):

    0x0800c0a8  str  r2,[r0]        ; RCC_CR      <- 0x83        (HSION|HSITRIM)
    0x0800c0ae  str  r4,[r0,#4]     ; RCC_PLLCFGR <- (PLL config)
    0x0800c0ca  str  r2,[r0,#8]     ; RCC_CFGR    <- 0x9400
    0x0800c0cc  ldr  r3,[r0]        ; RCC_CR
    0x0800c0ce  lsls r2,r3,#0xe     ;   test bit 17 = HSERDY
    0x0800c0d0  bpl  0x0800c0cc     ;   spin until HSE is ready
    ...
    0x0800c0f0  str  r2,[r0]        ; RCC_CR |= 0x01000000       (PLLON)
    0x0800c0f2  ldr  r3,[r0]        ; RCC_CR
    0x0800c0f4  lsls r2,r3,#6       ;   test bit 25 = PLLRDY
    0x0800c0f6  bpl  0x0800c0f2     ;   spin until the PLL locks

The literal pool at 0x0800c9f8/0x0800ca00/0x0800ca08 pins the bases as
RCC 0x40023800, FLASH 0x40023c00, PWR 0x40007000 — i.e. an STM32F2xx/F4xx.

THE MODEL.  On real silicon each clock-enable bit in ``RCC_CR`` is answered by a
matching *ready* bit once the oscillator/PLL has stabilised.  Model exactly that
coupling: a plain register file, except that a read of ``CR`` ORs in the ready
bit for every enable bit currently set.  So the firmware's own
`enable -> poll for ready` sequences complete on their own terms — no busy-wait
breaker, no forced constant, and a `CR` read still reflects precisely what the
firmware wrote.  (`AutoPeripheral`'s generic all-ones breaker is the wrong lever
here: it would also set reserved/HSEBYP bits the firmware later reads back.)

  bit 0  HSION     -> bit 1  HSIRDY
  bit 16 HSEON     -> bit 17 HSERDY
  bit 24 PLLON     -> bit 25 PLLRDY
  bit 26 PLLI2SON  -> bit 27 PLLI2SRDY
  bit 28 PLLSAION  -> bit 29 PLLSAIRDY   (F4 only; harmless on F2)

Every other RCC register keeps read-what-was-written semantics, so clock-tree
configuration the firmware reads back (PLLCFGR/CFGR/AHBENR/APBENR) is coherent.
Reset values are the STM32F4 defaults (CR = 0x00000083 -> HSI on and ready).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from halucinator.peripheral_models.auto_model import AutoPeripheral

log = logging.getLogger(__name__)

# HALucinator maps peripheral regions on 4 kB boundaries, so this model is mapped
# at the 4 kB-aligned page base 0x40023000 and RCC itself starts 0x800 into it.
PAGE_OFFSET = 0x800

CR = 0x00        # clock control      (absolute 0x40023800)
CFGR = 0x08      # clock configuration

# enable-bit -> ready-bit coupling in RCC_CR
CR_READY_FOR = {
    0: 1,        # HSION    -> HSIRDY
    16: 17,      # HSEON    -> HSERDY
    24: 25,      # PLLON    -> PLLRDY
    26: 27,      # PLLI2SON -> PLLI2SRDY
    28: 29,      # PLLSAION -> PLLSAIRDY
}

# STM32F4 reset values for the registers the bring-up path touches.
RESET_VALUES = {
    CR: 0x00000083,      # HSION | HSIRDY | HSITRIM=16
    0x04: 0x24003010,    # PLLCFGR
    CFGR: 0x00000000,
}


class Stm32Rcc(AutoPeripheral):
    """STM32F2/F4 RCC: a register file whose CR ready-bits track its enable-bits."""

    def __init__(self, name: str, address: int, size: int,
                 db_path: Optional[str] = None, **kwargs: Any) -> None:
        super().__init__(name, address, size, db_path=db_path, **kwargs)
        self.regs: Dict[int, int] = dict(RESET_VALUES)
        log.info("Stm32Rcc: modeling RCC @0x%08x (%d CR enable/ready pairs)",
                 address, len(CR_READY_FOR))

    def _ready_bits(self, cr: int) -> int:
        """CR value with the ready bit set for each enable bit that is set."""
        out = cr
        for en, rdy in CR_READY_FOR.items():
            if cr & (1 << en):
                out |= 1 << rdy
        return out

    def _sws_follows_sw(self, cfgr: int) -> int:
        """CFGR with SWS[3:2] (the clock actually in use) tracking SW[1:0] (the
        clock requested). The firmware sets SW=PLL then polls
        `(CFGR & 0xc) == 8` at 0x0800c100 to confirm the switch took effect; on
        real silicon SWS follows SW once the new source is stable."""
        return (cfgr & ~0xC) | ((cfgr & 0x3) << 2)

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        offset -= PAGE_OFFSET
        if offset < 0:                      # below RCC in the same 4 kB page
            return 0
        reg = offset & ~0x3
        val = self.regs.get(reg, 0)
        if reg == CR:
            val = self._ready_bits(val)
        elif reg == CFGR:
            val = self._sws_follows_sw(val)
        # byte/half-word reads take the addressed slice of the word
        shift = (offset & 0x3) * 8
        return (val >> shift) & self._mask(size)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> None:
        offset -= PAGE_OFFSET
        if offset < 0:
            return
        reg = offset & ~0x3
        shift = (offset & 0x3) * 8
        mask = self._mask(size) << shift
        cur = self.regs.get(reg, 0)
        self.regs[reg] = (cur & ~mask) | ((value << shift) & mask)
