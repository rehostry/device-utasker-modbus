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


# --------------------------------------------------------------------------
# SCB_VTOR — the one register in this window that MUST NOT be guessed
# --------------------------------------------------------------------------
SCB_VTOR = 0xE000ED08


class ScsCatchAll(AutoPeripheral):
    """AutoPeripheral for the whole System Control Space, with **SCB_VTOR
    modelled as the real read/write register it is**.

    WHY (root cause of the 2026-08-16 boot failure).  uTasker's software frame
    dispatch reads the vector table base and then indexes it (0x0800c780..0x0800c810)::

        0x0800c780  ldr   r0,[pc,...]      ; r0 = 0xe000ed08   SCB_VTOR
        0x0800c786  ldr   r4,[r0]          ; r4 = vector table base
        ...
        0x0800c806  ldr   r3,[r2]          ; r2 = 0xe000e104   NVIC_ISER1
        0x0800c808  lsls  r0,r3,#2         ;   bit 29 -> IRQ 61 = ETH, enabled?
        0x0800c80c  ldrmi r1,[r4,#0x134]   ;   yes -> RAM vector 77 = ETH handler
        0x0800c810  blxmi r1               ;   ... and call it directly

    ``fnStartTick``/``fnEnterInterrupt`` relocate the table into SRAM by writing
    **VTOR = 0x20000000** (observed at pc=0x0800c11a in the MMIO trace) and then
    install handlers there, so ``[r4 + 0x134]`` is a live SRAM word.

    The plain ``AutoPeripheral`` catch-all has no register file: an unwritten
    read returns 0, and once its *windowed busy-wait breaker* decides the
    repeated ``ldr r4,[VTOR]`` at pc=0x0800c786 is a spin (2048 of the last 8192
    reads in this window — reached in ~21 s of guest time on a quiet box) it
    starts returning **0xFFFFFFFF**.  Both are fatal the moment the very same
    breaker escalates ``NVIC_ISER1`` and makes the ``ldrmi`` predicate true:

        VTOR = 0xFFFFFFFF -> ldr [0xFFFFFFFF + 0x134] = **0x00000133** -> UC_ERR_READ_UNMAPPED
        VTOR = 0x00000000 -> ldr [0x00000134]                          -> UC_ERR_READ_UNMAPPED

    The observed crash is exactly the first one (``unmapped read at 0x133 ...
    from pc=0x800c80c``).  VTOR is a *base-address* register, not a status
    register, so the busy-wait breaker has no business rewriting it: the fix is
    to give it the architectural behaviour (write-through, read-back, low 7 bits
    reserved) and leave every other register in the window — notably the NVIC
    enable/pending aliases whose escalation drives this firmware's software ISR
    dispatch — exactly as ``AutoPeripheral`` had them.

    ``vtor_reset`` is the reset value (the config's ``machine.vector_base``),
    used until the firmware relocates the table itself.

    AND THE NVIC ENABLE/PENDING ALIASES, for the same reason.  ``model_nvic``
    (default on) additionally gives ISER/ICER/ISPR/ICPR their architectural
    set/clear-alias semantics over the whole window.  MEASURED, in this order:

      * VTOR alone: the round trip works from t=5.5 s, then the breaker
        escalates ``NVIC_ISER1`` to 0xFFFFFFFF at ~t=14 s, the ``ldrmi``
        predicate goes true on a *fabricated* enable bit, and the device stops
        answering ARP for the rest of the run.
      * with the NVIC modelled, ISER1 reads back **what the firmware actually
        wrote** -- 0x20000000 at pc=0x0800c29e, i.e. IRQ 32+29 = 61 = ETH on
        STM32F4 -- so the dispatch fires on the real enable bit and calls the
        handler the firmware installed at RAM vector 77, which is what the
        hardware would have done.

    That also removes the last thing the busy-wait breaker was silently
    deciding on this window: escalation on a *status* register is a reasonable
    guess, escalation on an interrupt-enable mask is not.
    """

    # Absolute addresses -- this model is mapped at 0xE0000000 (the whole SCS
    # window), not at the 0xE000E000 page, so offsets are not page-relative.
    NVIC_ISER, NVIC_ISER_END = 0xE000E100, 0xE000E140
    NVIC_ICER, NVIC_ICER_END = 0xE000E180, 0xE000E1C0
    NVIC_ISPR, NVIC_ISPR_END = 0xE000E200, 0xE000E240
    NVIC_ICPR, NVIC_ICPR_END = 0xE000E280, 0xE000E2C0

    def __init__(self, name: str, address: int, size: int,
                 db_path: Optional[str] = None,
                 vtor_reset: int = 0, model_nvic: bool = True,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, db_path=db_path, **kwargs)
        self.vtor = int(vtor_reset) & 0xFFFFFF80
        self.model_nvic = bool(model_nvic)
        self.enabled: Dict[int, int] = {}      # ISER/ICER index -> enable mask
        self.pending: Dict[int, int] = {}      # ISPR/ICPR index -> pending mask
        log.info("ScsCatchAll: SCB_VTOR modelled (reset 0x%08x), NVIC %s",
                 self.vtor, "modelled" if self.model_nvic else "left to AutoPeripheral")

    # ---- decode -------------------------------------------------------
    def _bank(self, addr: int):
        """-> (which, index) for a modelled NVIC register, else None."""
        if not self.model_nvic:
            return None
        reg = addr & ~0x3
        if self.NVIC_ISER <= reg < self.NVIC_ISER_END:
            return "en", (reg - self.NVIC_ISER) // 4
        if self.NVIC_ICER <= reg < self.NVIC_ICER_END:
            return "en", (reg - self.NVIC_ICER) // 4
        if self.NVIC_ISPR <= reg < self.NVIC_ISPR_END:
            return "pend", (reg - self.NVIC_ISPR) // 4
        if self.NVIC_ICPR <= reg < self.NVIC_ICPR_END:
            return "pend", (reg - self.NVIC_ICPR) // 4
        return None

    def _is_clear_alias(self, addr: int) -> bool:
        reg = addr & ~0x3
        return (self.NVIC_ICER <= reg < self.NVIC_ICER_END
                or self.NVIC_ICPR <= reg < self.NVIC_ICPR_END)

    # ---- access -------------------------------------------------------
    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        addr = self.address + offset
        shift = (addr & 0x3) * 8
        if addr & ~0x3 == SCB_VTOR:
            val = self.vtor
        else:
            bank = self._bank(addr)
            if bank is None:
                return super().hw_read(offset, size, pc=pc, **kwargs)
            which, i = bank
            val = (self.enabled if which == "en" else self.pending).get(i, 0)
        # Keep the access in the MMIO trace, then answer from the register file
        # instead of from AutoPeripheral's busy-wait breaker.
        self._record(pc, addr, size, val, "r")
        return (val >> shift) & self._mask(size)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        addr = self.address + offset
        shift = (addr & 0x3) * 8
        if addr & ~0x3 == SCB_VTOR:
            mask = self._mask(size) << shift
            new = ((self.vtor & ~mask) | ((value << shift) & mask)) & 0xFFFFFF80
            if new != self.vtor:
                log.info("ScsCatchAll: SCB_VTOR <- 0x%08x (pc=0x%08x)", new, pc)
            self.vtor = new
            self._record(pc, addr, size, value, "w")
            return True
        bank = self._bank(addr)
        if bank is None:
            return super().hw_write(offset, size, value, pc=pc, **kwargs)
        which, i = bank
        store = self.enabled if which == "en" else self.pending
        bits = (value & self._mask(size)) << shift
        # write-1-to-CLEAR on the ICER/ICPR aliases, write-1-to-SET on ISER/ISPR
        store[i] = (store.get(i, 0) & ~bits) if self._is_clear_alias(addr) \
            else (store.get(i, 0) | bits)
        self._record(pc, addr, size, value, "w")
        return True
