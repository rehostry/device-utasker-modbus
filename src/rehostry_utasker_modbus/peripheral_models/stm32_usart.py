# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Device model of the STM32F2/F4 USART/UART register block.

WHY THIS EXISTS.  The uTasker MODBUS-slave image carries uTasker's own serial
command console -- banner ``uTasker-MODBUS-slave  `` @0x0801552a, ``ADMIN``
@0x080154ad, ``Command line blocked`` @0x08012eb4 -- and that console is the
second entry in this row's M8 inventory (see STATUS.md, 2026-09-17).  Until this
model existed the whole 0x40000000 SoC window was ``AutoPeripheral``, so the
console's bytes went into the catch-all and nothing could be read back.

REVERSED, from the firmware's own driver (all addresses in ``uTaskerMODBUS.bin``):

  ``fnConfigSCI``  0x0800cac0..0x0800cb32   channel -> {base, RCC bit, IRQ}
      channel 0 -> 0x40011000 (USART1), RCC_APB2ENR |= 0x10, IRQ 37
      channel 1 -> 0x40004400 (USART2), RCC_APB1ENR |= 0x20000, IRQ 38
      channel 2 -> 0x40004800 (USART3), RCC_APB1ENR |= 0x40000, IRQ 39

  ``fnTxByte``     0x0800d172
      0x0800d186  ldr  r2,[r0]        ; SR
      0x0800d188  lsls r3,r2,#24      ;   bit 7  = TXE
      0x0800d18a  bpl  <busy>         ;   not empty -> return 1
      0x0800d18c  ldr  r2,[r0,#12]    ; CR1
      0x0800d18e  orr  r2,#0x80       ;   |= TXEIE
      0x0800d192  str  r2,[r0,#12]
      0x0800d194  str  r1,[r0,#4]     ; DR <- the byte

  ``USART1_IRQHandler`` 0x0800c84c  (0x0800c87e = USART2, 0x0800c8b0 = USART3)
      0x0800c85c  ldr  r0,[r4,#12]    ; CR1
      0x0800c85e  lsls r1,r0,#26      ;   bit 5  = RXNEIE
      0x0800c862  ldr  r0,[r4]        ; SR
      0x0800c864  lsls r1,r0,#26      ;   bit 5  = RXNE
      0x0800c854  ldr  r0,[r4,#4]     ; DR  -> r0
      0x0800c858  bl   0x0800c946     ; fnSciRxByte(byte, channel)
      0x0800c868  ldr  r0,[r4,#12]    ; CR1
      0x0800c86a  lsls r1,r0,#24      ;   bit 7  = TXEIE
      0x0800c86e  ldr  r0,[r4]        ; SR
      0x0800c870  lsls r1,r0,#24      ;   bit 7  = TXE
      0x0800c876  bl   0x0800f460     ; fnSciTxByte(channel)

so the register semantics this model owes the firmware are exactly:

  +0x00 SR   TXE(7) and TC(6) set -- our transmitter is never busy;
             RXNE(5) set while a host byte is queued for this sub-block.
  +0x04 DR   read  -> pop the queued host byte (clears RXNE, as the hardware
                      does on a DR read);
             write -> one transmitted byte, appended to the capture buffer.
  +0x08 BRR, +0x0c CR1, +0x10 CR2, +0x14 CR3, +0x18 GTPR
             plain write-through / read-back, so the driver reads back exactly
             the configuration it wrote (notably CR1.UE/TXEIE/RXNEIE, which is
             what the ISR above branches on).

NOTHING IS SYNTHESISED ON THE FIRMWARE'S BEHALF.  This model only mints the
*wire* condition ("a byte arrived", "the transmitter is empty").  Every byte in
and out passes through the firmware's own driver: `fnSciRxByte` for input and
`fnSciTxByte`/`fnTxByte` for output.  Cf. RULES 1c -- the host mints the wire
field, the firmware does the transform.

ONE MODEL, SEVERAL UARTS.  STM32 USARTs sit on a 0x400 stride, so one mapped
page can hold more than one of them (USART1 @+0x000 and USART6 @+0x400 in page
0x40011000; USART2 @+0x400, USART3 @+0x800, UART4 @+0xc00 in page 0x40004000).
Each 0x400 sub-block gets its own register file, RX queue and TX capture, keyed
by its absolute base address, and `INSTANCES` lets the console bridge reach them
without the framework having to hand out references.

Env knobs (diagnostic only):
  HAL_UT_UART_TRACE=1   log every register access
  HAL_UT_UART_EVENTS=1  log UE/TXEIE/RXNEIE transitions and TX/RX bytes
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from halucinator.peripheral_models.auto_model import AutoPeripheral

log = logging.getLogger(__name__)

STRIDE = 0x400          # STM32 USART register-block stride

SR = 0x00
DR = 0x04
BRR = 0x08
CR1 = 0x0C
CR2 = 0x10
CR3 = 0x14
GTPR = 0x18

SR_RXNE = 1 << 5
SR_TC = 1 << 6
SR_TXE = 1 << 7

CR1_RXNEIE = 1 << 5
CR1_TXEIE = 1 << 7
CR1_TE = 1 << 3
CR1_RE = 1 << 2
CR1_UE = 1 << 13

#: absolute sub-block base -> :class:`Uart`.  Populated as pages are mapped.
INSTANCES: Dict[int, "Uart"] = {}

#: the three channels uTasker's own ``fnConfigSCI`` can select on this image.
CHANNEL_BASE = {0: 0x40011000, 1: 0x40004400, 2: 0x40004800}


class Uart:
    """One USART register block: its register file, RX queue and TX capture."""

    def __init__(self, base: int) -> None:
        self.base = base
        self.regs: Dict[int, int] = {SR: SR_TXE | SR_TC}
        self.rxq = bytearray()
        self.tx = bytearray()
        self.n_tx = 0
        self.n_rx = 0
        self.configured = False      # CR1.UE has been set at least once

    # ---- the wire, as seen by the host ------------------------------------
    def push_rx(self, data: bytes) -> None:
        self.rxq.extend(data)

    def take_tx(self) -> bytes:
        out = bytes(self.tx)
        self.tx.clear()
        return out

    def rx_pending(self) -> bool:
        return bool(self.rxq)

    # ---- the firmware's own configuration, read back ----------------------
    def cr1(self) -> int:
        return self.regs.get(CR1, 0)

    def enabled(self) -> bool:
        return bool(self.cr1() & CR1_UE)

    def rx_int_armed(self) -> bool:
        return bool(self.cr1() & CR1_RXNEIE)

    def tx_int_armed(self) -> bool:
        return bool(self.cr1() & CR1_TXEIE)


def uart(base: int) -> Optional[Uart]:
    """The :class:`Uart` for an absolute register-block base, or None."""
    return INSTANCES.get(base)


class Stm32Usart(AutoPeripheral):
    """A mapped page of one or more STM32 USART/UART register blocks."""

    def __init__(self, name: str, address: int, size: int,
                 db_path: Optional[str] = None, **kwargs: Any) -> None:
        super().__init__(name, address, size, db_path=db_path, **kwargs)
        self.page = address
        self.page_size = size
        self.trace = os.environ.get("HAL_UT_UART_TRACE") == "1"
        self.events = os.environ.get("HAL_UT_UART_EVENTS", "1") == "1"
        self.blocks: Dict[int, Uart] = {}
        for off in range(0, size, STRIDE):
            u = Uart(address + off)
            self.blocks[off] = u
            INSTANCES[address + off] = u
        log.info("Stm32Usart: modeling %d UART block(s) at 0x%08x..0x%08x",
                 len(self.blocks), address, address + size)

    # ---- helpers ----------------------------------------------------------
    def _split(self, offset: int):
        sub = (offset // STRIDE) * STRIDE
        return self.blocks[sub], (offset - sub) & ~0x3, (offset & 0x3) * 8

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        u, reg, shift = self._split(offset)
        if reg == SR:
            val = SR_TXE | SR_TC | (SR_RXNE if u.rxq else 0)
        elif reg == DR:
            if u.rxq:
                val = u.rxq.pop(0)
                u.n_rx += 1
                if self.events:
                    log.error("uart 0x%08x: firmware read RX byte 0x%02x (%r), "
                              "%d left queued", u.base, val,
                              chr(val) if 32 <= val < 127 else ".", len(u.rxq))
            else:
                val = 0
        else:
            val = u.regs.get(reg, 0)
        if self.trace:
            log.error("uart 0x%08x: rd +0x%02x = 0x%08x (pc=0x%08x)",
                      u.base, reg, val, pc)
        return (val >> shift) & self._mask(size)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> None:
        u, reg, shift = self._split(offset)
        mask = self._mask(size) << shift
        if reg == DR:
            byte = (value >> shift) & 0xFF
            u.tx.append(byte)
            u.n_tx += 1
            if self.trace:
                log.error("uart 0x%08x: TX byte 0x%02x (%r)", u.base, byte,
                          chr(byte) if 32 <= byte < 127 else ".")
            return
        if reg == SR:
            # SR is write-to-clear on real silicon; every flag this model serves
            # is recomputed on read, so a clear is a no-op rather than a store.
            return
        cur = u.regs.get(reg, 0)
        new = (cur & ~mask) | ((value << shift) & mask)
        u.regs[reg] = new
        if reg == CR1 and self.events and (cur ^ new) & (CR1_UE | CR1_TE | CR1_RE):
            if (new & CR1_UE) and not u.configured:
                u.configured = True
            log.error("uart 0x%08x: CR1 0x%04x -> 0x%04x (UE=%d TE=%d RE=%d "
                      "TXEIE=%d RXNEIE=%d) pc=0x%08x", u.base, cur, new,
                      bool(new & CR1_UE), bool(new & CR1_TE), bool(new & CR1_RE),
                      bool(new & CR1_TXEIE), bool(new & CR1_RXNEIE), pc)
        elif self.trace:
            log.error("uart 0x%08x: wr +0x%02x = 0x%08x (pc=0x%08x)",
                      u.base, reg, new, pc)
