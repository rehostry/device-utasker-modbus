# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Device model of the STM32F2/F4 Ethernet MAC + DMA (0x40028000 / 0x40029000).

REVERSED from the firmware's own bring-up and RX path:

  * ``fnSimulateEthernetIn`` (0x0800c77c) reads the **current RX descriptor**:

        0x0800c782  ldr.w r6,[pc,#0x6f8]   ; r6 = 0x40029014  (ETH_DMASR)
        0x0800c788  ldr   r7,[r6,#0x38]    ; r7 = *(0x4002904c) = ETH_DMACHRDR
        0x0800c78a  ldr   r0,[r7,#4]       ; descriptor word 1  <-- faulted

    With an unmodelled DMA, ``ETH_DMACHRDR`` reads 0, so the descriptor walk
    dereferences NULL (UC_ERR_READ_UNMAPPED at 0x4).

  * ``fnReadMII_PHY`` / ``fnWriteMII_PHY`` (0x0800c32c / 0x0800c342) drive the
    MII management interface (``ETH_MACMIIAR`` busy bit + ``ETH_MACMIIDR``).

THE MODEL.  A register file plus the three couplings real silicon provides, so
the firmware's own sequences complete on their own terms:

  1. **Descriptor ring ownership.**  The firmware publishes its ring bases in
     ``ETH_DMARDLAR``/``ETH_DMATDLAR``; the DMA engine's "current descriptor"
     registers (``ETH_DMACHRDR``/``ETH_DMACHTDR``) then point into those rings.
     Model them as tracking the published ring base, so a descriptor walk lands
     on the firmware's own descriptors in RAM instead of NULL.
  2. **Self-clearing busy bits.**  ``ETH_DMABMR.SR`` (software reset) and
     ``ETH_MACMIIAR.MB`` (MII busy) are set by software and cleared by hardware
     when the operation completes; clear them on read so the poll loops exit.
  3. **A link-up PHY.**  MII reads return a generic IEEE-802.3 PHY with the link
     established and auto-negotiation complete, so the driver brings the
     interface up rather than parking it in "cable unplugged".

Everything else is read-what-was-written, so configuration the driver reads back
stays coherent.  Gated by nothing: this is a plain device model.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from halucinator.peripheral_models.auto_model import AutoPeripheral

import os
_TRACE = os.environ.get("HAL_UT_ETH_TRACE") == "1"

log = logging.getLogger(__name__)

# Offsets relative to the model's base (0x40028000).
MACCR = 0x0000
MACMIIAR = 0x0010        # MII address: PA[15:11] MR[10:6] MW[1] MB[0]
MACMIIDR = 0x0014        # MII data
DMABMR = 0x1000          # bus mode; bit0 = SR (software reset)
DMARDLAR = 0x100C        # receive descriptor list address
DMATDLAR = 0x1010        # transmit descriptor list address
DMASR = 0x1014           # status
DMAOMR = 0x1018          # operation mode
DMACHTDR = 0x1048        # current host transmit descriptor
DMACHRDR = 0x104C        # current host receive descriptor
DMACHTBAR = 0x1050       # current host transmit buffer address
DMACHRBAR = 0x1054       # current host receive buffer address

MACMIIAR_MB = 1 << 0     # MII busy — hardware-cleared
DMABMR_SR = 1 << 0       # software reset — hardware-cleared

# ETH_DMASR bits [16:0] are **rc_w1** (RM0090 §33.8.14): software acknowledges an
# event by writing a 1 to its bit. `EMAC_Interrupt` (0x0800c400) depends on it:
#
#   0x0800c408  ldr r0,[r4]        ; r4 = 0x40029014 = ETH_DMASR
#   0x0800c40a  lsls r2,r0,#25     ; bit 6 = RS (receive status)
#   0x0800c40c  bpl 0x800c41c
#   0x0800c412  str r3,[r4]        ; r3 = 0x00010040 = RS|NIS -> ACKNOWLEDGE
#   0x0800c418  bl  uTaskerStateChange('E', 4)
#   0x0800c41c  ldr r0,[r4,#8] / ldr r1,[r4] / tst (r0&r1),#0x0001e7ff
#   0x0800c428  bne 0x800c408      ; ...loop while any enabled event is pending
#
# Store that 0x00010040 verbatim and RS is still set on the next pass, so the ISR
# spins on 0x0800c408 forever (MEASURED: 100% of guest time in that block plus
# uTaskerStateChange, no scheduler passes, device answers nothing).
DMASR_RC_W1 = 0x0001FFFF

# The ONE writer that must still SET the flag: `fnSimulateEthernetIn`
# (0x0800c77c..0x0800c816) is uTasker's software-reception shim, standing in for
# the DMA engine — it lands the frame in the RX descriptor and then does
# `ldr r1,[r6]; orr r1,#0x40; str r1,[r6]` at 0x0800c7e0..0x0800c7e6 to raise RS
# exactly as the DMA would. Nothing on real silicon *sets* DMASR from software,
# so this range is the stand-in for hardware, not a software acknowledgement.
SIM_RX_LO, SIM_RX_HI = 0x0800C77C, 0x0800C816

# The board's PHY is a Microchip **LAN8742A**: fnConfigEthernet reads PHYIDR1/2
# (MII regs 2 and 3), forms (PHYIDR1 << 16) | PHYIDR2, masks off the low 4
# revision bits, and compares against the literal 0x0007c130 at 0x0800d0b8:
#
#   0x0800c5e4  orr.w r0,r0,r5,lsl #16   ; ID = (reg2 << 16) | reg3
#   0x0800c5e8  lsrs  r0,r0,#4           ; drop the revision nibble
#   0x0800c5ea  lsls  r0,r0,#4
#   0x0800c5f0  cmp   r0,r1              ; r1 = 0x0007c130  (LAN8742A)
#   0x0800c5f2  beq   0x0800c5fa         ; match -> continue bring-up
#   0x0800c5f4  mov.w r0,#-1             ; MISMATCH -> abort with an error,
#                                        ; skipping the descriptor-ring setup
#
# So the PHY identity is load-bearing: with any other ID the driver bails out
# before publishing ETH_DMARDLAR/ETH_DMATDLAR and the RX descriptor walk in
# fnSimulateEthernetIn then dereferences NULL. Model the real part.
PHY_REGS = {
    0x00: 0x1000,        # BMCR: auto-negotiation enabled
    # BMSR: 100BASE-TX FD/HD + 10BASE-T FD/HD capable, autoneg complete (bit5),
    # LINK UP (bit2), autoneg capable (bit3), extended caps (bit0).
    0x01: 0x782D,
    0x02: 0x0007,        # PHYIDR1  (LAN8742A, upper half of 0x0007c130)
    0x03: 0xC130,        # PHYIDR2  (LAN8742A, lower half)
    0x04: 0x01E1,        # ANAR
    0x05: 0x45E1,        # ANLPAR: link partner able, autoneg ack
    0x06: 0x0007,        # ANER
    0x1F: 0x8000,        # LAN8742A PHY Special Control/Status: autoneg done
}


class Stm32Eth(AutoPeripheral):
    """STM32F2/F4 Ethernet MAC+DMA: descriptor rings, self-clearing busy bits,
    and a link-up PHY."""

    def __init__(self, name: str, address: int, size: int,
                 db_path: Optional[str] = None, **kwargs: Any) -> None:
        super().__init__(name, address, size, db_path=db_path, **kwargs)
        self.regs: Dict[int, int] = {}
        log.info("Stm32Eth: modeling ETH MAC+DMA @0x%08x", address)

    # ---- MII / PHY -----------------------------------------------------
    def _phy_read(self) -> int:
        """PHY register selected by the last MACMIIAR write (MR field, bits 10:6)."""
        ar = self.regs.get(MACMIIAR, 0)
        reg = (ar >> 6) & 0x1F
        return PHY_REGS.get(reg, 0x0000)

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        reg = offset & ~0x3
        if reg == MACMIIAR:
            # MII transfer completes immediately: report not-busy.
            val = self.regs.get(reg, 0) & ~MACMIIAR_MB
        elif reg == MACMIIDR:
            val = self._phy_read()
        elif reg == DMABMR:
            # The software reset completes immediately.
            val = self.regs.get(reg, 0) & ~DMABMR_SR
        elif reg in (DMACHRDR, DMACHRBAR):
            # Current RX descriptor / buffer. The DMA engine advances this as it
            # consumes the ring, and this firmware's software-reception path
            # advances it explicitly too (`str r0,[r6,#0x38]` at 0x0800c7de), so
            # an explicitly-written value must be honoured. Only fall back to the
            # ring head before anything has been published.
            val = self.regs.get(reg) or self.regs.get(DMARDLAR, 0)
        elif reg in (DMACHTDR, DMACHTBAR):
            val = self.regs.get(reg) or self.regs.get(DMATDLAR, 0)
        else:
            val = self.regs.get(reg, 0)
        if _TRACE:
            log.error("ETH rd  +0x%04x -> 0x%08x  (pc=0x%08x)", offset, val, pc)
        shift = (offset & 0x3) * 8
        return (val >> shift) & self._mask(size)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> None:
        reg = offset & ~0x3
        shift = (offset & 0x3) * 8
        mask = self._mask(size) << shift
        cur = self.regs.get(reg, 0)
        written = (value << shift) & mask
        if reg == DMASR and not (SIM_RX_LO <= pc < SIM_RX_HI):
            # Software acknowledgement: rc_w1 (see DMASR_RC_W1 above). Writes
            # from the DMA stand-in keep plain store semantics.
            self.regs[reg] = cur & ~(written & DMASR_RC_W1)
        else:
            self.regs[reg] = (cur & ~mask) | written
        if _TRACE:
            log.error("ETH wr  +0x%04x <- 0x%08x  (pc=0x%08x)", offset, value, pc)
