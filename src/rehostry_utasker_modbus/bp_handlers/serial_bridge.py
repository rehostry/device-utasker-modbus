# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Host <-> firmware serial bridge for the uTasker MODBUS-slave rehost.

This drives the second entry of this row's M8 inventory: uTasker's OWN serial
command console.  It is the exact analogue of ``eth_bridge``, one layer down --
where that one hands frames to ``fnSimulateEthernetIn``, this one makes the
*wire* condition true in ``peripheral_models/stm32_usart.py`` and then calls the
firmware's OWN USART interrupt handler, so every byte in and out is moved by the
firmware's own driver:

    host byte -> Stm32Usart RX FIFO (SR.RXNE goes true)
              -> USARTn_IRQHandler   (the address the FIRMWARE installed in its
                                      own RAM vector table -- see below)
              -> reads CR1 / SR / DR through the model
              -> fnSciRxByte(byte, channel)  0x0800c946   (uTasker's input queue)
              -> the console task parses it and calls fnDebugMsg
              -> fnSciTxByte(channel)        0x0800f460
              -> fnTxByte                    0x0800d172   -> USART DR
              -> Stm32Usart TX capture -> host

NOTHING IS SYNTHESISED.  The host supplies only the received byte; the reply is
composed entirely inside the guest, and the model never writes a reply byte of
its own.

WHY CALLING THE ISR IS FAITHFUL, AND HOW THAT IS CHECKED AT RUN TIME.  This is a
partial flash image with no IRQ vectors (see utasker_config.yaml), so the core
cannot deliver IRQ 37/38/39 to a handler.  uTasker relocates its vector table
into SRAM at 0x20000000 (``main`` @0x0800c11a writes VTOR) and ``fnConfigSCI``
installs its own USART handler there.  Before the first injection this bridge
READS that table back and checks that the address it is about to call is the one
the firmware itself installed:

    vector for IRQ n  =  [0x20000000 + 0x40 + 4*n]

If the firmware's own table names a different handler, the bridge logs the
mismatch and refuses to inject rather than calling an address of our choosing.

Transport, as with ``eth_bridge``: plain files in the same spool directory.
    <spool>/tty_in/<seq>_<base>.bytes    bytes waiting to be received
    <spool>/tty_out_<base>.bin           append-only stream of transmitted bytes

Env:
  HAL_UT_TTY        "0" disables the bridge entirely (the M8 falsification knob
                    is a harness flag, not this; see attack.py --console-deaf)
  HAL_UT_TTY_DEAF   "1" ingests host bytes into the model's RX FIFO but NEVER
                    calls the firmware's ISR -- the inert-control check
  HAL_UT_ETH_SPOOL  spool directory (shared with eth_bridge)
"""
from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, List, Optional

from ..peripheral_models import stm32_usart

log = logging.getLogger(__name__)

#: the three USART interrupt handlers in this image, keyed by register-block base.
#: Recovered from the firmware (see stm32_usart.py's header) and CHECKED against
#: the firmware's own RAM vector table before the first injection.
ISR_FOR: Dict[int, int] = {
    0x40011000: 0x0800C84C,      # USART1, channel 0, IRQ 37
    0x40004400: 0x0800C87E,      # USART2, channel 1, IRQ 38
    0x40004800: 0x0800C8B0,      # USART3, channel 2, IRQ 39
}
IRQ_FOR: Dict[int, int] = {0x40011000: 37, 0x40004400: 38, 0x40004800: 39}
CHANNEL_FOR: Dict[int, int] = {0x40011000: 0, 0x40004400: 1, 0x40004800: 2}

RAM_VECTOR_BASE = 0x20000000     # the table `main` relocates to and VTOR points at
FN_SCI_RX_BYTE = 0x0800C946      # uTasker's own "a byte arrived" driver entry
FN_SCI_TX_BYTE = 0x0800F460      # uTasker's own "send the next queued byte"

#: how many TX-drain ISR calls to allow after each burst of host input before
#: going quiet again.  Bounded on purpose: an unbounded drain would call the ISR
#: forever whenever the driver leaves TXEIE set, which would perturb every other
#: seam in the run.
DRAIN_BUDGET = 64


class SerialBridge:
    """Moves bytes between the host spool and the firmware's own serial driver."""

    def __init__(self, spool: str) -> None:
        self.spool = spool
        self.inbox = os.path.join(spool, "tty_in")
        os.makedirs(self.inbox, exist_ok=True)
        self.enabled = os.environ.get("HAL_UT_TTY", "1") != "0"
        self.deaf = os.environ.get("HAL_UT_TTY_DEAF") == "1"
        self.drain: Dict[int, int] = {b: 0 for b in ISR_FOR}
        self.n_isr: Dict[int, int] = {b: 0 for b in ISR_FOR}
        self.n_in: Dict[int, int] = {b: 0 for b in ISR_FOR}
        self.n_out: Dict[int, int] = {b: 0 for b in ISR_FOR}
        self.vector_tries = 0
        self.vector_ok: Dict[int, bool] = {}
        self.rx_hits = 0
        self.tx_hits = 0

    # ---- the firmware's own vector table, read back --------------------
    def check_vectors(self, uc: Any) -> None:
        """Confirm the handler we are about to call is the one the FIRMWARE
        installed for that IRQ in its own relocated vector table.

        Re-checked until every entry agrees (the table is filled by the firmware
        during its own bring-up, so an early read can legitimately see zeros); a
        single early failure must not latch the bridge off for the whole run.
        """
        if all(self.vector_ok.get(b) for b in ISR_FOR) or self.vector_tries > 500:
            return
        first = self.vector_tries == 0
        self.vector_tries += 1
        for base, isr in ISR_FOR.items():
            if self.vector_ok.get(base):
                continue
            addr = RAM_VECTOR_BASE + 0x40 + 4 * IRQ_FOR[base]
            try:
                word = int.from_bytes(bytes(uc.mem_read(addr, 4)), "little")
            except Exception as exc:                       # noqa: BLE001
                log.error("serial_bridge: cannot read IRQ %d vector at 0x%08x: %s",
                          IRQ_FOR[base], addr, exc)
                self.vector_ok[base] = False
                continue
            ok = (word & ~1) == isr
            self.vector_ok[base] = ok
            if ok or first:
                log.error("serial_bridge: IRQ %d vector [0x%08x] = 0x%08x, calling "
                          "0x%08x -- firmware's own handler: %s",
                          IRQ_FOR[base], addr, word, isr, "YES" if ok else "NO")

    # ---- host -> firmware ----------------------------------------------
    def _ingest(self) -> None:
        try:
            names = sorted(n for n in os.listdir(self.inbox) if n.endswith(".bytes"))
        except OSError:
            return
        for n in names:
            p = os.path.join(self.inbox, n)
            try:
                with open(p, "rb") as fh:
                    data = fh.read()
                os.remove(p)
            except OSError:
                continue
            try:
                base = int(n.split("_")[-1].split(".")[0], 16)
            except ValueError:
                continue
            u = stm32_usart.uart(base)
            if u is None or not data:
                continue
            u.push_rx(data)
            self.n_in[base] = self.n_in.get(base, 0) + len(data)
            self.drain[base] = DRAIN_BUDGET
            log.error("serial_bridge: queued %d byte(s) for 0x%08x (%r)",
                      len(data), base, data[:32])

    # ---- firmware -> host ----------------------------------------------
    def flush(self) -> None:
        for base in ISR_FOR:
            u = stm32_usart.uart(base)
            if u is None:
                continue
            out = u.take_tx()
            if not out:
                continue
            self.n_out[base] = self.n_out.get(base, 0) + len(out)
            path = os.path.join(self.spool, "tty_out_%08x.bin" % base)
            try:
                with open(path, "ab") as fh:
                    fh.write(out)
            except OSError as exc:
                log.error("serial_bridge: TX spool write failed: %s", exc)
            log.error("serial_bridge: 0x%08x transmitted %d byte(s): %r",
                      base, len(out), out[:64])

    # ---- the scheduler-loop safe point ---------------------------------
    def step(self, uc: Any, inject: Callable[..., None]) -> bool:
        """Do at most ONE unit of serial work.  Returns True if it borrowed the
        CPU (in which case the caller must not inject anything else)."""
        if not self.enabled:
            return False
        self.flush()
        self._ingest()
        if self.deaf:
            return False
        self.check_vectors(uc)
        # (1) a queued host byte is waiting: deliver it through the firmware's ISR.
        for base in _order():
            u = stm32_usart.uart(base)
            if u is None or not u.rx_pending():
                continue
            if not self.vector_ok.get(base, False):
                continue
            inject(uc, ISR_FOR[base])
            self.n_isr[base] = self.n_isr.get(base, 0) + 1
            return True
        # (2) the driver has output queued (it set TXEIE itself): let the ISR
        #     drain it, for a bounded number of calls per input burst.
        for base in _order():
            u = stm32_usart.uart(base)
            if u is None or not u.tx_int_armed() or self.drain.get(base, 0) <= 0:
                continue
            if not self.vector_ok.get(base, False):
                continue
            self.drain[base] -= 1
            inject(uc, ISR_FOR[base])
            self.n_isr[base] = self.n_isr.get(base, 0) + 1
            return True
        return False

    def stats(self) -> Dict[str, Any]:
        return {
            "isr_calls": {"0x%08x" % b: n for b, n in self.n_isr.items() if n},
            "bytes_in": {"0x%08x" % b: n for b, n in self.n_in.items() if n},
            "bytes_out": {"0x%08x" % b: n for b, n in self.n_out.items() if n},
            "fnSciRxByte_entries": self.rx_hits,
            "fnSciTxByte_entries": self.tx_hits,
            "vector_ok": {"0x%08x" % b: v for b, v in self.vector_ok.items()},
        }


def _order() -> List[int]:
    return list(ISR_FOR)
