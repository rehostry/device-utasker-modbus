# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Host <-> firmware Ethernet bridge for the uTasker MODBUS-slave rehost.

The rehost drives the firmware's real network stack (ARP -> IP -> TCP -> MODBUS
on :502) by moving Ethernet frames across the two seams the firmware itself
provides, so no frame is ever synthesised on the firmware's behalf:

RX (host -> firmware) — ``fnSimulateEthernetIn(frame_ptr, length)`` @0x0800c77c
    The driver's own software frame-reception entry point.  Reversed:
        0x0800c78a  ldr r7,[r6,#0x38]     ; r7 = ETH_DMACHRDR (cur RX descriptor)
        0x0800c7a6  adds r0,r2,#4         ; FL = length + 4 (CRC)
        0x0800c7ae  str  r3,[r7]          ; RDES0 = status | FL<<16
        0x0800c7b2  ldr  r0,[r7,#8]       ; RDES2 = buffer address
        0x0800c7b4  bl   memcpy           ; copy the frame into the RX buffer
        0x0800c7de  str  r0,[r6,#0x38]    ; advance DMACHRDR to RDES3
        0x0800c7e6  str  r1,[r6]          ; ETH_DMASR |= 0x40  (RS: frame received)
    i.e. it lands the frame in the firmware's own descriptor ring and raises the
    receive flag exactly as the DMA engine would.  We call it with a borrowed
    context (save regs -> set r0/r1 -> run to a sentinel LR -> restore).

TX (firmware -> host) — ``fnStartEthTx(length, end_ptr)`` @0x0800c816
    Observed (never intercepted): the frame is ``[end_ptr - length, end_ptr)``
    (see ``rsb ip,ip,#0`` / ``add r0,ip`` at 0x0800c832..0x0800c83c).  We copy
    those bytes out and hand them to the host.

Transport is two plain files in a spool directory (atomic rename), which keeps
the emulator and the host tool decoupled and needs no extra sockets:
    <spool>/to_fw/*.frame    frames waiting to be received by the firmware
    <spool>/from_fw.pcap     append-only stream of transmitted frames
                             (2-byte big-endian length prefix + raw frame)

Env:
  HAL_UT_ETH_SPOOL   spool directory (default /tmp/rehostry_utasker_eth)
  HAL_UT_ETH_VERBOSE =1 log every frame's first bytes
"""
from __future__ import annotations

import logging
import os
import struct
import time
from typing import Any, Optional, Tuple

from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler

log = logging.getLogger(__name__)

FN_SIMULATE_ETHERNET_IN = 0x0800C77C   # (frame_ptr, length) -> lands frame in RX ring
FN_START_ETH_TX = 0x0800C816           # (length, end_ptr)   -> frame being transmitted
# uTasker's system tick.  fnStartTick (0x0800c2c6) configures the Cortex-M SysTick
# (SYST_CSR=0xe000e010 <- 7 = ENABLE|TICKINT|CLKSOURCE, reload 0x802c7f) and installs
# _RealTimeInterrupt as the SysTick (exception 15) handler in a RAM vector table
# (str handler,[0x2000003c]; offset 0x3c = vector 15).  _RealTimeInterrupt clears
# SCB_ICSR.PENDSTCLR (0xe000ed04 bit 25) and calls fnRtmkSystemTick, which advances
# uTaskerSystemTick and fires the uTasker software timers.
#
# In the rehost the SCS window (0xE000E000) is the AutoPeripheral catch-all, so
# SysTick never counts and exception 15 never fires: fnRtmkSystemTick is never
# reached, uTaskerSystemTick is frozen, and every uTasker software timer stays
# armed forever.  The firmware is polled-task healthy until the TCP stack arms its
# first timer (right after the first MODBUS/TCP data segment), at which point the
# Ethernet/TCP task switches to timer-wait and is never rescheduled -- exactly one
# request per session, "sessions die on idle gaps", the ~25 s warm-up.
#
# There is no IRQ vector table in this partial flash image, so the core cannot
# deliver exception 15 to a valid handler.  Instead we drive the firmware's OWN
# SysTick ISR directly through the same borrowed-context seam the RX path uses --
# a faithful model of "the periodic tick fired", advancing the RTOS clock so its
# timers expire and the Ethernet/TCP task keeps being scheduled.
FN_REAL_TIME_INTERRUPT = 0x0800C2AC    # SysTick ISR: -> fnRtmkSystemTick (uTasker tick)
FN_RTMK_SYSTEM_TICK = 0x0800E86A       # the tick body itself: advance clock + fire timers
FN_EMAC_INTERRUPT = 0x0800C400         # ETH ISR: posts the RX event to task 'E' (0x45)
FN_UTASKER_STATE_CHANGE = 0x0800E6F8   # uTaskerStateChange(task_id, state): mark ready
ETH_TASK_ID = 0x45                     # 'E' -- the uTasker Ethernet task
ETH_RX_STATE = 4                       # the state EMAC_Interrupt posts (task-ready bit 2)
# uTaskerSchedule's per-task dispatch body (0x0800e690 is the function entry,
# which runs only once; 0x0800e698 is inside its task loop and therefore recurs).
# This is the periodic safe point at which a pending host frame is delivered.
TICK_PC = 0x0800E698
TRAP = 0x0800C084                      # sentinel LR: the reset vector word, never
                                       # executed as code -> a safe return trap
SCRATCH = 0x2002F000                   # frame staging buffer inside SRAM, above the
                                       # firmware's heap/rings and below init SP
                                       # (0x2002fffc); 0x400 bytes is > 1 MTU frame
SCRATCH_LEN = 0x400

GP_REGS = list(range(13))


def _spool() -> str:
    return os.environ.get("HAL_UT_ETH_SPOOL", "/tmp/rehostry_utasker_eth")


class EthBridge(BPHandler):
    def __init__(self) -> None:
        self.spool = _spool()
        self.inbox = os.path.join(self.spool, "to_fw")
        self.txlog = os.path.join(self.spool, "from_fw.pcap")
        self.verbose = os.environ.get("HAL_UT_ETH_VERBOSE") == "1"
        os.makedirs(self.inbox, exist_ok=True)
        self.installed = False
        self.n_tx = 0
        self.n_rx = 0
        self.saved: Optional[dict] = None
        self._busy = False
        # ---- keeping the uTasker RTOS alive after the handshake -----------
        # ROOT CAUSE.  This firmware's system tick is the Cortex-M SysTick
        # (exception 15): fnStartTick programs SYST_CSR/RVR and installs
        # _RealTimeInterrupt (-> fnRtmkSystemTick) as the vector-15 handler. In the
        # rehost the SCS window (0xE000E000) is the AutoPeripheral catch-all, so
        # SysTick never counts and exception 15 never fires -- the RTOS clock is
        # frozen. Separately, fnTaskEthernet (which drains the RX descriptor ring)
        # runs *continuously* during bring-up but, once the TCP connection is up,
        # switches to event-driven: it then only runs when the ETH ISR posts its RX
        # event via uTaskerStateChange('E', 4). That ISR never fires either. So after
        # the first request the Ethernet task stops consuming frames AND the clock
        # stops -- exactly the "one request per boot / sessions die on idle" wall.
        #
        # FIX (device-side, via the firmware's OWN primitives on the borrowed-context
        # seam, no core change): once the first request has been served, on the
        # scheduler-loop safe point keep BOTH alive when no frame is waiting --
        #   * re-mark the Ethernet task ready  (uTaskerStateChange('E', 4)), so it
        #     keeps draining the RX ring exactly as it did while polling; and
        #   * advance the RTOS clock          (fnRtmkSystemTick), so uTasker/TCP
        #     timers fire (delayed-ACK, retransmit, ...).
        # Both are gated to AFTER the first served request: the handshake + first
        # request already complete on the firmware's own polling, and injecting
        # either during that window perturbs it (breaks ARP/TCP). "First served" =
        # ARP reply + SYN-ACK + 1st MODBUS response = 3 TX frames.
        #
        # Wall-clock rates: the wake must be fast enough that a freshly delivered
        # frame is drained within the client's per-request timeout; the tick is kept
        # near the firmware's real ~20 Hz so TCP timers advance at a realistic pace
        # (a wildly fast clock trips TCP timeouts). Neither fires while a host frame
        # is pending, so the clock never runs ahead of actual network activity.
        self._after_tx = int(os.environ.get("HAL_UT_TICK_AFTER_TX", "3"))
        self._tick_fn = int(os.environ.get("HAL_UT_TICK_FN", str(FN_RTMK_SYSTEM_TICK)), 0)
        self._tick_hz = float(os.environ.get("HAL_UT_TICK_HZ", "20"))
        self._tick_interval = (1.0 / self._tick_hz) if self._tick_hz > 0 else 0.0
        self._last_tick = 0.0
        self.n_tick = 0
        self._isr_fn = int(os.environ.get("HAL_UT_ISR_FN", str(FN_UTASKER_STATE_CHANGE)), 0)
        self._isr_enabled = os.environ.get("HAL_UT_ISR", "1") == "1"
        _r0 = os.environ.get("HAL_UT_ISR_R0")
        _r1 = os.environ.get("HAL_UT_ISR_R1")
        self._isr_r0 = int(_r0, 0) if _r0 is not None else ETH_TASK_ID
        self._isr_r1 = int(_r1, 0) if _r1 is not None else ETH_RX_STATE
        self._wake_hz = float(os.environ.get("HAL_UT_WAKE_HZ", "200"))
        self._wake_interval = (1.0 / self._wake_hz) if self._wake_hz > 0 else 0.0
        self._last_wake = 0.0
        self._inflight: Optional[str] = None       # 'frame' | 'tick'
        # Optional free-running fallback (off by default); wall-clock Hz.
        self._tick_hz = float(os.environ.get("HAL_UT_TICK_HZ", "0"))
        self._tick_interval = (1.0 / self._tick_hz) if self._tick_hz > 0 else 0.0
        self._last_tick = 0.0
        self.n_tick = 0
        # Injecting before the driver has published its descriptor ring is fatal:
        # ETH_DMACHRDR still reads 0, so fnSimulateEthernetIn dereferences NULL and
        # the emulation dies with UC_ERR_READ_UNMAPPED. The firmware itself calls
        # fnSimulateEthernetIn periodically once its ETH driver is running, so use
        # that as the readiness signal and refuse to inject until it is seen.
        self.driver_up = False

    def register_handler(self, qemu: Any, addr: int, func_name: str, **kwargs: Any):
        return EthBridge.on_setup

    # ---- context borrow/restore (as the ION call-injection harness) -----
    def _save(self, uc) -> None:  # noqa: ANN001
        A = self._A
        s = {"gp": [uc.reg_read(getattr(A, "UC_ARM_REG_R%d" % i)) for i in GP_REGS]}
        s["sp"] = uc.reg_read(A.UC_ARM_REG_SP)
        s["lr"] = uc.reg_read(A.UC_ARM_REG_LR)
        s["pc"] = uc.reg_read(A.UC_ARM_REG_PC)
        s["cpsr"] = uc.reg_read(A.UC_ARM_REG_CPSR)
        self.saved = s

    def _restore(self, uc) -> None:  # noqa: ANN001
        A = self._A
        s = self.saved
        for i, v in zip(GP_REGS, s["gp"]):
            uc.reg_write(getattr(A, "UC_ARM_REG_R%d" % i), v)
        uc.reg_write(A.UC_ARM_REG_SP, s["sp"])
        uc.reg_write(A.UC_ARM_REG_LR, s["lr"])
        uc.reg_write(A.UC_ARM_REG_CPSR, s["cpsr"])
        # As above: PC reads back with bit0 clear, so re-assert the Thumb bit or
        # the resumed instruction decodes as ARM (UC_ERR_INSN_INVALID).
        uc.reg_write(A.UC_ARM_REG_PC, s["pc"] | 1)
        self.saved = None

    # ---- host -> firmware ----------------------------------------------
    def _next_frame(self) -> Optional[Tuple[str, bytes]]:
        try:
            names = sorted(n for n in os.listdir(self.inbox) if n.endswith(".frame"))
        except OSError:
            return None
        for n in names:
            p = os.path.join(self.inbox, n)
            try:
                with open(p, "rb") as fh:
                    data = fh.read()
                os.remove(p)
            except OSError:
                continue
            if data:
                return n, data
        return None

    def _inject_call(self, uc, func_addr: int,
                     r0: Optional[int] = None, r1: Optional[int] = None) -> None:  # noqa: ANN001
        """Borrow the CPU context and call ``func_addr`` to a sentinel LR (_trap).

        The Thumb bit MUST be set on both the target and (on restore) the resumed
        PC: this is an ARMv7-M (Thumb-only) target, and a PC with bit0 clear makes
        unicorn decode in ARM mode -> UC_ERR_INSN_INVALID at the first instruction.
        """
        A = self._A
        self._save(uc)
        if r0 is not None:
            uc.reg_write(A.UC_ARM_REG_R0, r0)
        if r1 is not None:
            uc.reg_write(A.UC_ARM_REG_R1, r1)
        uc.reg_write(A.UC_ARM_REG_LR, TRAP | 1)          # Thumb sentinel
        uc.reg_write(A.UC_ARM_REG_PC, func_addr | 1)
        self._busy = True

    def _inject_tick(self, uc) -> None:  # noqa: ANN001
        """Drive the firmware's own system-tick body (fnRtmkSystemTick, the work
        the SysTick ISR does) so the uTasker RTOS clock advances and its software
        timers fire. Without this the TCP timers (delayed-ACK / retransmit) never
        fire in the rehost, because SysTick never counts (SCS = AutoPeripheral)."""
        self._inflight = "tick"
        self._inject_call(uc, self._tick_fn)
        self.n_tick += 1
        if self.n_tick == 1:
            log.error("eth_bridge: tick inject #1 -> fnRtmkSystemTick@0x%08x "
                      "(uTasker system tick)", self._tick_fn)

    def _inject_isr(self, uc) -> None:  # noqa: ANN001
        """Drive the firmware's own ETH ISR so it posts the RX event to the
        Ethernet task (see FN_EMAC_INTERRUPT), waking it to drain the RX ring."""
        self._inflight = "isr"
        self._inject_call(uc, self._isr_fn, r0=self._isr_r0, r1=self._isr_r1)
        self.n_isr = getattr(self, "n_isr", 0) + 1
        if self.n_isr == 1:
            log.error("eth_bridge: RX-wake inject #1 -> uTaskerStateChange"
                      "(0x%02x, %d) (marks Ethernet task ready)",
                      self._isr_r0, self._isr_r1)

    def _inject(self, uc) -> None:  # noqa: ANN001
        """Stage a pending host frame and call the firmware's own RX entry point."""
        if not self.driver_up:
            return                            # ring not published yet -> unsafe
        got = self._next_frame()
        if got is None:
            return
        name, frame = got
        frame = frame[:SCRATCH_LEN]
        uc.mem_write(SCRATCH, frame)
        self._inflight = "frame"
        self._inject_call(uc, FN_SIMULATE_ETHERNET_IN, r0=SCRATCH, r1=len(frame))
        self.n_rx += 1
        log.error("eth_bridge: RX inject #%d %s (%d bytes) -> fnSimulateEthernetIn",
                  self.n_rx, name, len(frame))

    # ---- firmware -> host ----------------------------------------------
    def _capture_tx(self, uc) -> None:  # noqa: ANN001
        A = self._A
        length = uc.reg_read(A.UC_ARM_REG_R0) & 0xFFFFFFFF
        end = uc.reg_read(A.UC_ARM_REG_R1) & 0xFFFFFFFF
        if not (0 < length <= 1600) or end < length:
            return
        try:
            frame = bytes(uc.mem_read(end - length, length))
        except Exception:  # noqa: BLE001
            return
        self.n_tx += 1
        try:
            with open(self.txlog, "ab") as fh:
                fh.write(struct.pack(">H", len(frame)) + frame)
        except OSError as exc:
            log.error("eth_bridge: TX spool write failed: %s", exc)
        if self.verbose or self.n_tx <= 8:
            eth_type = struct.unpack(">H", frame[12:14])[0] if len(frame) >= 14 else 0
            log.error("eth_bridge: TX #%d len=%d ethertype=0x%04x dst=%s src=%s",
                      self.n_tx, len(frame), eth_type,
                      frame[0:6].hex(":"), frame[6:12].hex(":"))

    @bp_handler(["on_setup"])
    def on_setup(self, qemu: Any, addr: int) -> Tuple[bool, Any]:
        if self.installed:
            return False, None
        uc = getattr(qemu, "_uc", None)
        if uc is None:
            return False, None
        try:
            import unicorn
            from unicorn import arm_const as A
            self._A = A

            def _tx(uc_, address, size, ud):  # noqa: ANN001
                self._capture_tx(uc_)

            def _rx_entry(uc_, address, size, ud):  # noqa: ANN001
                # Any call into fnSimulateEthernetIn that is NOT ours proves the
                # driver is up and its RX descriptor ring is live.
                if not self._busy and not self.driver_up:
                    self.driver_up = True
                    log.error("eth_bridge: ETH driver is live -- injection enabled")

            def _trap(uc_, address, size, ud):  # noqa: ANN001
                # An injected call (frame RX or tick ISR) returned into our sentinel
                # -> put the firmware back exactly where we borrowed it. After a
                # delivered frame, queue a short tick burst so the RTOS clock steps
                # forward enough to wake the timer-waiting Ethernet/TCP task.
                if self._busy and self.saved is not None:
                    self._restore(uc_)
                    self._busy = False
                    self._inflight = None

            def _tick(uc_, address, size, ud):  # noqa: ANN001
                # Scheduler-loop safe point. Never act while a borrowed call is in
                # flight. Priority: (1) drain queued ticks so uTasker timers fire and
                # the Ethernet/TCP task is rescheduled; (2) optional free-running
                # tick fallback; (3) deliver one pending host frame.
                if self._busy or self.saved is not None or not self.driver_up:
                    return
                # (a) deliver a pending host frame first (sets _busy if one was queued).
                self._inject(uc_)
                if self._busy:
                    return
                # After the first served request the ETH/TCP task stops polling and
                # its RTOS clock is frozen. Keep both alive via the firmware's own
                # primitives, free-running (only when no frame is waiting):
                if self.n_tx < self._after_tx:
                    return
                now = time.monotonic()
                # (b) re-mark the Ethernet task ready so it keeps draining the RX ring.
                if (self._isr_enabled and self._wake_interval > 0.0
                        and now - self._last_wake >= self._wake_interval):
                    self._last_wake = now
                    self._inject_isr(uc_)
                    return
                # (c) advance the RTOS clock so uTasker/TCP timers fire.
                if (self._tick_interval > 0.0
                        and now - self._last_tick >= self._tick_interval):
                    self._last_tick = now
                    self._inject_tick(uc_)

            uc.hook_add(unicorn.UC_HOOK_CODE, _tx,
                        begin=FN_START_ETH_TX, end=FN_START_ETH_TX)
            uc.hook_add(unicorn.UC_HOOK_CODE, _rx_entry,
                        begin=FN_SIMULATE_ETHERNET_IN, end=FN_SIMULATE_ETHERNET_IN)
            uc.hook_add(unicorn.UC_HOOK_CODE, _trap, begin=TRAP, end=TRAP)
            tick = int(os.environ.get("HAL_UT_ETH_TICK", str(TICK_PC)), 0)
            uc.hook_add(unicorn.UC_HOOK_CODE, _tick, begin=tick, end=tick)
            self.installed = True
            log.error("eth_bridge: installed (tick@0x%08x tx@0x%08x rx@0x%08x) spool=%s",
                      tick, FN_START_ETH_TX, FN_SIMULATE_ETHERNET_IN, self.spool)
        except Exception as exc:  # noqa: BLE001
            log.error("eth_bridge: install failed: %s", exc)
        return False, None
