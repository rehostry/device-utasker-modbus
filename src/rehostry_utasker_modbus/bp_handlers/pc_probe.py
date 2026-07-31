# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""DIAGNOSTIC: locate where the uTasker boot spins.

Installs a ``UC_HOOK_BLOCK`` sampler (cheap: one callback per translation block,
sampled 1-in-N) that periodically logs the hot-PC histogram, plus an optional
first-N-blocks trace so the boot path from ``main`` is visible. This is the same
lever used on the ION7400 rehost to pin its post-`*_PowerUp` walls.

Install it from a symbol that is reached early (``main``); at that point the
backend's ``_uc`` exists, which it does not at config-parse time.

Env knobs:
  HAL_UT_PROBE_EVERY  (default 1.0)   seconds between histogram dumps
  HAL_UT_PROBE_MOD    (default 512)   sample 1 block in MOD
  HAL_UT_PROBE_TRACE  (default 60)    log the first N distinct blocks in order
"""
from __future__ import annotations

import logging
import os
import time
from collections import Counter
from typing import Any, Tuple

from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler

log = logging.getLogger(__name__)


class PcProbe(BPHandler):
    _started = False

    def __init__(self) -> None:
        self.every = float(os.environ.get("HAL_UT_PROBE_EVERY", "1.0"))
        self.mod = int(os.environ.get("HAL_UT_PROBE_MOD", "512"), 0)
        self.trace_n = int(os.environ.get("HAL_UT_PROBE_TRACE", "60"), 0)
        self.hist: Counter = Counter()
        self.n = 0
        self.seen: list = []
        self.t0 = 0.0
        self.tlast = 0.0

    def register_handler(self, qemu: Any, addr: int, func_name: str, **kwargs: Any):
        return PcProbe.on_setup

    @bp_handler(["on_setup"])
    def on_setup(self, qemu: Any, addr: int) -> Tuple[bool, Any]:
        if PcProbe._started:
            return False, None
        uc = getattr(qemu, "_uc", None)
        if uc is None:
            return False, None
        PcProbe._started = True
        try:
            import unicorn

            hb = getattr(unicorn, "UC_HOOK_BLOCK", 8)

            def _blk(uc_, address, size, ud):  # noqa: ANN001
                pc = address & 0xFFFFFFFE
                if len(self.seen) < self.trace_n and pc not in self.seen:
                    self.seen.append(pc)
                    log.error("UT-TRACE block #%d 0x%08x", len(self.seen), pc)
                self.n += 1
                if self.n % self.mod:
                    return
                self.hist[pc] += 1
                if self.t0 == 0.0:
                    self.t0 = time.time()
                now = time.time() - self.t0
                if now - self.tlast >= self.every:
                    self.tlast = now
                    top = self.hist.most_common(10)
                    log.error("UT-HIST t=%5.1fs blk=%d | %s", now, self.n,
                              " ".join("0x%08x:%d" % (p, c) for p, c in top))

            # Targeted watch list: HAL_UT_WATCH=0xaaaa,0xbbbb -> log each hit count
            # (the block trace only reports *new* blocks, so it can't show whether a
            # already-seen function ran again after an event).
            watch = os.environ.get("HAL_UT_WATCH", "")
            self.wcount = {}
            for tok in [t for t in watch.replace(" ", "").split(",") if t]:
                a = int(tok, 0)
                self.wcount[a] = 0

                def _w(uc_, address, size, ud, _a=a):  # noqa: ANN001
                    self.wcount[_a] += 1
                    n = self.wcount[_a]
                    if n == 1 or n % 50 == 0:
                        log.error("UT-WATCH 0x%08x hit #%d", _a, n)

                uc.hook_add(unicorn.UC_HOOK_CODE, _w, begin=a, end=a)
            if self.wcount:
                log.error("pc_probe: watching %s",
                          ",".join("0x%08x" % a for a in self.wcount))

            uc.hook_add(hb, _blk)
            log.error("pc_probe: block sampler installed at 0x%08x (mod=%d)",
                      addr, self.mod)
        except Exception as exc:  # noqa: BLE001
            log.error("pc_probe: install failed: %s", exc)
        return False, None
