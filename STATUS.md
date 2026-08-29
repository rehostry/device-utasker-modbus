<!-- rehostry-census: milestone=M4 landed=true verdict=M4-OK verified=2026-08-28 method=live-run -->
<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# STATUS — uTasker MODBUS slave (STM32F4 / ARMv7E-M) rehost

**Current milestone: M4 — a genuine MODBUS/TCP round-trip on :502 against the
firmware's own stack.** Verified end to end: ARP resolve -> TCP 3-way handshake ->
FC03 request -> the firmware's own MODBUS reply.

## What runs

A cold boot under HALucinator's in-process **unicorn** backend reaches, in order:

| stage | evidence |
|---|---|
| reset -> `main` (0x0800c088) | block trace |
| RCC clock bring-up: HSE ready, PLL locked, SW->PLL confirmed | `peripheral_models/stm32_rcc.py` |
| `fnInitialiseHeap` (0x0800e46c), `uTaskerStart` (0x0800e528) | block trace |
| `uTaskerSchedule` (0x0800e690) dispatch loop | steady state, ~10 task passes/s |
| `fnConfigEthernet` (0x0800c42c) completes: PHY identified, MAC set, **descriptor rings published** (`ETH_DMARDLAR=0x200028d8`, `ETH_DMATDLAR=0x20003ad8`), DMA started | `HAL_UT_ETH_TRACE=1` |
| `fnInitModbus` (0x0801480c) + `fnMODBUS` task (0x080113a8) scheduled | `HAL_UT_WATCH` hit counts (~50 in 20 s) |
| `fnTaskEthernet` (0x08013604) / `fnEthernetEvent` (0x0800c2ee) polling | ~200 hits in 20 s |

The firmware is a **MODBUS/TCP slave on port 502** (`f6 01` inside
`cMODBUS_default` at 0x08015540) with IP **192.168.0.3** (uTasker network
parameters at 0x08012ea4). It programmed MAC `00:00:00:00:00:00`
(`ETH_MACA0HR=0x80000000`, `ETH_MACA0LR=0`).

## Walls cleared (each a faithful device model, no firmware patching)

1. **ARMv7E-M vs Cortex-M3.** `uTaskerStart+0x112` executes `smulbb r8,r1,r8`
   (0x0800e63a), a DSP multiply the default M3 decoder rejects
   (`UC_ERR_INSN_INVALID`). Cleared with `HAL_CORTEXM_CPU_MODEL=UC_CPU_ARM_CORTEX_M4`
   on the `rehostry/core-patches` core.
2. **RCC clock bring-up** (`stm32_rcc.py`). `main` spins on `RCC_CR` bit 17
   (HSERDY) at 0x0800c0cc, then bit 25 (PLLRDY) at 0x0800c0f2, then on
   `RCC_CFGR.SWS == PLL` at 0x0800c100. Modelled as the real enable->ready
   coupling (each `*ON` bit answered by its `*RDY` bit; `SWS` follows `SW`), so
   the firmware's own polls complete rather than being broken by a forced
   constant.
3. **Ethernet PHY identity** (`stm32_eth.py`). `fnConfigEthernet` forms
   `(PHYIDR1<<16)|PHYIDR2`, masks the revision nibble, and compares against
   `0x0007c130` at 0x0800c5f0. **A mismatch returns -1 and skips the whole
   descriptor-ring setup**, after which the RX walk dereferences NULL. Modelled
   the actual part (**LAN8742A**) plus self-clearing `ETH_DMABMR.SR` /
   `ETH_MACMIIAR.MB` and DMA current-descriptor registers that honour the
   firmware's own advance.

## Frame plumbing in place

`bp_handlers/eth_bridge.py` bridges frames both ways using seams the firmware
itself provides, and both are verified to fire:

* **RX**: `fnSimulateEthernetIn(frame_ptr, len)` @0x0800c77c — the driver's own
  software-reception entry point (it memcpy's into the RX descriptor buffer,
  advances `ETH_DMACHRDR`, and raises `ETH_DMASR.RS`). Called with a borrowed CPU
  context. Injection is confirmed working ("RX inject #1 ... 60 bytes").
* **TX**: `fnStartEthTx(len, end_ptr)` @0x0800c816 — observed, never intercepted;
  the frame is `[end_ptr-len, end_ptr)`.

`tools/modbus_peer.py` is the host peer (raw ARP / IPv4 / TCP / MBAP) that drives
a real FC03 round-trip once RX delivery reaches the stack.

## M4 — the round-trip (achieved)

```
[peer] ARP who-has 192.168.0.3
[peer] firmware MAC = 00:00:00:00:00:00
[peer] TCP SYN -> 192.168.0.3:502
[peer] SYN-ACK (seq=0x00000000)
[peer] MODBUS FC03 addr=0 count=4  (000100000006010300000004)
[peer] MODBUS response: 000100000003018302
```

Every stage is the firmware's own code, confirmed by hit counts on its symbols:

| stage | firmware symbol | frame |
|---|---|---|
| ARP request answered | `fnProcessARP` 0x0801338a -> `fnStartEthTx` 0x0800c816 | TX #1, 42 B, ethertype 0x0806 |
| TCP handshake | uTasker TCP | TX #2, 58 B, ethertype 0x0800 (SYN-ACK) |
| MODBUS listener accepted | `fnMODBUSListener` 0x08012738 | — |
| **MODBUS PDU parsed + answered** | `fnHandleMODBUS_input` 0x08011b60 | TX #3, 63 B |

The reply decodes as MBAP(txn=1, proto=0, len=3, unit=1) + PDU `83 02`, i.e.
**FC03 | 0x80 with exception code 0x02 (ILLEGAL DATA ADDRESS)** — a correct,
firmware-generated protocol response saying holding register 0 is outside this
slave's map. Nothing in the reply is synthesised by the host peer; it is the bytes
`fnSendMODBUS_response` put on the wire. (Finding an address range that returns
register *data* rather than an exception is follow-up work: only one session per
boot currently completes, so a multi-request sweep over a single TCP connection is
the next small step.)

### The bug that had blocked it

Injection appeared to work but nothing was ever processed. Two Thumb-state
mistakes in the call-injection harness, not firmware modelling:

* `reg_write(PC, fnSimulateEthernetIn)` — **bit 0 clear** made unicorn decode the
  ARMv7-M (Thumb-only) target in ARM mode -> `UC_ERR_INSN_INVALID` at the
  function's first instruction.
* the same on **restore**: `PC` reads back with bit 0 clear, so resuming the
  borrowed context re-entered Thumb code in ARM mode.

Both fixed by re-asserting the Thumb bit (`| 1`). With that, RX -> ARP -> IP ->
TCP -> MODBUS runs clean with **zero** emulator faults.

### Still open: `cortex_m_scs.py` is not wired in

`peripheral_models/cortex_m_scs.py` models NVIC ISER/ICER/ISPR/ICPR aliasing. It
turned out **not** to be required for M4 — uTasker's software ISR dispatch is
gated on `NVIC_ISER1` bit 29 reading back, and the catch-all `AutoPeripheral`
already satisfies that via its busy-wait escalation. The model is kept because it
is correct and will matter for interrupt-accurate work, but wiring it regresses
the RTOS tick: splitting the `0xE0000000` window so the SCS page gets its own
model drops task dispatch from ~200 `fnTaskEthernet` passes / 20 s to **one**,
even when every non-NVIC register is delegated back to `AutoPeripheral`. Left
unwired with that caveat recorded in the config.

## PASS 2 — panel + attack

* **`utasker_panel.py` (console script `rehostry-utasker-modbus-panel`, port 8787).**
  Holds a MODBUS/TCP session against the firmware's own stack and shows the slave's
  live holding-register map. Probing recovered the map: **registers 2..6 exist**
  (0, 1 and >=7 answer exception 0x02), values e.g. `[16, 65504, 768, 64512, 0]`,
  low bits live.
* **`attack.py` — unauthenticated MODBUS FC06 write.** Verified on a live boot:
  register 2, before `96`, wrote `0x1234`, read back **`0x1244`**, `landed=true`.
  The registers are live so `landed` compares the read-back's **high byte**; raw
  values are reported so the check is auditable.
* **`modbus.py`** — the raw-Ethernet ARP/IPv4/TCP/MODBUS client (there is no host
  TCP/IP stack behind the firmware, so the host side speaks Ethernet itself), with
  a `Session` that tracks seq/ack so several requests share one connection.
## The RTOS-tick wall — root-caused and fixed (2026-07-31)

The device used to serve **one MODBUS request per boot** and then go quiet; a
second request (or the same session after a short idle) got no reply, so the
attack's read → write → read-back could not complete in one session. Root-caused
to two coupled RTOS-scheduling facts, both a consequence of the same missing
interrupt delivery, and fixed **device-side** by driving the firmware's own
primitives on the existing borrowed-context seam (no core change):

1. **The uTasker system tick never fires.** `fnStartTick` (0x0800c2c6) programs the
   Cortex-M **SysTick** (`SYST_CSR`=7, reload 0x802c7f) and installs
   `_RealTimeInterrupt` (→ `fnRtmkSystemTick`, 0x0800e86a) as the **exception-15**
   handler in a RAM vector table. But the SCS window (0xE000E000) is the
   `AutoPeripheral` catch-all, so SysTick never counts and exception 15 never fires:
   `uTaskerSystemTick` is frozen and every uTasker software timer (TCP delayed-ACK,
   retransmit, …) stays armed forever.
2. **The Ethernet task stops polling.** `fnTaskEthernet` (0x08013604) drains the RX
   descriptor ring. It is scheduled *continuously* during bring-up (`uTaskerSchedule`
   dispatches it every pass), but once the TCP connection is up it becomes
   event-driven: it then only runs when the ETH ISR posts its RX event via
   `uTaskerStateChange('E', 4)` (see `EMAC_Interrupt` 0x0800c400). No ETH IRQ ever
   fires in the rehost, so after the first request the task never consumes another
   frame — the tick alone just makes TCP retransmit the first reply forever.

**Fix** (`bp_handlers/eth_bridge.py`): after the first request has been served
(3 TX frames: ARP reply + SYN-ACK + 1st MODBUS response), at the scheduler-loop
safe point and only when no host frame is pending, the bridge free-runs two of the
firmware's own calls — `uTaskerStateChange('E', 4)` (keep the Ethernet task
draining the ring, ~200 Hz) and `fnRtmkSystemTick` (advance the RTOS clock, ~20 Hz,
matching the real ~50 ms tick so TCP timers pace realistically). Both are gated to
*after* the handshake, which the firmware still completes on its own polling;
injecting either earlier perturbs ARP/TCP. A full multi-request session now works:

```
holding registers [2,3,4,5,6] = [16, 65504, 768, 64512, 0]   # 5 distinct reads, one session
FC06 write 0x1234 -> reg 2 -> firmware read-back 0x1244       # landed=True
```

Verified: `python -m rehostry_utasker_modbus.attack` →
`RESULT: {"booted": true, "landed": true}` reliably (4/4 runs). The oracle is
unchanged — `landed` is still the firmware's own read-back high byte.

**Residual note:** a ~25 s warm-up before the first connect is still used (the
network stack must finish bring-up before ARP/SYN); it is no longer about
"one read per session".
* **Bug fixed in `eth_bridge.py`:** injecting a frame before the ETH driver
  published its descriptor ring killed the emulation (`ETH_DMACHRDR` reads 0 ->
  NULL deref -> `UC_ERR_READ_UNMAPPED`). The bridge now waits for the firmware's
  own periodic call into `fnSimulateEthernetIn` as a readiness signal before
  injecting anything.
* **Run it with the lab venv python** (as `spawn.py` does); a different
  interpreter resolves a different halucinator and the boot dies early.

## Reproduce

```bash
pip install pyelftools
python3 tools/extract_firmware.py /path/to/uEmu.uTasker_MODBUS.out   # see PROVENANCE.md
# boot straight off the spawn recipe (single source of truth):
python3 -c "import subprocess; from rehostry_utasker_modbus import spawn, paths; \
  subprocess.run(spawn.spawn_argv(overlays=[paths.PROBE_OVERLAY]), \
                 cwd=spawn.spawn_cwd(), env=spawn.spawn_env())"      # + PC/watch diagnostics
python3 -c "import subprocess; from rehostry_utasker_modbus import spawn, paths; \
  subprocess.run(spawn.spawn_argv(overlays=[paths.ETH_BRIDGE_OVERLAY]), \
                 cwd=spawn.spawn_cwd(), env=spawn.spawn_env())"      # + the frame bridge
python3 tools/modbus_peer.py arp               # host peer: ARP (currently no reply)
```

Diagnostics: `HAL_UT_PROBE_TRACE=N`, `HAL_UT_WATCH=0xaddr,...`,
`HAL_UT_ETH_TRACE=1`, `HAL_UT_ETH_VERBOSE=1`.

---

## 2026-08-16 — the boot regression on pinned core `2364f4c`, root-caused and fixed

Against the pinned fleet core **`2364f4c`** this device reported
`RESULT: {"booted": false, "landed": false}` on every solo run (independent
repeats at loads 2.04 / 1.63 / 1.77). It is now
`RESULT: {"booted": true, "landed": true}` again, and — more importantly — it no
longer depends on a race it was quietly losing.

### What was actually happening

The emulator was **dying ~21 s into the boot**, before the attack's 25 s warm-up
even ended:

```
AutoPeripheral: WINDOWED busy-wait at pc=0x0800c786 addr=0xe000ed08 -> 0xffffffff (tier 0)
AutoPeripheral: WINDOWED busy-wait at pc=0x0800c806 addr=0xe000e104 -> 0xffffffff (tier 0)
UnicornBackend: unmapped read at 0x133 (size 4, value 0x0) from pc=0x800c80c
UnicornBackend: UcError Invalid memory read (UC_ERR_READ_UNMAPPED) at PC=0x0800c80c lr=0x0800c7b8
```

`fnSimulateEthernetIn` ends with uTasker's **software ISR dispatch**:

```
0x0800c780  ldr   r0,[pc,...]     ; r0 = 0xe000ed08  SCB_VTOR
0x0800c786  ldr   r4,[r0]         ; r4 = vector table base
0x0800c806  ldr   r3,[r2]         ; r2 = 0xe000e104  NVIC_ISER1
0x0800c808  lsls  r0,r3,#2        ;   bit 29 -> IRQ 32+29 = 61 = ETH enabled?
0x0800c80c  ldrmi r1,[r4,#0x134]  ;   yes -> RAM vector 77 = the ETH handler
0x0800c810  blxmi r1              ;   ... and call it
```

The SCS window was the plain `AutoPeripheral` catch-all, which has **no register
file**: an unwritten read returns 0, and once its *windowed busy-wait breaker*
decides a repeatedly-read address is a spin it returns **0xFFFFFFFF**. It applied
that to **both** registers in that sequence:

* `NVIC_ISER1` escalating to 0xFFFFFFFF makes the `ldrmi` predicate true on a
  **fabricated** enable bit, and
* `SCB_VTOR` escalating to 0xFFFFFFFF makes the handler fetch land at
  `0xFFFFFFFF + 0x134` = **0x00000133** — the exact fault observed.
  (VTOR left at the catch-all default 0 would fetch 0x134: equally unmapped.)

The breaker is *count*-based (2048 of the last 8192 reads of the window), so this
was always going to fire — the only question was when in wall-clock. **Bisected
mechanically to one core commit**, `b6ab243..2364f4c` (a single commit):

| core | MMIO recording | emulator |
|---|---|---|
| `b6ab243` | on (db_path forwarded unconditionally) | alive at **400 s**, no escalation |
| `2364f4c` | off (now opt-in via `HAL_MMIO_TRACE=1`) | dies at **~21 s** |
| `2364f4c` + `HAL_MMIO_TRACE=1` | on | alive at 60 s, no escalation |
| `2364f4c` + `HAL_CORTEXM_RESTORE_NESTED_IPSR=1` | off | dies at ~21 s (the other half of that commit is not involved) |

So `2364f4c` is **not the bug** — it removed the per-access recording overhead
that had been slowing the guest by more than an order of magnitude, and the
device had been surviving only because it never ran long enough to reach the
breaker. This device's earlier green runs were bought by that overhead, and by
machine load. **No core change is required or requested.**

### The fix (device-side, three faithful register models)

1. **`peripheral_models/cortex_m_scs.py` → new `ScsCatchAll`**, now wired to the
   SCS window. `AutoPeripheral` plus a real register file for the two things the
   breaker had no business guessing:
   * **`SCB_VTOR`** — write-through/read-back, reset = `machine.vector_base`. The
     firmware relocates the table itself, writing **0x20000000** at pc=0x0800c11a
     (visible in the MMIO trace), so `[r4+0x134]` becomes a live SRAM word.
   * **NVIC `ISER`/`ICER`/`ISPR`/`ICPR`** — architectural set/clear aliasing.
     `ISER1` now reads back **what the firmware wrote** (0x20000000 at
     pc=0x0800c29e = IRQ 61 = ETH), so the dispatch fires on the real enable bit
     rather than on a fabricated one.
2. **`peripheral_models/stm32_eth.py` → `ETH_DMASR` is rc_w1** (RM0090
   §33.8.14). With VTOR and the NVIC modelled the *real* `EMAC_Interrupt`
   (0x0800c400) finally runs, and it acknowledges the receive event with
   `str 0x00010040,[ETH_DMASR]` (RS|NIS). Storing that verbatim left RS set and
   the ISR span forever (measured: 100 % of guest time in 0x0800c408 +
   `uTaskerStateChange`, zero scheduler passes, device answered nothing).
   Writes from the DMA stand-in `fnSimulateEthernetIn` (0x0800c77c..0x0800c816),
   which is uTasker's software-reception shim and the only "hardware" writer of
   that register, keep plain-store semantics.

Net effect: **no busy-wait escalation happens on the SCS window at all any more**,
so the device no longer races the breaker. A 120 s soak answers ARP on every
poll and completes a MODBUS FC03 on every session, with the slave's live register
2 stepping 0x0010, 0x0020, 0x0030 … as the RTOS clock advances.

### Oracle hardening (strengthened, not weakened)

This device's rendezvous with the guest is a **spool directory**, not a socket, so
the fleet's port-level guidance does not apply literally — but the same defect
did. `attack.py` used the fixed shared path `/tmp/rehostry_utasker_eth` for every
run, i.e. it graded *whatever serviced that directory*.

**Measured, this session:** a ~90-line decoy with **no emulator and no firmware**
that services that path answered ARP, the TCP handshake and MODBUS, and produced
`landed: True` with a plausible register map (`frames_seen=19,
modbus_answers=8`).

`run_attack` now mints a **fresh, unguessable spool per spawn**
(`secrets.token_hex`), hands it to the emulator it starts via
`HAL_UT_ETH_SPOOL`, and gates the verdict on `_verify_child`: the child must
exist, its own log must announce the bridge installed **on that private path**,
and it must still be alive when the oracle runs. `landed` is
`firmware read-back AND provenance.ok`.

* **Decoy control:** with the decoy squatting the old shared path for the whole
  run, the real attack landed and the decoy recorded `frames_seen=0
  modbus_answers=0` — it was never contacted.
* **Guest-stall control:** image replaced with `0xE7FE` (`b .`) throughout
  (`sha256 0f6f8f8a…`), restored afterwards to
  `sha256 dc28f4280d97e92c8736ebfe8148238b2a06f2b612bd8e18b94e4c49cb8ca860`
  (verified byte-identical). The emulator process, peripheral server and IRQ
  thread all still came up and the client still injected frames; every
  firmware-derived term collapsed:
  `RESULT: {"booted": false, "landed": false}`.

The `landed` predicate itself is **unchanged**: still the firmware's own FC03
read-back after an unauthenticated FC06 write, compared on the high byte.

### Verification (pinned core `2364f4c`, fresh isolated venv, python 3.12)

| run | load before / after | result |
|---|---|---|
| 1 | 1.55 / 1.83 | `RESULT: {"booted": true, "landed": true}` |
| 2 (polluted env: `PYTHONPATH=HALUCINATOR_SRC=/nonexistent/x`) | 1.76 / 2.28 | `RESULT: {"booted": true, "landed": true}` |
| 3 (full result dict, provenance captured) | 2.20 / 2.13 | `booted: true, landed: true, provenance.ok: true` |

Firmware-side evidence, identical across runs:

```
holding registers [2,3,4,5,6] = [16, 65504, 768, 64512, 0]
FC06 write 0x1234 -> reg 2 -> firmware read-back 0x1244   (landed=True)
provenance: {spawned: true, bridge_bound: true, alive: true, ok: true}
```

### On the "it passed under parallelism" report — the record says otherwise

This device was handed over as the fleet's one suspected **parallelism-induced
false pass**. Checking the recorded verdicts does not support that:

| record | core | harness | verdict |
|---|---|---|---|
| `clean-device-results.tsv` (2026-08-13) | **not recorded** (installed from the shared tree) | serial, one venv per device | pass |
| `dev-pinned-results.tsv` (2026-08-15) | `b6ab243` | fleet census | pass |
| `fixed-census-results.tsv` (2026-08-16) | `2364f4c` | **parallel** census | fail |
| `rerun-serial-results.tsv` | `2364f4c` | serial | fail |
| `recheck-results.tsv` ×2 | `2364f4c` | solo | fail |

Every pass is on a core **older than `2364f4c`**; every run on `2364f4c` fails,
*including the parallel one*. The discriminating variable is the core (MMIO
recording on vs. off, i.e. guest throughput), not concurrency — and the older,
unrecorded core in the 2026-08-13 row is exactly the ambiguity the pinning was
introduced to remove. So: no false pass under parallelism is demonstrable for
this device, and the pass/fail split is fully accounted for by the bisect above.

Load would have shifted the same race — the breaker is count-based, so a slower
guest reaches the fatal escalation later in wall-clock, and a slow enough guest
lands before it — which is why a green run on this device *was* worth
distrusting. That mode is now gone: the escalation no longer happens on this
window at all.
