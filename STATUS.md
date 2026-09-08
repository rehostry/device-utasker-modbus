<!-- rehostry-census: milestone=M7 landed=true verdict=M4-OK verified=2026-09-05 method=live-run note=M5-and-M8-EACH-DEFINED-and-UNMET-at-1-of-4-CORRECTED-2026-09-08-from-undefined-single-interface-against-the-firmware-s-OWN-serial-menu(FTP-WEB-TELNET-beside-MODBUS);the-ARP-ICMP-substrate-disposal-STANDS -->
<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# STATUS — uTasker MODBUS slave (STM32F4 / ARMv7E-M) rehost

**Current milestone: M7.** M4 is a genuine MODBUS/TCP round-trip on :502
against the firmware's own stack, verified end to end: ARP resolve -> TCP 3-way
handshake -> FC03 request -> the firmware's own MODBUS reply. On the **same
boot and the same TCP session** the rehost is also **M6 (stateful)** and **M7
(adversarial-input tolerance)**, each graded off M4 rather than off the other.

**M5 and M8 are UNDEFINED here, not failed.** One link, one application service
on it (MODBUS/TCP on :502), one peer.

> ⚠ **SUPERSEDED 2026-09-08 (lane INVAPPLY).** The firmware's **own serial configuration menu** declares an FTP server, a WEB server and a TELNET server beside MODBUS/TCP. **M5 and M8 are each DEFINED and UNMET at 1 of 4.** The ARP/ICMP disposal below is correct and stands.
> See *M5/M8 INTERFACE INVENTORY* at the end of this file. **No rung moves.**
 RULES §1a excludes two function codes over
one framing layer as a second interface, and the ARP replies and the TCP
handshake underneath are **stack-level reflexes** — substrate, by the
2026-09-02 ruling — not a second interface, however genuinely the guest computes
them. The 2026-09-02 ruling that **M6/M7 do not require M5** is what makes those
two rungs claimable here on their own evidence.

**No `path=` in the census header, on purpose.** The M6 and M7 phases run on the
*default* invocation `python3 -m rehostry_utasker_modbus.attack`, so the rung a
verifier reads is the rung the documented command produces (playbook w35).
`--no-ladder` restores the M4-only run. A whole run is ~34 s.

## 2026-09-05 — M4 → M7

### Could the gate print M7 before this session? No.

`run_attack` assigned `"M0"` / `"M3"` / `"M4"` and had **no branch above M4 at
all**, so no behaviour of the firmware could have produced a higher rung.
Nothing about the device changed to reach M6 and M7; the run now measures two
rungs it could already demonstrate, and both `M6` and `M7` are shown to be
*printable* by a run — `--m7-wellformed` prints `M6`, the default path prints
`M7`.

### The register map, re-derived — and only ONE register is a usable witness

`STATUS`'s existing note that "the low bits are live" understates it. Measured
on an untouched boot, three back-to-back `FC03 2,5` reads:

```
[0x0010, 0xFFF0, 0x0100, 0xFF00, 0x0000]
[0x0020, 0xFFE0, 0x0200, 0xFE00, 0x0000]
[0x0030, 0xFFD0, 0x0300, 0xFD00, 0x0000]
```

Registers **2..5 ramp on their own** with the firmware's execution — `%2` by
`+0x10`, `%3` by `-0x10`, `%4` by `+0x100`, `%5` by `-0x100` — and **register 6
does not move at all**: a value written there is served back byte-exact
(`0xBEEF -> 0xBEEF`, `0x1357 -> 0x1357`), whereas a write to `%5` came back
`0x2468 -> 0x2368`. So register 6 is the only sound attacker-controlled state
witness on this device, and 2..5 are what proves the guest is running its own
state machine between two reads.

### M6 — the same input at two different states, two different correct outputs

**3 of 3 rounds, six per-round terms each.** Each round reads state A with two
**bare queries that carry no value of their own** (`FC03 6,1` and `FC03 2,5`),
writes a fresh 16-bit random into register 6, and reads state B with the same
two. Three witnesses of three different kinds, all of which must differ and be
correct in every round:

| witness | what it shows |
|---|---|
| **the attacker's value** | `FC03 6,1` differs between the reads and equals the value this round drew from the run's RNG. |
| **the guest's own clock** | register 4 has ADVANCED between the two reads. **No phase of this run ever writes register 4**, so the movement is the firmware's own execution and not an after-effect of our traffic. |
| **an invariant the firmware maintains between two of its own registers** | `reg5 == -reg4` mod 2¹⁶, at BOTH reads. No request carries either side of that relation, and a replayed or fabricated block does not satisfy it while also ramping. |

**A refutation I found by running it, and did not paper over.** The first cut
asserted the same pairing for `%2`/`%3` as well, and **failed 3 of 3 rounds** —
correctly. The M4 phase earlier in the same run does an `FC06` write into
register **2**, which desyncs that pair permanently, while `%4`/`%5` are never
written and stay paired. The invariant was real; my statement of it was wrong.
The check now covers only the pair no phase writes, `tests/test_milestone_gate.py`
pins that reasoning, and the ramp witness was moved off register 2 for the same
reason.

### M7 — adversarial input handled as the device would, known-good after

**8 of 8 classes, four distinct exception codes, 7 of the 8 predicted from an
upstream spec.**

| class | frame | predicted | source |
|---|---|---|---|
| `illegal_function` | FC `0x41` | exception `0x01` | MODBUS v1.1b — 0x41 is user-defined; this slave implements FC 3/6/8 |
| `illegal_read_address` | `FC03 7,1` | exception `0x02` | MODBUS v1.1b — the map is registers 2..6 |
| `illegal_write_address` | `FC06 0,<rand>` | exception `0x02` | MODBUS v1.1b — register 0 is below the map |
| `zero_quantity` | `FC03 2,0` | exception `0x03` | MODBUS v1.1b — quantity must be 1..125 |
| `quantity_over_125` | `FC03 2,126` | exception `0x03` | MODBUS v1.1b — 126 exceeds the maximum |
| `truncated_pdu` | `03 00` | exception `0x02` | a 2-byte FC03 PDU cannot carry an address and a quantity |
| `mbap_length_short` | MBAP length `2`, 6-byte PDU | exception `0x03` | TCP/IP guide v1.0b — the length field counts unit id + PDU |
| `mbap_protocol_id_nonzero` | MBAP protocol id `0x0001` | exception `0x0A` | **firmware-recovered, NOT spec-predicted** — see below |

**The honest caveat on the last row.** The TCP/IP implementation guide §4.1 says
the protocol id MUST be `0x0000`, so the spec-derived prediction is only *"this
frame must not be executed"* — which is asserted, and holds (register 6 is
unchanged). The specific code this build answers with, `0x0A` GATEWAY PATH
UNAVAILABLE, is **not** what the spec prescribes; it was recovered by probing
this firmware and is therefore a **regression check, not a prediction**. It is
labelled `source: "firmware-recovered"` in the result and a test pins that
label, because a probe-derived constant presented as a spec prediction is
Rule 1's circularity wearing a citation. The firmware also **echoes the bad
protocol id back** in the response MBAP (`1111 0001 0003 01 86 0a`), which is
itself guest-composed evidence.

One predicate, applied identically to both arms: *the reply is an exception
carrying the predicted code, AND register 6 is unchanged, AND a bare `FC03`
answers afterwards.* Silence is **not** a rejection on this device — it answers
exceptions — so a missing reply is its own outcome (`answered_at_all`) and is
never folded into "refused".

**The discriminator, and it is not a liveness poll.** MODBUS unit id `0` is the
broadcast address and differs from an accepted write in **one byte**. This
firmware answers **nothing** and still **applies** the write:

```
[m7_broadcast_discriminator] unit id 0 FC06 reg6=0x28DD -> SILENCE,
                             reg6 0xC09F -> 0x28DD
```

One frame draws silence *and* changes the guest's state. That rules out "the
seam is dead" and "the parser drops everything" at once, which a liveness poll
cannot do — §1a evidence form 3, decided by a byte the guest emitted.

**"…and known-good traffic still works afterwards"** is its own term, measured
after all eight classes and the discriminator: a fresh random into register 6,
echoed byte-exact, read back byte-exact, and a full five-register block read.

### The two rung-specific knobs, both arms

| arm | M4 | M6 | M7 | milestone | guard |
|---|---|---|---|---|---|
| default path (×3) | `landed:true` | **3/3** | **8/8** | `M7` | `M4-OK` |
| `--m6-freeze` | `landed:true` | **0/3** | 8/8 | `M7` | `M4-OK` |
| `--m7-wellformed` | `landed:true` | 3/3 | **0/8** | `M6` | `M4-OK` |
| `--no-ladder` | `landed:true` | skipped | skipped | `M4` | `M4-OK` |
| `HAL_SEAM_CONTROL=1` | `landed:false` | skipped | skipped | `M3` | `WALL-M3` |
| firmware moved aside | `booted:false` | — | — | `M0` | `WALL-M0` |

`--m6-freeze` sends the state-changing `FC06` with **MBAP protocol id 0x0001**
instead of the mandatory `0x0000`, so **the firmware's own stack** refuses it
and register 6 never moves — measured `reg6 0x0000 -> 0x0000` against a
commanded `0x7EFC`, in all three rounds. The two bare read-backs are untouched
and the predicate is unchanged, so the arm is scored by exactly the predicate
under test (playbook w33.1). **M7 stays 8/8 and the milestone stays `M7`** —
both M6's control and a running demonstration that this scorer does not chain
M7 ← M6.

`--m7-wellformed` sends each class's well-formed twin under the **same**
predicate. All eight are answered normally rather than with an exception
(`03024cf0`, `060006ddef`, `030a01b0fdf02100df00ddef`, …) and the write-shaped
twin also moves the state witness (`reg6 0x4CF0 -> 0xDDEF`), so the phase scores
**0/8, milestone falls to `M6`**, with M4 and M6 untouched. That is what shows
the exceptions in the live arm were the firmware discriminating rather than a
seam that refuses everything — one arm, both jobs.

### What the new phases would have broken, and did not

Per playbook w33.2, the pre-existing control was re-read against them.
`HAL_SEAM_CONTROL=1`'s whole claim is that **no MODBUS PDU was ever sent**, and
both phases send plenty. Both are therefore skipped whenever it is armed, and
the run says so rather than measuring nothing quietly:

```
"ladder_skipped_reason": "HAL_SEAM_CONTROL=1 -- the M6/M7 phases transmit
 MODBUS PDUs, which would contradict this control's claim that none were sent"
```

A defect inside the new phases is a **harness fault, not a device result**: it
sets `harness_fault` and blanks the milestone to `null`, so the fleet guard
scores a bare `WALL` and credits **no rung at all**, including the M4 the run
already had (playbook w29.2/w37.3).


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

* **`utasker_panel.py` (console script `rehostry-utasker-modbus-panel`, port 29293).**
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

# THE INVOCATION THE CENSUS HEADER NAMES -- M1..M4, then M6 and M7 on the same
# boot and the same TCP session (~34 s):
python3 -m rehostry_utasker_modbus.attack

# the two rung-specific falsification knobs, both arms
python3 -m rehostry_utasker_modbus.attack --m6-freeze       # M6 3/3 -> 0/3, still M7
python3 -m rehostry_utasker_modbus.attack --m7-wellformed   # M7 8/8 -> 0/8, drops to M6
python3 -m rehostry_utasker_modbus.attack --no-ladder       # the M4-only run
HAL_SEAM_CONTROL=1 python3 -m rehostry_utasker_modbus.attack   # the seam control -> M3
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

## 2026-09-08 (HAL_PY) — the fleet's stock "no emulator" arm was INERT here, and an inert control is worse than no control

`spawn.spawn_argv` built its argv as `python or sys.executable` — **no env term anywhere in the chain**, so the fleet's stock control arm `HAL_PY=/usr/bin/false` — *"make sure no emulator ever exists"* — could not take effect on this device by any route at all. DEVICE-PLAYBOOK **w74**.

The call sites on the evidence path (`spawn.py:25`) now pass
`os.environ.get("HAL_PY") or sys.executable` — the repair
`device-vesc-bldc-f405` found independently and `device-apc-nmc3-su` carries.

Measured, **both arms, no boot**: `subprocess.Popen` is intercepted at the
moment of the spawn, `argv[0]` is read and the call aborted
(`scratch-batch-s0909-halpy/prove_halpy_arms.py`).

| | `HAL_PY=/usr/bin/false` | `HAL_PY` unset |
|---|---|---|
| before | `/Users/user/Development/rehostry/.venv-dev/bin/python` — **INERT** | `/Users/user/Development/rehostry/.venv-dev/bin/python` |
| after | `/usr/bin/false` — **REACHABLE** | `/Users/user/Development/rehostry/.venv-dev/bin/python` — **unchanged** |

**The right-hand column is the whole argument.** With `HAL_PY` unset the
expression *is* `sys.executable`, so no run that does not set it can behave
differently from before: this can only ever make a control stronger, never a
rung easier. **The milestone is untouched and the census header is unchanged.**

The agreement control, run in the same process and the same environment on each
arm — `spawn_argv()` called with no interpreter argument — returned
`/usr/bin/false` on the set arm and `/Users/user/Development/rehostry/.venv-dev/bin/python` on the unset arm. Without it
*"the arm did nothing"* and *"my experiment did nothing"* are the same output.

**No recorded evidence on this device ever rested on `HAL_PY`.** STATUS.md,
README.md and `docs/` were grepped: this device cites no `HAL_PY`-based control
arm, so nothing here is re-scored and no claim is withdrawn. The trap was that
the next agent to copy a sibling's stock arm would have got a control that
passes while proving nothing.


---

## 2026-09-08 (lane INVAPPLY) — M5/M8 INTERFACE INVENTORY, applied from the audit

**No milestone moved. Nothing was re-run. `milestone=` is untouched.** This
section records an inventory and a `k of n`, not a rung.

Source: `scratch-batch-s0907/M5-M8-INVENTORY-AUDIT.md`, which upheld RULES §1a's
`duet3-tool1lc` reading (*"an unmodelled link with a real peer still counts"*)
and §1b's separation of the two questions, and found three defects travelling
with the argument: **one number published for both rungs**, `n` **wrong in both
directions**, and `shared_substrate` **nulled where §1a requires it stated**.

⚠ **M5 and M8 take DIFFERENT denominators (§1b).** M5 asks about
**independence**; M8 asks about **coverage of what the image declares**. A
declaration is M8's currency. For M5 the declarations are collapsed wherever
two are **transports of one application** (§1a's solo1 ruling).

⚠ **The inventory is of the FIRMWARE UNDER TEST, not the product** (RULES §1d,
2026-09-08). The test is: *would this firmware, running, ever serve that
interface?*

**Method.** Byte census over **every image this row loads**
(`scratch-batch-s0907/laneINVAPPLY/census/`), not `grep` — w74 records `grep` in
this shell as a function returning a **silent false zero** on any NUL-containing
file, which is every image here. Each run prints `files_examined` (w85: *a check
whose input is empty passes*) and carries a negative control (`ZZ_NEG_zzq` = 0
on every image) and a **context-checked** positive control. ⚠ The audit's own
part-number control was a **false positive** — `24C` matched hex digits in a key
blob — so every control below was read in context before it was believed.
**ELF symbol tables are excluded as an inventory source** (`robot` scored
`CAN = 5991`).

### The image this row loads

```
  uTaskerMODBUS.bin  (90,185 bytes) -- the only image the config loads.
  files_examined = 1;  negative control ZZ_NEG_zzq = 0;
  positive control "WEB server" = 4, context-checked at 0x109cc.
```

### The firmware's own serial configuration menu, verbatim in that image

```
  @0x109cc:  ...Terminal menu login. FTP server. WEB server.
             WEB server authentication. TELNET server.  Telnet port...
  @0x15e88:  set_telnet
  @0x159e9:  Show Ethernet statistics
```

Rule 1 names *"the firmware's own published menu"* as a valid inventory source,
and this is one, in the image's own bytes. It does not shrink when this rehost
implements less.

### The inventory — M5 and M8 both **DEFINED and UNMET at 1 of 4**

```python
INTERFACE_INVENTORY = {
  "derivation": "the firmware's own serial configuration menu, verbatim in "
                "uTaskerMODBUS.bin",
  "declared_services": [            # M8 currency (§1b).  n = 4.
    "MODBUS/TCP :502  -- GRADED, AT M4  (MODBUS x2, uTaskerMODBUS.bin)",
    "FTP server       -- 'FTP server' x2, uTaskerMODBUS.bin",
    "WEB server       -- 'WEB server' x4 + 'WEB server authentication'",
    "TELNET server    -- 'TELNET server' + 'Telnet port' + set_telnet @0x15e88",
  ],
  "m8": "DEFINED and UNMET at 1 of 4",
  "m5": "DEFINED and UNMET at 1 of 4",
  "shared_substrate": "all four share the one Ethernet MAC and uTasker's "
                      "TCP/IP stack -- §1a's shared-substrate ruling says that "
                      "is NOT a disqualifier (the adam6000 / harmony-ph6x12 "
                      "shape).",
  "not_interfaces": [
    "ARP / ICMP -- the image's own 'Rx ICMP' x2 and ARP counters are "
    "SUBSTRATE (§1a's stack-level-reflex ruling), however genuinely the guest "
    "computes them.  The row's existing text already disposes of these "
    "correctly and that disposal STANDS.",
  ],
}
```

**Why M5 and M8 agree at 4 here, without fusing them.** MODBUS/TCP, FTP and
HTTP are three distinct applications on three distinct well-known endpoints.
The fourth, TELNET, carries the *terminal menu* — and the terminal menu is also
reachable on the serial line, so telnet is arguably a **transport** of it. But
the serial terminal menu is **not itself a separate entry in the declared list**,
so collapsing telnet into it removes nothing from either denominator. The two
numbers were computed separately and agree; they are not one variable.

### What the row already had right, and keeps

The superseded paragraph's disposal of ARP and the TCP handshake as **substrate**
is correct and is untouched — §1a's substrate ruling excludes exactly *"ARP,
ICMP echo"*. What fell is only *"one link, one application service on it"*: the
image's own menu declares three more.

**Not padded.** An entry is here only if §1a would count it. Anything I could
not source to this row's own image is recorded as **disputed**, with the
reason, rather than silently included or excluded — padding `n` makes M8
unreachable for bookkeeping reasons, which is the failure this section exists
to avoid.
