<!-- rehostry-census: milestone=M8 landed=true verdict=M4-OK verified=2026-09-29 method=live-run n=2of2 note=M5-and-M8-EACH-MET-at-2-of-2-2026-09-29;n-IS-THE-PARITY-INVENTORY-of-TWO-DECLARED-INTERFACES-derived-from-the-IMAGE-S-OWN-BYTES-(MODBUS-TCP-502-port-0x01f6-in-cMODBUS_default-0x08015540-plus-uTasker-S-OWN-SERIAL-COMMAND-CONSOLE-banner-0x0801552a)-and-is-NOT-a-count-of-commands-menu-entries-or-round-trip-keys;NO-ENTRY-WAS-REMOVED-the-denominator-is-the-SAME-2-as-2026-09-17-and-k-moved-because-the-SECOND-ENTRY-NOW-PASSES-M4;a-candidate-EXPANSION-to-4-was-REFUTED-LIVE-uTasker-s-OWN-fnConfigSCI-OPENS-THREE-USARTS-(CR1-UE-TE-RE-RXNEIE-at-pc-0x0800cdce-0x0800d09c)-but-a-CRC-VALID-MODBUS-RTU-FC03-to-USART1-0x40011000-and-USART2-0x40004400-at-slave-addresses-1-8-and-0xff-drew-NOTHING-on-a-boot-where-the-console-ANSWERED-(positive-control)-and-the-guest-s-OWN-up_time-ADVANCED-0-01-22-to-0-01-38-(so-the-RTU-end-of-frame-clock-was-RUNNING)-so-they-fail-RULES-1d-and-n-STAYS-2;the-console-entry-was-CLOSED-by-modelling-the-STM32-USART-(peripheral_models-stm32_usart-py-reversed-from-fnTxByte-0x0800d172)-and-CALLING-THE-HANDLER-THE-FIRMWARE-ITSELF-INSTALLED-in-its-relocated-RAM-vector-table-(-0x20000000-plus-0x40-plus-4-IRQ-read-back-0x0800c84d-0x0800c87f-0x0800c8b1-refused-while-it-still-read-0x0800e3d1)-so-fnSciRxByte-0x0800c946-and-fnSciTxByte-0x0800f460-move-EVERY-byte-and-the-model-mints-only-SR-TXE-and-SR-RXNE;console-seam-3-of-3-ROUNDS-x-7-TERMS-on-3-of-3-DEFAULT-RUNS-with-the-guest-s-OWN-menu-token-sets-as-a-SHRINK-GUARD-its-OWN-ipstat-counter-ADDITION-INVARIANT-(Total-Rx-169-equals-sum-169-Total-Tx-57-equals-sum-57)-its-OWN-Free-heap-0x38a0-from-0x8000-and-a-PER-ROUND-RANDOM-undeclared-token-refused-with-its-OWN-double-question-mark;KNOB---console-deaf-(bytes-still-queued-into-the-model-s-RX-FIFO-but-the-firmware-s-OWN-ISR-NEVER-CALLED)-gives-console-0-of-3-parity-1-of-2-and-M7-with-502-UNTOUCHED;---no-console-gives-parity-1-of-2-as-NOT-MEASURED-which-is-a-DIFFERENT-FIELD-from-measured-and-failed;FALSE-FLOOR-REMOVED-the-module-constants-M5_AT_M4-1-and-M8_AT_M4-1-are-GONE-and-the-numerator-is-computed-from-the-run;CHECK-3-credited-but-not-entitled-0-over-ALL-11-ARMS-via-tools-entitled-py-committed-BEFORE-the-graded-arms;M4-M6-M7-RE-RUN-2026-09-29-and-UNCHANGED-(3-of-3-and-8-of-8);DEFECT-FOUND-IN-MY-OWN-WORK-run_attack-s-child-log-path-was-a-FIXED-basename-and-provenance-bridge_bound-is-read-BACK-out-of-it-so-two-concurrent-arms-truncated-each-other-and-one-COMPLETED-round-trip-printed-landed-false-M3-now-pid-stamped-false-NEGATIVES-only-never-a-false-positive;box-at-load-19-to-26-with-ten-lanes-so-EVERY-witness-here-is-a-GUEST-EMITTED-VALUE-not-elapsed-time -->
<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# STATUS — uTasker MODBUS slave (STM32F4 / ARMv7E-M) rehost

**Current milestone: M8 — interface parity, MET at 2 of 2.** M4 is a genuine
MODBUS/TCP round-trip on :502 against the firmware's own stack, verified end to
end: ARP resolve -> TCP 3-way handshake -> FC03 request -> the firmware's own
MODBUS reply. On the **same boot and the same TCP session** the rehost is also
**M6 (stateful)** and **M7 (adversarial-input tolerance)**, each graded off M4
rather than off the other. On the **same boot**, the inventory's **second** entry
— uTasker's own serial command console — also reaches M4, so **M5 and M8 are each
MET at 2 of 2** (2026-09-29, lane `s0929-laneE`; see the section at the end).

> ⚠ **THE OPENING OF THIS FILE USED TO CONTRADICT ITSELF, AND THAT IS FIXED HERE.**
> Until 2026-09-29 this paragraph read *"M5 and M8 are UNDEFINED here, not
> failed. One link, one application service on it, one peer"* — and was then
> **superseded twice** by blockquotes below it (1 of 4 on 2026-09-08, 1 of 2 on
> 2026-09-17), leaving a flat `UNDEFINED` claim, two corrections, and a dangling
> half-sentence, all on the same screen. A reader who stopped at the bold text got
> **n = 1**, which means M5/M8 *undefined*; a reader who continued got **n = 2**,
> which means *defined*. Those are opposite claims about the same row. The
> superseded text and its orphaned fragment are now **deleted rather than layered
> over**, and the live statement is the one above: **the inventory has TWO
> entries, n = 2, and both of them now pass M4.** The row has been bitten three
> times by a denominator that read one way in prose and another in the header;
> this file now states the number once.

**What is still substrate, unchanged.** RULES §1a excludes two function codes over
one framing layer as a second interface, and the ARP replies and the TCP
handshake underneath are **stack-level reflexes** — substrate, by the 2026-09-02
ruling — not a second interface, however genuinely the guest computes them. That
disposal stands and nothing in the M8 work touches it. The 2026-09-02 ruling that
**M6/M7 do not require M5** is what made those two rungs claimable here on their
own evidence, and the same reasoning applies to M8: it is a **coverage** rung
graded off each entry's own M4 witness, not off M6 or M7.

**No `path=` in the census header, on purpose.** The M6, M7 and console phases all
run on the *default* invocation `python3 -m rehostry_utasker_modbus.attack`, so
the rung a verifier reads is the rung the documented command produces (playbook
w35). `--no-ladder` restores the M4-only run. A whole default run is ~34 s of
MODBUS work plus ~2 min of console work (three rounds of seven exchanges, each
waited out to quiescence rather than to a deadline).

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

> ⚠ **SUPERSEDED 2026-09-17 (lane `s0907-laneM5`) — see *M5/M8 RE-DERIVED,
> 1 of 2* at the end of this file.** The block below is kept verbatim so the
> correction can be checked against what it corrected. Nothing in it was
> deleted.

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

## 2026-09-08 (lane `s0907-laneEXP2`) — THE CODE NOW PRINTS WHAT THE HEADER CLAIMS

**Bookkeeping. No milestone moved, `landed` did not move, `booted` did not
move; the census header is untouched.** Live before and after: `booted:true
landed:true milestone:"M7"`.

The M5/M8 inventory above was applied on 2026-09-08 and corrected line 1 of
this file to `M5-and-M8-EACH-DEFINED-and-UNMET-at-1-of-4`. It did not touch
`attack.py`, so for a day every live run printed

```
  "m5_m8_status": "UNDEFINED: one link, one application service (MODBUS/TCP on :502), one peer..."
```

while the header said the opposite. ⚠ **A header corrected without its code is
a correction that no run reproduces** (playbook w120.6, which reported this and
correctly declined to fix it as out of its scope).

`M5_M8_STATUS` now states the corrected inventory — four declared services from
the firmware's own serial configuration menu at 0x109cc, the two denominators
computed separately, and the ARP/TCP substrate disposal **unchanged and still
stated**, because that half was always right. `tests/test_m5_m8_status.py`
couples the header and the constant so the pair cannot drift again, and asserts
that the string decides no rung.

Tests **15 → 25**, **6 of 6** deliberate size-changing breaks caught with the
test count unchanged on every one. Two of those six were caught only after
adding the tests they exposed as missing: one that the sentence *"not a second
interface"* survives verbatim (deleting `not` inverts the claim and every
keyword check still passed), and one that a **run** puts the whole string in
its result dict rather than the constant merely existing.


## 2026-09-17 (lane `s0907-laneM5`) — M5/M8 RE-DERIVED: **1 of 2**, and `n` moved in BOTH directions

**No rung moved.** `milestone` is still `M7`, `landed` is still `true`,
`booted` is still `true`, and M4/M6/M7 were **re-run live on 2026-09-17** rather
than quoted. What changed is the inventory, and it changed because the
2026-09-08 derivation was reading the wrong kind of table.

### What the `1 of 4` reading got wrong

It took this block for a manifest of services:

```
  0x08015990  [enable/disable] FTP server        0x08015f40  set_ftp
  0x080159ac  [enable/disable] WEB server        0x08015f48  set_web
  0x080157e4  [enable/disable] Telnet service    0x08015e84  set_telnet
  0x08010a04  "   Telnet port number = "
```

⚠ **The same table, in the same image, also offers:**

```
  0x08015cd2  Go to USB menu          0x0801587e  Go to utFAT disk interface
  0x08015ce2  Go to I2C menu          0x08015cec  CAN commands
```

on an STM32F429 MODBUS demo that implements **none** of the four. Censused
across the whole image, each of `USB`, `I2C`, `CAN` and `utFAT` occurs **only
inside that menu table and nowhere else** — no descriptors, no FAT layer, no
bus driver strings. **It is uTasker's generic `debug.c` command list: what the
console can PRINT, not what the firmware SERVES.** That is playbook w92.2's
lesson ("a vendor's debug-module list is not a capability manifest") arriving at
a different vendor, and it is what RULES §1d exists to catch — *"would this
firmware, running, ever serve that interface?"*

### The three entries that came OUT, each with its evidence

Byte census over `uTaskerMODBUS.bin` (90,185 B, the only image this row loads),
in Python — **not `grep`**, which in this shell is a function returning a silent
false zero on any NUL-containing file (w74). Negative control
`ZZ_NEG_zzq_not_present` = 0. Positive controls read **in context** before being
believed (the audit's own `24C` control was a false positive on hex digits).

| candidate | tokens censused | hits |
|---|---|---|
| **WEB server** | `HTTP` `200 OK` `Content-` `Connection:` `Server:` `text/` `.htm` `404` | **0, all eight** |
| **FTP server** | `220 ` `230 ` `530 ` `150 ` `226 ` `257 ` `RETR` `STOR` `LIST` `PASV` `PORT ` `Service ready` | **0, all twelve** |
| **TELNET server** | settled **live**, below | — |

### TELNET was settled LIVE, and the firmware answered for itself

One boot, one bridge, SYNs sent one at a time with an 8 s collection window, to
the firmware's own uNetwork stack:

```
  :502  502_pos_control_1   -> SYN-ACK      (seq 0)
  :20   :21   :22   :25   :69   :80   :161  :443  :503  :992
  :2323 :4444 :8000 :8080                   -> RST-ACK, EVERY ONE
  :23   telnet                              -> RST-ACK
  :4444 negative control                    -> RST-ACK  (the same refusal)
  :502  502_pos_control_1 (mid-probe)       -> SYN-ACK  (seq 12500)
  :502  502_pos_control_2 (last)            -> SYN-ACK  (seq 25000)
```

Three things make this evidence rather than an observation:

* **The guest composed every reply.** The RST-ACK acknowledgement numbers
  advance monotonically **59194 → 59211** across the seventeen probes, and the
  three SYN-ACK initial sequence numbers step **0 → 12500 → 25000** on the
  firmware's own ISN generator. Neither counter exists on the host side.
* **:4444 is the negative control** — a port nothing could plausibly claim — and
  :23, :80 and :21 draw **exactly the same refusal** it does.
* **:502 is the liveness control and it was run FIRST, MIDDLE and LAST.** Without
  it a refusal cannot be told from a stack that died mid-probe, which is the
  whole difficulty with reading a negative.

A separate one-boot sweep of **1040 ports** (1..1024 plus 16 common high ports)
produced **exactly one SYN-ACK: :502**, with the liveness control answering in
both the first and the last batch.

**Could the refusals have been composed host-side? Searched, and no — with one
hit disposed of rather than a clean zero claimed.** Every host-side artifact
(22 files: all `src/**.py`, all `configs/*.yaml`, `tools/*.py` and the probe
itself) was scanned for RST construction. The scan found **one** genuine
host-side RST send, and it is not in the receive path:

```
  portprobe2.py:132   modbus.send(modbus.tcp(mac, dport, sport, seq + 1,
                                             (sa["seq"] + 1) & 0xFFFFFFFF, 0x04))
```

That is the probe **tearing down a half-open connection**, it is **sent** rather
than received, and it fires only inside `if syn_ack:` — so it runs on **:502
alone**, which is precisely the port that did *not* answer with RST-ACK. Every
other match is prose in this repo or an unrelated register offset (`0x04` as
`PLLCFGR`, `ANAR`, a memory base). The classifier itself only ever reads
`raw_flags` out of frames taken from the bridge's `from_fw.pcap`, which is the
guest's transmit stream. **Positive control: the same search finds the host's
own SYN construction at `portprobe2.py:104`, so it was capable of finding a
send.**

⚠ **I refuted my own sweep's weaker half and am not quoting it as more than it
is.** 849 of those 1040 ports produced **no reply at all** rather than a RST —
and **:502 itself was one of them** in its own natural batch, because 16 SYNs
per batch outruns the bridge's one-frame-per-scheduler-pass injection rate. **A
silence in that sweep is a throughput artifact, not a refusal.** Only the 191
RSTs and the SYN-ACKs are informative, which is why the seventeen ports that
matter were re-probed **one at a time** in the table above.

### ⚠ THE LIMIT OF THIS TELL, and why this row survives it

The tell — *"a declared service whose token appears only inside the menu table
and nowhere else in the image is a vendor's generic menu, not this build's
service"* — was swept read-only across the other rows whose denominators came
from a configuration menu. **It fires on `apc-sumx` and `apc-rpdu2g-aos`**
(`ConsoleSSHPort` and `ftpPort` are menu-only in their `*-app.bin`) **and it is
WRONG there**: the sibling `*-aos.bin` that the same row loads carries
`SSH-2.0`×6, `ssh-rsa`×10, `diffie-hellman`×2, `220 `×2, `230 `×1, `RETR`×2.
Those services are real.

**A "menu only" verdict computed on ONE image of a multi-image row is not a row
verdict** — w68's trap (*"a census over a subset of a row's images is a census
that manufactures negatives"*) in mirror image.

**This row survives the tell because it loads exactly one image**
(`uTaskerMODBUS.bin`, 90,185 B, `paths.FIRMWARE_BIN`, the only `file:` in
`utasker_config.yaml`) **and that image contains no HTTP and no FTP code
anywhere in it.** There is no sibling for the code to be hiding in. Applied to
the five APC rows, three grblhal/flipper/rusefi rows and this one — **ten images,
negative control 0 on every one — the tell changes `n` on this row alone.**

### The entry that went IN — and it was hiding in plain sight

The menu the previous reading was quoting **is itself the published interface of
uTasker's serial command console**:

```
  0x0801552a  "uTasker-MODBUS-slave  "      the banner
  0x080154b3  "  uTasker&STM32"
  0x080154ad  "ADMIN"
  0x08012eb4  "Command line blocked"
  0x08015b68  "Leave command mode"
```

A link (the UART) with a peer (an operator's terminal) exchanging structured
messages, declared by the firmware's own bytes. §1a's `duet3-tool1lc` ruling
counts exactly that — *"an unmodelled link with a real peer still counts"* — and
**this rehost does not drive it**. The previous reading counted the menu's
**contents** and walked past the menu's **own** interface.

### The inventory

```python
# M8's currency is DECLARATIONS (§1b) -- of the IMAGE UNDER TEST (§1d).
M8_DECLARED_INTERFACES = [
    "MODBUS/TCP :502 -- GRADED, AT M4 (port 0x01f6 in cMODBUS_default "
    "@0x08015540; fnMODBUSListener 0x08012738)",
    "uTasker serial command console -- banner 'uTasker-MODBUS-slave  ' "
    "@0x0801552a, 'ADMIN' @0x080154ad, 'Command line blocked' @0x08012eb4; "
    "NOT driven by this rehost",
]

# M5's currency is §1a-INDEPENDENT interfaces -- a DIFFERENT expression over a
# DIFFERENT list object.
M5_INDEPENDENT_INTERFACES = [
    "MODBUS/TCP :502 application service -- own transport endpoint, own "
    "application logic (fnHandleMODBUS_input)",
    "uTasker command console on the serial line -- own transport endpoint "
    "(the UART), own application logic (the command interpreter)",
]

assert M5_INDEPENDENT_INTERFACES is not M8_DECLARED_INTERFACES
```

**M5 = DEFINED and UNMET at 1 of 2. M8 = DEFINED and UNMET at 1 of 2.**

⚠ **The invariant here is NOT `m5_n != m8_n`.** w92.1's defect is **one
VARIABLE, not one VALUE** — `duet3-mb6hc` is legitimately M5 = M8 = 6 from two
expressions. Nothing collapses on this row either, so the two agree, and what is
asserted is that they are not the same object. Both arms, 2026-09-17:

```
  ARM A (as shipped):  m5 = DEFINED and UNMET at 1 of 2
                       m8 = DEFINED and UNMET at 1 of 2   distinct objects: True
  ARM B (re-fused, `M5_INDEPENDENT_INTERFACES = M8_DECLARED_INTERFACES`):
                       AssertionError: M5 (independence, RULES §1a) and M8
                       (coverage, RULES §1b) must be computed from two SEPARATE
                       expressions over two SEPARATE lists...
```

### `shared_substrate`, stated — and on this row it really is nothing

**The two entries share nothing below uTasker's cooperative scheduler.**
MODBUS/TCP :502 runs over the Ethernet MAC and uTasker's TCP/IP stack; the
command console runs over the UART. They share the scheduler, and the scheduler
is named here so a reader applying a stricter rule can weigh it. (§1a's
shared-substrate ruling requires this field be **stated**; a previous lane on
the APC family set it to `None` and that was simply false *there*. It is stated
here, with its reason, rather than nulled.)

### What I refused to count, and why

* **ARP / ICMP, the TCP handshake, and the RST-ACKs themselves** — substrate
  (§1a's stack-level-reflex ruling). The RSTs are **evidence about** the
  inventory, never an entry in it. The row's existing disposal stands unchanged.
* **WEB / FTP** — menu labels with no implementing code (§1d).
* **TELNET** — no listener anywhere in 1..1024, and in any case a *transport* of
  the console application, which §1a's solo1 ruling collapses.
* **USB / I²C / CAN / utFAT** — tokens that occur only inside the menu table.
* **Registers 2..5 ramping on their own** — the firmware's own state, not a
  peer.

### ⚠ DISPUTED — recorded, not silently excluded

**TELNET.** `set_telnet` @0x08015e84 and `   Telnet port number = ` @0x08010a04
are a **config key whose value is a TCP port number**, which is a firmware-side
statement that the service has its own transport endpoint. A reader who weighs
that above the live refusal — on the theory that the server is compiled in but
gated behind a saved parameter this boot leaves clear — gets **M8 1 of 3**. I
exclude it, because no port in 1..1024 answered and because the same table's
USB/I²C/CAN/utFAT entries are demonstrably not in this build. The evidence is
written down so that number can be re-derived rather than argued about.

### The ladder, enumerated — and there is no M5 branch, correctly

`ast` over `attack.py`: the milestone values **written** are exactly
`{None, "M0", "M3", "M4", "M6", "M7"}`, and every one is **printable** by a
documented invocation (firmware moved aside → `M0`; `HAL_SEAM_CONTROL=1` → `M3`;
`--no-ladder` → `M4`; `--m7-wellformed` → `M6`; default → `M7`; a harness fault →
`None`). `"M5"` does not occur in the module in any form. **WRITTEN ==
PRINTABLE**, and the gate cannot print a rung no phase of this run measures —
which is the correct shape for a row whose M5 is *defined and unmet*, not for
one that is being quietly capped. `_extend_milestone` is pure (`bool` and
`result.get` only, no `try`), reads `M5_M8_STATUS` exactly once — to **write** it
into the result — and no `if` in it tests that name.

**NEW `M4-OK` credits created by this correction: 0.** Nothing here is a rung.

### The live re-run behind `verified=2026-09-17`, with BOTH arms of every control

Eight arms, this session. **Load is reported per run, never averaged** — the box
is shared. Every row scored by **importing**
`scratch-census-guard-a48/census_score.py`
(sha256 `56cd3ab36c942ff1141dd8a24dfa6a09a813080ed8c69d50950869db592f13cc`),
never a fork.

| arm | load at launch | booted | landed | milestone | guard | M6 | M7 |
|---|---|---|---|---|---|---|---|
| default #1 | 3.74 | true | true | **M7** | `M4-OK` | 3/3 | 8/8 |
| default #2 | 5.67 | true | true | **M7** | `M4-OK` | 3/3 | 8/8 |
| default #3 | 5.56 | true | true | **M7** | `M4-OK` | 3/3 | 8/8 |
| `--m6-freeze` | 6.76 | true | true | M7 | `M4-OK` | **0/3** | 8/8 |
| `--m7-wellformed` | 6.61 | true | true | **M6** | `M4-OK` | 3/3 | **0/8** |
| `--no-ladder` | 5.99 | true | true | **M4** | `M4-OK` | — | — |
| `HAL_SEAM_CONTROL=1` | 5.57 | true | **false** | M3 | **`WALL-M3`** | — | — |
| `HAL_PY=/usr/bin/false` | 5.81 | **false** | false | M0 | **`WALL-M0`** | — | — |

**N-of-N, not `>= 1`:** the default path is **3 of 3** runs at `M7`, each with
M6 3/3 and M7 8/8 — `passed == rounds` in every phase of every run. The six
milestone values the ladder can write are the six these eight arms printed, so
**WRITTEN == PRINTABLE** is demonstrated by runs and not only by `ast`.

**NEW `M4-OK` credits created by this session: 0.** The row was already
`M4-OK`/M7 and still is. Nothing in this correction is a rung.

**Core worktrees: unmodified.** This row runs against the installed
`halucinator@dev` core through its own venv; `spawn.py` deliberately strips
`HALUCINATOR_SRC` and `PYTHONPATH` so no out-of-tree core can shadow it. I
state this rather than patch it (RULES §2a).

---

## 2026-09-29 (lane `s0929-laneE`) — **M7 → M8**: the second inventory entry is now DRIVEN, parity **2 of 2**

**THE DENOMINATOR DID NOT MOVE. NO ENTRY WAS REMOVED.** The inventory is the same
**two** entries the 2026-09-17 lane derived from the image's own bytes, and the
`k` moved because the **second one now passes M4**, not because the `n` got
smaller. A candidate *expansion* to 4 appeared during this work and was
**refuted on a live measurement** (below) — the one direction that costs the rung,
tested rather than waved away.

### What was missing, in one line

The 2026-09-17 inventory recorded its second entry as *"uTasker serial command
console … **NOT driven by this rehost**"*. The whole 0x40000000 SoC window was one
`AutoPeripheral` catch-all, so the console's bytes went into the catch-all and
nothing could be read back. Two new pieces close it, and neither synthesises a
byte on the firmware's behalf.

### 1. `peripheral_models/stm32_usart.py` — the wire, and only the wire

Reversed from the firmware's own code:

```
fnConfigSCI   0x0800cac0..0x0800cb32   channel -> {base, RCC bit, IRQ}
      ch0 -> 0x40011000 USART1, RCC_APB2ENR |= 0x10,    IRQ 37
      ch1 -> 0x40004400 USART2, RCC_APB1ENR |= 0x20000, IRQ 38
      ch2 -> 0x40004800 USART3, RCC_APB1ENR |= 0x40000, IRQ 39

fnTxByte      0x0800d172
      0x0800d186  ldr  r2,[r0]      ; SR
      0x0800d188  lsls r3,r2,#24    ;   bit 7 = TXE
      0x0800d18c  ldr  r2,[r0,#12]  ; CR1
      0x0800d18e  orr  r2,#0x80     ;   |= TXEIE
      0x0800d194  str  r1,[r0,#4]   ; DR <- the byte

USART1_IRQHandler 0x0800c84c   (0x0800c87e = USART2, 0x0800c8b0 = USART3)
      CR1 bit5 RXNEIE & SR bit5 RXNE -> ldr r0,[r4,#4] (DR) -> bl 0x0800c946  fnSciRxByte
      CR1 bit7 TXEIE  & SR bit7 TXE  ->                        bl 0x0800f460  fnSciTxByte
```

The model answers `SR.TXE`/`SR.TC` set, `SR.RXNE` set while a host byte is queued,
pops that byte on a `DR` read and captures a `DR` write. Everything else is plain
write-through/read-back, because the ISR **branches on CR1** and a model that did
not return what the driver wrote would make the firmware's own ISR do nothing —
and the seam would have looked dead for a reason that was ours.

**It mints the wire condition and nothing else.** The reply is composed entirely
inside the guest: `fnSciRxByte` in, `fnSciTxByte` → `fnTxByte` → `DR` out. This
is RULES §1c's shape — the host mints the wire field, the firmware does the
transform.

### 2. `bp_handlers/serial_bridge.py` — and it calls the handler the FIRMWARE installed

This image has no IRQ vectors (it starts at 0x0800c080 with only SP+Reset), so the
core cannot deliver IRQ 37/38/39. uTasker relocates its vector table into SRAM at
0x20000000 and `fnConfigSCI` installs its own handler there. **The bridge reads
that table back before it calls anything**, at `[0x20000000 + 0x40 + 4*IRQ]`, and
refuses to inject if the address is not the one it expected.

⭐ **That check earned its keep on the first boot, in both directions.** Early in
the boot the three vectors read `0x0800e3d1` — uTasker's default handler — and the
bridge declined. Once `fnConfigSCI` had run they read:

```
serial_bridge: IRQ 37 vector [0x200000d4] = 0x0800e3d1, calling 0x0800c84c -- firmware's own handler: NO
serial_bridge: IRQ 38 vector [0x200000d8] = 0x0800e3d1, calling 0x0800c87e -- firmware's own handler: NO
serial_bridge: IRQ 39 vector [0x200000dc] = 0x0800e3d1, calling 0x0800c8b0 -- firmware's own handler: NO
   ... later, after fnConfigSCI ...
serial_bridge: IRQ 37 vector [0x200000d4] = 0x0800c84d, calling 0x0800c84c -- firmware's own handler: YES
serial_bridge: IRQ 38 vector [0x200000d8] = 0x0800c87f, calling 0x0800c87e -- firmware's own handler: YES
serial_bridge: IRQ 39 vector [0x200000dc] = 0x0800c8b1, calling 0x0800c8b0 -- firmware's own handler: YES
```

`0x0800c84d` / `0x0800c87f` / `0x0800c8b1` are exactly the three addresses
recovered by disassembly, with the Thumb bit — **the firmware's own statement of
who handles those interrupts**, not our choice of entry point. (An early version
latched the first `NO` and disabled the bridge for the whole run; it now re-checks
until the table agrees, because a table the firmware has not filled in yet is not
a disagreement.)

**It shares `eth_bridge`'s borrowed-context machinery deliberately.** Two
independent borrowers would each keep their own `_busy` flag and could inject a
call while the other's was in flight, corrupting the saved context. One borrower,
one `_busy`. Serial work is *not* gated on the ETH driver being up (different
link), and it injects only when the host has queued a byte or the firmware's own
driver has left `TXEIE` set — so **a run that never uses the console is
byte-identical to one without it**, which is what kept M4/M6/M7 unmoved.

### ⚠ A1 WAS REFUTED, AND IT MATTERED: the firmware opens THREE UARTs

Part A of `predictions/2026-09-29-m8-serial-console.md` predicted **exactly one**
configured block, and USART1. Measured on the first boot with the USART page
mapped:

```
uart 0x40011000: CR1 0x0000 -> 0x2024 (UE=1 TE=0 RE=1 TXEIE=0 RXNEIE=1) pc=0x0800cdce
uart 0x40011000: CR1 0x2024 -> 0x202c (UE=1 TE=1 RE=1 TXEIE=0 RXNEIE=1) pc=0x0800d09c
uart 0x40004400: CR1 0x0000 -> 0x2024 ...
uart 0x40004800: CR1 0x0000 -> 0x2024 ...
```

**Three blocks opened, all with UE|TE|RE|RXNEIE.** "A UART is open" would have
grown the denominator from 2 to 4. So the question became a measurement, and it
was run twice.

**Which one carries the console: asked, not assumed.** The same bytes go to all
three in **one observation window**, and the window closes only once at least one
has answered and gone quiet — so the block that answers is the **positive control
for the two that do not**, in the same window. (An earlier version waited on each
block in turn, which meant a silent block was observed in a *different* window
from the answering one and its silence was always arguable.) Every default run
since:

```
console_probe: the firmware opened 3 USART blocks; 1 answered a bare CR: ['0x40004800']
   result={'0x40011000': 0, '0x40004400': 0, '0x40004800': 719}
```

**Are USART1/USART2 MODBUS-RTU slave ports?** A well-formed FC03 with a correct
CRC-16 was delivered to both at slave addresses **1..8 and 0xff**. The firmware's
own driver **read every byte** (the model logged each `DR` read, so `fnSciRxByte`
ran) and **transmitted nothing**.

⚠ **The first arm of that test was not interpretable and I did not quote it as if
it were.** `eth_bridge` only advances the RTOS clock after three TX frames, so in
a console-only boot `fnRtmkSystemTick` never fires and an RTU **end-of-frame
timer** could never expire — the silence would have been the model's, not the
firmware's. *A null result eliminates nothing unless the model was right.* It was
re-run with a MODBUS/TCP session first and `HAL_UT_TICK_HZ=20`, on a boot where
the console answered (positive control) and the guest's own `up_time` advanced
`0:01:22 -> 0:01:38` (so the clock demonstrably was running). Both blocks stayed
silent in that arm too.

**Verdict:** an open link with no application behind it fails §1d's test — *would
this firmware, running, ever serve that interface?* — so they are recorded under
`not_interfaces` with their measurement, and **n stays 2**.

### The console's own published menu is the SHRINK GUARD, not the denominator

`device-vesc-bms`'s formula, applied: *the firmware's own published menu, parsed
from the guest's bytes every run, with a pre-registered token set as a shrink
guard — mismatch either way VOIDS parity.* Parsed live, every round:

```
     Main menu            1 2 3 4 5 6 7 8 9 a help quit                (12 tokens)
   Stats. menu            up ipstat r_ipstat up_time memory help quit   ( 7 tokens)
```

⚠ **And it is emphatically NOT the interface inventory.** This row's own
2026-09-17 finding is that this table is a **command list**, not a capability
manifest — it offers *Go to USB menu*, *Go to I2C menu*, *CAN commands* and *Go to
utFAT disk interface* on a build that implements none of them. 12 ≠ 2, and a test
asserts the guard's size is not the denominator.

### The console seam's M4 — seven terms per round, 3 of 3 rounds, three default runs

| term | what it is constructed from |
|---|---|
| `menu_matches_registered` | the guest's own main-menu tokens == the pre-registered 12. **Mismatch either way VOIDS.** |
| `stats_menu_matches` | `5` navigates, and the guest prints exactly its 7 stats tokens — a second declared command, and the firmware's own menu state machine |
| `ipstat_invariant` | **a VALUE with an invariant the firmware maintains**: `Total Rx frames` == the sum of its own nine per-protocol Rx counters, `Total Tx frames` == the sum of its four Tx counters, both non-zero. Measured every round: **Rx 169 = 169, Tx 57 = 57** |
| `memory_invariant` | **a second VALUE, of a different kind**: `Free heap = 0x38a0 from 0x8000`, with 0 < free < total (and the boot banner's own `OS Heap use = 0x3040 from 0x8000` is the same total) |
| `undeclared_refused` | a **per-round random** token (`z` + 3 random bytes hex) draws the guest's own `??` and **no menu** |
| `discriminates` | RULES §1c: a boolean "it replied" is the weak case. The declared and undeclared replies must **differ** |
| `alive_after` | the menu still answers after the bad token |

**Rule 2, per entry:** `passed == rounds`, never `>= 1`. Three rounds, seven terms,
all true, on each of **3 of 3** default runs.

**A reply still arriving when its ceiling expires is `growing`, and the round is
recorded UNMEASURED — never failed.** A probe that stops a fixed time after the
last byte it happened to see has produced five false failures on this fleet;
`console.read_until_quiet` returns `quiet` / `silent` / `growing` as three distinct
statuses and *cannot-measure never shares a value with measured-and-bad*.

### Each entry has its OWN witness, and each witness carries a VALUE

⚠ On another row **two entries were DECLARED ANSWERED BUT NOT DRIVEN**, sharing
one `Done!` string at one address. Here:

* **MODBUS/TCP :502** — the FC06 read-back of an attacker-chosen 16-bit value
  through the firmware's own MODBUS engine (`0x1234 -> 0x1244`, high byte
  compared because the low bits are live), gated on provenance.
* **the serial console** — the guest's own `ipstat` counter-addition invariant and
  its own `Free heap` figure, plus a declared/undeclared discrimination.

They share no term, no variable and no string, and a test asserts it.

### ⚠ THE FALSE FLOOR I FOUND IN THIS ROW AND REMOVED

`attack.py` carried

```python
M5_AT_M4 = 1          # MODBUS/TCP :502
M8_AT_M4 = 1          # same seam, counted under the other rung's currency
```

and `INTERFACE_INVENTORY["m8"]` was built from them. **A hard-coded numerator
credits an interface in a run that never touched it, and no control arm can move
it.** Both are gone; `interface_parity(result)` computes the numerator from the
run's own observations, and `tests/test_m5_m8_status.py` asserts the constants no
longer exist and that a run which drove nothing reports **0 of 2**.

`M5_M8_STATUS` was likewise a string beginning `"DEFINED and UNMET at 1 of 2"` —
the same floor in prose. It is now `M5_M8_DERIVATION` (the static *derivation*,
which is a property of the image) plus `m5_m8_status(parity)`, which prefixes the
run's measured `k of n`.

### The falsification knob — `--console-deaf`, and it BINDS

The host's bytes are still queued into the USART model's RX FIFO and the model
still answers `SR`/`DR`; the **only** thing removed is the call to the firmware's
own ISR, so nothing reaches `fnSciRxByte`.

```
console_probe: the firmware opened 3 USART blocks; 0 answered a bare CR: []
console: no opened USART block answered a bare CR; the console entry was DRIVEN and did not answer
console: 0/3 rounds (deaf arm=True, voided=False, unmeasured=0) -> False
RESULT: landed:true  milestone:"M7"  modbus_round_trip:true  m6:3/3  m7:8/8
        console_round_trip:false  interface_parity_full:false
PARITY: 1 of 2  passed=[0]
```

**Parity 2 of 2 -> 1 of 2, M8 -> M7, and :502 untouched.** That is the
control-gated verdict for M8.

⚠ **And it fails as MEASURED-AND-FAILED, not as voided.** The first cut treated
"no block answered" as a void, which printed *"no parity is published"* — a knob
whose outcome is indistinguishable from a measurement error is not a knob.
`len(answered) == 0` is now a **failed entry** and only `len(answered) > 1` (the
seam not identified) voids.

**`--no-console` is the other half, and the two are different fields.** It skips
the phase with the USART page still mapped, so the machine is identical:
`console_round_trip: null` + `console_skipped_reason: "console_phase=False"`,
parity **1 of 2** because the entry was **NOT MEASURED**. The deaf arm is
`console_round_trip: false` + `0/3` + a `failed_reason`. *Unmeasured is never
implied-refused.*

### ⚠ A DEFECT IN MY OWN WORK, and a latent one in this row that it exposed

I ran two arms of this device **concurrently**, and `run_attack` built its child
log path from a **fixed basename**:

```python
log_path = os.path.join(ld, "utasker_modbus_attack.log")
```

`provenance.bridge_bound` is read back **out of that file**, so the second arm's
`open(..., "w")` **truncated the first arm's log** and the first could no longer
find its own `spool=` line. The measured consequence: an arm with
`write_acknowledged: true` and `after_hex: 0x1244` — a **completed round trip** —
printed `landed: false, milestone: M3`.

* The path now carries the pid and a millisecond stamp.
* **No recorded result was ever inflated by this.** The string searched for
  contains the run's own unguessable private spool path, so a false *positive* was
  never possible; it manufactures false *negatives*, which is how it was caught.
* The affected arm (`--console-deaf`, first attempt) is **discarded, not
  reinterpreted**, and was re-run alone. The re-run is the one quoted above.

### Every arm, this session

**⚠ THE BOX WAS AT LOAD 21–26 (ten lanes).** Every load figure is reported per run
and never averaged, and **no verdict here rests on elapsed time** — the witnesses
are values the guest emitted (counters, heap figures, register read-backs, menu
tokens). The one place wall-clock enters is the quiescence window, and that is
constructed so a slow box yields `growing` → *unmeasured*, not a failure.

| arm | load at launch | booted | landed | milestone | M6 | M7 | console | parity | `entitled()` |
|---|---|---|---|---|---|---|---|---|---|
| default #1 | 20.98 | true | true | **M8** | 3/3 | 8/8 | **3/3** | **2 of 2** | M8 |
| default #2 | 23.65 | true | true | **M8** | 3/3 | 8/8 | **3/3** | **2 of 2** | M8 |
| default #3 | 21.90 | true | true | **M8** | 3/3 | 8/8 | **3/3** | **2 of 2** | M8 |
| `--console-deaf` | 21.90 | true | true | **M7** | 3/3 | 8/8 | **0/3** | **1 of 2** | M7 |
| `--console-deaf` (1st try, VOID) | 23.88 | true | *false* | *M3* | 3/3 | 8/8 | 0/3 | 0 of 2 | M3 |
| `--no-console` | 23.65 | true | true | M7 | 3/3 | 8/8 | **not measured** | 1 of 2 | M7 |
| `--m6-freeze` | 21.38 | true | true | M8 | **0/3** | 8/8 | 3/3 | 2 of 2 | M8 |
| `--m7-wellformed` | 21.43 | true | true | M8 | 3/3 | **0/8** | 3/3 | 2 of 2 | M8 |
| `--no-ladder` | 19.51 | true | true | **M4** | skipped | skipped | not measured | 1 of 2 | M4 |
| `HAL_SEAM_CONTROL=1` | 19.72 | true | **false** | **M3** | — | — | — | 0 of 2 | M3 |
| `HAL_PY=/usr/bin/false` | 20.26 | **false** | false | **M0** | — | — | — | 0 of 2 | M0 |

**N-of-N, not `>= 1`:** the default path is **3 of 3** runs at `M8`, each with M6
3/3, M7 8/8 and the console 3/3 — `passed == rounds` in every phase of every run.
The seven milestone values the ladder can write are the seven these eleven arms
printed, so **WRITTEN == PRINTABLE** is demonstrated by runs and not only by `ast`.

The `--console-deaf` first attempt is in the table **because it is in the record**,
voided by the log-path defect above, not deleted from it. Note that `entitled()`
agrees with it too: its observations genuinely did not support M4, *because the
provenance term it reads was the one that broke*. The check caught no
credited-but-not-entitled; the **log-path race** is what caught that arm, and a
reader should see both facts.

⚠ **`--m6-freeze` and `--m7-wellformed` now print `M8`, where they used to print
`M7` and `M6`.** That is not a regression and not a cap being lifted: **M8 is a
COVERAGE rung** and, per the 2026-09-02 ruling that a scorer chaining
`M7 <- M6 <- M5` is a defect in the scorer, it is graded off each entry's own M4
witness — which those two knobs do not touch. Each knob is still demonstrably
binding, in its own column: `0/3` and `0/8`. **A reader must not read `M8` on
those two arms as a claim about M6 or M7**; the per-rung numbers in the row are
the claim, and on those arms one of them is deliberately false.

**The firmware image is byte-identical before and after every arm**
(`sha256 dc28f4280d97e92c8736ebfe8148238b2a06f2b612bd8e18b94e4c49cb8ca860`,
checked on both sides of every chain).

### The ladder, enumerated — and M5 is deliberately not a milestone VALUE

`ast` over `attack.py`: the milestone values **written** are exactly
`{None, "M0", "M3", "M4", "M6", "M7", "M8"}`, and every one is **printable** by a
documented invocation (firmware moved aside → `M0`; `HAL_SEAM_CONTROL=1` → `M3`;
`--no-ladder` → `M4`; `--m7-wellformed` → `M6`; `--console-deaf` → `M7`; default →
`M8`; a harness fault → `None`). **WRITTEN == PRINTABLE.**

⚠ **`"M5"` is still not a milestone value, and that is not a cap.** This row's
independent set and its declared set are the **same two entries**, so
`len(passed) == 2` makes M5 and M8 true *together* and `len(passed) < 2` makes both
false: an "M5 but not M8" state has no shape on this row. M5's own `k of n` is
published in `interface_parity["m5"]`, computed from a **separate expression over
a separate list** (w92.1's invariant is one VARIABLE, not one VALUE).

### CHECK 3 — `entitled()` over the OBSERVATIONS, and why the term enumerator cannot do it

`tools/entitled.py` re-derives the rung from §0's own wording applied to the run's
**observations** — it recomputes the FC06 high-byte comparison from
`attack.after`/`attack.value` rather than reading `attack.landed`, re-checks every
console round's terms, and never reads `milestone`, `landed`,
`interface_parity_full` or `m5_m8_status`. It was **committed before the graded
arms were run** (`699927c`), and it reports `credited-but-not-entitled`.

**Run over all eleven arms of this session: `credited-but-not-entitled` = 0**, with
the independent derivation agreeing with the printed rung on every one
(`M8 M8 M8 M7 M7 M4 M3 M0 M8 M8 M3`). `landed` assignment sites in `attack.py`
= **2** (> 0, asserted).

⚠ The fleet's standard `enumerate_ladder.py` **cannot** do this: it runs
`itertools.product((False, True), repeat=len(TERMS))` into the ladder, so it
quantifies over the ladder's **terms** and never inspects how a term is
**constructed**. A ladder can be a correct function of its terms while a term is
itself circular, and it reports CLEAN either way.

⚠ **Checks 1 and 2 are 0 BY CONSTRUCTION on this row and prove nothing.** `landed`
is built from `modbus_round_trip AND provenance.ok` and `milestone` is then derived
*from* `landed`, so "landed without M4" and "landed disagrees with the rung" cannot
fire. `entitled.py` says so in its own output rather than presenting the zeros as a
pass, and it asserts the `landed` **assignment-site count is > 0** — a `landed`
never assigned from an observation would be derived from the rung instead.

### Emulator-free controls (`tests/test_console_seam.py`, 17 tests)

The numerator can reach **zero** with the **real** graders:

* `test_a_dead_wire_credits_no_interface` — the real `run_console` against a spool
  no emulator is servicing: `0` rounds, `failed_reason` set, `voided` false,
  parity **1 of 2**.
* `test_a_TRUNCATED_menu_does_not_match_and_so_VOIDS` / `..._an_EXTENDED_menu...` —
  the shrink guard, **both** directions.
* `test_the_ipstat_invariant_CATCHES_a_fabricated_block` — a plausible-but-wrong
  total (`20 -> 21`) breaks the Rx invariant and leaves the Tx one intact.
* `test_a_zeroed_ipstat_block_fails_the_nonzero_term` — all-zeros adds up
  perfectly, which is exactly why `rx_nonzero`/`tx_nonzero` are separate terms.
* `test_the_bridge_refuses_a_handler_the_firmware_did_not_install` — vectors
  reading `0x0800e3d1`: no injection at all.
* `test_the_DEAF_knob_ingests_but_never_calls_the_firmware` — the knob is not
  inert in the other direction either: the bytes still reach the model's RX FIFO.
* `test_an_empty_inventory_is_a_FAULT_and_never_0_of_0` — `all([])` is vacuously
  true and has scored a dead arm as perfect twice on this fleet.

### What is NOT claimed

* **`up_time` is recorded, not graded.** It advances only when the free-running
  RTOS tick is on, and the default path leaves it off (`eth_bridge.__init__`
  assigns `self._tick_hz` **twice**, the second with default `"0"`, which disables
  the free-running tick — that looks like an unintended duplicate and is recorded
  rather than changed, because changing it would perturb the MODBUS evidence this
  session had to leave untouched).
* **The `ipstat` cross-check is corroboration, not a gating term.** It is reported:
  `guest_total_tx 57` == `host_frames_received 57` exactly, and
  `guest_total_rx 169 >= host_frames_injected 112`. It is the deaf-console guard —
  those numbers exist in no handler, model or config of ours — and it gates
  nothing, so no other rung's evidence is imported into this one.
* **USART1/USART2 at slave addresses outside 1..8 and 0xff were not probed.** If a
  MODBUS-RTU slave were listening there on some other address the sweep would have
  missed it; the exclusion rests on 10 addresses, a positive control and a running
  clock, and that is what it rests on.
* **No core change.** This row runs against the installed core through
  `.venv-dev`; `spawn.py` strips `HALUCINATOR_SRC`/`PYTHONPATH`.

**NEW `M4-OK` credits created by this session: 1** — the serial console seam. The
row was already `M4-OK` on :502 and still is; `verdict=` is unchanged because
`landed: true` means M4 and only M4.

### Scored by the fleet guard, IMPORTED and never forked

Every arm scored by importing `scratch-census-guard-a48/census_score.py`
(sha256 `56cd3ab36c942ff1141dd8a24dfa6a09a813080ed8c69d50950869db592f13cc`):

```
default #1 / #2 / #3      booted:true  landed:true   M8  M4-OK   "milestone M8"
--console-deaf            booted:true  landed:true   M7  M4-OK   "milestone M7; unmet sub-goal(s) disclosed: console_round_trip"
--console-deaf (1st, VOID) booted:true landed:false  M3  WALL-M3 "landed:false -- no claim to check"
--no-console              booted:true  landed:true   M7  M4-OK   "milestone M7"
--m6-freeze               booted:true  landed:true   M8  M4-OK   "milestone M8"
--m7-wellformed           booted:true  landed:true   M8  M4-OK   "milestone M8"
--no-ladder               booted:true  landed:true   M4  M4-OK   "milestone M4"
HAL_SEAM_CONTROL=1        booted:true  landed:false  M3  WALL-M3 "landed:false -- no claim to check"
HAL_PY=/usr/bin/false     booted:false landed:false  M0  WALL-M0 "landed:false -- no claim to check"
```

**CHECK 1 — `DEFECT-landed-without-M4`: 0.** **CHECK 2 — landed-vs-rung
disagreement: 0.** ⚠ Both are **0 by construction** here, stated rather than
claimed as a pass: `landed` is built from `modbus_round_trip AND provenance.ok`
and `milestone` is derived *from* `landed`, so neither check can fire on this row.
**CHECK 3 — `credited-but-not-entitled`: 0 over all eleven arms**, computed over
each run's OBSERVATIONS by `tools/entitled.py`, which was committed before the
graded arms ran. That is the one of the three that could have failed.

**No performance regression from the serial bridge.** `--no-ladder` (the same
MODBUS work, with the USART page mapped and the bridge installed) completed in
27 s at load 19.5; the pre-change baseline was 34 s at load 5.1. Both are
wall-clock on a shared box and are **indicative only** — the structural reason a
console-free run is unaffected is that the bridge injects nothing at all unless a
byte is queued or the firmware's own driver has left `TXEIE` set.

### Referral to `device-utasker-usb` — and it is NOT corroboration

`device-utasker-usb` records its own M8 gap as *"reached `fnEndpointData`, never
reached `fnCommandInput`… find what starts the `maintenace` task"*. That row and
this one share uTasker and a vendor tree, so "the uTasker command task is never
dispatched" looks like one finding seen twice.

⚠ **It is not. Measured here: on THIS image the command console task runs
perfectly well with no help at all** — the firmware printed its own
`Hello, world... NUCLEO-F429ZI (STM32F429ZI)`, `Serial number:`,
`Software version V1.4.012` and its full Main menu unprompted, and answered
`help` / `5` / `ipstat` / `memory` / `up_time` / `quit` / an unknown token. So
uTasker's console task is **not** the thing that fails to be dispatched, and the
USB row's wall must be **USB-specific** (the event that wakes the task which
drains the USB CDC queue), not a general uTasker scheduling gap.

**Two sibling rows agreeing is one observation until each has been measured
separately.** This is the measurement for this row; the USB row still needs its
own.
