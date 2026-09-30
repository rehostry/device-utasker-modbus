<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Pre-registered predictions — M8 attempt on `device-utasker-modbus`

Lane `s0929-laneE`, 2026-09-29. **Part A is committed BEFORE the first recon
boot; Part B is committed BEFORE the first graded arm.** Each prediction names
what would refute it. A refutation of my own prediction is the result.

## The question

The row is **M7**, with **M5 and M8 each DEFINED and UNMET at 1 of 2**. The
inventory's second entry is *uTasker's own serial command console* — banner
`uTasker-MODBUS-slave  ` @0x0801552a, `ADMIN` @0x080154ad, `Command line
blocked` @0x08012eb4 — which the 2026-09-17 lane added and explicitly recorded
as **NOT driven by this rehost**. Closing it at M4 closes parity to **2 of 2**.

The denominator is **NOT touched by this attempt**. Nothing is removed; the
inventory stays the same two entries derived on 2026-09-17 from the image's own
bytes. If the console cannot be driven, the honest outcome is *still* 1 of 2 and
the answer is "not measured" or "measured and failed", never a smaller `n`.

## Why a UART is a legitimate second interface here, before any of it is run

Its own transport endpoint (the USART, a different link) and its own application
logic (uTasker's command interpreter, a different parser in a different task) —
RULES §1a's `duet3-tool1lc` shape, already recorded in this row's
`M5_INDEPENDENT_INTERFACES`. It is *not* substrate: nothing in the IP/link layer
answers a console command.

## Part A — recon (committed 2026-09-29 before the first boot with a USART page)

**A1 — exactly one UART register block is configured, and it is USART1
(0x40011000).** uTasker's own `fnConfigSCI` (0x0800cac0..0x0800cb32) can select
only three: channel 0 -> 0x40011000 / RCC_APB2ENR bit 4 / IRQ 37, channel 1 ->
0x40004400, channel 2 -> 0x40004800. I predict the firmware sets `CR1.UE`
(bit 13) on **exactly one** of them and that it is **0x40011000**.

*Refuted if* more than one block, or a different block, is enabled — or if none
is, which would mean this image never opens a serial port at all and the console
entry is unreachable rather than undriven.

**A2 — the console does not speak first.** uTasker's command console is
request/response: it prints its menu in answer to input. I predict the TX
capture is **empty or near-empty before any host byte is injected**. This is
recon, not a graded term: a banner appearing unprompted would be *welcome*
evidence, and its absence refutes nothing.

**A3 — `fnSciRxByte` (0x0800c946) is never reached on a boot with no injected
input.** The rehost delivers no serial interrupts today, so the firmware's own
receive path must be cold. *Refuted if* it is hit with no host byte queued — in
which case something else in this rehost is already feeding the console and my
whole reading of the seam is wrong.

## Part B — the graded arms (committed 2026-09-29 before the first graded run)

Registered after Part A's recon boot and **before** any arm whose result is
quoted as evidence. Recon informed the model; these are the terms.

**B1 — the firmware's own USART1 ISR, called on the borrowed-context seam with a
byte queued in the model's RX FIFO, reaches `fnSciRxByte`.** The ISR at
0x0800c84c reads CR1, tests RXNEIE, reads SR, tests RXNE, reads DR and calls
0x0800c946. Every one of those reads is answered by `stm32_usart.py`, and the
byte is the one the host queued.

*Refuted if* `fnSciRxByte` is not entered, or is entered with a different byte.

**B2 — the console answers with ITS OWN bytes, and the answer contains a token
that is in the IMAGE and nowhere in the host side.** I predict the captured TX,
after a carriage return is injected, contains printable text that appears as a
string constant in `uTaskerMODBUS.bin`.

*Refuted if* TX stays empty, or if everything in it can be found in this repo's
Python.

**B3 — the console DISCRIMINATES: a command its own menu declares is answered
differently from a command it does not have.** Rule 1c's weak-case guard: a
boolean "it replied" is cheap. The graded term is that a *declared* command and
an *undeclared* one draw *different* firmware-composed answers, N of N rounds.

*Refuted if* both draw the same bytes, or if either is silent.

**B4 — parity becomes 2 of 2 only if BOTH entries pass in the SAME run.** The
MODBUS/TCP entry must still be at M4 with the USART page modelled: replacing
part of the AutoPeripheral catch-all with a real register file is a change to
the machine and could regress it. I predict M4/M6/M7 on :502 are **unchanged**.

*Refuted if* any of M4, M6 or M7 moves — in which case the console work is
withdrawn rather than the MODBUS evidence weakened.

**B5 — the falsification knob.** `--console-deaf` queues the host bytes but
never calls the firmware's ISR. I predict the console entry then FAILS and
parity returns to **1 of 2**, while :502 is untouched. A knob that cannot move
parity down is inert and proves nothing.

*Refuted if* the console entry still passes with the ISR never called.
