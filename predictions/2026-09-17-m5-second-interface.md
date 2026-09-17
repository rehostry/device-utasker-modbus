<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Pre-registered predictions — M5 attempt on `device-utasker-modbus`

Lane `s0907-laneM5`, 2026-09-17. **Committed BEFORE any graded arm was run.**
Each prediction names what would refute it. A refutation of my own prediction is
the result, not a failure.

## The question

The row records **M5 and M8 each DEFINED and UNMET at 1 of 4**, the denominator
taken from the firmware's own serial configuration menu (`FTP server`,
`WEB server`, `TELNET server` beside MODBUS/TCP). The M5 rung asks whether a
**second §1a-independent interface** can be driven to M4 **in the same run** as
MODBUS/TCP :502. WEB (HTTP :80) would be the `adam6000-tm4c` shape exactly —
two application services on distinct transport endpoints.

RULES §1d's test governs whether a menu entry is an interface of THIS image:
*"would this firmware, running, ever serve that interface?"*

## P1 — the image contains NO HTTP server

A uTasker HTTP server cannot answer without emitting a status line and a
content type. I predict `uTaskerMODBUS.bin` contains **zero** occurrences of
each of `HTTP`, `HTTP/1.0`, `Content-Type`, `text/html`, `index.htm`, `GET `.

**Refuted if** any of those appears, in printable context, as server code.

## P2 — the image contains NO FTP server

uTasker's FTP server carries a literal reply-code table. I predict **zero**
occurrences of `220`, `230`, `331`, `USER`, `PASS`, `RETR`, `STOR`, `PASV`,
`Type set to`.

**Refuted if** an FTP reply-code table is present.

## P3 — live: :502 answers a SYN, :80 and :21 do not

Against the firmware's own uNetwork stack, over the existing raw-Ethernet
bridge, on one boot:

* **:502 SYN -> SYN-ACK** (positive control; this is the graded M4 seam).
* **:80 SYN -> NO SYN-ACK.**
* **:21 SYN -> NO SYN-ACK.**
* **an unused high port (:4444) SYN -> NO SYN-ACK** (negative control).
* **:502 SYN again, after all of the above -> SYN-ACK** (the liveness control
  that makes a silence mean "not listening" rather than "the stack died").

**Refuted if** :80 or :21 returns a SYN-ACK — in which case this row has a
genuine second application service and M5 is reachable.
**The probe is void** if the trailing :502 SYN does not answer, because then no
silence on any other port is interpretable.

## P4 — TELNET is the one I am unsure about, and I am saying so in advance

`[enable/disable] Telnet service` @0x080157e4, `set_telnet` @0x08015e84 and
`   Telnet port number = ` @0x08010a04 are in the image. A config key whose
value is a **TCP port number** is a firmware-side statement that the service has
its own transport endpoint. uTasker's telnet server is thin — it tunnels the
existing debug/command interface — so the absence of protocol strings is weak
evidence either way.

**I predict :23 does NOT return a SYN-ACK**, because the telnet server is
started from the `usServers` bitmask in the saved network parameters and this
MODBUS demo build's default has it clear.

**Refuted if** :23 returns a SYN-ACK. If it does, then:
  * the second interface is the **telnet command console**, and
  * it is §1a-independent of MODBUS/TCP **only** if it carries its own
    application logic — which it would (uTasker's command interpreter, a
    different parser, a different task) on its own transport endpoint;
  * `shared_substrate` would be *one Ethernet MAC + one uTasker TCP/IP stack*,
    which §1a's shared-substrate ruling says is **not** a disqualifier.

## P5 — what I will NOT do

If P1/P2 hold and P4 is not refuted, the honest outcome is
**`M5-UNDEFINED — one interface`** for this row, together with a **correction
downward** of the recorded `1 of 4`: a menu label with no implementing code
fails §1d, and padding `n` makes M8 unreachable for bookkeeping reasons.
**I will not manufacture a second interface to reach M5.**

I will also NOT count, and say why:
  * ARP / ICMP / the TCP handshake — substrate (§1a), the row's existing
    disposal, unchanged;
  * the serial/USB debug command menu — it is the same application as telnet
    would be, on a different transport (§1a's solo1 collapse);
  * `Go to USB menu`, `Go to I2C menu`, `CAN commands`, `Go to utFAT disk
    interface` — these sit in the SAME menu table as `WEB server` and `FTP
    server`. If that table were a capability manifest they would all be
    entries; that they are plainly not is itself evidence about the table.
