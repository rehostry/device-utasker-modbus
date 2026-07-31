<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# rehostry / device-utasker-modbus

A **uTasker MODBUS/TCP slave** on **STM32F2/F4 (ARMv7E-M, Cortex-M4)** rehosted
under [HALucinator](https://github.com/halucinator/halucinator)'s in-process
**unicorn** backend. First **uTasker** target in the rehostry corpus.

```
uTasker MODBUS slave (STM32F4, ARMv7E-M)
  flash image @0x0800c080  ──▶  RCC / ETH+PHY device models + AutoPeripheral
  reset ▸ main ▸ clock bring-up ▸ uTaskerStart ▸ uTaskerSchedule
        ▸ fnConfigEthernet (rings live) ▸ fnInitModbus ▸ fnMODBUS task
        ▸ ARP ▸ TCP :502 ▸ fnHandleMODBUS_input ▸ MODBUS reply   [M4]
```

> **Status: M4 reached, with a panel and attack.** The RTOS boots, schedules its tasks, brings the Ethernet
> MAC/PHY fully up, and answers a **real MODBUS/TCP request on :502** — ARP
> resolve, TCP 3-way handshake, FC03 request, and the firmware's own MODBUS reply
> (`000100000003018302`). Zero emulator faults. See [`STATUS.md`](STATUS.md).

## What's real

* **The RTOS is the firmware's own.** uTasker's `uTaskerStart` /
  `uTaskerSchedule` cooperative scheduler runs and dispatches its task list
  (~10 passes/s), including the MODBUS task `fnMODBUS` (0x080113a8) and the
  Ethernet task `fnTaskEthernet` (0x08013604).
* **Three faithful device models**, each reversed from the firmware's own polling
  code — no firmware patching, no forced constants:
  * `peripheral_models/stm32_rcc.py` — RCC enable→ready coupling (HSERDY,
    PLLRDY, `CFGR.SWS` follows `SW`).
  * `peripheral_models/stm32_eth.py` — ETH MAC/DMA: **LAN8742A** PHY (the driver
    aborts on any other PHY ID), self-clearing busy bits, descriptor-ring
    registers.
  * `peripheral_models/cortex_m_scs.py` — NVIC set/clear-register semantics.
    Correct but **not wired in**: it proved unnecessary for M4 and wiring it
    regresses the RTOS tick (see [`STATUS.md`](STATUS.md)).
* **Frame plumbing on the firmware's own seams:** RX via `fnSimulateEthernetIn`
  (the driver's software-reception entry point, driven with a borrowed CPU
  context), TX observed at `fnStartEthTx`. The MODBUS reply bytes are whatever
  `fnHandleMODBUS_input` / `fnSendMODBUS_response` produced — the host peer
  synthesises nothing.

## Core dependency

Needs the **`rehostry/core-patches`** HALucinator core for two things:

1. `HAL_CORTEXM_CPU_MODEL=UC_CPU_ARM_CORTEX_M4` — the firmware executes
   `smulbb` (ARMv7E-M DSP) at 0x0800e63a, which the default Cortex-M3 decoder
   rejects with `UC_ERR_INSN_INVALID`.
2. `AutoPeripheral` — the MMIO catch-all for the STM32 SoC window.

`spawn.py` (the single boot recipe) points at it and sets the CPU model
automatically via `HAL_CORTEXM_CPU_MODEL`.

## Supply the firmware (not redistributed)

```bash
pip install pyelftools
python3 tools/extract_firmware.py /path/to/uEmu.uTasker_MODBUS.out
```

The image comes from the public **uEmu** research corpus; uTasker itself is under
its vendor's own licence, so this package does not redistribute it. Full detail
and hashes: [`PROVENANCE.md`](PROVENANCE.md).

> **Run from a source/editable checkout (`pip install -e .`).** `extract_firmware.py`
> writes the flash image and symbol map into the package's `configs/` dir *inside
> this source tree*; those files (and the firmware) are git-ignored and not
> redistributed. A non-editable wheel (`pip install .`) bundles none of them, so
> the console scripts above only resolve the firmware when the package is installed
> editable (or run straight from this checkout) after you supply your own image.

## Run

`spawn.py` is the single boot recipe (both configs + the Cortex-M4 CPU-model
knob). The console scripts drive it; for a diagnostic overlay, drive `spawn.py`
directly:

```bash
rehostry-utasker-modbus-panel                  # boot + live MODBUS panel
python3 -m rehostry_utasker_modbus.attack      # self-boot + unauth FC06 write
# plain boot / diagnostic overlays, straight off the spawn recipe:
python3 -c "import subprocess; from rehostry_utasker_modbus import spawn, paths; \
  subprocess.run(spawn.spawn_argv(overlays=[paths.PROBE_OVERLAY]), \
                 cwd=spawn.spawn_cwd(), env=spawn.spawn_env())"
python3 tools/modbus_peer.py arp               # ARP round-trip (proves RX -> stack -> TX)
python3 tools/modbus_peer.py fc03              # full MODBUS/TCP FC03 round-trip  [M4]
```

Diagnostics: `HAL_UT_PROBE_TRACE=N`, `HAL_UT_WATCH=0xaddr,...`,
`HAL_UT_ETH_TRACE=1`, `HAL_UT_ETH_VERBOSE=1`.

## Panel and attack

A live web panel ships as the console script `rehostry-utasker-modbus-panel`
(module `utasker_panel`), served on **http://127.0.0.1:8787**:

```sh
rehostry-utasker-modbus-panel      # boots the rehost + opens the panel
rehostry-utasker-modbus panel      # same, via the main CLI
```

It holds a real MODBUS/TCP session against the firmware's **own** network stack and
shows the slave's live holding-register map — probing recovered the map as
**registers 2..6** (0, 1 and >=7 answer exception 0x02 ILLEGAL DATA ADDRESS), whose
low bits track device state:

```
holding registers [2, 3, 4, 5, 6] = [16, 65504, 768, 64512, 0]
```

The attack is an **unauthenticated MODBUS FC06 write**. MODBUS/TCP has no
authentication, authorisation or integrity protection: anything that reaches :502
can write this slave's live registers, and the firmware keeps no record that a
value was written rather than measured. Measured on a live boot:

```
register 2: before 96 -> wrote 0x1234 -> read back 0x1244   landed: true
```

Because these registers are live, `landed` compares the **high byte** of the
read-back (a drifting low nibble cannot fake it), and the raw before/after values
are reported so the check is auditable. Headless:

```sh
rehostry-utasker-modbus attack     # exit 0 only if the slave serves the forged value
```

**RTOS-tick fix (2026-07-31):** the firmware used to serve **one MODBUS request per
boot** and then go quiet — root-caused to the Cortex-M **SysTick never firing** in
the rehost (SCS = `AutoPeripheral`), which freezes the uTasker RTOS clock, *and* the
Ethernet task switching from polling to event-driven once TCP is up (its RX event is
posted by an ETH ISR that never fires). Both are now driven device-side through the
firmware's own calls (`uTaskerStateChange('E', 4)` to keep the Ethernet task
draining the ring, `fnRtmkSystemTick` to advance the clock), gated to after the
handshake. A full read → write → read-back session now completes in one connection
(`landed=True` reliably). See [`STATUS.md`](STATUS.md) for the full analysis. A
~25 s warm-up before the first connect is still used while the network stack brings
itself up.

(`attack.ModbusWriteAttack` is the reusable seam: `connect` / `read_map` / `arm` /
`restore`, plus the scripted `run_modbus_write_demo`. `modbus.Session` is the
raw-Ethernet MODBUS client.)

## Layout

```
src/rehostry_utasker_modbus/
├── peripheral_models/stm32_rcc.py       RCC enable->ready coupling
├── peripheral_models/stm32_eth.py       ETH MAC+DMA + LAN8742A PHY
├── peripheral_models/cortex_m_scs.py    NVIC semantics (not yet wired -- see STATUS)
├── utasker_panel.py                     live MODBUS slave panel (:8787) + attack
├── attack.py                            unauthenticated MODBUS FC06 write
├── modbus.py                            raw-Ethernet ARP/IPv4/TCP/MODBUS client
├── cli.py · paths.py · spawn.py         device descriptor + spawn recipe
├── bp_handlers/eth_bridge.py            RX inject / TX capture on firmware seams
├── bp_handlers/pc_probe.py              block-PC sampler + address watch list
└── configs/                             device config, overlays, symbol table
tools/extract_firmware.py                derive the flash image + symbols from the ELF
tools/modbus_peer.py                     host-side ARP/IPv4/TCP/MODBUS peer
```

## License

Code, configs and docs: **AGPL-3.0-or-later** ([`LICENSE`](LICENSE)). The uTasker
firmware is its vendor's and is **not** part of this distribution — see
[`PROVENANCE.md`](PROVENANCE.md).
