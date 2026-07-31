<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Firmware provenance

**The firmware is not redistributed by this package.** It is derived locally from
a public research corpus; only the derivation tool, the models and the configs
are committed here (`*.bin` / `*.out` / `*.elf` are git-ignored).

## Upstream

| | |
|---|---|
| corpus | **uEmu real-world firmware set** — <https://github.com/MCUSec/uEmu-real_world_firmware> |
| corpus revision | `c1a9049` ("GPSTracker: no need for manual input peripheral address") |
| file | `uEmu.uTasker_MODBUS.out` |
| sha256 (ELF) | `1c42831f637ee4749ea8256c39d828f0ee0ac4294c187b914ba1f9b65217055e` |
| firmware | **uTasker** demo project, **MODBUS slave** build (`uTasker-MODBUS-slave`, string at flash `0x0801552a`) |
| target | STM32F2xx/F4xx, ARMv7E-M (Cortex-M4 — uses DSP `smulbb`) |
| PHY | Microchip **LAN8742A** (the driver checks PHY ID `0x0007c130`) |

The corpus ships no licence file of its own; **uTasker** is published by M.J.Butcher
Consulting under its own (dual/commercial) licence terms. Because those terms are
the vendor's and not ours to sublicense, this package deliberately **does not**
redistribute the image — obtain it yourself from the corpus above and derive the
flash image locally.

## Derivation

```bash
pip install pyelftools
python3 tools/extract_firmware.py /path/to/uEmu.uTasker_MODBUS.out
```

which writes into `src/rehostry_utasker_modbus/configs/`:

| file | sha256 (first 16) | notes |
|---|---|---|
| `uTaskerMODBUS.bin` | `dc28f4280d97e92c` | 90 185 bytes; PT_LOAD segments flattened, `0xff`-padded from `0x08000000` |
| `utasker_addrs.yaml` | — | 965 symbols, `addr -> name`, Thumb LSB cleared |

The ELF has exactly two `PT_LOAD` segments — `0x0800c080` (8 bytes: initial SP
`0x2002fffc` + reset `0x08015ecd`) and `0x0800c088..0x08016049` (code/rodata).
There is a ~48 KB region below `0x0800c080` (a bootloader) that is **not** in the
ELF, which is why only SP and Reset exist as vectors and why the rehost runs the
cooperative scheduler rather than relying on a populated vector table.

## Scope of use

This is a defensive-security research rehost of a publicly-published demo
firmware, run entirely in an emulator on the operator's own machine.
