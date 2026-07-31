# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI for the uTasker MODBUS/TCP-slave rehost."""
from __future__ import annotations

import argparse
import sys

from . import paths


def cmd_info(_args: argparse.Namespace) -> int:
    print(f"{'device':16s}: uTasker MODBUS/TCP slave demo")
    print(f"{'arch':16s}: ARMv7E-M (STM32F2/F4), Cortex-M4 decoder required")
    print(f"{'entry':16s}: 0x{paths.ENTRY:08x}  (vector[1] | Thumb)")
    print(f"{'init sp':16s}: 0x{paths.INIT_SP:08x}")
    print(f"{'vector base':16s}: 0x{paths.VECTOR_BASE:08x}")
    print(f"{'network':16s}: 192.168.0.3, MODBUS/TCP :502 (registers 2..6)")
    print(f"{'firmware':16s}: {paths.firmware_bin()} "
          f"({'present' if paths.firmware_present() else 'MISSING'})")
    return 0


def cmd_panel(args: argparse.Namespace) -> int:
    from . import utasker_panel
    argv = ["--emulator", args.emulator]
    if args.http_port is not None:
        argv += ["--http-port", str(args.http_port)]
    if args.hal_log is not None:
        argv += ["--hal-log", args.hal_log]
    if args.no_open:
        argv += ["--no-open"]
    if args.no_boot:
        argv += ["--no-boot"]
    return utasker_panel.main(argv)


def cmd_attack(args: argparse.Namespace) -> int:
    """Headless unauthenticated MODBUS write against a separately-running rehost
    with the Ethernet bridge (boot it via `rehostry-utasker-modbus-panel`, or use
    the self-booting `python -m rehostry_utasker_modbus.attack`)."""
    from . import attack as attack_mod

    def stage(name, **d):
        note = d.get("note")
        if note:
            print(f"[attack] {name}: {note}", flush=True)

    reg = attack_mod.TARGET_REGISTER if args.reg is None else args.reg
    val = attack_mod.ATTACK_VALUE if args.value is None else int(args.value, 0)
    res = attack_mod.run_modbus_write_demo(on_stage=stage, reg=reg, value=val)
    if res.get("error"):
        print("[attack] no MODBUS session -- start the rehost with the eth bridge "
              "first", file=sys.stderr)
        return 1
    atk = res.get("attack", {})
    print(f"\nUnauthenticated MODBUS FC06 write -- register {atk.get('reg')}:")
    print(f"  authentication required: {atk.get('authentication_required')}")
    print(f"  before   : {atk.get('before')}")
    print(f"  wrote    : {atk.get('value_hex')}")
    print(f"  read back: {atk.get('after_hex')}")
    print(f"  SLAVE SERVES THE ATTACKER'S VALUE: {atk.get('landed')}")
    return 0 if atk.get("landed") else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="rehostry-utasker-modbus",
        description="Standalone uTasker MODBUS/TCP-slave HALucinator device "
                    "(STM32F2/F4, ARMv7E-M).")
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("panel", help="boot the firmware and serve the live "
                                      "MODBUS/TCP slave panel (+ the attack)")
    pa.add_argument("--http-port", type=int, default=None)
    pa.add_argument("--hal-log", default=None)
    pa.add_argument("--emulator", default="unicorn")
    pa.add_argument("--no-open", action="store_true")
    pa.add_argument("--no-boot", action="store_true")
    pa.set_defaults(func=cmd_panel)

    a = sub.add_parser("attack", help="unauthenticated MODBUS FC06 write against a "
                                      "live holding register")
    a.add_argument("--reg", type=int, default=None)
    a.add_argument("--value", default=None, help="e.g. 0x1234")
    a.set_defaults(func=cmd_attack)

    i = sub.add_parser("info", help="print the device descriptor + firmware status")
    i.set_defaults(func=cmd_info)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
