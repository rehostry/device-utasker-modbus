# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Controls for the SECOND inventory entry -- uTasker's own serial console.

These need no emulator, which is the point: they show that the console entry's
numerator can reach ZERO with the REAL graders, so the 1 in "1 of 2" (and the 2
in "2 of 2") is earned rather than a floor.

⚠ Why this file exists at all. The parity numerator used to be the module
constants `M5_AT_M4 = 1` / `M8_AT_M4 = 1`. A constant numerator cannot be moved
by any arm, so no control could ever have falsified it. Everything here moves it.
"""
from __future__ import annotations

import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from rehostry_utasker_modbus import attack, console          # noqa: E402

# a real console reply, captured from the guest on 2026-09-29
MAIN_MENU = (
    b"help\r\n\r\n\r\n     Main menu\n\r===================\n\r"
    b"1              Configure LAN interface\n\r"
    b"2              Configure serial interface\n\r"
    b"3              Go to I/O menu\n\r"
    b"4              Go to administration menu\n\r"
    b"5              Go to overview/statistics menu\n\r"
    b"6              Go to USB menu\n\r7              Go to I2C menu\n\r"
    b"8              Go to utFAT disk interface\n\r"
    b"9              FTP/TELNET commands\n\ra              CAN commands\n\r"
    b"help           Display menu specific help\n\r"
    b"quit           Leave command mode\n\r")
STATS_MENU = (
    b"5\r\n\r\n\r\n   Stats. menu\n\r===================\n\r"
    b"up               go to main menu\n\r"
    b"ipstat           Show Ethernet statistics\n\r"
    b"r_ipstat         Reset Ethernet statistics\n\r"
    b"up_time          Show operating time\n\r"
    b"memory           Show memory use\n\r"
    b"help             Display menu specific help\n\r"
    b"quit             Leave command mode\n\r\n\r#")
IPSTAT = (
    b"ipstat\r\n\r\nEthernet Statistics\r\n\r\nTotal Rx frames = 20\r\n"
    b"Rx overruns = 0\r\nRx ARP = 1\r\nRx ICMP = 0\r\nRx UDP = 0\r\n"
    b"Rx TCP = 12\r\nRx checksum errors = 0\r\nRx other protocols = 0\r\n"
    b"Foreign Rx ARP = 1\r\nForeign Rx ICMP = 0\r\nForeign Rx UDP = 0\r\n"
    b"Foreign Rx TCP = 6\r\nTotal Tx frames = 7\r\nARP sent = 1\r\n"
    b"ICMP sent = 0\r\nUDP sent = 0\r\nTCP sent = 6\r\nOther events = 0\r\n\r\n#")
MEMORY = (b"memory\r\n\r\nSystem memory use:\r\n==================\r\n"
          b"Free heap = 0x38a0 from 0x8000\r\n"
          b"Unused stack = 0x00000000 (0x00000000)\r\n\r\n#")


# --- the parsers ----------------------------------------------------------
def test_the_menu_parser_reads_the_guests_own_tokens():
    assert set(console.parse_menu(MAIN_MENU)) == attack.CONSOLE_MAIN_MENU_TOKENS
    assert set(console.parse_menu(STATS_MENU)) == attack.CONSOLE_STATS_MENU_TOKENS


def test_the_menu_parser_ignores_the_title_and_its_rule():
    """`     Main menu` is indented and `=====` is the rule; neither is a
    command, and a parser that counted them would inflate the token set and so
    would VOID every run."""
    toks = console.parse_menu(MAIN_MENU)
    assert "Main" not in toks
    assert not any(t.startswith("=") for t in toks)


def test_a_TRUNCATED_menu_does_not_match_and_so_VOIDS():
    """⚠ THE SHRINK GUARD, in the direction that matters. A console that answers
    with FEWER commands than it declares must not score as coverage."""
    short = MAIN_MENU.replace(b"a              CAN commands\n\r", b"")
    assert set(console.parse_menu(short)) != attack.CONSOLE_MAIN_MENU_TOKENS


def test_an_EXTENDED_menu_also_does_not_match():
    """Mismatch EITHER WAY voids: a menu with a command we never registered means
    the guard is out of date, and an out-of-date guard guards nothing."""
    longer = MAIN_MENU + b"b              Something new\n\r"
    assert set(console.parse_menu(longer)) != attack.CONSOLE_MAIN_MENU_TOKENS


def test_the_ipstat_invariant_holds_on_the_guests_own_block():
    inv = console.ipstat_invariants(console.parse_ipstat(IPSTAT))
    assert inv["rx_adds_up"] and inv["tx_adds_up"]
    assert inv["total_rx"] == 20 and inv["rx_parts_sum"] == 20
    assert inv["total_tx"] == 7 and inv["tx_parts_sum"] == 7


def test_the_ipstat_invariant_CATCHES_a_fabricated_block():
    """A transcript with a plausible-but-wrong total. This is the arm that makes
    the counter witness a VALUE check and not a "did it print something" check."""
    faked = IPSTAT.replace(b"Total Rx frames = 20", b"Total Rx frames = 21")
    inv = console.ipstat_invariants(console.parse_ipstat(faked))
    assert inv["rx_adds_up"] is False
    assert inv["tx_adds_up"] is True          # only the Rx side was disturbed


def test_a_zeroed_ipstat_block_fails_the_nonzero_term():
    """All-zeros is the classic negative: a dead stack adds up perfectly."""
    zeroed = console.parse_ipstat(IPSTAT)
    zeroed = {k: 0 for k in zeroed}
    inv = console.ipstat_invariants(zeroed)
    assert inv["rx_adds_up"] and inv["tx_adds_up"]     # 0 == 0
    assert inv["rx_nonzero"] is False and inv["tx_nonzero"] is False


def test_the_heap_figures_must_cohere():
    assert console.parse_memory(MEMORY)["coherent"] is True
    swapped = MEMORY.replace(b"Free heap = 0x38a0 from 0x8000",
                             b"Free heap = 0x9000 from 0x8000")
    assert console.parse_memory(swapped)["coherent"] is False
    assert console.parse_memory(b"memory\r\n#")["coherent"] is False


def test_uptime_is_parsed_as_a_number_of_seconds():
    assert console.parse_uptime(
        b"The device has been operating for 0 Days 0:01:22") == 82
    assert console.parse_uptime(b"nothing here") is None


# --- quiescence is not a budget ------------------------------------------
def test_read_until_quiet_separates_silent_from_growing_from_quiet():
    """⚠ "cannot measure" must never share a value with "measured and bad"."""
    with tempfile.TemporaryDirectory() as d:
        console.set_spool(d)
        base = console.USART3
        data, status = console.read_until_quiet(base, 0, quiet=0.3, ceiling=1.0)
        assert status == "silent" and data == b""
        with open(console.out_path(base), "wb") as fh:
            fh.write(b"hello")
        data, status = console.read_until_quiet(base, 0, quiet=0.3, ceiling=3.0)
        assert status == "quiet" and data == b"hello"


# --- the floor: the real graders against a dead wire ---------------------
def test_a_dead_wire_credits_no_interface():
    """THE CONTROL THAT SHOWS THE NUMERATOR CAN REACH ZERO.

    The REAL `run_console` against a spool no emulator is servicing. Nothing
    answers, so the console entry must fail -- and it must fail as "driven and
    did not answer", not as "voided", because that is the outcome the
    `--console-deaf` arm produces and a knob whose outcome is indistinguishable
    from a measurement error is not a knob.
    """
    import random
    saved = (attack.CONSOLE_QUIET_S, attack.CONSOLE_CEILING_S,
             attack.CONSOLE_PROBE_CEILING_S)
    try:
        attack.CONSOLE_QUIET_S = 0.2
        attack.CONSOLE_CEILING_S = 0.6
        attack.CONSOLE_PROBE_CEILING_S = 0.6
        with tempfile.TemporaryDirectory() as d:
            console.set_spool(d)
            out = attack.run_console(lambda *a, **k: None, random.Random(1),
                                     rounds=2)
    finally:
        (attack.CONSOLE_QUIET_S, attack.CONSOLE_CEILING_S,
         attack.CONSOLE_PROBE_CEILING_S) = saved
    assert out["ok"] is False
    assert out["passed"] == 0
    assert out.get("voided") is False
    assert "did not answer" in out.get("failed_reason", "")
    # and the parity it produces is 1 of 2 -- MEASURED AND FAILED
    parity = attack.interface_parity({"modbus_round_trip": True,
                                      "provenance": {"ok": True},
                                      "console_round_trip": bool(out["ok"]),
                                      "console": out})
    assert parity["m8"] == "1 of 2"
    assert parity["interface_parity_full"] is False


# --- the bridge must not call a handler the firmware did not install -----
class _FakeUc:
    def __init__(self, word: int) -> None:
        self.word = word
        self.reads = 0

    def mem_read(self, addr: int, n: int) -> bytes:
        self.reads += 1
        return self.word.to_bytes(4, "little")


def test_the_bridge_refuses_a_handler_the_firmware_did_not_install():
    """The ISR address is CHECKED against the firmware's own relocated vector
    table before it is ever called. Recorded live on 2026-09-29: early in the
    boot those vectors read 0x0800e3d1 (uTasker's default handler) and the bridge
    declined; once `fnConfigSCI` had run they read 0x0800c84d / 0x0800c87f /
    0x0800c8b1 -- exactly the three addresses derived by disassembly -- and it
    proceeded."""
    from rehostry_utasker_modbus.bp_handlers import serial_bridge
    with tempfile.TemporaryDirectory() as d:
        sb = serial_bridge.SerialBridge(d)
        wrong = _FakeUc(0x0800E3D1)
        sb.check_vectors(wrong)
        assert not any(sb.vector_ok.values())
        calls = []
        # queue a byte so step() would inject if it were willing to
        from rehostry_utasker_modbus.peripheral_models import stm32_usart
        stm32_usart.INSTANCES.clear()
        stm32_usart.Stm32Usart("u", 0x40011000, 0x1000)
        stm32_usart.uart(0x40011000).push_rx(b"\r")
        took = sb.step(wrong, lambda *a, **k: calls.append(a))
        assert took is False
        assert calls == []


def test_the_bridge_accepts_the_handler_the_firmware_DID_install():
    from rehostry_utasker_modbus.bp_handlers import serial_bridge
    from rehostry_utasker_modbus.peripheral_models import stm32_usart
    with tempfile.TemporaryDirectory() as d:
        sb = serial_bridge.SerialBridge(d)
        right = _FakeUc(0x0800C84D)          # USART1 handler | Thumb bit
        sb.check_vectors(right)
        assert sb.vector_ok[0x40011000] is True
        stm32_usart.INSTANCES.clear()
        stm32_usart.Stm32Usart("u", 0x40011000, 0x1000)
        stm32_usart.uart(0x40011000).push_rx(b"\r")
        calls = []
        took = sb.step(right, lambda uc, addr: calls.append(addr))
        assert took is True
        assert calls == [0x0800C84C]


def test_the_DEAF_knob_ingests_but_never_calls_the_firmware():
    """The knob must not be inert in the other direction either: the host's bytes
    still reach the model's RX FIFO, so the ONLY thing it removes is the
    firmware's own ISR call."""
    from rehostry_utasker_modbus.bp_handlers import serial_bridge
    from rehostry_utasker_modbus.peripheral_models import stm32_usart
    with tempfile.TemporaryDirectory() as d:
        os.environ["HAL_UT_TTY_DEAF"] = "1"
        try:
            sb = serial_bridge.SerialBridge(d)
        finally:
            del os.environ["HAL_UT_TTY_DEAF"]
        assert sb.deaf is True
        stm32_usart.INSTANCES.clear()
        stm32_usart.Stm32Usart("u", 0x40011000, 0x1000)
        console.set_spool(d)
        console.send(0x40011000, b"help\r")
        calls = []
        took = sb.step(_FakeUc(0x0800C84D), lambda *a: calls.append(a))
        assert took is False
        assert calls == []
        # ingested all the same: the wire condition is true, nobody answers it
        assert bytes(stm32_usart.uart(0x40011000).rxq) == b"help\r"


# --- the USART model itself ----------------------------------------------
def test_the_model_answers_TXE_and_tracks_RXNE_off_the_queue():
    from rehostry_utasker_modbus.peripheral_models import stm32_usart as U
    U.INSTANCES.clear()
    page = U.Stm32Usart("u", 0x40011000, 0x1000)
    u = U.uart(0x40011000)
    assert page.hw_read(U.SR, 4) & U.SR_TXE          # transmitter never busy
    assert not page.hw_read(U.SR, 4) & U.SR_RXNE     # nothing queued
    u.push_rx(b"AB")
    assert page.hw_read(U.SR, 4) & U.SR_RXNE
    assert page.hw_read(U.DR, 4) == ord("A")
    assert page.hw_read(U.DR, 4) == ord("B")
    assert not page.hw_read(U.SR, 4) & U.SR_RXNE     # cleared by the DR reads


def test_the_model_captures_transmitted_bytes_and_never_mints_one():
    from rehostry_utasker_modbus.peripheral_models import stm32_usart as U
    U.INSTANCES.clear()
    page = U.Stm32Usart("u", 0x40004000, 0x1000)
    u = U.uart(0x40004800)                # USART3 is +0x800 into that page
    assert u is not None
    page.hw_write(0x800 + U.DR, 4, ord("z"))
    assert u.take_tx() == b"z"
    assert u.take_tx() == b""             # and nothing appears on its own


def test_CR1_is_read_back_exactly_as_written():
    """The ISR branches on CR1.RXNEIE and CR1.TXEIE, so a model that did not
    return what the driver wrote would make the firmware's own ISR do nothing and
    the seam would look dead for a reason that is ours, not the firmware's."""
    from rehostry_utasker_modbus.peripheral_models import stm32_usart as U
    U.INSTANCES.clear()
    page = U.Stm32Usart("u", 0x40011000, 0x1000)
    page.hw_write(U.CR1, 4, 0x202C)
    assert page.hw_read(U.CR1, 4) == 0x202C
    u = U.uart(0x40011000)
    assert u.enabled() and u.rx_int_armed() and not u.tx_int_armed()
