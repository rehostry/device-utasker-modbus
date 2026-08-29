# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Live MODBUS/TCP slave panel for the uTasker rehost.

Boots the REAL uTasker MODBUS-slave firmware under HALucinator (unicorn), holds a
MODBUS/TCP session against **its own network stack**, and serves a self-contained
web page showing:

  * the slave's live holding-register map (registers 2..6), polled over MODBUS,
  * the protocol path each response travelled, and the raw MBAP+PDU bytes,
  * a "write register" box (an ordinary FC06 write, no credentials), and
  * the attack button: the same unauthenticated FC06 write used to tamper with a
    live register, verified by read-back (see ``attack.py``).

WHAT IS REAL HERE.  Every value shown arrives in a MODBUS response the firmware
composed: the request crosses its Ethernet driver
(``fnSimulateEthernetIn``/``fnStartEthTx``), its ARP/IPv4/TCP stack, and
``fnMODBUSListener`` -> ``fnHandleMODBUS_input`` -> ``fnSendMODBUS_response``. The
panel synthesises nothing; the host side is a raw-Ethernet client
(``modbus.Session``) because there is no host TCP/IP stack behind the firmware.

HONEST CAVEAT.  The firmware completes **one MODBUS session per boot** reliably, so
the panel holds a single long-lived session and polls over it. If the session drops,
the panel reports it rather than silently reconnecting.

Transport is plain ``/state`` polling (no Server-Sent Events): a module-level
``_STATE`` dict guarded by a lock, a ``GET /state`` snapshot the page polls every
1.5 s, and ``POST`` endpoints that kick daemon threads. This survives proxies
(e.g. Cloudflare tunnels) that buffer ``text/event-stream``.

Run:
    rehostry-utasker-modbus-panel      # boot firmware + open the panel
    rehostry-utasker-modbus panel      # same, via the main CLI
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import attack, modbus, paths, spawn

# This device boots from its own two configs (see spawn.py); the panel adds
# only the Ethernet frame bridge, which is what carries the MODBUS session.
PANEL_OVERLAYS = [paths.ETH_BRIDGE_OVERLAY]

_LOCK = threading.Lock()
_STATE = {
    "phase": "BOOT", "booted": False, "session": False,
    "regs": {}, "polls": 0, "last_pdu": "", "last_decode": "",
    "attack": None, "log": [],
    "valid_registers": list(attack.VALID_REGISTERS),
    "target_register": attack.TARGET_REGISTER,
    "attack_value": "0x%04x" % attack.ATTACK_VALUE,
    "fw_ip": modbus.FW_IP, "port": modbus.MODBUS_PORT,
}

ARGS: argparse.Namespace
_SESSION = {"s": None, "sport": 50500}
_PROC = {"p": None}
_ARMED = {"v": False}


def _fresh_session():
    """Open a MODBUS session for one burst of requests.

    HARD CONSTRAINT: this firmware completes **one MODBUS/TCP session per boot** --
    a second connect attempt after the first session is spent gets no SYN-ACK, and a
    session that has sat idle answers the first request and then goes quiet. So the
    panel does all of its MODBUS work in one back-to-back burst per boot, and the
    attack button **reboots the firmware with the attack armed** so the fresh boot's
    single session carries read-map -> write -> verify.
    """
    _SESSION["sport"] += 1
    modbus.drain_inbox()
    a = attack.ModbusWriteAttack(sport=_SESSION["sport"])
    return a if a.connect() else None


def _set(**kw) -> None:
    with _LOCK:
        _STATE.update(kw)


def _log(line: str) -> None:
    with _LOCK:
        _STATE["log"].append(line)
        if len(_STATE["log"]) > 200:
            del _STATE["log"][:len(_STATE["log"]) - 200]


def kill_tree(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, OSError):
        pass
    try:
        proc.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass


def boot_firmware(hal_log: str, emulator: str) -> subprocess.Popen:
    argv = spawn.spawn_argv(emulator=emulator, overlays=PANEL_OVERLAYS)
    env = spawn.spawn_env(extra={"HAL_ION_QUIET": "1"})
    logf = open(hal_log, "w")
    sys.stderr.write("[utasker_panel] booting firmware: %s\n"
                     "[utasker_panel] cwd=%s  log=%s\n"
                     % (" ".join(os.path.basename(a) for a in argv),
                        spawn.spawn_cwd(), hal_log))
    sys.stderr.flush()
    return subprocess.Popen(argv, cwd=spawn.spawn_cwd(), env=env,
                            stdin=subprocess.DEVNULL,
                            stdout=logf, stderr=subprocess.STDOUT,
                            preexec_fn=os.setsid)


def _read_map_burst(a) -> dict:  # noqa: ANN001
    """Read the whole register map back-to-back over one session.

    The requests must be consecutive: each one costs a frame round-trip through
    the injection bridge, and the firmware's MODBUS/TCP session does not survive
    idle gaps between requests (a burst of ten reads works; one read every 2.5 s
    stops answering after the first). So the map is read in a burst on connect and
    on an explicit refresh, rather than polled continuously.
    """
    out = {}
    for r in attack.VALID_REGISTERS:
        out[r] = modbus.reg_value(a.session.read_holding(r, 1))
    return out


def _publish(regs: dict) -> None:
    alive = any(v is not None for v in regs.values())
    with _LOCK:
        _STATE["regs"] = {str(k): v for k, v in regs.items()}
        _STATE["polls"] += 1
        _STATE["session"] = alive
        _STATE["last_decode"] = ("FC03 holding registers %s" % list(regs.values())
                                 if alive else "no reply")


def modbus_connect() -> None:
    """Open one MODBUS session and read the register map once."""
    # Let the firmware settle before the first attempt. Connecting the instant the
    # listener answers yields a fragile session (only the first register read gets a
    # reply); the stack needs its ARP/ETH bring-up to finish first.
    time.sleep(float(os.environ.get("UTASKER_WARMUP_S", "25")))
    atk = attack.ModbusWriteAttack(sport=50500)
    tries = 0
    while _SESSION["s"] is None:
        # Drop anything left queued by a failed attempt: the bridge delivers one
        # frame per scheduler pass, so a stale backlog would be replayed later.
        modbus.drain_inbox()
        tries += 1
        if tries % 10 == 1:
            _log("waiting for the firmware's MODBUS listener (attempt %d)" % tries)
        if atk.connect():
            _SESSION["s"] = atk
            _set(booted=True, session=True, phase="MODBUS")
            _log("MODBUS/TCP session up to %s:%d -- no credentials were offered "
                 "or requested" % (modbus.FW_IP, modbus.MODBUS_PORT))
            regs = _read_map_burst(atk)
            _publish(regs)
            _log("holding registers %s = %s"
                 % (list(attack.VALID_REGISTERS), list(regs.values())))
            if _ARMED["v"]:
                _ARMED["v"] = False
                _log("unauthenticated FC06 write -> register %d = 0x%04x"
                     % (attack.TARGET_REGISTER, attack.ATTACK_VALUE))
                res = atk.arm(attack.TARGET_REGISTER, attack.ATTACK_VALUE)
                _set(attack=res)
                if res.get("landed"):
                    _log("TAMPERED: the slave now serves %s for register %d "
                         "(was %s) -- with no authentication at any point"
                         % (res.get("after_hex"), res["reg"], res.get("before")))
                else:
                    _log("write not confirmed: %s"
                         % (res.get("note") or "read-back did not match"))
                after = _read_map_burst(atk)
                _publish(after)
            return
        time.sleep(2.0)


def _do_refresh() -> None:
    a = _fresh_session()
    if a is None:
        _log("could not open a MODBUS session")
        _set(session=False)
        return
    regs = _read_map_burst(a)
    _publish(regs)
    _log("refreshed: %s" % list(regs.values()))


def _do_write(reg: int, value: int) -> None:
    a = _fresh_session()
    if a is None:
        _log("could not open a MODBUS session")
        return
    ack = a.session.write_single(reg, value)
    ok = bool(ack and not (ack[0] & 0x80))
    _log("FC06 wrote 0x%04x to register %d (%s)"
         % (value, reg, "acknowledged" if ok else "rejected"))


def _do_attack() -> None:
    """Arm the attack and reboot the firmware.

    The firmware allows one MODBUS session per boot and that session is already
    spent by the map read, so the attack cannot open its own. Rebooting with the
    attack armed lets the fresh boot's single session carry read -> write -> verify.
    """
    _log("arming the unauthenticated write and rebooting the firmware "
         "(one MODBUS session per boot)")
    _ARMED["v"] = True
    _SESSION["s"] = None
    _set(session=False, phase="REBOOT", attack=None, regs={})
    proc = _PROC["p"]
    if proc is not None:
        kill_tree(proc)
    modbus.drain_inbox()
    _PROC["p"] = boot_firmware(ARGS.hal_log, ARGS.emulator)
    threading.Thread(target=modbus_connect, daemon=True).start()


INDEX_HTML = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>uTasker MODBUS/TCP slave</title>
<style>
 :root{color-scheme:dark}
 body{background:#0d1117;color:#e6edf3;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;margin:0;padding:18px}
 h1{font-size:18px;margin:0 0 4px} .sub{color:#8b949e;font-size:12px;margin-bottom:16px}
 .wrap{display:flex;flex-wrap:wrap;gap:14px;align-items:flex-start}
 .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;min-width:300px}
 .card h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;margin:0 0 10px}
 .row{display:flex;justify-content:space-between;gap:14px;padding:3px 0;font-variant-numeric:tabular-nums}
 .row span:first-child{color:#8b949e}
 .bad{color:#f85149} .ok{color:#3fb950}
 .pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600}
 .pill.on{background:#3fb95022;color:#3fb950;border:1px solid #3fb95055}
 .pill.off{background:#8b949e22;color:#8b949e;border:1px solid #8b949e55}
 button{background:#21262d;color:#e6edf3;border:1px solid #30363d;border-radius:6px;padding:8px 14px;font-size:13px;cursor:pointer;margin:3px 4px 3px 0}
 button:hover{background:#30363d}
 button.atk{background:#a4331f;border-color:#c9432a} button.atk:hover{background:#c9432a}
 input{background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:6px;padding:7px 9px;font:13px ui-monospace,Menlo,monospace;width:70px}
 table{width:100%;border-collapse:collapse;font:13px ui-monospace,Menlo,monospace}
 td,th{text-align:left;padding:4px 6px;border-bottom:1px solid #21262d}
 th{color:#8b949e;font-weight:600;font-size:11px;text-transform:uppercase}
 .flow{font:11px ui-monospace,Menlo,monospace;color:#8b949e;margin-top:8px;line-height:1.7}
 .log{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:8px;height:150px;overflow:auto;font:11px/1.5 ui-monospace,Menlo,monospace;color:#8b949e}
 .note{color:#8b949e;font-size:11px;margin-top:8px;line-height:1.5}
 details.brief{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px 12px;margin:0 0 16px}
 details.brief summary{cursor:pointer;font-weight:600;color:#e6edf3}
 details.brief .body{margin-top:8px}
 details.brief p{margin:6px 0;color:#8b949e;line-height:1.55}
 details.brief b{color:#e6edf3} details.brief code{font:12px ui-monospace,Menlo,monospace}
</style></head><body>
<h1>uTasker MODBUS/TCP slave <span class="pill on">STM32F4 / ARMv7E-M</span></h1>
<div class="sub">Real firmware answering MODBUS on its <b>own</b> network stack:
host &rarr; <code>fnSimulateEthernetIn</code> &rarr; ARP/IPv4/TCP &rarr;
<code>fnMODBUSListener</code> &rarr; <code>fnHandleMODBUS_input</code> &rarr;
<code>fnSendMODBUS_response</code>. Every value below is in a response the firmware composed.</div>
<details class="brief" open>
 <summary>About this panel — what it is, what to do, what to expect</summary>
 <div class="body">
  <p><b>Device.</b> A rehosted STM32F4 (ARMv7E-M) running uTasker's MODBUS/TCP
     <b>slave</b> firmware under HALucinator/unicorn — an industrial field device
     answering MODBUS on <code>port 502</code> over its own network stack. Its
     holding-register map is registers <b>2..6</b>; 0, 1 and &ge;7 answer
     exception 0x02 (ILLEGAL DATA ADDRESS).</p>
  <p><b>Steps.</b> 1) The firmware boots automatically when the panel starts
     (~2 min to reach the MODBUS listener) — wait for the register table to fill;
     2) optionally set a reg/value and click <b>Write</b>, then <b>Re-read map</b>,
     to see an ordinary FC06 write; 3) click <b>Tamper with register 2</b> to fire
     the unauthenticated-write attack.</p>
  <p><b>What you're seeing.</b> <em>Holding registers (live, over MODBUS)</em> are
     read straight from the firmware's own MODBUS engine — real values, not
     synthesised. <em>session / polls / last response</em> and the <em>Event log</em>
     are host bookkeeping (the panel's polling of <code>/state</code>). The
     <em>Write a register</em> box and the attack card send FC06 requests the
     firmware actually services.</p>
  <p><b>The attack.</b> MODBUS/TCP has no authentication, authorisation or
     integrity — anything that reaches <code>:502</code> can issue function code 6
     (write single register). <b>Tamper with register 2</b> writes
     <code>0x1234</code> into live register 2 with no credentials, reboots the
     firmware with the write armed (it allows one MODBUS session per boot), then
     reads&nbsp;→ writes&nbsp;→ reads back through the firmware's own engine.</p>
  <p><b>Expect.</b> Success shows <b>slave serves attacker value: YES</b> and an
     event-log line <em>TAMPERED: the slave now serves 0x12xx for register 2</em>.
     Because these registers are live (low bits drift), the verdict compares the
     read-back's <b>high byte</b> (0x12) to the byte written — a drifting low
     nibble cannot fake it. A slave that authenticated or rejected the write would
     show <b>not confirmed</b> instead (<code>landed=false</code>).</p>
 </div>
</details>
<div class="wrap">
  <div class="card" style="flex:1 1 330px">
    <h2>Holding registers (live, over MODBUS)</h2>
    <table id="regs"><tr><th>reg</th><th>value</th><th>hex</th></tr></table>
    <div class="row" style="margin-top:8px"><span>session</span><b id="ss">--</b></div>
    <div class="row"><span>polls</span><b id="pl">0</b></div>
    <div class="row"><span>last response</span><b id="ld" style="font:11px ui-monospace,Menlo,monospace">--</b></div>
    <div class="note">Read in a burst on connect and on <b>Re-read map</b> — the
      firmware's session does not survive idle gaps between requests, so the panel
      does not poll continuously. Registers 0, 1 and &ge;7 answer exception 0x02
      (ILLEGAL DATA ADDRESS) -- this slave's map is 2..6. Their low bits are
      <b>live</b> and drift between polls.</div>
  </div>
  <div class="card" style="flex:1 1 300px">
    <h2>Write a register (FC06)</h2>
    <div>An ordinary MODBUS write. <b>No credentials are offered or requested</b> --
      the protocol has none.</div>
    <div style="margin-top:10px">
      reg <input id="rg" value="2"> = <input id="vl" value="0x00ff">
      <button onclick="doWrite()">Write</button>
      <button onclick="post('/refresh')">Re-read map</button>
    </div>
    <h2 style="margin-top:16px">Unauthenticated-write attack</h2>
    <div>The same FC06 write used to tamper with a live register, verified by
      read-back through the firmware's own MODBUS engine.</div>
    <div style="margin-top:10px">
      <button class="atk" onclick="post('/attack')">Tamper with register <span id="tr">2</span></button>
    <div class="note">Reboots the firmware with the write armed: it allows one
      MODBUS session per boot, and the map read already used this one.</div>
    </div>
    <div id="atk" style="margin-top:10px"></div>
    <div class="note">These registers are live, so the check compares the
      <b>high byte</b> of the read-back -- a drifting low nibble cannot fake it.</div>
  </div>
  <div class="card" style="flex:1 1 100%"><h2>Event log</h2><div class="log" id="log"></div></div>
</div>
<script>
function fmt(v){return (v===null||v===undefined)?'--':v;}
function render(s){
  var t='<tr><th>reg</th><th>value</th><th>hex</th></tr>';
  (s.valid_registers||[]).forEach(function(r){
    var v=(s.regs||{})[String(r)];
    var hex=(v===null||v===undefined)?'--':'0x'+Number(v).toString(16).padStart(4,'0');
    t+='<tr><td>'+r+'</td><td>'+fmt(v)+'</td><td>'+hex+'</td></tr>';
  });
  document.getElementById('regs').innerHTML=t;
  document.getElementById('ss').innerHTML = s.session
    ? '<span class="pill on">'+s.fw_ip+':'+s.port+'</span>'
    : '<span class="pill off">connecting…</span>';
  document.getElementById('pl').textContent=s.polls;
  document.getElementById('ld').textContent=s.last_decode||'--';
  document.getElementById('tr').textContent=s.target_register;
  var a=s.attack,h='';
  if(a){
    h+='<div class="row"><span>register</span><b>'+a.reg+'</b></div>';
    h+='<div class="row"><span>wrote</span><b class="bad">'+a.value_hex+'</b></div>';
    h+='<div class="row"><span>before</span><b>'+fmt(a.before)+'</b></div>';
    h+='<div class="row"><span>read back</span><b class="bad">'+fmt(a.after_hex)+'</b></div>';
    h+='<div class="row"><span>authentication required</span><b class="bad">NO</b></div>';
    h+='<div class="row"><span>slave serves attacker value</span><b class="'+(a.landed?'bad':'')+'">'+(a.landed?'YES':'not confirmed')+'</b></div>';
    if(a.note) h+='<div class="note">'+a.note+'</div>';
  }
  document.getElementById('atk').innerHTML=h;
  document.getElementById('log').innerHTML=(s.log||[]).slice(-60).reverse()
    .map(function(l){return '<div>'+l+'</div>';}).join('');
}
function doWrite(){
  var r=document.getElementById('rg').value, v=document.getElementById('vl').value;
  fetch('/write',{method:'POST',body:JSON.stringify({reg:r,value:v})})
    .then(()=>setTimeout(poll,600));
}
function post(p){fetch(p,{method:'POST'}).then(()=>setTimeout(poll,800));}
// Poll /state (plain GET) instead of SSE: buffering proxies (e.g. Cloudflare
// tunnels) would never flush a server-push stream to a phone.
function poll(){fetch('/state').then(r=>r.json()).then(render).catch(()=>{});}
poll(); setInterval(poll, 1500);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a) -> None:  # noqa: ARG002
        pass

    def _send(self, code: int, ctype: str, body: bytes, cache: bool = True) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if not cache:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, "text/html; charset=utf-8", INDEX_HTML.encode(), cache=False)
        elif path == "/state":
            with _LOCK:
                body = json.dumps(_STATE).encode()
            self._send(200, "application/json", body, cache=False)
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/write":
            n = int(self.headers.get("Content-Length") or 0)
            try:
                req = json.loads(self.rfile.read(n) or b"{}")
                reg = int(str(req.get("reg", attack.TARGET_REGISTER)), 0)
                val = int(str(req.get("value", 0)), 0)
            except (ValueError, TypeError):
                self._send(400, "application/json", b'{"error":"bad request"}')
                return
            threading.Thread(target=_do_write, args=(reg, val), daemon=True).start()
        elif path == "/refresh":
            threading.Thread(target=_do_refresh, daemon=True).start()
        elif path == "/attack":
            threading.Thread(target=_do_attack, daemon=True).start()
        else:
            self._send(404, "text/plain", b"not found")
            return
        self._send(200, "application/json", b'{"ok":true}', cache=False)


def main(argv=None) -> int:
    global ARGS
    p = argparse.ArgumentParser(
        prog="rehostry-utasker-modbus-panel",
        description="Live MODBUS/TCP slave panel for the uTasker rehost.")
    p.add_argument("--http-port", type=int,
                   default=int(os.environ.get("UTASKER_HTTP_PORT", "29293")))
    p.add_argument("--hal-log", default=os.environ.get(
        "UTASKER_HAL_LOG", "/tmp/rehostry_utasker_panel_hal.log"))
    p.add_argument("--emulator", default="unicorn")
    p.add_argument("--no-boot", action="store_true",
                   help="don't spawn the firmware (talk to an already-running one)")
    p.add_argument("--no-open", action="store_true", help="don't open a browser")
    ARGS = p.parse_args(argv)

    if not ARGS.no_boot and not paths.firmware_present():
        sys.stderr.write(
            "firmware not found at %s\n"
            "  derive it from the uEmu corpus ELF:\n"
            "    python3 tools/extract_firmware.py /path/to/uEmu.uTasker_MODBUS.out\n"
            "  (see PROVENANCE.md)\n" % paths.firmware_bin())
        return 1

    _PROC["p"] = boot_firmware(ARGS.hal_log, ARGS.emulator) if not ARGS.no_boot else None
    proc = _PROC["p"]
    threading.Thread(target=modbus_connect, daemon=True).start()

    httpd = ThreadingHTTPServer(("127.0.0.1", ARGS.http_port), Handler)
    httpd.daemon_threads = True
    url = f"http://127.0.0.1:{ARGS.http_port}"
    sys.stderr.write(
        f"[utasker_panel] serving {url}\n"
        f"[utasker_panel] the boot takes ~2 min to reach the MODBUS listener; open\n"
        f"[utasker_panel] {url} to watch the slave's registers -- and fire the\n"
        f"[utasker_panel] unauthenticated-write attack\n")
    sys.stderr.flush()
    if not ARGS.no_open:
        threading.Thread(
            target=lambda: (time.sleep(0.8), webbrowser.open(url)), daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[utasker_panel] shutting down\n")
    finally:
        if proc is not None:
            kill_tree(proc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
