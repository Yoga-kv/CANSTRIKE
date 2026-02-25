# CANStrike v4.0 — CAN Bus Attack & Analysis Utility
### CANPico + vcan0 | Kali Linux | AI Analyst

> ⚠️ **For authorized security research & penetration testing only.**

---

## Quick Start

```bash
# Install dependencies
pip3 install -r requirements.txt

# Setup vcan0 (one-time, for simulation)
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0

# Run with built-in ECU simulator (no hardware needed)
python3 canstrike.py --simulate

# Run interactive menu
python3 canstrike.py

# Connect directly to vcan0
python3 canstrike.py --vcan vcan0

# Connect CANPico hardware
python3 canstrike.py --port /dev/ttyACM0

# Run automated playbook
python3 canstrike.py --playbook example_playbook.json
```

---

## What's New in v4.0

| Feature | Description |
|---------|-------------|
| **Delta-Diff Analysis** | Captures baseline vs triggered traffic — isolates ONLY frames that changed, appeared, or disappeared |
| **Live Bus Monitor** | Real-time scrolling table showing all IDs, Hz rate, count, latest data |
| **UDS / OBD-II Layer** | Full diagnostic service client: read PIDs, DTCs, DIDs, Security Access, ECU Reset, Routine Control |
| **Mutating Replay** | Four mutation strategies: none / bitflip / stepping / boundary values |
| **Smart Fuzzer** | Four strategies: random / bitflip / boundary (0x00,0x7F,0x80,0xFF) / increment |
| **Baseline Analyst** | AI scorer now compares baseline vs triggered for accurate attack recommendations |
| **HTML Pentest Report** | Generates a full professional HTML report with findings, captures, attack log, charts |
| **Session Save/Load** | Pickle captures to `.cansession` files — reload anytime |
| **Playbook Scripting** | JSON-driven automation: chain capture → analyse → attack → report |
| **Responsive Simulator** | vcan0 ECUs now respond to OBD-II and UDS requests |

---

## Full Menu (21 options)

### RECON & MONITOR
| # | Feature |
|---|---------|
| 1 | Detect CAN Baudrate |
| 2 | Capture Packets |
| 3 | Identify Responsible Packet (3-run cross-reference) |
| 4 | **Live Bus Monitor** — real-time scrolling view |
| 5 | **Baseline → Trigger Delta Diff** — what actually changed? |

### AI ANALYSIS
| # | Feature |
|---|---------|
| 6 | AI Analysis — (scores all attack vectors) |

### ATTACKS
| # | Feature |
|---|---------|
| 7 | **Replay + Mutation** (none / bitflip / step / boundary) |
| 8 | DoS Flooding |
| 9 | Freeze DOM |
| 10 | Bus-Off Attack |
| 11 | **Smart Fuzzer** (random / bitflip / boundary / increment) |
| 12 | ID Spoofing |

### UDS / OBD-II
| # | Feature |
|---|---------|
| 13 | Full UDS/OBD-II sub-menu (12 service functions) |

### SCRIPTING
| # | Feature |
|---|---------|
| 14 | Run JSON Playbook (automated attack chain) |

### UTILITY
| # | Feature |
|---|---------|
| 15 | Save Session to disk |
| 16 | Load Session from disk |
| 17 | Export CSV / JSON |
| 18 | **Generate HTML Pentest Report** |
| 19 | Connect / Switch Device |

### SIMULATOR
| # | Feature |
|---|---------|
| 20 | Start vcan0 ECU Simulator |
| 21 | Stop vcan0 Simulator |

---

## UDS / OBD-II Services (Option 13)

| Sub-option | Service | ISO |
|-----------|---------|-----|
| Read PID | Read live data (RPM, speed, temp...) | OBD-II SID 01 |
| Read DTCs | Fault code retrieval | OBD-II SID 03 |
| Scan PIDs | Find all supported PIDs | OBD-II SID 01 |
| Session Control | Enter Extended/Programming mode | UDS 0x10 |
| ECU Reset | Hard/soft/key-off reset | UDS 0x11 |
| Read DID | Read Data By Identifier (VIN, cal IDs...) | UDS 0x22 |
| Security Access | Seed+key unlock attempt | UDS 0x27 |
| Tester Present | Keep-alive message | UDS 0x3E |
| DID Scan | Enumerate all responsive DIDs in range | UDS 0x22 |
| Write DID | Write value to DID | UDS 0x2E |
| Routine Control | Start/stop/result routines | UDS 0x31 |

---

## Playbook Scripting

Create a JSON file with a `steps` array. Commands:

```json
{
  "name": "My Test",
  "steps": [
    { "cmd": "capture",      "duration": 5 },
    { "cmd": "analyse" },
    { "cmd": "uds_session",  "mode": 3 },
    { "cmd": "uds_read_did", "did": "0xF190" },
    { "cmd": "uds_dtcs" },
    { "cmd": "dos",          "fps": 1000, "duration": 5 },
    { "cmd": "fuzz",         "duration": 10, "strategy": "boundary" },
    { "cmd": "replay",       "id": "0x100", "data": "FF00FF00FF00FF00",
                             "count": 20, "mutate": "bitflip" },
    { "cmd": "spoof",        "id": "0x7E0", "data": "0201030000000000", "count": 10 },
    { "cmd": "export_html",  "filename": "report.html", "title": "My Test",
                             "tester": "Me", "target": "Test Vehicle" },
    { "cmd": "sleep",        "seconds": 2 }
  ]
}
```

---

## Delta-Diff Workflow (Option 5)

Best way to identify exactly which frames are responsible for an action:

```
Option 5 →
  Step 1: Capture BASELINE (5s) — bus at rest, nothing happening
  Step 2: Perform the action (press brake, unlock door, etc.)
  Step 3: Capture TRIGGERED (3s) — immediately after action
  
  Result: Shows ONLY frames that:
    • Appeared (new IDs not in baseline)    → HIGH confidence candidates
    • Disappeared (IDs gone after action)   → May indicate state change
    • Changed data (same ID, different bytes) → Payload changed = likely responsible
    • Changed rate (same ID, different Hz)  → Timing changed = involved in action
```

---

## HTML Report (Option 18)

Generates a self-contained HTML file with:
- Executive summary
- Bus statistics and traffic table
- Delta-diff findings (colour-coded by type)
- AI analyst results with attack scores
- UDS/OBD-II service findings
- Attack execution log
- All captures as searchable table

---

## Architecture (12 Classes)

```
BusInterface (ABC)
├── CANPicoBackend    — USB SLCAN serial driver
└── VCanBackend       — python-can SocketCAN driver

VCanSimulator         — 6 responsive ECUs on vcan0
SessionManager        — pickle save/load captures
LiveMonitor           — real-time terminal frame view
UDSClient             — OBD-II + UDS service layer
Analyst               — AI scorer + delta-diff engine
AttackEngine          — all 9 attack methods
Reporter              — CSV / JSON / HTML output
ScriptEngine          — JSON playbook runner
CANStrikeMenu         — interactive menu (21 options)
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `No module named 'can'` | `pip3 install python-can` |
| `No module named 'serial'` | `pip3 install pyserial` |
| `No module named 'rich'` | `pip3 install rich` |
| `vcan0` not found | `sudo modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0` |
| Permission denied `/dev/ttyACM0` | `sudo usermod -aG dialout $USER && newgrp dialout` |
| No frames on vcan0 | Start simulator (option 20) first |
| UDS no response | Check req/response IDs (default 0x7E0/0x7E8), try session control first |
