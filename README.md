# ECU Simulator & UDS Diagnostic Shell

A Python-based automotive network simulator and interactive diagnostic tool for researching and testing vehicle ECU behaviour over CAN bus — without needing physical hardware.

---

## Overview

This project simulates a small in-vehicle CAN network consisting of three ECUs communicating over a virtual CAN interface (`vcan0`). Each ECU broadcasts realistic periodic signals and responds to **UDS (Unified Diagnostic Services, ISO 14229)** diagnostic requests, making it a self-contained testbed for:

- Learning how automotive diagnostics work
- Developing and testing UDS client tooling
- Researching attack detection via DTC (Diagnostic Trouble Code) monitoring
- Practising automotive security testing techniques safely on a PC

---

## Components

### `ecu_sim.py` — Vehicle Network Simulator

Spawns three simulated ECUs on the CAN bus:

| ECU | Periodic Signals | UDS Address |
|---|---|---|
| Engine ECU | RPM, throttle position, coolant temperature | `0x7E0` / `0x7E8` |
| ABS ECU | Wheel speeds (FL/FR/RL/RR), ABS status, brake pressure | `0x7E1` / `0x7E9` |
| Gateway ECU | Heartbeat counter | `0x7E2` / `0x7EA` |

Each ECU supports the following UDS services:

- `0x10` — Diagnostic Session Control (Default / Extended / Programming)
- `0x11` — ECU Reset
- `0x19` — Read DTC Information
- `0x14` — Clear DTC Information
- `0x22` — Read Data By Identifier (live sensor data, VIN, serial number)
- `0x2E` — Write Data By Identifier (requires security unlock)
- `0x27` — Security Access (seed/key challenge-response)
- `0x3E` — Tester Present

**Fault simulation:**
- Engine ECU sets DTC `P0217` (coolant overtemperature) automatically when simulated coolant exceeds 85°C
- ABS ECU sets DTC `C5A00` on simulated ABS activation events
- Gateway ECU sets DTC `U_FF01` when it detects unknown CAN IDs on the bus — useful for attack detection testing

### `uds_cli.py` — Interactive UDS Shell

A REPL-style command-line interface for sending UDS requests to any simulated ECU. Features a context-aware prompt showing the active ECU, current session, and security lock state.

### `dtc_detection.py` — DTC Attack Monitor

A test harness that captures DTC snapshots before, during, and after arbitrary attack functions, reporting any new DTCs that were triggered — revealing whether the attack was detected by the vehicle diagnostic system.

---

## Requirements

- Python 3.11+
- [`python-can`](https://python-can.readthedocs.io/)

```bash
pip install python-can
```

For Linux `vcan` support:

```bash
sudo apt install can-utils
```

---

## Setup

### Linux (recommended — uses real kernel vcan driver)

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

To make `vcan0` persist across reboots, add `vcan` to `/etc/modules`.

### Cross-platform (virtual interface, no drivers needed)

Change the top of both files:

```python
INTERFACE = "virtual"
CHANNEL   = "sim_net"
```

---

## Usage

**Terminal 1 — start the simulator:**
```bash
python ecu_sim.py
```

**Terminal 2 — open the diagnostic shell:**
```bash
python uds_cli.py
```

### CLI Commands

| Command | Description |
|---|---|
| `ecu [name]` | Show or switch active ECU (`engine`, `abs`, `gateway`) |
| `session <type>` | Open a diagnostic session (`default`, `extended`, `programming`) |
| `unlock` | Perform security access seed/key challenge |
| `read <DID>` | Read a data identifier, e.g. `read F190` |
| `write <DID> <hex>` | Write a data identifier, e.g. `write 0002 64` |
| `dtc list [mask]` | List stored DTCs with decoded status bits |
| `dtc count [mask]` | Count stored DTCs |
| `dtc clear` | Clear all DTCs |
| `reset [soft\|hard]` | Reset the ECU |
| `ping` | Send Tester Present to keep session alive |
| `raw <hex>` | Send raw UDS bytes, e.g. `raw 1003` |
| `help` | Show all commands |

### Example session

```
uds [engine|def|🔒] > session extended
  ✓ Session changed → Extended

uds [engine|ext|🔒] > unlock
  ✓ Unlocked

uds [engine|ext|🔓] > read F190
  ✓ VIN: 1HGCM82633A123456

uds [engine|ext|🔓] > dtc list
  ✓ DTCs:
      P0217  status=0x29 [testFailed, confirmedDTC, warningIndicatorRequested]

uds [engine|ext|🔓] > dtc clear
  ✓ DTCs cleared
```

### Monitoring traffic with `candump` (Linux)

```bash
candump vcan0
```

---

## Architecture

```
┌─────────────────────────────────────────────┐
│            vcan0 / virtual bus              │
│                                             │
│   ┌───────────┐ ┌─────────┐ ┌───────────┐   │
│   │ Engine ECU│ │ ABS ECU │ │  Gateway  │   │
│   │ 0x7E0/E8  │ │ 0x7E1/E9│ │ 0x7E2/EA  │   │
│   └───────────┘ └─────────┘ └───────────┘   │
│        ▲             ▲            ▲         │
│        └─────────────┴────────────┘         │
│                      │                      │
│             ┌─────────────────┐             │
│             │   uds_cli.py    │             │
│             │  (UDS tester)   │             │
│             └─────────────────┘             │
└─────────────────────────────────────────────┘
```

Each ECU runs in its own thread with a single shared `can.Bus` socket, handling both periodic signal broadcasting and UDS request/response in one event loop. ISO 15765-2 multi-frame transport (First Frame / Flow Control / Consecutive Frames) is implemented for responses longer than 7 bytes.

---

## Security Research Notes

- The seed/key algorithm (`seed ^ 0xDEAD`) is intentionally trivial. Real ECUs use proprietary algorithms, often requiring firmware extraction to reverse-engineer.
- The Gateway ECU's unknown-ID detection and automatic DTC generation models how a real IDS (Intrusion Detection System) node might behave on a vehicle network.
- This simulator is intended for **educational and research purposes only**. Never connect attack tooling to a real vehicle network without authorisation.

---

## License

MIT