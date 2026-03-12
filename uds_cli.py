"""
Interactive UDS CLI Shell
Connects to the ECU simulator over python-can virtual bus and lets you
send UDS commands interactively.

Usage:
    python uds_cli.py

Run alongside the ECU simulator (ecu_sim.py) in a separate terminal.
"""

import random
import readline  # enables arrow-key history in the REPL
import struct
import time
from enum import IntEnum

import can

INTERFACE = "socketcan"
CHANNEL = "vcan0"

# ── ECU registry ────────────────────────────────────────────────────────────
ECUS = {
    "engine": {"tx": 0x7E0, "rx": 0x7E8, "name": "Engine ECU"},
    "abs": {"tx": 0x7E1, "rx": 0x7E9, "name": "ABS ECU"},
    "gateway": {"tx": 0x7E2, "rx": 0x7EA, "name": "Gateway ECU"},
}


# ── UDS constants ────────────────────────────────────────────────────────────
class SID(IntEnum):
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    READ_DATA_BY_ID = 0x22
    WRITE_DATA_BY_ID = 0x2E
    SECURITY_ACCESS = 0x27
    READ_DTC_INFO = 0x19
    CLEAR_DTC = 0x14
    TESTER_PRESENT = 0x3E
    NEGATIVE_RESPONSE = 0x7F


NRC_NAMES = {
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLength",
    0x22: "conditionsNotCorrect",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
}

SESSION_NAMES = {0x01: "Default", 0x02: "Programming", 0x03: "Extended"}

KNOWN_DIDS = {
    0xF190: "VIN",
    0xF18C: "ECU Serial Number",
    0x0001: "Engine RPM",
    0x0002: "Throttle Position",
    0x0003: "Coolant Temp",
    0x0010: "Vehicle Speed",
    0x0011: "ABS Active",
}

DTC_STATUS_BITS = {
    0: "testFailed",
    1: "testFailedThisMonitoringCycle",
    2: "pendingDTC",
    3: "confirmedDTC",
    4: "testNotCompletedSinceLastClear",
    5: "testFailedSinceLastClear",
    6: "testNotCompletedThisMonitoringCycle",
    7: "warningIndicatorRequested",
}


def dtc_prefix(code: int) -> str:
    prefix = {0b00: "P", 0b01: "C", 0b10: "B", 0b11: "U"}[(code >> 22) & 0x03]
    return f"{prefix}{code & 0x3FFF:04X}"


def decode_status(status: int) -> str:
    return (
        ", ".join(v for i, v in DTC_STATUS_BITS.items() if status & (1 << i)) or "none"
    )


# ── Transport ────────────────────────────────────────────────────────────────


def encode_sf(data: bytes) -> bytes:
    assert len(data) <= 7
    return bytes([len(data)]) + data + bytes(7 - len(data))


def decode_sf(raw: bytes) -> bytes | None:
    if not raw:
        return None
    length = raw[0] & 0x0F
    return bytes(raw[1 : 1 + length])


# ── UDS Client ───────────────────────────────────────────────────────────────


class UDSClient:
    def __init__(self, ecu_key: str):
        self.ecu_key = ecu_key
        self.ecu = ECUS[ecu_key]
        self.bus = can.interface.Bus(interface=INTERFACE, channel=CHANNEL)
        self.session = 0x01
        self.unlocked = False
        self._seed = 0

    def switch_ecu(self, ecu_key: str):
        self.ecu_key = ecu_key
        self.ecu = ECUS[ecu_key]
        self.session = 0x01
        self.unlocked = False
        print(f"  → Switched to {self.ecu['name']}")

    def send_recv(self, payload: bytes, timeout: float = 1.0) -> bytes | None:
        self.bus.send(
            can.Message(
                arbitration_id=self.ecu["tx"],
                data=encode_sf(payload),
                is_extended_id=False,
            )
        )

        deadline = time.monotonic() + timeout
        buf = b""
        expected_len = None
        sn_expected = 1

        while time.monotonic() < deadline:
            msg = self.bus.recv(timeout=0.1)
            if not msg or msg.arbitration_id != self.ecu["rx"]:
                continue

            d = bytes(msg.data)
            frame_type = (d[0] & 0xF0) >> 4

            if frame_type == 0:  # Single Frame
                return decode_sf(d)

            elif frame_type == 1:  # First Frame — send Flow Control
                expected_len = ((d[0] & 0x0F) << 8) | d[1]
                buf = d[2:]
                fc = bytes([0x30, 0x00, 0x00]) + bytes(5)
                self.bus.send(
                    can.Message(
                        arbitration_id=self.ecu["tx"], data=fc, is_extended_id=False
                    )
                )

            elif frame_type == 2:  # Consecutive Frame
                sn = d[0] & 0x0F
                if sn != sn_expected & 0x0F:
                    return None  # sequence error
                buf += d[1:]
                sn_expected += 1
                if expected_len and len(buf) >= expected_len:
                    return buf[:expected_len]

        return None

    def close(self):
        self.bus.shutdown()

    # ── security unlock helper ──
    def do_security_unlock(self) -> bool:
        r = self.send_recv(bytes([SID.SECURITY_ACCESS, 0x01]))
        if not r or r[0] != SID.SECURITY_ACCESS + 0x40:
            print("  ✗ Failed to get seed")
            return False
        seed = int.from_bytes(r[2:4], "big")
        key = seed ^ 0xDEAD  # must match ECU sim algorithm
        r2 = self.send_recv(bytes([SID.SECURITY_ACCESS, 0x02]) + key.to_bytes(2, "big"))
        if r2 and r2[0] == SID.SECURITY_ACCESS + 0x40:
            self.unlocked = True
            return True
        print("  ✗ Key rejected")
        return False


# ── Response pretty-printer ──────────────────────────────────────────────────


def fmt_response(raw: bytes | None, sid_sent: int) -> str:
    if raw is None:
        return "  ✗ No response (timeout)"
    sid = raw[0]
    data = raw[1:]

    if sid == SID.NEGATIVE_RESPONSE:
        nrc = data[1] if len(data) > 1 else 0
        name = NRC_NAMES.get(nrc, f"0x{nrc:02X}")
        return f"  ✗ Negative Response — {name}"

    pos_sid = sid_sent + 0x40
    if sid != pos_sid:
        return f"  ? Unexpected SID 0x{sid:02X}: {raw.hex()}"

    # Decode by service
    if sid_sent == SID.DIAGNOSTIC_SESSION_CONTROL:
        sub = data[0] if data else 0
        name = SESSION_NAMES.get(sub, f"0x{sub:02X}")
        return f"  ✓ Session changed → {name}"

    if sid_sent == SID.ECU_RESET:
        return f"  ✓ ECU Reset accepted (type=0x{data[0]:02X})"

    if sid_sent == SID.TESTER_PRESENT:
        return "  ✓ Tester Present acknowledged"

    if sid_sent == SID.SECURITY_ACCESS:
        sub = data[0] if data else 0
        if sub == 0x01:
            seed = int.from_bytes(data[1:3], "big") if len(data) >= 3 else 0
            return f"  ✓ Seed received: 0x{seed:04X}"
        elif sub == 0x02:
            return "  ✓ Security unlocked"

    if sid_sent == SID.READ_DATA_BY_ID:
        if len(data) < 2:
            return f"  ✗ Response too short: {raw.hex()}"
        did = int.from_bytes(data[0:2], "big")
        val = data[2:]
        name = KNOWN_DIDS.get(did, f"DID 0x{did:04X}")
        try:
            decoded = val.decode("ascii").strip()
        except Exception:
            decoded = val.hex()
        return f"  ✓ {name}: {decoded}"

    if sid_sent == SID.WRITE_DATA_BY_ID:
        did = int.from_bytes(data[0:2], "big") if len(data) >= 2 else 0
        return f"  ✓ DID 0x{did:04X} written"

    if sid_sent == SID.READ_DTC_INFO:
        sub = data[0] if data else 0
        if sub == 0x01:  # count
            count = int.from_bytes(data[3:5], "big") if len(data) >= 5 else 0
            return f"  ✓ DTC count: {count}"
        elif sub == 0x02:  # by status mask
            payload = data[2:]  # skip sub + availability mask
            if not payload:
                return "  ✓ No DTCs stored"
            lines = ["  ✓ DTCs:"]
            for i in range(0, len(payload) - 3, 4):
                code = int.from_bytes(payload[i : i + 3], "big")
                status = payload[i + 3]
                lines.append(
                    f"      {dtc_prefix(code)}  status=0x{status:02X} [{decode_status(status)}]"
                )
            return "\n".join(lines)

    if sid_sent == SID.CLEAR_DTC:
        return "  ✓ DTCs cleared"

    return f"  ✓ Raw: {raw.hex()}"


# ── Command handlers ─────────────────────────────────────────────────────────


def cmd_ecu(client: UDSClient, args: list[str]):
    if not args:
        print(
            f"  Current ECU: {client.ecu['name']}  (session={SESSION_NAMES.get(client.session,'?')}  unlocked={client.unlocked})"
        )
        print(f"  Available  : {', '.join(ECUS.keys())}")
        return
    key = args[0].lower()
    if key not in ECUS:
        print(f"  ✗ Unknown ECU '{key}'. Choose from: {', '.join(ECUS.keys())}")
        return
    client.switch_ecu(key)


def cmd_session(client: UDSClient, args: list[str]):
    MAP = {
        "default": 0x01,
        "programming": 0x02,
        "extended": 0x03,
        "1": 0x01,
        "2": 0x02,
        "3": 0x03,
    }
    sub = MAP.get(args[0].lower()) if args else None
    if sub is None:
        print("  Usage: session <default|extended|programming>")
        return
    r = client.send_recv(bytes([SID.DIAGNOSTIC_SESSION_CONTROL, sub]))
    client.session = sub
    print(fmt_response(r, SID.DIAGNOSTIC_SESSION_CONTROL))


def cmd_unlock(client: UDSClient, args: list[str]):
    ok = client.do_security_unlock()
    print("  ✓ Unlocked" if ok else "  ✗ Unlock failed")


def cmd_read(client: UDSClient, args: list[str]):
    if not args:
        print("  Usage: read <DID_hex>  e.g. read F190")
        print(
            "  Known DIDs:",
            ", ".join(f"0x{k:04X} ({v})" for k, v in KNOWN_DIDS.items()),
        )
        return
    try:
        did = int(args[0], 16)
    except ValueError:
        print("  ✗ Invalid DID (provide hex, e.g. F190)")
        return
    r = client.send_recv(bytes([SID.READ_DATA_BY_ID, (did >> 8) & 0xFF, did & 0xFF]))
    print(fmt_response(r, SID.READ_DATA_BY_ID))


def cmd_write(client: UDSClient, args: list[str]):
    if len(args) < 2:
        print("  Usage: write <DID_hex> <hex_data>  e.g. write 0002 64")
        return
    try:
        did = int(args[0], 16)
        data = bytes.fromhex(args[1])
    except ValueError:
        print("  ✗ Invalid arguments")
        return
    payload = bytes([SID.WRITE_DATA_BY_ID, (did >> 8) & 0xFF, did & 0xFF]) + data
    r = client.send_recv(payload)
    print(fmt_response(r, SID.WRITE_DATA_BY_ID))


def cmd_dtc(client: UDSClient, args: list[str]):
    sub_map = {"list": 0x02, "count": 0x01, "clear": None}
    sub_str = args[0].lower() if args else "list"
    mask = int(args[1], 16) if len(args) > 1 else 0xFF

    if sub_str == "clear":
        r = client.send_recv(bytes([SID.CLEAR_DTC, 0xFF, 0xFF, 0xFF]))
        print(fmt_response(r, SID.CLEAR_DTC))
        return

    sub = sub_map.get(sub_str)
    if sub is None:
        print("  Usage: dtc [list|count|clear] [status_mask_hex]")
        return
    r = client.send_recv(bytes([SID.READ_DTC_INFO, sub, mask]))
    print(fmt_response(r, SID.READ_DTC_INFO))


def cmd_reset(client: UDSClient, args: list[str]):
    t = {"soft": 0x01, "hard": 0x03}.get(args[0].lower(), 0x01) if args else 0x01
    r = client.send_recv(bytes([SID.ECU_RESET, t]))
    client.session = 0x01
    client.unlocked = False
    print(fmt_response(r, SID.ECU_RESET))


def cmd_ping(client: UDSClient, args: list[str]):
    r = client.send_recv(bytes([SID.TESTER_PRESENT, 0x00]))
    print(fmt_response(r, SID.TESTER_PRESENT))


def cmd_raw(client: UDSClient, args: list[str]):
    if not args:
        print("  Usage: raw <hex_bytes>  e.g. raw 1003")
        return
    try:
        payload = bytes.fromhex("".join(args))
    except ValueError:
        print("  ✗ Invalid hex")
        return
    r = client.send_recv(payload)
    sid = payload[0] if payload else 0
    print(fmt_response(r, sid))
    if r:
        print(f"  Raw bytes: {r.hex()}")


def cmd_help(_client, _args):
    print("""
  ┌─────────────────────────────────────────────────────────────┐
  │                    UDS CLI — Commands                       │
  ├──────────────────┬──────────────────────────────────────────┤
  │ ecu [name]       │ Show/switch active ECU                   │
  │                  │   engine | abs | gateway                 │
  ├──────────────────┼──────────────────────────────────────────┤
  │ session <type>   │ Open diagnostic session                  │
  │                  │   default | extended | programming       │
  ├──────────────────┼──────────────────────────────────────────┤
  │ unlock           │ Security access (seed/key)               │
  ├──────────────────┼──────────────────────────────────────────┤
  │ read <DID>       │ ReadDataByIdentifier  e.g. read F190     │
  │ write <DID> <v>  │ WriteDataByIdentifier e.g. write 0002 64 │
  ├──────────────────┼──────────────────────────────────────────┤
  │ dtc list [mask]  │ List DTCs  (mask default=FF)             │
  │ dtc count [mask] │ Count DTCs                               │
  │ dtc clear        │ Clear all DTCs                           │
  ├──────────────────┼──────────────────────────────────────────┤
  │ reset [soft|hard]│ ECU Reset                                │
  │ ping             │ Tester Present                           │
  │ raw <hex>        │ Send raw UDS bytes  e.g. raw 3E00        │
  ├──────────────────┼──────────────────────────────────────────┤
  │ help             │ Show this help                           │
  │ exit / quit      │ Exit the shell                           │
  └──────────────────┴──────────────────────────────────────────┘
  Known DIDs:""")
    for did, name in KNOWN_DIDS.items():
        print(f"    0x{did:04X}  {name}")


COMMANDS = {
    "ecu": cmd_ecu,
    "session": cmd_session,
    "unlock": cmd_unlock,
    "read": cmd_read,
    "write": cmd_write,
    "dtc": cmd_dtc,
    "reset": cmd_reset,
    "ping": cmd_ping,
    "raw": cmd_raw,
    "help": cmd_help,
    "?": cmd_help,
}


# ── REPL ─────────────────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════╗
║          UDS Interactive Shell  v1.0                 ║
║  Connected to: virtual CAN bus  (sim_net)            ║
║  Type  help  for available commands                  ║
╚══════════════════════════════════════════════════════╝
"""


def prompt(client: UDSClient) -> str:
    sess = SESSION_NAMES.get(client.session, "?")[0:3].lower()
    lock = "🔓" if client.unlocked else "🔒"
    return f"uds [{client.ecu_key}|{sess}|{lock}] > "


def run_shell():
    print(BANNER)
    client = UDSClient("engine")

    while True:
        try:
            line = input(prompt(client)).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            break

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("exit", "quit", "q"):
            print("Bye!")
            break

        handler = COMMANDS.get(cmd)
        if handler:
            try:
                handler(client, args)
            except Exception as e:
                print(f"  ✗ Error: {e}")
        else:
            print(f"  ✗ Unknown command '{cmd}'. Type help for a list.")

    client.close()


if __name__ == "__main__":
    run_shell()
