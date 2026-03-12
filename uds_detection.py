"""
DTC (Diagnostic Trouble Code) Detection During Attack Testing
Polls all simulated ECUs for DTCs before, during, and after each attack phase,
reporting any new codes that were triggered by the attack.

Run alongside ecu_sim.py.
"""

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

import can

from ecu_sim import ABSECU, CANDecoder, EngineECU, GatewayECU

INTERFACE = "socketcan"
CHANNEL = "vcan0"

# ── UDS constants ──────────────────────────────────────────────────────────

ECUS = {
    "engine": {"tx": 0x7E0, "rx": 0x7E8},
    "abs": {"tx": 0x7E1, "rx": 0x7E9},
    "gateway": {"tx": 0x7E2, "rx": 0x7EA},
}

SID_READ_DTC = 0x19
SID_TESTER_PRESENT = 0x3E
SUB_DTC_BY_STATUS = 0x02
SUB_DTC_COUNT = 0x01

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


# ── Data models ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DTC:
    ecu: str
    code: int  # raw 3-byte integer as received on the wire
    status: int

    @property
    def code_str(self) -> str:
        # Top 2 bits of the first wire byte select the prefix
        high_byte = (self.code >> 16) & 0xFF
        prefix = {0b00: "P", 0b01: "C", 0b10: "B", 0b11: "U"}[(high_byte >> 6) & 0x03]
        # Remaining 14 bits (mask off top 2) form the numeric part
        number = self.code & 0x3FFF
        return f"{prefix}{number:04X}"

    @property
    def status_str(self) -> str:
        return (
            ", ".join(v for i, v in DTC_STATUS_BITS.items() if self.status & (1 << i))
            or "none"
        )

    def __str__(self):
        return f"[{self.ecu:>7}] {self.code_str}  status=0x{self.status:02X} ({self.status_str})"


@dataclass
class AttackPhaseResult:
    phase_name: str
    start_time: datetime
    end_time: datetime | None = None
    dtcs_before: set[DTC] = field(default_factory=set)
    dtcs_during: list[set[DTC]] = field(default_factory=list)
    dtcs_after: set[DTC] = field(default_factory=set)

    @property
    def new_dtcs(self) -> set[DTC]:
        all_seen = self.dtcs_after.copy()
        for s in self.dtcs_during:
            all_seen |= s
        return all_seen - self.dtcs_before

    def summary(self) -> str:
        duration = (
            f"{(self.end_time - self.start_time).total_seconds():.1f}s"
            if self.end_time
            else "N/A"
        )
        lines = [
            f"\n=== Phase: {self.phase_name} ===",
            f"  Duration   : {duration}",
            f"  DTCs before: {len(self.dtcs_before)}",
            f"  DTCs after : {len(self.dtcs_after)}",
            f"  NEW DTCs   : {len(self.new_dtcs)}",
        ]
        for d in sorted(self.new_dtcs, key=lambda x: x.code):
            lines.append(f"    ⚠  {d}")
        return "\n".join(lines)


# ── Transport ──────────────────────────────────────────────────────────────


def encode_sf(data: bytes) -> bytes:
    assert len(data) <= 7
    return bytes([len(data)]) + data + bytes(7 - len(data))


def decode_sf(raw: bytes) -> bytes | None:
    if not raw:
        return None
    length = raw[0] & 0x0F
    return bytes(raw[1 : 1 + length])


def recv_uds(bus: can.BusABC, rx_id: int, timeout: float = 1.0) -> bytes | None:
    """Receive a UDS response, handling single-frame and multi-frame (ISO 15765-2)."""
    deadline = time.monotonic() + timeout
    buf = b""
    expected_len = None
    sn_expected = 1

    while time.monotonic() < deadline:
        msg = bus.recv(timeout=0.1)
        if not msg or msg.arbitration_id != rx_id:
            continue
        d = bytes(msg.data)
        frame_type = (d[0] & 0xF0) >> 4

        if frame_type == 0:  # Single Frame
            return decode_sf(d)
        elif frame_type == 1:  # First Frame
            expected_len = ((d[0] & 0x0F) << 8) | d[1]
            buf = d[2:]
            # Send Flow Control
            fc = bytes([0x30, 0x00, 0x00]) + bytes(5)
            bus.send(
                can.Message(arbitration_id=rx_id - 8, data=fc, is_extended_id=False)
            )
        elif frame_type == 2:  # Consecutive Frame
            sn = d[0] & 0x0F
            if sn != sn_expected & 0x0F:
                return None
            buf += d[1:]
            sn_expected += 1
            if expected_len and len(buf) >= expected_len:
                return buf[:expected_len]
    return None


# ── UDS DTC reader ─────────────────────────────────────────────────────────


class UDSClient:
    def __init__(self):
        self.bus = can.interface.Bus(
            interface=INTERFACE, channel=CHANNEL, bitrate=500_000
        )

    def clear_all_dtcs(self):
        """Send ClearDTC (0x14) to all ECUs to reset state between phases."""
        for _, ecu in ECUS.items():
            req = bytes([0x14, 0xFF, 0xFF, 0xFF])
            self.bus.send(
                can.Message(
                    arbitration_id=ecu["tx"], data=encode_sf(req), is_extended_id=False
                )
            )
            time.sleep(0.05)

    def read_dtcs(self, ecu_name: str, status_mask: int = 0xFF) -> set[DTC]:
        ecu = ECUS[ecu_name]
        req = bytes([SID_READ_DTC, SUB_DTC_BY_STATUS, status_mask])
        self.bus.send(
            can.Message(
                arbitration_id=ecu["tx"], data=encode_sf(req), is_extended_id=False
            )
        )

        resp = recv_uds(self.bus, ecu["rx"])
        if not resp or resp[0] != SID_READ_DTC + 0x40:
            return set()

        dtcs: set[DTC] = set()
        payload = resp[2:]  # skip positive SID + sub-func + availability mask
        if len(payload) < 3:
            return dtcs
        payload = payload[1:]  # skip availability mask byte
        for i in range(0, len(payload) - 3, 4):
            code = int.from_bytes(payload[i : i + 3], "big")
            status = payload[i + 3]
            dtcs.add(DTC(ecu_name, code, status))
        return dtcs

    def read_all_dtcs(self, status_mask: int = 0xFF) -> set[DTC]:
        result: set[DTC] = set()
        for ecu_name in ECUS:
            result |= self.read_dtcs(ecu_name, status_mask)
        return result

    def close(self):
        self.bus.shutdown()


# ── Background DTC monitor ─────────────────────────────────────────────────


class DTCMonitor:
    def __init__(self, client: UDSClient, poll_interval: float = 0.5):
        self.client = client
        self.poll_interval = poll_interval
        self._snapshots: list[set[DTC]] = []
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self):
        self._running = True
        self._snapshots.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> list[set[DTC]]:
        self._running = False
        if self._thread:
            self._thread.join()
        return list(self._snapshots)

    def _loop(self):
        while self._running:
            snap = self.client.read_all_dtcs()
            with self._lock:
                self._snapshots.append(snap)
            time.sleep(self.poll_interval)


# ── Attack test harness ────────────────────────────────────────────────────


class DTCAttackTester:
    """
    Wraps an arbitrary attack callable and captures DTC deltas around it.

    Usage:
        tester = DTCAttackTester()
        result = tester.run_phase("CAN Fuzzing", my_attack_fn, duration=10)
        print(result.summary())
    """

    def __init__(
        self,
        engine: "EngineECU",
        abs_ecu: "ABSECU",
        gateway: "GatewayECU",
        poll_interval: float = 0.5,
    ):
        self.engine = engine
        self.abs_ecu = abs_ecu
        self.gateway = gateway
        self.client = UDSClient()
        self.monitor = DTCMonitor(self.client, poll_interval)
        self.results: list[AttackPhaseResult] = []

    def _reset_all(self):
        # 1. Reset physical state so _update_state() stops regenerating faults
        self.engine.reset_faults()
        self.abs_ecu.reset_faults()
        self.gateway.uds_dtcs.clear()
        self.gateway.anomalies.clear()
        # 2. Wait long enough for _update_state() to run and clear auto-DTCs
        time.sleep(3.0)
        # 3. Now clear whatever remains via UDS
        self.client.clear_all_dtcs()
        time.sleep(0.5)

    def run_phase(
        self,
        phase_name: str,
        attack_fn,
        duration: float = 10.0,
        settle_time: float = 2.0,
    ) -> AttackPhaseResult:
        result = AttackPhaseResult(phase_name=phase_name, start_time=datetime.now())

        print(f"\n[{phase_name}] Reading baseline DTCs...")
        result.dtcs_before = self.client.read_all_dtcs()

        print(f"[{phase_name}] Launching attack for {duration}s...")
        self.monitor.start()
        attack_thread = threading.Thread(target=attack_fn, daemon=True)
        attack_thread.start()
        attack_thread.join(timeout=duration)

        result.dtcs_during = self.monitor.stop()

        print(f"[{phase_name}] Settling for {settle_time}s...")
        time.sleep(settle_time)
        result.dtcs_after = self.client.read_all_dtcs()
        result.end_time = datetime.now()

        self.results.append(result)
        print(result.summary())
        return result

    def full_report(self) -> str:
        lines = ["=" * 60, "FULL DTC ATTACK TEST REPORT", "=" * 60]
        lines += [r.summary() for r in self.results]
        total = sum(len(r.new_dtcs) for r in self.results)
        lines += ["=" * 60, f"Total new DTCs across all phases: {total}", "=" * 60]
        return "\n".join(lines)

    def close(self):
        self.client.close()


# ── Example attacks ────────────────────────────────────────────────────────


def fuzz_can_bus(stop_event: threading.Event):
    """Send random CAN frames to trigger the Gateway's unknown-ID detection."""
    import random

    bus = can.interface.Bus(interface=INTERFACE, channel=CHANNEL, bitrate=500_000)
    while not stop_event.is_set():
        arb_id = random.randint(0x000, 0x7FF)
        data = bytes(random.randint(0, 255) for _ in range(8))
        bus.send(can.Message(arbitration_id=arb_id, data=data, is_extended_id=False))
        time.sleep(0.001)
    bus.shutdown()


def replay_diag_frames():
    """Replay diagnostic session requests to all ECUs."""
    bus = can.interface.Bus(interface=INTERFACE, channel=CHANNEL, bitrate=500_000)
    for _ in range(50):
        # Broadcast extended session request
        bus.send(
            can.Message(
                arbitration_id=0x7DF,
                data=encode_sf(bytes([0x10, 0x03])),
                is_extended_id=False,
            )
        )
        time.sleep(0.05)
    bus.shutdown()


# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # ── Start the simulated network ──────────────────────────────────────
    engine = EngineECU()
    abs_ecu = ABSECU()
    gateway = GatewayECU()
    decoder = CANDecoder()

    for e in [engine, abs_ecu, gateway, decoder]:
        e.start()

    time.sleep(1)  # let ECUs settle before testing

    tester = DTCAttackTester(engine, abs_ecu, gateway, poll_interval=0.5)
    stop_evt = threading.Event()

    try:
        # ── Phase 1: CAN fuzzing → triggers U_FF01 on Gateway ────────────
        tester.run_phase(
            "CAN Bus Fuzzing",
            lambda: fuzz_can_bus(stop_evt),
            duration=10,
            settle_time=3,
        )

        # ── Phase 2: Engine fault injection → P0217 / P0219 ──────────────
        def engine_faults():
            engine.inject_fault("overheat")
            time.sleep(2)
            engine.inject_fault("rpm_spike")
            time.sleep(2)

        tester.run_phase(
            "Engine Fault Injection",
            engine_faults,
            duration=6,
            settle_time=2,
        )

        # ── Phase 3: ABS fault injection → C0035 / C0265 ─────────────────
        def abs_faults():
            abs_ecu.inject_fault("wheel_loss")
            time.sleep(2)
            abs_ecu.inject_fault("pressure")
            time.sleep(2)

        tester.run_phase(
            "ABS Fault Injection",
            abs_faults,
            duration=6,
            settle_time=2,
        )

        # ── Phase 4: Diagnostic frame replay ─────────────────────────────
        tester.run_phase(
            "DiagSession Replay",
            replay_diag_frames,
            duration=5,
            settle_time=2,
        )

        print(tester.full_report())

    finally:
        stop_evt.set()
        tester.close()
        for e in [engine, abs_ecu, gateway, decoder]:
            e.stop()
