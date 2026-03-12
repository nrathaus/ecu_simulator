"""
Multi-ECU CAN Network Simulator + UDS (ISO 14229)
Simulates Engine ECU, ABS ECU, Gateway — all with UDS diagnostic support.
Works with socketcan + vcan0 (Linux) or python-can 'virtual' interface.
"""

import random
import struct
import threading
import time
from enum import IntEnum

import can

INTERFACE = "socketcan"
CHANNEL = "vcan0"

# ── CAN IDs ────────────────────────────────────────────────────────────────
ID_ENGINE_RPM = 0x0C0
ID_ENGINE_TEMP = 0x0C1
ID_ABS_WHEEL_SPEED = 0x1A0
ID_ABS_STATUS = 0x1A1
ID_GATEWAY_HEARTBEAT = 0x7FF

ID_UDS_FUNCTIONAL = 0x7DF
ID_UDS_ENGINE_REQ = 0x7E0
ID_UDS_ENGINE_RESP = 0x7E8
ID_UDS_ABS_REQ = 0x7E1
ID_UDS_ABS_RESP = 0x7E9
ID_UDS_GW_REQ = 0x7E2
ID_UDS_GW_RESP = 0x7EA


# ── UDS constants ──────────────────────────────────────────────────────────
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


class NRC(IntEnum):
    SUB_FUNC_NOT_SUPPORTED = 0x12
    INCORRECT_LENGTH = 0x13
    CONDITIONS_NOT_CORRECT = 0x22
    REQUEST_OUT_OF_RANGE = 0x31
    SECURITY_ACCESS_DENIED = 0x33
    INVALID_KEY = 0x35
    SERVICE_NOT_SUPPORTED = 0x11


class Session(IntEnum):
    DEFAULT = 0x01
    PROGRAMMING = 0x02
    EXTENDED = 0x03


DTC_TEST_FAILED = 0x01
DTC_CONFIRMED = 0x08
DTC_CHECK_ENGINE_LAMP = 0x20


def make_bus() -> can.BusABC:
    return can.interface.Bus(interface=INTERFACE, channel=CHANNEL, bitrate=500_000)


# ── ISO 15765-2 single-frame helpers ───────────────────────────────────────


def encode_uds(data: bytes) -> bytes:
    """Single-frame only (payload ≤ 7 bytes)."""
    assert len(data) <= 7, f"Payload too long for single-frame: {len(data)} bytes"
    return bytes([len(data)]) + data + bytes(7 - len(data))


def decode_uds(raw: bytes) -> bytes | None:
    """Decode a single-frame UDS message."""
    if not raw:
        return None
    length = raw[0] & 0x0F
    return bytes(raw[1 : 1 + length])


def send_uds_response(bus: can.BusABC, arb_id: int, data: bytes) -> None:
    """
    Send a UDS response using ISO 15765-2 framing.
    - Single Frame  (SF) for payloads up to 7 bytes.
    - First Frame + Consecutive Frames (FF/CF) for longer payloads.
    Flow Control from the tester is assumed with block size 0 (send all).
    """
    if len(data) <= 7:
        # Single Frame: [0x0N, d0..dN, padding]
        frame = bytes([len(data)]) + data + bytes(7 - len(data))
        bus.send(can.Message(arbitration_id=arb_id, data=frame, is_extended_id=False))
        return

    # First Frame: [0x1N_high, 0xNN_low, d0..d5]
    length = len(data)
    ff = bytes([0x10 | (length >> 8), length & 0xFF]) + data[:6]
    bus.send(can.Message(arbitration_id=arb_id, data=ff, is_extended_id=False))

    # Wait for Flow Control (FC) frame from tester (up to 200 ms)
    deadline = time.monotonic() + 0.2
    while time.monotonic() < deadline:
        fc = bus.recv(timeout=0.05)
        if fc and fc.arbitration_id != arb_id:  # ignore own frames
            if (fc.data[0] & 0xF0) == 0x30:  # FC frame type
                break
    else:
        return  # no FC received — abort

    # Consecutive Frames: [0x2N, d0..d6]
    remaining = data[6:]
    sn = 1
    while remaining:
        chunk = remaining[:7]
        cf = bytes([0x20 | (sn & 0x0F)]) + chunk + bytes(7 - len(chunk))
        bus.send(can.Message(arbitration_id=arb_id, data=cf, is_extended_id=False))
        remaining = remaining[7:]
        sn += 1
        time.sleep(0.001)  # 1 ms separation time (ST_min)


# ── UDS server mixin ───────────────────────────────────────────────────────


class UDSServer:
    """
    Mixin that adds a UDS responder to an ECU.
    Subclass must set:
      self.uds_rx_ids  — set of CAN IDs this ECU accepts
      self.uds_tx_id   — CAN ID used for replies
      self.bus         — shared can.BusABC instance (single bus per ECU)
    """

    _session: int = Session.DEFAULT
    _sec_unlocked: bool = False
    _sec_seed: int = 0
    uds_data_ids: dict[int, bytes] = {}
    uds_dtcs: list[tuple[int, int]] = []
    bus = None
    uds_txt_id = None

    def _calc_key(self, seed: int) -> int:
        return seed ^ 0xDEAD

    def _pos(self, sid: int, payload: bytes = b"") -> None:
        if self.bus is None:
            return
        if self.uds_tx_id is None:
            return
        send_uds_response(self.bus, self.uds_tx_id, bytes([sid + 0x40]) + payload)

    def _neg(self, sid: int, nrc: int) -> None:
        if self.bus is None:
            return
        if self.uds_tx_id is None:
            return
        send_uds_response(
            self.bus, self.uds_tx_id, bytes([SID.NEGATIVE_RESPONSE, sid, nrc])
        )

    def handle_uds(self, msg: can.Message) -> None:
        payload = decode_uds(bytes(msg.data))
        if not payload:
            return
        sid, data = payload[0], payload[1:]
        print(f"{sid=} {data=}")
        {
            SID.DIAGNOSTIC_SESSION_CONTROL: self._h_session,
            SID.ECU_RESET: self._h_reset,
            SID.TESTER_PRESENT: self._h_tester_present,
            SID.SECURITY_ACCESS: self._h_security_access,
            SID.READ_DATA_BY_ID: self._h_read_data,
            SID.WRITE_DATA_BY_ID: self._h_write_data,
            SID.READ_DTC_INFO: self._h_read_dtc,
            SID.CLEAR_DTC: self._h_clear_dtc,
        }.get(sid, lambda s, d: self._neg(s, NRC.SERVICE_NOT_SUPPORTED))(sid, data)

    def _h_session(self, sid, data):
        if not data:
            return self._neg(sid, NRC.INCORRECT_LENGTH)
        sub = data[0]
        if sub not in (Session.DEFAULT, Session.EXTENDED, Session.PROGRAMMING):
            return self._neg(sid, NRC.SUB_FUNC_NOT_SUPPORTED)
        self._session, self._sec_unlocked = sub, False
        self._pos(sid, bytes([sub, 0x00, 0x19, 0x01, 0xF4]))

    def _h_reset(self, sid, data):
        t = data[0] if data else 0x01
        self._pos(sid, bytes([t]))
        self._session, self._sec_unlocked = Session.DEFAULT, False

    def _h_tester_present(self, sid, data):
        self._pos(sid, bytes([data[0] if data else 0x00]))

    def _h_security_access(self, sid, data):
        if not data:
            return self._neg(sid, NRC.INCORRECT_LENGTH)
        sub = data[0]
        if sub == 0x01:
            self._sec_seed = random.randint(0x0001, 0xFFFE)
            self._pos(sid, bytes([0x01]) + self._sec_seed.to_bytes(2, "big"))
        elif sub == 0x02:
            if len(data) < 3:
                return self._neg(sid, NRC.INCORRECT_LENGTH)
            key = int.from_bytes(data[1:3], "big")
            if key == self._calc_key(self._sec_seed):
                self._sec_unlocked = True
                self._pos(sid, bytes([0x02]))
            else:
                self._neg(sid, NRC.INVALID_KEY)
        else:
            self._neg(sid, NRC.SUB_FUNC_NOT_SUPPORTED)

    def _h_read_data(self, sid, data):
        if len(data) < 2:
            return self._neg(sid, NRC.INCORRECT_LENGTH)
        did = int.from_bytes(data[:2], "big")
        val = self.uds_data_ids.get(did)
        if val is None:
            return self._neg(sid, NRC.REQUEST_OUT_OF_RANGE)
        self._pos(sid, data[:2] + val)

    def _h_write_data(self, sid, data):
        if len(data) < 3:
            return self._neg(sid, NRC.INCORRECT_LENGTH)
        if not self._sec_unlocked:
            return self._neg(sid, NRC.SECURITY_ACCESS_DENIED)
        did = int.from_bytes(data[:2], "big")
        if did not in self.uds_data_ids:
            return self._neg(sid, NRC.REQUEST_OUT_OF_RANGE)
        self.uds_data_ids[did] = bytes(data[2:])
        self._pos(sid, data[:2])

    def _h_read_dtc(self, sid, data):
        if not data:
            return self._neg(sid, NRC.INCORRECT_LENGTH)
        sub, mask = data[0], data[1] if len(data) > 1 else 0xFF
        if sub == 0x01:
            count = sum(1 for _, s in self.uds_dtcs if s & mask)
            self._pos(sid, bytes([0x01, mask, 0x09, (count >> 8) & 0xFF, count & 0xFF]))
        elif sub == 0x02:
            matched = [(c, s) for c, s in self.uds_dtcs if s & mask]
            payload = bytes([0x02, mask])
            for code, status in matched:
                payload += code.to_bytes(3, "big") + bytes([status])
            self._pos(sid, payload)
        else:
            self._neg(sid, NRC.SUB_FUNC_NOT_SUPPORTED)

    def _h_clear_dtc(self, sid, data):
        group = int.from_bytes(data[:3], "big") if len(data) >= 3 else 0xFFFFFF
        if group == 0xFFFFFF:
            self.uds_dtcs.clear()
        self._pos(sid, b"")


# ── ECUs ───────────────────────────────────────────────────────────────────


class EngineECU(UDSServer, threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self, daemon=True, name="EngineECU")
        self.bus = make_bus()  # single shared bus
        self.uds_rx_ids = {ID_UDS_ENGINE_REQ, ID_UDS_FUNCTIONAL}
        self.uds_tx_id = ID_UDS_ENGINE_RESP
        self._stop = threading.Event()
        self.rpm = 800
        self.throttle = 0.0
        self.coolant = 20.0
        self.uds_data_ids = {
            0xF190: b"1HGCM82633A123456",
            0x0001: b"\x03\x20",
            0x0002: b"\x00",
            0x0003: b"\x00\xc8",
        }
        self.uds_dtcs = []

    def run(self):
        t_broadcast = time.monotonic()
        while not self._stop.is_set():
            try:
                msg = self.bus.recv(timeout=0.01)
            except Exception:
                break

            if msg and msg.arbitration_id in self.uds_rx_ids:
                self.handle_uds(msg)

            now = time.monotonic()
            if now - t_broadcast >= 0.010:
                self._update_state()
                self._broadcast()
                t_broadcast = now

    def _update_state(self):
        self.coolant = min(90, self.coolant + random.uniform(0, 0.3))
        self.throttle = max(0, min(100, self.throttle + random.uniform(-2, 3)))
        self.rpm = int(800 + self.throttle * 55 + random.uniform(-30, 30))
        self.uds_data_ids[0x0001] = self.rpm.to_bytes(2, "big")
        self.uds_data_ids[0x0002] = bytes([int(self.throttle)])
        self.uds_data_ids[0x0003] = int(self.coolant * 10).to_bytes(2, "big")
        dtc = (0x000217, DTC_TEST_FAILED | DTC_CONFIRMED | DTC_CHECK_ENGINE_LAMP)
        if self.coolant > 85:
            if dtc not in self.uds_dtcs:
                self.uds_dtcs.append(dtc)
        else:
            self.uds_dtcs = [x for x in self.uds_dtcs if x != dtc]

    def _broadcast(self):
        self.bus.send(
            can.Message(
                arbitration_id=ID_ENGINE_RPM,
                data=struct.pack(">HB5x", self.rpm, int(self.throttle)),
                is_extended_id=False,
            )
        )
        self.bus.send(
            can.Message(
                arbitration_id=ID_ENGINE_TEMP,
                data=struct.pack(">H6x", int(self.coolant * 10)),
                is_extended_id=False,
            )
        )

    def stop(self):
        self._stop.set()
        self.join(timeout=1)
        try:
            self.bus.shutdown()
        except Exception:
            pass


class ABSECU(UDSServer, threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self, daemon=True, name="ABSECU")
        self.bus = make_bus()
        self.uds_rx_ids = {ID_UDS_ABS_REQ, ID_UDS_FUNCTIONAL}
        self.uds_tx_id = ID_UDS_ABS_RESP
        self._stop = threading.Event()
        self.speed_kph = 0.0
        self.abs_active = False
        self.uds_data_ids = {
            0xF190: b"1HGCM82633A654321",
            0x0010: b"\x00\x00",
            0x0011: b"\x00",
        }
        self.uds_dtcs = []

    def run(self):
        t_broadcast = time.monotonic()
        while not self._stop.is_set():
            try:
                msg = self.bus.recv(timeout=0.01)
            except Exception:
                break

            if msg and msg.arbitration_id in self.uds_rx_ids:
                self.handle_uds(msg)

            now = time.monotonic()
            if now - t_broadcast >= 0.020:
                self._update_state()
                self._broadcast()
                t_broadcast = now

    def _update_state(self):
        self.speed_kph = min(120, self.speed_kph + random.uniform(0, 0.3))
        if random.random() < 0.002:
            self.abs_active = True
            self.speed_kph = max(0, self.speed_kph - random.uniform(10, 30))
            dtc = (0x005A00, DTC_TEST_FAILED | DTC_CONFIRMED)
            if dtc not in self.uds_dtcs:
                self.uds_dtcs.append(dtc)
        else:
            self.abs_active = False
        self.uds_data_ids[0x0010] = int(self.speed_kph * 10).to_bytes(2, "big")
        self.uds_data_ids[0x0011] = bytes([0x01 if self.abs_active else 0x00])

    def _broadcast(self):
        wheel = int(self.speed_kph * 100)
        noise = lambda: max(0, wheel + random.randint(-10, 10))
        self.bus.send(
            can.Message(
                arbitration_id=ID_ABS_WHEEL_SPEED,
                data=struct.pack(">HHHH", noise(), noise(), noise(), noise()),
                is_extended_id=False,
            )
        )
        flags = 0x01 if self.abs_active else 0x00
        bp = random.randint(50, 200) if self.abs_active else random.randint(0, 30)
        self.bus.send(
            can.Message(
                arbitration_id=ID_ABS_STATUS,
                data=struct.pack(">BB6x", flags, bp),
                is_extended_id=False,
            )
        )

    def stop(self):
        self._stop.set()
        self.join(timeout=1)
        try:
            self.bus.shutdown()
        except Exception:
            pass


class GatewayECU(UDSServer, threading.Thread):
    KNOWN_IDS = {
        ID_ENGINE_RPM,
        ID_ENGINE_TEMP,
        ID_ABS_WHEEL_SPEED,
        ID_ABS_STATUS,
        ID_GATEWAY_HEARTBEAT,
        ID_UDS_FUNCTIONAL,
        ID_UDS_ENGINE_REQ,
        ID_UDS_ENGINE_RESP,
        ID_UDS_ABS_REQ,
        ID_UDS_ABS_RESP,
        ID_UDS_GW_REQ,
        ID_UDS_GW_RESP,
    }

    def __init__(self):
        threading.Thread.__init__(self, daemon=True, name="GatewayECU")
        self.bus = make_bus()
        self.uds_rx_ids = {ID_UDS_GW_REQ, ID_UDS_FUNCTIONAL}
        self.uds_tx_id = ID_UDS_GW_RESP
        self._stop = threading.Event()
        self.counter = 0
        self.anomalies: list[can.Message] = []
        self.uds_data_ids = {
            0xF190: b"1HGCM82633AGWTEST",
            0xF18C: b"\x01\x02\x03\x04",
        }
        self.uds_dtcs = []

    def run(self):
        hb = threading.Thread(target=self._heartbeat, daemon=True)
        hb.start()
        while not self._stop.is_set():
            try:
                msg = self.bus.recv(timeout=0.1)
            except Exception:
                break
            if not msg:
                continue
            if msg.arbitration_id in self.uds_rx_ids:
                self.handle_uds(msg)
            elif msg.arbitration_id not in self.KNOWN_IDS:
                self.anomalies.append(msg)
                dtc = (0x00FF01, DTC_TEST_FAILED | DTC_CONFIRMED)
                if dtc not in self.uds_dtcs:
                    self.uds_dtcs.append(dtc)
                print(
                    f"[Gateway] ⚠ Unknown ID 0x{msg.arbitration_id:03X} "
                    f"data={bytes(msg.data).hex()} → DTC U_FF01 set"
                )

    def _heartbeat(self):
        while not self._stop.is_set():
            try:
                self.bus.send(
                    can.Message(
                        arbitration_id=ID_GATEWAY_HEARTBEAT,
                        data=struct.pack(">B7x", self.counter & 0xFF),
                        is_extended_id=False,
                    )
                )
            except Exception:
                break
            self.counter += 1
            time.sleep(1.0)

    def stop(self):
        self._stop.set()
        self.join(timeout=1)
        try:
            self.bus.shutdown()
        except Exception:
            pass


# ── Passive decoder ────────────────────────────────────────────────────────


class CANDecoder(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="Decoder")
        self.bus = make_bus()
        self._stop = threading.Event()
        self.verbose = 0

    def run(self):
        print(f"\n{'TIME':>9}  {'ID':>6}  DECODED")
        print("─" * 60)
        while not self._stop.is_set():
            try:
                msg = self.bus.recv(timeout=0.1)
            except Exception:
                break
            if not msg:
                continue
            if self.verbose == 0:
                continue
            aid, d, ts = msg.arbitration_id, bytes(msg.data), f"{msg.timestamp:.3f}"

            if aid == ID_ENGINE_RPM:
                rpm, thr = struct.unpack(">HB5x", d)
                print(f"{ts:>9}  0x{aid:03X}  RPM={rpm}  Throttle={thr}%")
            elif aid == ID_ENGINE_TEMP:
                (raw,) = struct.unpack(">H6x", d)
                print(f"{ts:>9}  0x{aid:03X}  Coolant={raw/10:.1f}°C")
            elif aid == ID_ABS_WHEEL_SPEED:
                fl, fr, rl, rr = struct.unpack(">HHHH", d)
                print(
                    f"{ts:>9}  0x{aid:03X}  Wheels "
                    f"FL={fl/100:.1f} FR={fr/100:.1f} RL={rl/100:.1f} RR={rr/100:.1f} km/h"
                )
            elif aid == ID_ABS_STATUS:
                flags, bp = struct.unpack(">BB6x", d)
                print(
                    f"{ts:>9}  0x{aid:03X}  ABS={'YES' if flags&1 else 'no'}  BrakePressure={bp}"
                )
            elif aid in (ID_UDS_ENGINE_RESP, ID_UDS_ABS_RESP, ID_UDS_GW_RESP):
                payload = decode_uds(d)
                ecu = {
                    ID_UDS_ENGINE_RESP: "EngineECU",
                    ID_UDS_ABS_RESP: "ABSECU",
                    ID_UDS_GW_RESP: "Gateway",
                }.get(aid, "ECU")
                if payload:
                    sid = payload[0]
                    tag = "POS" if sid != SID.NEGATIVE_RESPONSE else "NEG"
                    print(
                        f"{ts:>9}  0x{aid:03X}  UDS [{ecu}] {tag} "
                        f"SID=0x{sid:02X} data={payload[1:].hex()}"
                    )

    def stop(self):
        self._stop.set()
        self.join(timeout=1)
        try:
            self.bus.shutdown()
        except Exception:
            pass


# ── Example UDS tester ─────────────────────────────────────────────────────


def run_uds_tester():
    """Demo: open extended session, unlock security, read DIDs and DTCs."""
    time.sleep(1)
    bus = make_bus()

    def send_recv(
        payload: bytes,
        rx_id: int = ID_UDS_ENGINE_RESP,
        tx_id: int = ID_UDS_ENGINE_REQ,
        timeout: float = 1.0,
    ) -> bytes | None:
        bus.send(
            can.Message(
                arbitration_id=tx_id, data=encode_uds(payload), is_extended_id=False
            )
        )
        deadline = time.monotonic() + timeout
        buf = b""
        expected_len = None
        sn_expected = 1

        while time.monotonic() < deadline:
            try:
                msg = bus.recv(timeout=0.1)
            except Exception:
                return None
            if not msg or msg.arbitration_id != rx_id:
                continue

            d = bytes(msg.data)
            frame_type = (d[0] & 0xF0) >> 4

            if frame_type == 0:  # Single Frame
                return decode_uds(d)

            elif frame_type == 1:  # First Frame
                expected_len = ((d[0] & 0x0F) << 8) | d[1]
                buf = d[2:]
                # Send Flow Control: ContinueToSend, BS=0, ST=0
                fc = bytes([0x30, 0x00, 0x00]) + bytes(5)
                bus.send(
                    can.Message(arbitration_id=tx_id, data=fc, is_extended_id=False)
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

    print("\n[Tester] ── UDS session on Engine ECU ──")

    r = send_recv(bytes([SID.DIAGNOSTIC_SESSION_CONTROL, Session.EXTENDED]))
    print(f"[Tester] DiagSession   : {r.hex() if r else 'timeout'}")

    r = send_recv(bytes([SID.SECURITY_ACCESS, 0x01]))
    print(f"[Tester] Seed          : {r.hex() if r else 'timeout'}")
    if r and r[0] == SID.SECURITY_ACCESS + 0x40:
        seed = int.from_bytes(r[2:4], "big")
        key = seed ^ 0xDEAD
        r2 = send_recv(bytes([SID.SECURITY_ACCESS, 0x02]) + key.to_bytes(2, "big"))
        print(f"[Tester] Key response  : {r2.hex() if r2 else 'timeout'}")

    r = send_recv(bytes([SID.READ_DATA_BY_ID, 0xF1, 0x90]))
    if r and r[0] == SID.READ_DATA_BY_ID + 0x40:
        print(f"[Tester] VIN           : {r[3:].decode(errors='replace')}")

    r = send_recv(bytes([SID.READ_DATA_BY_ID, 0x00, 0x01]))
    if r and r[0] == SID.READ_DATA_BY_ID + 0x40:
        print(f"[Tester] Live RPM      : {int.from_bytes(r[3:5], 'big')}")

    r = send_recv(bytes([SID.READ_DTC_INFO, 0x02, 0xFF]))
    print(f"[Tester] DTCs          : {r.hex() if r else 'timeout'}")

    r = send_recv(bytes([SID.TESTER_PRESENT, 0x00]))
    print(f"[Tester] TesterPresent : {r.hex() if r else 'timeout'}")

    try:
        bus.shutdown()
    except Exception:
        pass


# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting simulated vehicle CAN network with UDS support...")

    ecus = [EngineECU(), ABSECU(), GatewayECU(), CANDecoder()]
    for e in ecus:
        e.start()

    tester_thread = threading.Thread(target=run_uds_tester, daemon=True)
    tester_thread.start()

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        for e in ecus:
            e.stop()
        print("Done.")
