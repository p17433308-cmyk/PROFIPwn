"""
PROFINET protocol fuzzer — structure-aware mutations of DCP, RT, and alarm frames.
"""
import struct
import random
import time
import os
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass

from .protocols.profinet_dcp import (
    build_dcp_frame, build_ethernet_frame, DCP_MULTICAST_MAC,
    PROFINET_ETHER_TYPE, DCPFrame, DCPBlock, DCPServiceID,
    DCPServiceType, DCPOption,
)
from .protocols.profinet_rt import (
    RTFrame, AlarmFrame, build_rt_frame, build_alarm_frame, DataStatus,
)
from .protocols.profinet_dcp import build_ethernet_frame, PROFINET_ETHER_TYPE


INTERESTING_VALS = [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000,
                    0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]


@dataclass
class FuzzCase:
    name: str
    frame: bytes
    module: str
    description: str


@dataclass
class FuzzResult:
    case: FuzzCase
    sent: bool = False
    response: Optional[bytes] = None
    crashed: bool = False
    note: str = ""


class PROFINETFuzzer:
    """Structure-aware PROFINET protocol fuzzer."""

    def __init__(self, output_dir: str = "fuzz_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.cases: List[FuzzCase] = []

    def generate_dcp_fuzz_cases(self, count: int = 500) -> List[FuzzCase]:
        cases = []

        # 1. Invalid service IDs
        for sid in [0, 1, 2, 7, 0xFF]:
            frame = DCPFrame(service_id=sid, service_type=DCPServiceType.REQUEST, xid=1)
            frame_data = build_dcp_frame(frame)
            cases.append(FuzzCase(f"dcp_invalid_service_{sid}", frame_data, "dcp",
                                   f"Invalid service ID: {sid}"))

        # 2. Oversized block data
        for size in [256, 1024, 4096, 65535]:
            frame = DCPFrame(
                service_id=DCPServiceID.SET, service_type=DCPServiceType.REQUEST, xid=1,
                blocks=[DCPBlock(option=2, suboption=2, data=b"A" * size)],
            )
            cases.append(FuzzCase(f"dcp_oversize_{size}", build_dcp_frame(frame), "dcp",
                                   f"Oversized block data: {size} bytes"))

        # 3. Invalid option/suboption combinations
        for opt in range(256):
            for sub in [0, 1, 0xFF]:
                frame = DCPFrame(
                    service_id=DCPServiceID.GET, service_type=DCPServiceType.REQUEST, xid=1,
                    blocks=[DCPBlock(option=opt, suboption=sub, data=b"\x00" * 4)],
                )
                cases.append(FuzzCase(f"dcp_opt_{opt}_sub_{sub}", build_dcp_frame(frame), "dcp",
                                       f"Option {opt}, suboption {sub}"))
                if len(cases) >= count // 3:
                    break
            if len(cases) >= count // 3:
                break

        # 4. Malformed block lengths (direct byte manipulation)
        base = build_dcp_frame(DCPFrame(
            service_id=DCPServiceID.IDENTIFY, service_type=DCPServiceType.REQUEST,
            xid=1, blocks=[DCPBlock(option=0xFF, suboption=0xFF, data=b"\x00" * 8)],
        ))
        for bad_len in INTERESTING_VALS:
            mutated = bytearray(base)
            if len(mutated) > 14:
                struct.pack_into(">H", mutated, 12, bad_len & 0xFFFF)
            cases.append(FuzzCase(f"dcp_badlen_{bad_len}", bytes(mutated), "dcp",
                                   f"Corrupted block length: {bad_len}"))

        # 5. Empty and minimal frames
        cases.append(FuzzCase("dcp_empty", b"", "dcp", "Empty frame"))
        cases.append(FuzzCase("dcp_1byte", b"\x00", "dcp", "Single byte"))
        cases.append(FuzzCase("dcp_header_only", b"\xFE\xFE\x05\x00\x00\x00\x00\x01\x00\x01\x00\x00",
                               "dcp", "Header with zero data"))

        # 6. XID boundary values
        for xid in [0, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]:
            frame = DCPFrame(service_id=DCPServiceID.IDENTIFY,
                             service_type=DCPServiceType.REQUEST, xid=xid)
            cases.append(FuzzCase(f"dcp_xid_{xid:#x}", build_dcp_frame(frame), "dcp",
                                   f"XID boundary: {xid:#x}"))

        # 7. Random mutations on valid frames
        valid = build_dcp_frame(DCPFrame(
            service_id=DCPServiceID.SET, service_type=DCPServiceType.REQUEST, xid=42,
            blocks=[DCPBlock(option=2, suboption=2, data=b"test-device")],
        ))
        for i in range(min(100, count - len(cases))):
            mutated = bytearray(valid)
            num_mutations = random.randint(1, 5)
            for _ in range(num_mutations):
                if mutated:
                    pos = random.randint(0, len(mutated) - 1)
                    mutated[pos] = random.randint(0, 255)
            cases.append(FuzzCase(f"dcp_random_{i}", bytes(mutated), "dcp",
                                   f"Random mutation round {i}"))

        self.cases.extend(cases[:count])
        return cases[:count]

    def generate_rt_fuzz_cases(self, count: int = 300) -> List[FuzzCase]:
        cases = []

        # 1. Invalid frame IDs
        for fid in [0x0000, 0x00FF, 0x7FFF, 0xC000, 0xFFFF, 0xDEAD]:
            rt = RTFrame(frame_id=fid, io_data=b"\x00" * 40, cycle_counter=1,
                         data_status=DataStatus.normal_running())
            cases.append(FuzzCase(f"rt_frameid_{fid:#06x}", build_rt_frame(rt), "rt",
                                   f"Invalid frame ID: {fid:#06x}"))

        # 2. Oversized IO data
        for size in [0, 1, 255, 1024, 4096, 65535]:
            rt = RTFrame(frame_id=0x8001, io_data=b"\x41" * size,
                         cycle_counter=1, data_status=DataStatus.normal_running())
            cases.append(FuzzCase(f"rt_iosize_{size}", build_rt_frame(rt), "rt",
                                   f"IO data size: {size} bytes"))

        # 3. All data status combinations
        for ds in range(256):
            rt = RTFrame(frame_id=0x8001, io_data=b"\x00" * 40,
                         cycle_counter=1, data_status=ds)
            cases.append(FuzzCase(f"rt_datastatus_{ds:#04x}", build_rt_frame(rt), "rt",
                                   f"Data status: {ds:#04x}"))
            if len(cases) >= count // 2:
                break

        # 4. Transfer status values
        for ts in [0, 1, 0x7F, 0x80, 0xFF]:
            rt = RTFrame(frame_id=0x8001, io_data=b"\x00" * 40,
                         cycle_counter=1, data_status=DataStatus.normal_running(),
                         transfer_status=ts)
            cases.append(FuzzCase(f"rt_xferstatus_{ts}", build_rt_frame(rt), "rt",
                                   f"Transfer status: {ts}"))

        # 5. Alarm frame fuzzing
        for alarm_type in [0, 1, 2, 3, 0xFF, 0xFFFF]:
            alarm = AlarmFrame(alarm_type=alarm_type, slot_number=0xFFFF,
                               subslot_number=0xFFFF, alarm_data=b"\xFF" * 64)
            cases.append(FuzzCase(f"alarm_type_{alarm_type}", build_alarm_frame(alarm), "rt",
                                   f"Alarm type: {alarm_type}"))

        self.cases.extend(cases[:count])
        return cases[:count]

    def generate_all(self, dcp_count: int = 500, rt_count: int = 300) -> List[FuzzCase]:
        all_cases = []
        all_cases.extend(self.generate_dcp_fuzz_cases(dcp_count))
        all_cases.extend(self.generate_rt_fuzz_cases(rt_count))
        return all_cases

    def save_cases(self, cases: Optional[List[FuzzCase]] = None):
        cases = cases or self.cases
        for i, case in enumerate(cases):
            module_dir = self.output_dir / case.module
            module_dir.mkdir(exist_ok=True)
            filepath = module_dir / f"{i:05d}_{case.name}.bin"
            filepath.write_bytes(case.frame)

        manifest = []
        for i, case in enumerate(cases):
            manifest.append(f"{i:05d} | {case.module:<6} | {case.name:<40} | {case.description}")

        (self.output_dir / "manifest.txt").write_text("\n".join(manifest))

        print(f"\n  [*] Generated {len(cases)} fuzz cases")
        print(f"  [*] Saved to {self.output_dir}/")
        dcp = sum(1 for c in cases if c.module == "dcp")
        rt = sum(1 for c in cases if c.module == "rt")
        print(f"  [*] DCP: {dcp} | RT: {rt}")

    def write_pcap(self, cases: List[FuzzCase], path: str):
        """Export fuzz cases as a pcap file (Ethernet-framed)."""
        from .dissectors import write_pcap as _write_pcap
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        dst_mac = DCP_MULTICAST_MAC
        frames = []
        for c in cases:
            eth = build_ethernet_frame(dst_mac, src_mac, c.frame)
            frames.append(eth)
        _write_pcap(frames, path)
        return len(frames)

    @staticmethod
    def _liveness_probe(interface: str, dst_mac: bytes, timeout: float) -> bool:
        """Send a DCP Identify and check the target still answers."""
        import socket as _socket
        import select
        try:
            sock = _socket.socket(
                _socket.AF_PACKET, _socket.SOCK_RAW,
                _socket.htons(PROFINET_ETHER_TYPE))
            sock.bind((interface, 0))
            src_mac = b"\x00\x11\x22\x33\x44\x55"
            probe = build_dcp_frame(DCPFrame(
                service_id=DCPServiceID.IDENTIFY,
                service_type=DCPServiceType.REQUEST,
                xid=0xDEADDEAD,
                blocks=[DCPBlock(option=0xFF, suboption=0xFF, data=b"")],
            ))
            eth = build_ethernet_frame(dst_mac, src_mac, probe)
            sock.send(eth)
            ready, _, _ = select.select([sock], [], [], timeout)
            sock.close()
            return len(ready) > 0
        except OSError:
            return False

    def send_fuzz_cases(self, interface: str, dst_mac: bytes,
                        cases: List[FuzzCase], timeout: float = 1.0,
                        check_liveness: bool = True,
                        delay: float = 0.001) -> List[FuzzResult]:
        """Deliver fuzz cases over raw sockets to a live PROFINET target."""
        import socket as _socket
        results: List[FuzzResult] = []
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        try:
            sock = _socket.socket(
                _socket.AF_PACKET, _socket.SOCK_RAW,
                _socket.htons(PROFINET_ETHER_TYPE))
            sock.bind((interface, 0))
        except OSError as e:
            for c in cases:
                results.append(FuzzResult(case=c, note=f"socket error: {e}"))
            return results

        for case in cases:
            res = FuzzResult(case=case)
            try:
                eth = build_ethernet_frame(dst_mac, src_mac, case.frame)
                sock.send(eth)
                res.sent = True
            except OSError as e:
                res.note = f"send error: {e}"

            if check_liveness and res.sent:
                alive = self._liveness_probe(interface, dst_mac, timeout)
                if not alive:
                    res.crashed = True
                    res.note = "target unresponsive after case — LIKELY CRASH"

            results.append(res)
            if delay > 0:
                time.sleep(delay)
            if res.crashed:
                break

        sock.close()
        return results

    def run_against_target(self, target_cmd: str, timeout: int = 5) -> dict:
        """Run fuzz cases against a target process (for software-based testing)."""
        import subprocess
        results = {"total": 0, "crashes": 0, "timeouts": 0, "errors": []}

        for case in self.cases:
            results["total"] += 1
            input_path = self.output_dir / "current_input.bin"
            input_path.write_bytes(case.frame)

            cmd = target_cmd.replace("{input}", str(input_path))
            try:
                proc = subprocess.run(cmd.split(), capture_output=True, timeout=timeout)
                if proc.returncode < 0 or proc.returncode in (134, 139):
                    results["crashes"] += 1
                    crash_dir = self.output_dir / "crashes"
                    crash_dir.mkdir(exist_ok=True)
                    crash_path = crash_dir / f"crash_{case.name}.bin"
                    crash_path.write_bytes(case.frame)
                    results["errors"].append({
                        "case": case.name, "exit_code": proc.returncode,
                        "stderr": proc.stderr.decode(errors="replace")[:500],
                    })
            except subprocess.TimeoutExpired:
                results["timeouts"] += 1

            if results["total"] % 100 == 0:
                print(f"  [{results['total']}/{len(self.cases)}] "
                      f"crashes={results['crashes']} timeouts={results['timeouts']}")

        return results
