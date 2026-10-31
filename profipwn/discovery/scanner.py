"""
PROFINET DCP network scanner — discovers devices on Layer 2 without IP.
Sends DCP Identify multicast and collects responses.
"""
import struct
import socket
import time
import os
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Dict

from ..protocols.profinet_dcp import (
    build_identify_request, build_ethernet_frame, parse_dcp_response,
    DCP_MULTICAST_MAC, PROFINET_ETHER_TYPE, DCPOption, DCPSubOption,
)


SIEMENS_VENDOR_IDS = {
    0x002A: "Siemens AG",
    0x002B: "Siemens AG (alt)",
}

KNOWN_DEVICE_IDS = {
    (0x002A, 0x0101): "S7-300",
    (0x002A, 0x0102): "S7-400",
    (0x002A, 0x0201): "S7-1200",
    (0x002A, 0x0202): "S7-1500",
    (0x002A, 0x0203): "S7-1500 F",
    (0x002A, 0x0301): "ET 200SP",
    (0x002A, 0x0302): "ET 200MP",
    (0x002A, 0x0401): "SCALANCE X",
    (0x002A, 0x0402): "SCALANCE W",
    (0x002A, 0x0501): "CP 343-1",
    (0x002A, 0x0502): "CP 443-1",
    (0x002A, 0x0601): "SINAMICS",
    (0x002A, 0x0701): "SIMOTION",
}


@dataclass
class PROFINETDevice:
    mac_address: str = ""
    station_name: str = ""
    vendor: str = ""
    vendor_id: int = 0
    device_id: int = 0
    device_type: str = "Unknown"
    ip_address: str = ""
    netmask: str = ""
    gateway: str = ""
    roles: List[str] = field(default_factory=list)
    raw_response: bytes = b""

    def to_dict(self) -> Dict:
        return {
            "mac": self.mac_address,
            "name": self.station_name,
            "vendor": self.vendor,
            "vendor_id": f"0x{self.vendor_id:04X}",
            "device_id": f"0x{self.device_id:04X}",
            "device_type": self.device_type,
            "ip": self.ip_address,
            "netmask": self.netmask,
            "gateway": self.gateway,
            "roles": self.roles,
        }


def get_interface_mac(interface: str) -> bytes:
    """Get MAC address of a network interface."""
    if sys.platform == "linux":
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface[:15].encode()))
        s.close()
        return info[18:24]
    elif sys.platform == "darwin":
        import subprocess
        out = subprocess.check_output(["ifconfig", interface]).decode()
        for line in out.split("\n"):
            if "ether" in line:
                mac_str = line.strip().split()[1]
                return bytes(int(b, 16) for b in mac_str.split(":"))
    elif sys.platform == "win32":
        import subprocess
        out = subprocess.check_output(["getmac", "/v", "/fo", "csv"]).decode()
        for line in out.split("\n"):
            if interface in line:
                parts = line.split(",")
                for part in parts:
                    part = part.strip('"')
                    if "-" in part and len(part) == 17:
                        return bytes(int(b, 16) for b in part.split("-"))
    return b"\x00\x11\x22\x33\x44\x55"


class PROFINETScanner:
    def __init__(self, interface: str = "eth0", timeout: float = 3.0):
        self.interface = interface
        self.timeout = timeout
        self.devices: List[PROFINETDevice] = []

    def _create_raw_socket(self) -> socket.socket:
        """Create a raw Ethernet socket for Layer 2 communication."""
        if sys.platform == "win32":
            # Windows raw sockets are limited; use Scapy fallback
            raise OSError("Raw sockets require Scapy on Windows. Install: pip install scapy")

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(PROFINET_ETHER_TYPE))
        sock.bind((self.interface, 0))
        sock.settimeout(self.timeout)
        return sock

    def scan(self, use_scapy: bool = False) -> List[PROFINETDevice]:
        """Scan for PROFINET devices using DCP Identify multicast."""
        if use_scapy or sys.platform == "win32":
            return self._scan_scapy()
        return self._scan_raw()

    def _scan_raw(self) -> List[PROFINETDevice]:
        src_mac = get_interface_mac(self.interface)
        dcp_payload = build_identify_request(xid=0x00000001)
        frame = build_ethernet_frame(DCP_MULTICAST_MAC, src_mac, dcp_payload)

        sock = self._create_raw_socket()
        try:
            sock.send(frame)
            print(f"  [*] Sent DCP Identify multicast on {self.interface}")

            end_time = time.time() + self.timeout
            while time.time() < end_time:
                try:
                    data, addr = sock.recvfrom(65535)
                    self._process_response(data)
                except socket.timeout:
                    break
        finally:
            sock.close()

        return self.devices

    def _scan_scapy(self) -> List[PROFINETDevice]:
        try:
            from scapy.all import Ether, sendp, sniff, conf
        except ImportError:
            print("  [-] Scapy required. Install: pip install scapy")
            return []

        src_mac = get_interface_mac(self.interface)
        dcp_payload = build_identify_request(xid=0x00000001)

        pkt = Ether(
            dst="01:0e:cf:00:00:00",
            src=":".join(f"{b:02x}" for b in src_mac),
            type=PROFINET_ETHER_TYPE,
        ) / dcp_payload

        responses = []

        def handle_pkt(pkt):
            if pkt.haslayer(Ether) and pkt[Ether].type == PROFINET_ETHER_TYPE:
                responses.append(bytes(pkt[Ether].payload))

        print(f"  [*] Scanning with Scapy on {self.interface}")
        sendp(pkt, iface=self.interface, verbose=False)

        sniff(
            iface=self.interface,
            filter=f"ether proto 0x{PROFINET_ETHER_TYPE:04x}",
            timeout=self.timeout,
            prn=handle_pkt,
            store=0,
        )

        for resp_data in responses:
            self._process_response_payload(resp_data, "unknown")

        return self.devices

    def _process_response(self, raw_frame: bytes):
        if len(raw_frame) < 14:
            return
        dst_mac = raw_frame[0:6]
        src_mac = raw_frame[6:12]
        ether_type = struct.unpack(">H", raw_frame[12:14])[0]

        if ether_type != PROFINET_ETHER_TYPE:
            return

        mac_str = ":".join(f"{b:02x}" for b in src_mac)
        payload = raw_frame[14:]
        self._process_response_payload(payload, mac_str)

    def _process_response_payload(self, payload: bytes, mac_str: str):
        parsed = parse_dcp_response(payload)
        if not parsed:
            return
        if parsed["service_type"] != 1:  # Not a response
            return

        dev = PROFINETDevice(mac_address=mac_str, raw_response=payload)

        for block in parsed["blocks"]:
            if "name" in block:
                dev.station_name = block["name"]
            if "vendor" in block:
                dev.vendor = block["vendor"]
            if "vendor_id" in block:
                dev.vendor_id = block["vendor_id"]
                dev.device_id = block.get("device_id", 0)
                key = (dev.vendor_id, dev.device_id)
                dev.device_type = KNOWN_DEVICE_IDS.get(key, "Unknown")
                dev.vendor = SIEMENS_VENDOR_IDS.get(dev.vendor_id, dev.vendor or "Unknown")
            if "roles" in block:
                dev.roles = block["roles"]
            if "ip" in block:
                dev.ip_address = block["ip"]
                dev.netmask = block.get("netmask", "")
                dev.gateway = block.get("gateway", "")

        self.devices.append(dev)

    def print_results(self):
        if not self.devices:
            print("\n  No PROFINET devices found.")
            return

        print(f"\n  {'='*80}")
        print(f"  PROFINET DEVICES DISCOVERED — {len(self.devices)} device(s)")
        print(f"  {'='*80}")

        for i, dev in enumerate(self.devices, 1):
            print(f"\n  Device #{i}")
            print(f"    MAC:          {dev.mac_address}")
            print(f"    Station Name: {dev.station_name}")
            print(f"    Vendor:       {dev.vendor} (0x{dev.vendor_id:04X})")
            print(f"    Device ID:    0x{dev.device_id:04X} ({dev.device_type})")
            print(f"    IP:           {dev.ip_address}/{dev.netmask}")
            print(f"    Gateway:      {dev.gateway}")
            print(f"    Roles:        {', '.join(dev.roles) if dev.roles else 'Unknown'}")


