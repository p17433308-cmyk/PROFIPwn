"""
PROFINET DCP (Discovery and Configuration Protocol) implementation.

DCP operates on Layer 2 (Ethernet) — no IP stack needed.
It is completely unauthenticated by design.

Frame format:
  Ethernet Header (dst=multicast/unicast, src=attacker, type=0x8892)
  └─ PROFINET Frame ID (2 bytes): 0xFEFD (DCP multicast), 0xFEFE (DCP response)
  └─ DCP Header:
       Service ID (1 byte): Identify=5, Set=4, Get=3
       Service Type (1 byte): Request=0, Response=1
       Xid (4 bytes): Transaction ID
       Response Delay (2 bytes)
       Data Length (2 bytes)
  └─ DCP Blocks (variable)

References:
  - IEC 61158 / IEC 61784
  - Siemens PROFINET System Description (public)
"""
import struct
import socket
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from enum import IntEnum


# Ethernet
PROFINET_ETHER_TYPE = 0x8892
DCP_MULTICAST_MAC = b"\x01\x0e\xcf\x00\x00\x00"
LLDP_MULTICAST_MAC = b"\x01\x80\xc2\x00\x00\x0e"

# PROFINET Frame IDs
FRAME_ID_DCP_HELLO = 0xFEFC
FRAME_ID_DCP_GET_SET = 0xFEFD
FRAME_ID_DCP_IDENTIFY_REQ = 0xFEFE
FRAME_ID_DCP_IDENTIFY_RES = 0xFEFF
FRAME_ID_RT_CLASS1 = 0x8000  # RT Class 1 range: 0x8000-0xBFFF
FRAME_ID_RT_CLASS3 = 0x0100  # IRT range: 0x0100-0x7FFF
FRAME_ID_ALARM_HIGH = 0xFC01
FRAME_ID_ALARM_LOW = 0xFE01


class DCPServiceID(IntEnum):
    GET = 3
    SET = 4
    IDENTIFY = 5
    HELLO = 6


class DCPServiceType(IntEnum):
    REQUEST = 0
    RESPONSE = 1
    SUCCESS = 1
    NOT_SUPPORTED = 5


class DCPOption(IntEnum):
    IP = 1
    DEVICE = 2
    DHCP = 3
    CONTROL = 5
    DEVICE_INITIATIVE = 6
    ALL = 255


class DCPSubOption(IntEnum):
    # IP suboptions
    IP_MAC = 1
    IP_PARAMETER = 2
    IP_FULL_SUITE = 3
    # Device suboptions
    DEV_VENDOR = 1
    DEV_NAME = 2
    DEV_ID = 3
    DEV_ROLE = 4
    DEV_OPTIONS = 5
    DEV_ALIAS = 6
    DEV_INSTANCE = 7
    # Control suboptions
    CTRL_START = 1
    CTRL_STOP = 2
    CTRL_SIGNAL = 3
    CTRL_RESPONSE = 4
    CTRL_FACTORY_RESET = 5
    CTRL_RESET_TO_FACTORY = 6


@dataclass
class DCPBlock:
    option: int
    suboption: int
    data: bytes = b""
    block_qualifier: int = 0  # 0=temporary, 1=permanent (for Set)


@dataclass
class DCPFrame:
    service_id: DCPServiceID
    service_type: DCPServiceType
    xid: int = 0x00000001
    response_delay: int = 1
    blocks: List[DCPBlock] = field(default_factory=list)


def build_ethernet_frame(dst_mac: bytes, src_mac: bytes, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", PROFINET_ETHER_TYPE) + payload


def build_dcp_frame(frame: DCPFrame) -> bytes:
    blocks_data = b""
    for block in frame.blocks:
        block_data = block.data
        if frame.service_id == DCPServiceID.SET:
            block_data = struct.pack(">H", block.block_qualifier) + block.data
        block_hdr = struct.pack(">BBH", block.option & 0xFF, block.suboption & 0xFF,
                                min(len(block_data), 0xFFFF))
        blocks_data += block_hdr + block_data
        # Pad to even length
        if len(block_data) % 2:
            blocks_data += b"\x00"

    # Frame ID
    if frame.service_id == DCPServiceID.IDENTIFY:
        if frame.service_type == DCPServiceType.REQUEST:
            frame_id = FRAME_ID_DCP_IDENTIFY_REQ
        else:
            frame_id = FRAME_ID_DCP_IDENTIFY_RES
    else:
        frame_id = FRAME_ID_DCP_GET_SET

    buf = struct.pack(">H", frame_id)
    buf += struct.pack(">B", frame.service_id)
    buf += struct.pack(">B", frame.service_type)
    buf += struct.pack(">I", frame.xid)
    buf += struct.pack(">H", frame.response_delay)
    buf += struct.pack(">H", min(len(blocks_data), 0xFFFF))
    buf += blocks_data

    return buf


def build_identify_request(xid: int = 1, name_filter: Optional[str] = None) -> bytes:
    blocks = []
    if name_filter:
        blocks.append(DCPBlock(
            option=DCPOption.DEVICE,
            suboption=DCPSubOption.DEV_NAME,
            data=name_filter.encode("ascii"),
        ))
    else:
        blocks.append(DCPBlock(
            option=DCPOption.ALL,
            suboption=0xFF,
            data=b"",
        ))

    frame = DCPFrame(
        service_id=DCPServiceID.IDENTIFY,
        service_type=DCPServiceType.REQUEST,
        xid=xid,
        response_delay=128,
        blocks=blocks,
    )
    return build_dcp_frame(frame)


def build_set_name_request(name: str, xid: int = 1, permanent: bool = False) -> bytes:
    frame = DCPFrame(
        service_id=DCPServiceID.SET,
        service_type=DCPServiceType.REQUEST,
        xid=xid,
        blocks=[
            DCPBlock(
                option=DCPOption.DEVICE,
                suboption=DCPSubOption.DEV_NAME,
                data=name.encode("ascii"),
                block_qualifier=1 if permanent else 0,
            ),
        ],
    )
    return build_dcp_frame(frame)


def build_set_ip_request(ip: str, mask: str, gateway: str, xid: int = 1,
                          permanent: bool = False) -> bytes:
    ip_data = socket.inet_aton(ip) + socket.inet_aton(mask) + socket.inet_aton(gateway)
    frame = DCPFrame(
        service_id=DCPServiceID.SET,
        service_type=DCPServiceType.REQUEST,
        xid=xid,
        blocks=[
            DCPBlock(
                option=DCPOption.IP,
                suboption=DCPSubOption.IP_PARAMETER,
                data=ip_data,
                block_qualifier=1 if permanent else 0,
            ),
        ],
    )
    return build_dcp_frame(frame)


def build_factory_reset_request(xid: int = 1) -> bytes:
    frame = DCPFrame(
        service_id=DCPServiceID.SET,
        service_type=DCPServiceType.REQUEST,
        xid=xid,
        blocks=[
            DCPBlock(
                option=DCPOption.CONTROL,
                suboption=DCPSubOption.CTRL_FACTORY_RESET,
                data=b"",
            ),
        ],
    )
    return build_dcp_frame(frame)


def build_signal_request(xid: int = 1) -> bytes:
    """Flash LED on target device (DCP Signal / blink)."""
    frame = DCPFrame(
        service_id=DCPServiceID.SET,
        service_type=DCPServiceType.REQUEST,
        xid=xid,
        blocks=[
            DCPBlock(
                option=DCPOption.CONTROL,
                suboption=DCPSubOption.CTRL_SIGNAL,
                data=struct.pack(">H", 3),  # duration in seconds
            ),
        ],
    )
    return build_dcp_frame(frame)


def parse_dcp_response(data: bytes) -> Optional[dict]:
    if len(data) < 12:
        return None

    frame_id = struct.unpack(">H", data[0:2])[0]
    service_id = data[2]
    service_type = data[3]
    xid = struct.unpack(">I", data[4:8])[0]
    _resp_delay = struct.unpack(">H", data[8:10])[0]
    data_len = struct.unpack(">H", data[10:12])[0]

    result = {
        "frame_id": frame_id,
        "service_id": service_id,
        "service_type": service_type,
        "xid": xid,
        "blocks": [],
    }

    offset = 12
    while offset + 4 <= len(data) and offset < 12 + data_len:
        option = data[offset]
        suboption = data[offset + 1]
        block_len = struct.unpack(">H", data[offset + 2:offset + 4])[0]
        block_data = data[offset + 4:offset + 4 + block_len]

        block_info = {"option": option, "suboption": suboption, "raw": block_data}

        if option == DCPOption.DEVICE and suboption == DCPSubOption.DEV_NAME:
            block_info["name"] = block_data.decode("ascii", errors="replace")
        elif option == DCPOption.DEVICE and suboption == DCPSubOption.DEV_VENDOR:
            block_info["vendor"] = block_data.decode("ascii", errors="replace")
        elif option == DCPOption.DEVICE and suboption == DCPSubOption.DEV_ID:
            if len(block_data) >= 4:
                block_info["vendor_id"] = struct.unpack(">H", block_data[0:2])[0]
                block_info["device_id"] = struct.unpack(">H", block_data[2:4])[0]
        elif option == DCPOption.DEVICE and suboption == DCPSubOption.DEV_ROLE:
            if block_data:
                roles = []
                role_byte = block_data[0]
                if role_byte & 0x01:
                    roles.append("IO-Device")
                if role_byte & 0x02:
                    roles.append("IO-Controller")
                if role_byte & 0x04:
                    roles.append("IO-Multidevice")
                if role_byte & 0x08:
                    roles.append("IO-Supervisor")
                block_info["roles"] = roles
        elif option == DCPOption.IP and suboption == DCPSubOption.IP_PARAMETER:
            if len(block_data) >= 14:
                block_info["ip_info"] = block_data[:2]  # block info field
                block_info["ip"] = socket.inet_ntoa(block_data[2:6])
                block_info["netmask"] = socket.inet_ntoa(block_data[6:10])
                block_info["gateway"] = socket.inet_ntoa(block_data[10:14])

        result["blocks"].append(block_info)

        # Advance past block + padding
        offset += 4 + block_len
        if block_len % 2:
            offset += 1

    return result
