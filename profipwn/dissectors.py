"""
PROFINET Scapy dissector layers — decode, modify, replay PROFINET traffic.

Custom layers:
- ProfinetDCP: DCP Identify/Set/Get frames (EtherType 0x8892)
- ProfinetRT: Real-Time cyclic IO data
- ProfinetAlarm: Alarm frames (high/low priority)

These enable pcap decode → inspect → modify → replay workflows.
"""
import struct
from typing import List, Dict, Optional, Tuple

from .protocols.profinet_dcp import (
    PROFINET_ETHER_TYPE, DCP_MULTICAST_MAC,
    FRAME_ID_DCP_IDENTIFY_REQ, FRAME_ID_DCP_IDENTIFY_RES,
    FRAME_ID_DCP_GET_SET, FRAME_ID_DCP_HELLO,
    FRAME_ID_RT_CLASS1, FRAME_ID_ALARM_HIGH, FRAME_ID_ALARM_LOW,
    DCPServiceID, DCPServiceType, DCPOption, DCPSubOption,
    build_dcp_frame, build_ethernet_frame, parse_dcp_response, DCPFrame, DCPBlock,
)


# ── pcap file format helpers ──

PCAP_MAGIC = 0xA1B2C3D4
PCAP_LINK_ETHERNET = 1


def write_pcap(frames: List[bytes], path: str, link_type: int = PCAP_LINK_ETHERNET):
    """Write raw frames to a pcap file."""
    import time
    with open(path, "wb") as f:
        # Global header
        f.write(struct.pack("<IHHiIII",
            PCAP_MAGIC, 2, 4, 0, 0, 65535, link_type))
        ts = time.time()
        for i, frame in enumerate(frames):
            sec = int(ts + i * 0.001)
            usec = int(((ts + i * 0.001) - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)


def read_pcap(path: str) -> List[Tuple[float, bytes]]:
    """Read frames from a pcap file. Returns list of (timestamp, raw_frame)."""
    frames = []
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return frames
        magic = struct.unpack("<I", header[:4])[0]
        big_endian = magic == 0xD4C3B2A1
        fmt = ">" if big_endian else "<"

        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            sec, usec, incl_len, orig_len = struct.unpack(f"{fmt}IIII", pkt_hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            ts = sec + usec / 1_000_000
            frames.append((ts, data))
    return frames


# ── Dissector classes ──

class DissectedPacket:
    """A decoded PROFINET packet with layer info."""

    def __init__(self, raw: bytes):
        self.raw = raw
        self.layers: List[Dict] = []
        self.summary = ""
        self._dissect()

    def _dissect(self):
        data = self.raw
        if len(data) < 14:
            self.summary = f"Too short ({len(data)} bytes)"
            return

        # Ethernet header
        dst_mac = data[0:6]
        src_mac = data[6:12]
        ether_type = struct.unpack(">H", data[12:14])[0]

        self.layers.append({
            "layer": "Ethernet",
            "dst": ":".join(f"{b:02x}" for b in dst_mac),
            "src": ":".join(f"{b:02x}" for b in src_mac),
            "type": f"0x{ether_type:04X}",
        })

        if ether_type != PROFINET_ETHER_TYPE:
            self.summary = f"Non-PROFINET (EtherType 0x{ether_type:04X})"
            return

        payload = data[14:]
        if len(payload) < 2:
            return

        frame_id = struct.unpack(">H", payload[0:2])[0]

        if frame_id in (FRAME_ID_DCP_IDENTIFY_REQ, FRAME_ID_DCP_IDENTIFY_RES,
                        FRAME_ID_DCP_GET_SET, FRAME_ID_DCP_HELLO):
            self._dissect_dcp(payload, frame_id)
        elif 0x8000 <= frame_id <= 0xBFFF:
            self._dissect_rt(payload, frame_id)
        elif frame_id in (FRAME_ID_ALARM_HIGH, FRAME_ID_ALARM_LOW):
            self._dissect_alarm(payload, frame_id)
        else:
            self.layers.append({"layer": "PROFINET", "frame_id": f"0x{frame_id:04X}"})
            self.summary = f"PROFINET FrameID 0x{frame_id:04X}"

    def _dissect_dcp(self, payload: bytes, frame_id: int):
        if len(payload) < 12:
            return

        service_id = payload[2]
        service_type = payload[3]
        xid = struct.unpack(">I", payload[4:8])[0]
        resp_delay = struct.unpack(">H", payload[8:10])[0]
        data_len = struct.unpack(">H", payload[10:12])[0]

        svc_names = {3: "Get", 4: "Set", 5: "Identify", 6: "Hello"}
        type_names = {0: "Request", 1: "Response"}

        layer = {
            "layer": "DCP",
            "frame_id": f"0x{frame_id:04X}",
            "service": svc_names.get(service_id, f"Unknown({service_id})"),
            "type": type_names.get(service_type, f"Unknown({service_type})"),
            "xid": f"0x{xid:08X}",
            "data_length": data_len,
            "blocks": [],
        }

        # Parse blocks
        offset = 12
        while offset + 4 <= len(payload) and offset < 12 + data_len:
            opt = payload[offset]
            subopt = payload[offset + 1]
            blen = struct.unpack(">H", payload[offset + 2:offset + 4])[0]
            bdata = payload[offset + 4:offset + 4 + blen]

            block = {"option": opt, "suboption": subopt, "length": blen}
            if opt == DCPOption.DEVICE and subopt == DCPSubOption.DEV_NAME:
                block["name"] = bdata.decode("ascii", errors="replace")
            elif opt == DCPOption.IP and subopt == DCPSubOption.IP_PARAMETER and len(bdata) >= 14:
                import socket
                block["ip"] = socket.inet_ntoa(bdata[2:6])
                block["netmask"] = socket.inet_ntoa(bdata[6:10])
                block["gateway"] = socket.inet_ntoa(bdata[10:14])

            layer["blocks"].append(block)
            offset += 4 + blen
            if blen % 2:
                offset += 1

        self.layers.append(layer)
        self.summary = f"DCP {layer['service']} {layer['type']} XID=0x{xid:08X}"

    def _dissect_rt(self, payload: bytes, frame_id: int):
        # RT frame: FrameID(2) + IOData(variable) + IOPS(1) + CycleCounter(2) + DataStatus(1) + TransferStatus(1)
        io_data = payload[2:-4] if len(payload) > 6 else payload[2:]
        cycle_counter = struct.unpack(">H", payload[-4:-2])[0] if len(payload) >= 6 else 0
        data_status = payload[-2] if len(payload) >= 5 else 0

        self.layers.append({
            "layer": "RT",
            "frame_id": f"0x{frame_id:04X}",
            "io_data_len": len(io_data),
            "io_data_hex": io_data[:16].hex(),
            "cycle_counter": cycle_counter,
            "data_status": f"0x{data_status:02X}",
            "state": "run" if data_status & 0x10 else "stop",
        })
        self.summary = f"RT FrameID=0x{frame_id:04X} Cycle={cycle_counter} IO={len(io_data)}B"

    def _dissect_alarm(self, payload: bytes, frame_id: int):
        prio = "High" if frame_id == FRAME_ID_ALARM_HIGH else "Low"
        self.layers.append({
            "layer": "Alarm",
            "priority": prio,
            "frame_id": f"0x{frame_id:04X}",
            "data_hex": payload[2:].hex() if len(payload) > 2 else "",
        })
        self.summary = f"Alarm ({prio}) {len(payload) - 2}B"

    def __repr__(self):
        return f"<DissectedPacket: {self.summary}>"


# ── Capture & Replay ──

class PROFINETCapture:
    """Capture and replay PROFINET traffic."""

    def __init__(self):
        self.frames: List[Tuple[float, bytes]] = []

    def capture_raw(self, interface: str = "eth0", duration: float = 10.0,
                     frame_filter: Optional[int] = None) -> int:
        """
        Capture PROFINET frames using a raw socket.

        Requires root/CAP_NET_RAW. On systems without raw socket access,
        use load_pcap() to analyze pre-captured traffic.
        """
        import time
        import select

        try:
            import socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(PROFINET_ETHER_TYPE))
            sock.bind((interface, 0))
        except (OSError, AttributeError) as e:
            print(f"  [!] Raw capture not available: {e}")
            print(f"  [*] Use load_pcap() to analyze pre-captured traffic")
            return 0

        sock.setblocking(False)
        start = time.time()
        count = 0

        while time.time() - start < duration:
            ready, _, _ = select.select([sock], [], [], 0.5)
            if ready:
                data = sock.recv(65535)
                if frame_filter is not None and len(data) > 16:
                    fid = struct.unpack(">H", data[14:16])[0]
                    if fid != frame_filter:
                        continue
                self.frames.append((time.time(), data))
                count += 1

        sock.close()
        return count

    def load_pcap(self, path: str) -> int:
        """Load frames from a pcap file."""
        self.frames = read_pcap(path)
        return len(self.frames)

    def save_pcap(self, path: str) -> int:
        """Save captured frames to pcap."""
        raw_frames = [f for _, f in self.frames]
        write_pcap(raw_frames, path)
        return len(raw_frames)

    def dissect_all(self) -> List[DissectedPacket]:
        """Dissect all captured frames."""
        return [DissectedPacket(f) for _, f in self.frames]

    def replay(self, interface: str = "eth0", speed: float = 1.0,
               modify_fn=None) -> int:
        """
        Replay captured frames. Optional modify_fn receives raw bytes,
        returns modified bytes (or None to skip).
        """
        try:
            import socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.bind((interface, 0))
        except (OSError, AttributeError) as e:
            print(f"  [!] Raw replay not available: {e}")
            return 0

        import time
        sent = 0
        prev_ts = None

        for ts, frame in self.frames:
            if prev_ts is not None and speed > 0:
                delay = (ts - prev_ts) / speed
                if delay > 0:
                    time.sleep(delay)
            prev_ts = ts

            if modify_fn:
                frame = modify_fn(frame)
                if frame is None:
                    continue

            sock.send(frame)
            sent += 1

        sock.close()
        return sent

    def filter_by_frame_id(self, frame_id: int) -> 'PROFINETCapture':
        """Return a new capture containing only frames with matching ID."""
        filtered = PROFINETCapture()
        for ts, data in self.frames:
            if len(data) > 16:
                fid = struct.unpack(">H", data[14:16])[0]
                if fid == frame_id:
                    filtered.frames.append((ts, data))
        return filtered

    def print_summary(self):
        """Print dissection summary of captured frames."""
        packets = self.dissect_all()
        print(f"\n  {'='*70}")
        print(f"  PROFINET CAPTURE — {len(packets)} frames")
        print(f"  {'='*70}")

        type_counts: Dict[str, int] = {}
        for pkt in packets:
            layer_name = pkt.layers[-1]["layer"] if pkt.layers else "Unknown"
            type_counts[layer_name] = type_counts.get(layer_name, 0) + 1
            if len(packets) <= 50:
                print(f"  {pkt.summary}")

        print(f"\n  Frame types:")
        for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"    {t}: {c}")
