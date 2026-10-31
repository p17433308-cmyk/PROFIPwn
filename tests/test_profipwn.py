"""PROFIPwn integration tests — DCP frames, RT frames, dissectors."""
import struct
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from profipwn.protocols.profinet_dcp import (
    build_identify_request, build_set_name_request, build_set_ip_request,
    build_factory_reset_request, build_signal_request, build_ethernet_frame,
    build_dcp_frame, parse_dcp_response,
    PROFINET_ETHER_TYPE, DCP_MULTICAST_MAC,
    FRAME_ID_DCP_IDENTIFY_REQ, DCPServiceID,
)
from profipwn.protocols.profinet_rt import (
    RTFrame, AlarmFrame, build_rt_frame, build_alarm_frame,
    build_process_data_injection, build_provider_stop, build_data_invalid,
    DataStatus,
)


class TestDCPFrames:
    def test_identify_request_structure(self):
        pkt = build_identify_request(xid=0x12345678)
        assert len(pkt) >= 12
        frame_id = struct.unpack(">H", pkt[0:2])[0]
        assert frame_id == FRAME_ID_DCP_IDENTIFY_REQ
        assert pkt[2] == DCPServiceID.IDENTIFY
        xid = struct.unpack(">I", pkt[4:8])[0]
        assert xid == 0x12345678

    def test_set_name_request(self):
        pkt = build_set_name_request("TEST-PLC", xid=1)
        assert len(pkt) > 12
        assert pkt[2] == DCPServiceID.SET

    def test_set_ip_request(self):
        pkt = build_set_ip_request("192.168.1.100", "255.255.255.0", "192.168.1.1")
        assert len(pkt) > 12

    def test_factory_reset(self):
        pkt = build_factory_reset_request()
        assert len(pkt) > 12

    def test_ethernet_frame_wrapping(self):
        dcp = build_identify_request()
        src = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        frame = build_ethernet_frame(DCP_MULTICAST_MAC, src, dcp)
        assert frame[0:6] == DCP_MULTICAST_MAC
        assert frame[6:12] == src
        etype = struct.unpack(">H", frame[12:14])[0]
        assert etype == PROFINET_ETHER_TYPE

    def test_parse_roundtrip(self):
        pkt = build_identify_request(xid=0xAAAA)
        parsed = parse_dcp_response(pkt)
        assert parsed is not None
        assert parsed["xid"] == 0xAAAA


class TestRTFrames:
    def test_rt_frame_structure(self):
        rt = RTFrame(frame_id=0x8001, io_data=b"\x01\x02\x03\x04",
                      cycle_counter=100, data_status=DataStatus.normal_running(),
                      transfer_status=0)
        data = build_rt_frame(rt)
        frame_id = struct.unpack(">H", data[0:2])[0]
        assert frame_id == 0x8001

    def test_process_data_injection(self):
        pkt = build_process_data_injection(0x8001, b"\xFF" * 20)
        assert len(pkt) > 4

    def test_provider_stop(self):
        pkt = build_provider_stop(0x8001)
        assert len(pkt) > 0

    def test_alarm_frame(self):
        alarm = AlarmFrame(alarm_type=1, api=0, slot_number=1, subslot_number=1,
                            module_ident=0xDEAD, submodule_ident=0xBEEF,
                            alarm_specifier=1, alarm_data=b"\x00" * 8)
        pkt = build_alarm_frame(alarm)
        assert len(pkt) > 0


class TestDecode:
    def test_decode_dcp_identify(self):
        pkt = build_identify_request(xid=0xBEEF)
        parsed = parse_dcp_response(pkt)
        assert parsed is not None
        assert parsed["xid"] == 0xBEEF
        assert parsed["service_id"] == DCPServiceID.IDENTIFY

    def test_decode_set_name(self):
        pkt = build_set_name_request("test-plc", xid=42, permanent=True)
        parsed = parse_dcp_response(pkt)
        assert parsed is not None
        assert parsed["service_id"] == DCPServiceID.SET

    def test_rt_data_status_flags(self):
        rt = RTFrame(frame_id=0x8001, io_data=b"\x00" * 10,
                      data_status=DataStatus.normal_running())
        data = build_rt_frame(rt)
        ds = data[-2]
        assert ds & 0x10  # PROVIDER_RUN
        assert ds & 0x04  # DATA_VALID

    def test_provider_stop_flags(self):
        pkt = build_provider_stop(0x8001)
        ds = pkt[-2]
        assert not (ds & 0x10)  # PROVIDER_STOP (bit clear)


class TestFuzzResult:
    def test_fuzz_pcap_export(self, tmp_path):
        from profipwn.fuzzer import PROFINETFuzzer
        fuzzer = PROFINETFuzzer(output_dir=str(tmp_path / "fuzz"))
        cases = fuzzer.generate_dcp_fuzz_cases(10)
        pcap_path = str(tmp_path / "test.pcap")
        n = fuzzer.write_pcap(cases, pcap_path)
        assert n == len(cases)
        from profipwn.dissectors import read_pcap
        loaded = read_pcap(pcap_path)
        assert len(loaded) == len(cases)


class TestDissectors:
    def test_dissect_dcp_frame(self):
        from profipwn.dissectors import DissectedPacket
        dcp = build_identify_request(xid=0x1234)
        src = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        frame = build_ethernet_frame(DCP_MULTICAST_MAC, src, dcp)
        pkt = DissectedPacket(frame)
        assert "DCP" in pkt.summary
        assert len(pkt.layers) >= 2

    def test_pcap_write_read_roundtrip(self, tmp_path):
        from profipwn.dissectors import write_pcap, read_pcap
        frames = [b"\x00" * 14 + build_identify_request() for _ in range(3)]
        path = str(tmp_path / "test.pcap")
        write_pcap(frames, path)
        loaded = read_pcap(path)
        assert len(loaded) == 3
        for _, f in loaded:
            assert len(f) > 0
