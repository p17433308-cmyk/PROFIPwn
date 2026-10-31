# PROFIPwn — Offensive Security Framework for PROFINET Industrial Ethernet

**The first dedicated offensive security framework for PROFINET.**

PROFINET is the most widely deployed industrial Ethernet protocol, running on millions of Siemens and third-party PLCs, drives, and IO modules. DCP (Discovery and Configuration Protocol) operates on **Layer 2 with zero authentication** — no IP stack needed to attack. RT (Real-Time) process data frames carry sensor/actuator values with **no integrity or authentication**. PROFIPwn provides a complete attack toolkit for security researchers and ICS penetration testers.

## Why This Matters

| Protocol | What It Does | Security | Deployed In |
|----------|-------------|----------|-------------|
| **DCP** | Device discovery, name/IP assignment | None — unauthenticated Layer 2 | Every PROFINET device |
| **PROFINET RT** | Cyclic process data (sensor/actuator) | None — no auth, no integrity | Every PROFINET IO connection |
| **PROFINET Alarms** | Diagnostic/process alarms | None — spoofable | Every PROFINET device |

## Features

### Discovery
- **DCP Scanner** — Layer 2 device discovery without IP (raw sockets or Scapy)
- **Device Fingerprinting** — vendor ID, device ID, station name, roles (IO-Device/Controller/Supervisor)
- **Siemens Device Identification** — S7-1200/1500, ET 200SP/MP, SCALANCE, SINAMICS lookup table
- **JSON output** for integration with other tools

### Attacks — DCP (Layer 2)
- **Identity Spoofing** — change a device's station name (breaks IO-Controller connections)
- **IP Manipulation** — change device IP without auth (redirect traffic, isolate devices)
- **Factory Reset** — wipe all configuration (station name, IP, project assignment)
- **Name Collision** — set multiple devices to the same name (cascading IO failure)
- **DCP Flood** — overwhelm DCP processing (missed RT cycles, watchdog timeouts)

### Attacks — RT (Real-Time)
- **Process Data Injection** — inject crafted RT frames (manipulate sensor/actuator values)
- **Provider Stop** — tell IO-Controller the device stopped (forces safe state)
- **Data Invalid** — force substitute values (stale/default data, subtle disruption)
- **Alarm Flood** — exhaust alarm queue (legitimate alarms dropped)
- **Cycle Counter Desync** — inject future cycle counters (legitimate frames rejected as duplicates)

### Protocol Fuzzing
- **DCP Fuzzer** — invalid service IDs, oversized blocks, option/suboption enumeration, malformed lengths, boundary XIDs, random mutations
- **RT Fuzzer** — invalid frame IDs, oversized IO data, all data status combinations, transfer status values, alarm type fuzzing
- **Live network delivery** with crash detection (raw socket + DCP liveness probe)
- **pcap export** — write fuzz cases as Ethernet-framed pcap for Wireshark/replay
- **Subprocess fuzzing** — run cases against a target binary with crash/timeout detection

### Traffic Analysis
- **Packet Dissector** — decode DCP, RT, Alarm frames with full field breakdown
- **pcap read/write** — load and save standard pcap files
- **Live capture** — raw socket capture with frame ID filtering
- **Replay** — replay pcap at configurable speed with optional modification callback
- **Decode CLI** — dissect any PROFINET frame from hex on the command line

## Quick Start

```bash
pip install -e .

# Full demo (real packet construction, dissection, fuzzing, pcap — no network needed)
profipwn demo

# Discover PROFINET devices
profipwn scan -i eth0 --timeout 5
profipwn scan --json

# DCP attacks
profipwn attack dcp-spoof --target aa:bb:cc:dd:ee:ff --name "EVIL-PLC" --permanent
profipwn attack dcp-ip --target aa:bb:cc:dd:ee:ff --ip 0.0.0.0
profipwn attack factory-reset --target aa:bb:cc:dd:ee:ff
profipwn attack name-collision --name "collision-device" --count 50
profipwn attack dcp-flood --target aa:bb:cc:dd:ee:ff --count 1000

# RT attacks
profipwn attack rt-inject --target aa:bb:cc:dd:ee:ff --frame-id 0x8001 --data FF00FF00
profipwn attack rt-stop --target aa:bb:cc:dd:ee:ff --frame-id 0x8001
profipwn attack alarm-flood --target aa:bb:cc:dd:ee:ff --count 500
profipwn attack rt-desync --target aa:bb:cc:dd:ee:ff --frame-id 0x8001

# Fuzzing + pcap export
profipwn fuzz -m all -c 500 -o fuzz_output
profipwn fuzz -m dcp --pcap dcp_fuzz.pcap

# Traffic analysis
profipwn capture -i eth0 -d 10 -o capture.pcap
profipwn replay capture.pcap --dissect
profipwn decode "FEFE050000000001008000000002FF00"
```

## Architecture

```
profipwn/
├── protocols/
│   ├── profinet_dcp.py    # DCP build/parse (Identify, Set Name/IP, Factory Reset, Signal)
│   └── profinet_rt.py     # RT frames, Alarms, cycle generation
├── discovery/
│   └── scanner.py         # DCP scanner with device fingerprinting
├── attacks/
│   ├── dcp_attacks.py     # Identity spoof, IP manipulation, factory reset, flood
│   └── rt_attacks.py      # Process data injection, provider stop, alarm flood, desync
├── fuzzer.py              # Structure-aware fuzzer + live delivery + crash detection + pcap
├── dissectors.py          # Packet dissector + pcap read/write + capture + replay
└── cli.py                 # scan / attack / fuzz / capture / replay / decode / demo
```

## Tests

```bash
pytest tests/     # Protocol round-trips, DCP parsing, RT frames, dissectors, pcap
```

## Responsible Use

This tool is for **authorized security testing only**. Use it on:
- Your own test PLCs and bench setups
- Authorized ICS penetration testing engagements
- The built-in `demo` command (no network — real packet construction only)

PROFINET devices control physical processes — unauthorized testing can cause physical damage or safety hazards.

## References

- IEC 61158 / IEC 61784 — PROFINET specification
- AUTOSAR PROFINET System Description (Siemens, public)
- PROFINET Security Guideline (PI International)

## License

MIT
