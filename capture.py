"""
capture.py — Stage 1: Traffic Capture
======================================
Three real modes:
  • load_csv(path)       — CICFlowMeter-format CSV
  • load_pcap(path)      — PCAP / PCAPNG from Wireshark or tcpdump
  • capture_live(iface)  — Live sniffing (requires root/sudo)
"""

import os, sys, time
import numpy as np
import pandas as pd


def load_csv(path: str) -> pd.DataFrame:
    print(f"[Stage 1] Loading CSV: {path}")
    df = pd.read_csv(path, low_memory=False,
                     encoding="utf-8", encoding_errors="replace")
    df.columns = df.columns.str.strip()
    print(f"  Rows: {len(df):,}  |  Columns: {len(df.columns)}")
    return df


def load_pcap(path: str) -> pd.DataFrame:
    print(f"[Stage 1] Loading PCAP/PCAPNG: {path}")
    try:
        from scapy.all import rdpcap, PcapNgReader, PcapReader
    except ImportError:
        raise ImportError("scapy not installed. Run: pip install scapy")

    # Try PcapNgReader first (handles .pcapng), fall back to rdpcap
    packets = []
    try:
        ext = os.path.splitext(path)[1].lower()
        if ext == ".pcapng":
            with PcapNgReader(path) as reader:
                for pkt in reader:
                    packets.append(pkt)
        else:
            packets = list(rdpcap(path))
    except Exception:
        # Universal fallback
        try:
            packets = list(rdpcap(path))
        except Exception as e:
            raise RuntimeError(f"Cannot read file: {e}")

    print(f"  Packets read  : {len(packets):,}")

    if len(packets) == 0:
        print("  [!] No packets found in file.")
        return pd.DataFrame()

    df = _packets_to_df(packets)
    print(f"  Flows extracted: {len(df):,}")

    if len(df) == 0:
        print("  [!] No IP flows could be extracted.")
        print("      Make sure the capture contains IPv4/IPv6 traffic.")

    return df


def capture_live(interface: str, duration: int = 30) -> pd.DataFrame:
    print(f"[Stage 1] Live capture on {interface} for {duration}s ...")
    try:
        from scapy.all import sniff
    except ImportError:
        raise ImportError("scapy not installed. Run: pip install scapy")
    try:
        pkts = sniff(iface=interface, timeout=duration, filter="ip", store=True)
    except PermissionError:
        raise PermissionError(
            "Permission denied. Live capture requires root.\n"
            "Stop the server (Ctrl+C) and restart with: sudo python main.py"
        )
    except Exception as e:
        raise RuntimeError(f"Capture failed on {interface}: {e}")

    print(f"  Captured {len(pkts):,} packets")
    if len(pkts) == 0:
        return pd.DataFrame()
    df = _packets_to_df(list(pkts))
    print(f"  Flows: {len(df):,}")
    return df


# ── Packet → flow conversion ───────────────────────────────────────────────
def _packets_to_df(packets) -> pd.DataFrame:
    """
    Convert raw packets to bidirectional flow DataFrame.
    Handles Ethernet, IP-in-Ethernet, raw IP, and other encapsulations.
    """
    from scapy.all import IP, IPv6, TCP, UDP, Ether

    flows = {}
    skipped = 0

    for pkt in packets:
        # Extract IP layer — handle various encapsulations
        ip_pkt = None
        if pkt.haslayer(IP):
            ip_pkt = pkt[IP]
            proto  = int(ip_pkt.proto)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
        elif pkt.haslayer(IPv6):
            ip_pkt = pkt[IPv6]
            proto  = int(ip_pkt.nh)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
        else:
            skipped += 1
            continue   # non-IP packet, skip

        # Transport layer
        if pkt.haslayer(TCP):
            sp    = pkt[TCP].sport
            dp    = pkt[TCP].dport
            flags = int(pkt[TCP].flags)
            win   = pkt[TCP].window
        elif pkt.haslayer(UDP):
            sp    = pkt[UDP].sport
            dp    = pkt[UDP].dport
            flags = win = 0
        else:
            sp = dp = flags = win = 0

        fk = (src_ip, dst_ip, sp, dp, proto)
        rk = (dst_ip, src_ip, dp, sp, proto)

        if   fk in flows: key, fwd = fk, True
        elif rk in flows: key, fwd = rk, False
        else:
            flows[fk] = {
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": sp, "dst_port": dp, "proto": proto,
                "t0": float(pkt.time), "t1": float(pkt.time),
                "F": [], "B": [], "fi": [], "bi": [],
                "fin":0,"syn":0,"rst":0,"psh":0,
                "ack":0,"urg":0,"cwe":0,"ece":0,
                "wf": -1, "wb": -1,
            }
            key, fwd = fk, True

        fl  = flows[key]
        pl  = len(pkt)
        ts  = float(pkt.time)
        fl["t1"] = max(fl["t1"], ts)

        if fwd:
            if fl["F"]: fl["fi"].append(ts - fl["F"][-1][1])
            fl["F"].append((pl, ts))
            if fl["wf"] == -1 and proto == 6: fl["wf"] = win
        else:
            if fl["B"]: fl["bi"].append(ts - fl["B"][-1][1])
            fl["B"].append((pl, ts))
            if fl["wb"] == -1 and proto == 6: fl["wb"] = win

        if flags & 0x01: fl["fin"] += 1
        if flags & 0x02: fl["syn"] += 1
        if flags & 0x04: fl["rst"] += 1
        if flags & 0x08: fl["psh"] += 1
        if flags & 0x10: fl["ack"] += 1
        if flags & 0x20: fl["urg"] += 1
        if flags & 0x40: fl["cwe"] += 1
        if flags & 0x80: fl["ece"] += 1

    if skipped:
        print(f"  Skipped {skipped:,} non-IP packets")

    if not flows:
        return pd.DataFrame()

    return pd.DataFrame([_flow_row(fl) for fl in flows.values()])


def _flow_row(fl: dict) -> dict:
    F  = [p[0] for p in fl["F"]]
    B  = [p[0] for p in fl["B"]]
    A  = F + B
    at = sorted([p[1] for p in fl["F"]] + [p[1] for p in fl["B"]])
    ia = [at[i+1]-at[i] for i in range(len(at)-1)]
    dur = max((fl["t1"]-fl["t0"])*1e6, 1.0)

    def s(x):  return float(np.std(x))  if x else 0.0
    def m(x):  return float(np.mean(x)) if x else 0.0
    def mx(x): return float(np.max(x))  if x else 0.0
    def mn(x): return float(np.min(x))  if x else 0.0
    def sm(x): return float(np.sum(x))  if x else 0.0

    return {
        "Source IP": fl["src_ip"], "Destination IP": fl["dst_ip"],
        "Source Port": fl["src_port"], "Destination Port": fl["dst_port"],
        "Protocol": fl["proto"],
        "Flow Duration": dur,
        "Total Fwd Packets": len(F), "Total Backward Packets": len(B),
        "Total Length of Fwd Packets": sm(F), "Total Length of Bwd Packets": sm(B),
        "Fwd Packet Length Max": mx(F), "Fwd Packet Length Min": mn(F),
        "Fwd Packet Length Mean": m(F), "Fwd Packet Length Std": s(F),
        "Bwd Packet Length Max": mx(B), "Bwd Packet Length Min": mn(B),
        "Bwd Packet Length Mean": m(B), "Bwd Packet Length Std": s(B),
        "Flow Bytes/s": sm(A)/(dur/1e6), "Flow Packets/s": len(A)/(dur/1e6),
        "Flow IAT Mean": m(ia), "Flow IAT Std": s(ia),
        "Flow IAT Max": mx(ia), "Flow IAT Min": mn(ia),
        "Fwd IAT Total": sm(fl["fi"]), "Fwd IAT Mean": m(fl["fi"]),
        "Fwd IAT Std": s(fl["fi"]), "Fwd IAT Max": mx(fl["fi"]),
        "Fwd IAT Min": mn(fl["fi"]),
        "Bwd IAT Total": sm(fl["bi"]), "Bwd IAT Mean": m(fl["bi"]),
        "Bwd IAT Std": s(fl["bi"]), "Bwd IAT Max": mx(fl["bi"]),
        "Bwd IAT Min": mn(fl["bi"]),
        "Fwd PSH Flags": fl["psh"], "Bwd PSH Flags": 0,
        "Fwd URG Flags": fl["urg"], "Bwd URG Flags": 0,
        "Fwd Header Length": len(F)*20, "Bwd Header Length": len(B)*20,
        "Fwd Packets/s": len(F)/(dur/1e6), "Bwd Packets/s": len(B)/(dur/1e6),
        "Min Packet Length": mn(A), "Max Packet Length": mx(A),
        "Packet Length Mean": m(A), "Packet Length Std": s(A),
        "Packet Length Variance": float(np.var(A)) if A else 0.0,
        "FIN Flag Count": fl["fin"], "SYN Flag Count": fl["syn"],
        "RST Flag Count": fl["rst"], "PSH Flag Count": fl["psh"],
        "ACK Flag Count": fl["ack"], "URG Flag Count": fl["urg"],
        "CWE Flag Count": fl["cwe"], "ECE Flag Count": fl["ece"],
        "Down/Up Ratio": len(B)/max(len(F), 1),
        "Average Packet Size": m(A),
        "Avg Fwd Segment Size": m(F), "Avg Bwd Segment Size": m(B),
        "Fwd Avg Bytes/Bulk": 0, "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0, "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0, "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": len(F), "Subflow Fwd Bytes": sm(F),
        "Subflow Bwd Packets": len(B), "Subflow Bwd Bytes": sm(B),
        "Init_Win_bytes_forward": fl["wf"],
        "Init_Win_bytes_backward": fl["wb"],
        "act_data_pkt_fwd": len(F), "min_seg_size_forward": mn(F),
        "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0,
        "Idle Mean": 0,  "Idle Std": 0,  "Idle Max": 0,  "Idle Min": 0,
    }
