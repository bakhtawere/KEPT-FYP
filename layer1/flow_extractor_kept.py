"""KEPT Layer 1 - Phase 2. Trimmed features + normalization on top of the Phase 1 baseline."""

import argparse
import os
import time
import statistics
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

FLOW_TIMEOUT = 120.0
ACTIVE_GAP_THRESHOLD = 1.0

OUTPUT_DIR = os.path.expanduser("~/kept")
RAW_CSV = os.path.join(OUTPUT_DIR, "kept_flows_raw.csv")
NORMALIZED_CSV = os.path.join(OUTPUT_DIR, "kept_flows_normalized.csv")

SHORTLIST_FEATURES = [
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Mean",
    "Total Fwd Packets", "Total Bwd Packets", "Flow Bytes/s", "Flow Packets/s",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean",
    "Fwd Packet Length Max", "Bwd Packet Length Max",
    "SYN Flag Count", "ACK Flag Count", "FIN Flag Count",
    "RST Flag Count", "PSH Flag Count",
    "Active Mean", "Idle Mean", "Down/Up Ratio",
]


class Flow:
    def __init__(self, key, first_packet_time, proto):
        self.key = key
        self.proto = proto
        self.start_time = first_packet_time
        self.last_seen = first_packet_time
        self.packets = []
        self.forward_src = key[0]
        self.forward_sport = key[1]
        self.closed = False

    def add_packet(self, timestamp, direction, length, flags):
        self.packets.append((timestamp, direction, length, flags))
        self.last_seen = timestamp

    def duration(self):
        return max(self.last_seen - self.start_time, 0.0)


def make_flow_key(pkt):
    ip = pkt[IP]
    proto = ip.proto
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        return None, None
    a = (ip.src, sport)
    b = (ip.dst, dport)
    if a <= b:
        canon = (a[0], a[1], b[0], b[1], proto)
    else:
        canon = (b[0], b[1], a[0], a[1], proto)
    return canon, (ip.src, sport, ip.dst, dport, proto)


def get_tcp_flags(pkt):
    if TCP not in pkt:
        return {}
    f = pkt[TCP].flags
    return {
        "SYN": 1 if f & 0x02 else 0,
        "ACK": 1 if f & 0x10 else 0,
        "FIN": 1 if f & 0x01 else 0,
        "RST": 1 if f & 0x04 else 0,
        "PSH": 1 if f & 0x08 else 0,
        "URG": 1 if f & 0x20 else 0,
    }


class FlowTable:
    def __init__(self, on_flow_closed):
        self.flows = {}
        self.on_flow_closed = on_flow_closed

    def process_packet(self, pkt):
        if IP not in pkt:
            return
        canon_key, actual_dir_tuple = make_flow_key(pkt)
        if canon_key is None:
            return
        now = time.time()
        length = len(pkt)
        flags = get_tcp_flags(pkt)
        proto = canon_key[4]

        if canon_key not in self.flows:
            flow = Flow(canon_key, now, proto)
            flow.forward_src = actual_dir_tuple[0]
            flow.forward_sport = actual_dir_tuple[1]
            self.flows[canon_key] = flow
        else:
            flow = self.flows[canon_key]

        direction = "fwd" if actual_dir_tuple[0] == flow.forward_src and \
                              actual_dir_tuple[1] == flow.forward_sport else "bwd"
        flow.add_packet(now, direction, length, flags)

        if proto == 6 and (flags.get("FIN") or flags.get("RST")):
            self._close_flow(canon_key)

        self._expire_idle_flows(now)

    def _expire_idle_flows(self, now):
        for key in list(self.flows.keys()):
            flow = self.flows[key]
            if not flow.closed and (now - flow.last_seen) > FLOW_TIMEOUT:
                self._close_flow(key)

    def _close_flow(self, key):
        flow = self.flows.pop(key, None)
        if flow and len(flow.packets) > 0:
            flow.closed = True
            self.on_flow_closed(compute_features(flow))


def _stats(values):
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    return (
        sum(values) / len(values),
        statistics.pstdev(values) if len(values) > 1 else 0.0,
        max(values),
        min(values),
    )


def compute_features(flow):
    pkts = flow.packets
    duration = flow.duration()
    fwd = [p for p in pkts if p[1] == "fwd"]
    bwd = [p for p in pkts if p[1] == "bwd"]
    fwd_lengths = [p[2] for p in fwd]
    bwd_lengths = [p[2] for p in bwd]
    fwd_mean, fwd_std, fwd_max, fwd_min = _stats(fwd_lengths)
    bwd_mean, bwd_std, bwd_max, bwd_min = _stats(bwd_lengths)

    all_times = sorted(p[0] for p in pkts)
    iats = [t2 - t1 for t1, t2 in zip(all_times[:-1], all_times[1:])]
    iat_mean, iat_std, iat_max, iat_min = _stats(iats)

    fwd_times = sorted(p[0] for p in fwd)
    fwd_iats = [t2 - t1 for t1, t2 in zip(fwd_times[:-1], fwd_times[1:])]
    fwd_iat_mean, _, _, _ = _stats(fwd_iats)

    total_bytes = sum(p[2] for p in pkts)
    total_packets = len(pkts)

    flag_totals = defaultdict(int)
    for _, _, _, flags in pkts:
        for name, val in flags.items():
            flag_totals[name] += val

    active_periods, idle_periods = [], []
    for gap in iats:
        (idle_periods if gap > ACTIVE_GAP_THRESHOLD else active_periods).append(gap)
    act_mean, _, _, _ = _stats(active_periods)
    idle_mean, _, _, _ = _stats(idle_periods)

    return {
        "Src IP": flow.key[0], "Src Port": flow.key[1],
        "Dst IP": flow.key[2], "Dst Port": flow.key[3], "Protocol": flow.proto,
        "Flow Duration": round(duration, 6),
        "Total Fwd Packets": len(fwd), "Total Bwd Packets": len(bwd),
        "Total Length of Fwd Packets": sum(fwd_lengths),
        "Total Length of Bwd Packets": sum(bwd_lengths),
        "Fwd Packet Length Mean": round(fwd_mean, 3), "Fwd Packet Length Std": round(fwd_std, 3),
        "Fwd Packet Length Max": fwd_max, "Fwd Packet Length Min": fwd_min,
        "Bwd Packet Length Mean": round(bwd_mean, 3), "Bwd Packet Length Std": round(bwd_std, 3),
        "Bwd Packet Length Max": bwd_max, "Bwd Packet Length Min": bwd_min,
        "Flow Bytes/s": round(total_bytes / duration, 3) if duration > 0 else 0.0,
        "Flow Packets/s": round(total_packets / duration, 3) if duration > 0 else 0.0,
        "Flow IAT Mean": round(iat_mean, 6), "Flow IAT Std": round(iat_std, 6),
        "Flow IAT Max": round(iat_max, 6), "Flow IAT Min": round(iat_min, 6),
        "Fwd IAT Mean": round(fwd_iat_mean, 6),
        "SYN Flag Count": flag_totals.get("SYN", 0), "ACK Flag Count": flag_totals.get("ACK", 0),
        "FIN Flag Count": flag_totals.get("FIN", 0), "RST Flag Count": flag_totals.get("RST", 0),
        "PSH Flag Count": flag_totals.get("PSH", 0), "URG Flag Count": flag_totals.get("URG", 0),
        "Down/Up Ratio": round(len(bwd) / len(fwd), 3) if fwd else 0.0,
        "Average Packet Size": round(total_bytes / total_packets, 3) if total_packets else 0.0,
        "Active Mean": round(act_mean, 6), "Idle Mean": round(idle_mean, 6),
    }


def main():
    parser = argparse.ArgumentParser(description="KEPT Layer 1 - Phase 2")
    parser.add_argument("--iface", required=True, help="Network interface to sniff on")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    all_flows = []

    def on_closed(features):
        all_flows.append(features)
        print(f"\n--- FLOW CLOSED ({len(all_flows)} total) ---")
        print(f"  {features['Src IP']}:{features['Src Port']} -> "
              f"{features['Dst IP']}:{features['Dst Port']} "
              f"(proto {features['Protocol']}, {features['Flow Duration']}s)")
        _write_outputs(all_flows)

    print("KEPT Layer 1 - Phase 2 (trimmed feature set + normalization)")
    print(f"Listening on {args.iface}... (Ctrl+C to stop)")
    print(f"Output: {RAW_CSV} and {NORMALIZED_CSV}\n")

    table = FlowTable(on_flow_closed=on_closed)

    def handle(pkt):
        table.process_packet(pkt)

    try:
        sniff(iface=args.iface, prn=handle, store=False)
    except KeyboardInterrupt:
        print("\nStopped. Final write...")
        _write_outputs(all_flows)


def _write_outputs(all_flows):
    if not all_flows:
        return
    df = pd.DataFrame(all_flows)
    df.to_csv(RAW_CSV, index=False)

    trimmed = df[[c for c in SHORTLIST_FEATURES if c in df.columns]].copy()
    if len(trimmed) > 0:
        scaler = MinMaxScaler()
        if len(trimmed) > 1:
            trimmed[trimmed.columns] = scaler.fit_transform(trimmed)
        else:
            trimmed[trimmed.columns] = 0.0
    trimmed.to_csv(NORMALIZED_CSV, index=False)


if __name__ == "__main__":
    main()
