# KEPT: Layer 1 (Data Collection Layer)

## What Layer 1 does
Captures live network traffic, groups packets into flows (conversations
between two endpoints), and computes flow-level statistical features from
each one. This output feeds Layer 2 (AI-based anomaly detection).

## Base paper (implemented directly)
Draper-Gil, G., Habibi Lashkari, A., Mamun, M. S. I., & Ghorbani, A. A. (2016).
Characterization of Encrypted and VPN Traffic Using Time-Related Features.
Proceedings of the 2nd International Conference on Information Systems
Security and Privacy (ICISSP 2016), pp. 407-414.
https://doi.org/10.5220/0005740704070414

This is the paper behind CICFlowMeter. It defines:
- Flow identification: a 5-tuple of source IP, source port, destination IP,
  destination port, and protocol
- Direction: whichever side sends the first packet is "forward", the reply
  side is "backward"
- Flow termination: TCP flows close on a FIN or RST flag; UDP flows close
  after a period of inactivity
- The standard set of flow-level statistical features (durations, packet
  counts, byte counts, inter-arrival times, flag counts, etc.)

Phase 1 (flow_extractor_baseline.py) implements this method exactly,
unmodified, as instructed by the supervisor before introducing any changes.

## Phase 1: flow_extractor_baseline.py
Captures live packets with Scapy and reproduces the base paper's method with
no modifications. Outputs the full standard feature set (34 features) to the
console for each closed flow: IP/port/protocol identifiers, flow duration,
forward/backward packet and byte counts, packet length statistics, flow and
per-direction inter-arrival time statistics, TCP flag counts, bytes/packets
per second, and active/idle period statistics.

## Phase 2: flow_extractor_kept.py
Takes the validated Phase 1 logic and applies our own modifications, per the
project proposal:

1. Feature trimming: cuts the full feature set down to our own 21-feature
   shortlist (see below), instead of outputting everything.
2. Timeout decision resolved: drops the proposal's original "5-second
   sliding window" idea in favour of the base paper's own FIN/RST-and-timeout
   closing rule (120-second inactivity timeout). This is supported by two
   recent papers: a 2025 paper arguing fixed window sizes are inefficient for
   representing sessions of varying length, and a 2024 paper using the same
   120-second timeout for the same real-time reasoning.
3. Configurable interface: accepts --iface so it can run on any network
   interface, not a hardcoded default.
4. Dual CSV output: writes both a raw feature CSV (full set, same as Phase 1)
   and a normalized CSV (the 21-feature shortlist, scaled 0-1 with
   MinMaxScaler), matching the "Feature Extraction: pandas / MinMaxScaler"
   step in our own architecture diagram.

## Our 21-feature shortlist (Phase 2) and why each is kept
Backed by three supporting papers:

Buczak, A. L., & Guven, E. (2016). A Survey of Data Mining and Machine
Learning Methods for Cyber Security Intrusion Detection. IEEE
Communications Surveys & Tutorials, 18(2), 1153-1176.
https://doi.org/10.1109/COMST.2015.2494502
Supports flag-based features as signature-relevant to detection.

Vinayakumar, R., Soman, K. P., Poornachandran, P., Alazab, M., & Jolfaei, A.
(2019). Deep Learning Approach for Intelligent Intrusion Detection System.
IEEE Access, 7, 41525-41550. https://doi.org/10.1109/ACCESS.2019.2895334
Supports keeping time/sequence-related (IAT) features for deep-learning
based detection.

Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018). Toward
Generating a New Intrusion Detection Dataset and Intrusion Traffic
Characterization. ICISSP 2018, pp. 108-116.
https://doi.org/10.5220/0006639801080116
Source of CIC-IDS2017 (the dataset our schema matches), flags IAT as a key
discriminator.

The 21 features, by category:
- Inter-arrival time (5): Flow IAT Mean, Flow IAT Std, Flow IAT Max,
  Flow IAT Min, Fwd IAT Mean
- Packet count / volume (4): Total Fwd Packets, Total Bwd Packets,
  Flow Bytes/s, Flow Packets/s
- Packet length (4): Fwd Packet Length Mean, Bwd Packet Length Mean,
  Fwd Packet Length Max, Bwd Packet Length Max
- TCP flags (5): SYN Flag Count, ACK Flag Count, FIN Flag Count,
  RST Flag Count, PSH Flag Count
- Header / activity (3): Active Mean, Idle Mean, Down/Up Ratio

## Test environment
3-VM lab on VMware (NAT networking, all VMs mutually reachable):
- Kali Linux: attacker role
- Ubuntu 24.04.4 LTS: monitor role (initial testing)
- Windows 10: victim/target role (final live test)

## Live test results
Both scripts were run against real live traffic passing through the Windows
10 VM (actual browsing/HTTPS activity, not synthetic test packets).

Phase 1: captured multiple real flows with the full feature set. Example:
a flow to 58.65.192.225:80 lasting 9.08 seconds, 51 forward / 36 backward
packets, correctly computed byte counts, packet length stats, IAT stats, and
flag counts (0 SYN, 87 ACK, 1 RST, 50 PSH).

Phase 2: captured 29 flows in the same session. Produced
kept_flows_raw.csv (full feature set, same schema as Phase 1) and
kept_flows_normalized.csv (21-feature shortlist, MinMax-scaled to 0-1,
confirmed correct: minimum values at 0.0, maximums at 1.0).
