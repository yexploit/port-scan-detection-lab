## Port Scan Detection Engineering Lab

This project builds a **Port Scan Detection Engineering Lab** where you:

- Perform multiple **Nmap** scan types from Kali against a lab target.
- Capture and analyze network traffic / logs.
- Develop **detection logic and SIEM queries** (Splunk or ELK) to identify reconnaissance while reducing false positives.

> **Purpose**: Defensive, educational research only. All scans must be performed in an isolated lab you fully control (e.g., virtual machines on a host-only/internal network).

---

### 1. Lab Overview

- **Attacker VM**: Kali Linux  
  - Tool: Nmap (various scan types: SYN, connect, UDP, version, etc.)

- **Target VM**: Linux or Metasploitable server  
  - Running typical services (SSH, HTTP, etc.)  
  - Exposed only on an internal/host-only network.

- **Collector / SIEM**:  
  - Splunk or ELK stack ingesting network or firewall logs (optional but recommended).  
  - PCAP-based analyzer in this repo for standalone detection.

Traffic is captured (e.g., with `tcpdump`/Wireshark) and can also be logged by firewall/IDS/Netflow tools for SIEM ingestion.

---

### 2. Repository Structure

- `portscan_detection_study.md`  
  Report-style documentation: introduction, methodology, scan types, detection strategies, SPL/ELK queries, results, and conclusion.

- `portscan_analyzer.py`  
  Scapy-based analyzer for PCAP or live traffic. Detects:
  - Hosts performing many connection attempts to **many ports** or **many hosts** in a short window.  
  - SYN-only patterns (common in stealth/SYN scans).  
  - Outputs alerts and writes a CSV of suspected scan events.

- `plot_portscan_events.py`  
  Matplotlib CLI dashboard that visualizes:
  - Number of ports probed over time.  
  - Top suspected scanning IPs.

- `splunk_elk_portscan_queries.txt`  
  Example detection queries for Splunk and ELK (Kibana/Lucene/KQL) to identify port scans from indexed flow/firewall/IDS logs.

---

### 3. Requirements

On the analysis host (or Kali):

```bash
sudo apt update
sudo apt install -y python3-pip
pip3 install scapy matplotlib
```

You also need:

- **Nmap** on Kali (already installed on most Kali images).
- **Wireshark** or `tcpdump` to capture PCAPs.  
- Optional: Splunk or ELK stack for SIEM-based detection and dashboards.

---

### 4. Quick Start

1. From Kali, run different Nmap scans against the target (on an isolated lab network).  
2. Capture traffic on the target or a monitoring node and save as `portscan_lab.pcap`.  
3. Copy the PCAP into this folder and run:

```bash
python3 portscan_analyzer.py -r portscan_lab.pcap
```

4. Review console alerts and the generated CSV (`portscan_events.csv`).  
5. Visualize activity:

```bash
python3 plot_portscan_events.py
```

6. If using Splunk or ELK, ingest your logs/flows and apply the example queries from `splunk_elk_portscan_queries.txt`.

For full methodology and academic write-up, see `portscan_detection_study.md`.

